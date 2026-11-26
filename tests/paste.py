#!/usr/bin/env python3
"""Test upload, timed verification, retries, errors and opt-outs without external network."""
import errno
import json
import os
from pathlib import Path
import pty
import select
import subprocess
import tempfile
import time

source = Path(__file__).resolve().parents[1] / "server_audit.sh"
footer = source.read_text().split("# Optional legacy public paste.", 1)[1]
definitions = source.read_text().split("audit_number() {", 1)[1].split("\nAUDIT_TIMEOUT=", 1)[0]

with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    report = root / "report"
    report.write_text("redacted test report\nsecond line\n")
    script = root / "footer.sh"
    script.write_text(
        'set -uo pipefail\nhas() { command -v "$1" >/dev/null 2>&1; }\n'
        + "audit_number() {" + definitions
        + '\nFINAL="$TEST_REPORT"\nAUDIT_REPORT_LINES=1\nAUDIT_TMP="$TEST_DIR"\n# Optional legacy public paste.'
        + footer
    )
    nc = root / "nc"
    nc.write_text('#!/bin/bash\ncat > "$TEST_UPLOAD"\nprintf "%s\\n" "${TEST_URL:-https://termbin.com/test123}"\n')
    nc.chmod(0o700)
    curl = root / "curl"
    curl.write_text("""#!/usr/bin/env python3
import json, os, sys, time
from pathlib import Path
args=sys.argv[1:]
p=Path(os.environ['TEST_EVENTS'])
prev=[json.loads(i) for i in p.read_text().splitlines()] if p.exists() else []
method='POST' if '-X' in args and args[args.index('-X')+1]=='POST' else 'GET'
attempt=1+sum(i['method']==method for i in prev)
scenario=os.environ.get('TEST_SCENARIO','success')
if scenario=='retry':
    code=('503' if method=='POST' else '200') if attempt==1 else ('204' if method=='POST' else '404')
elif scenario=='failure':
    code='503' if method=='POST' else '403'
elif scenario=='timeout':
    code='000'
else:
    code='204' if method=='POST' else ('410' if scenario=='gone' else '404')
event={'time':time.monotonic(),'method':method,'attempt':attempt,'code':code,'args':args}
with p.open('a') as f: f.write(json.dumps(event)+'\\n')
print(code,end='')
sys.exit(28 if code=='000' else 0)
""")
    curl.chmod(0o700)
    upload = root / "uploaded"
    events = root / "events"
    status = root / "paste-delete-status"
    base = dict(os.environ)
    for key in ("PASTE", "PASTE_TTL", "SKIP_NET"):
        base.pop(key, None)
    base.update(PATH=str(root)+":"+base["PATH"],TEST_REPORT=str(report),TEST_DIR=str(root),
                TEST_UPLOAD=str(upload),TEST_EVENTS=str(events),PASTE_TTL="1")

    def reset():
        for p in (upload, events, status):
            p.unlink(missing_ok=True)
    def event_list():
        return [json.loads(row) for row in events.read_text().splitlines()] if events.exists() else []

    def interactive(answer, extra=None, limit=35):
        env=base | (extra or {})
        pid, fd = pty.fork()
        if pid == 0:
            os.execvpe("bash", ["bash", "-c", 'cat "$1" | bash', "bash", str(script)], env)
        output=bytearray()
        sent_at=None
        link_at=None
        deadline=time.monotonic()+limit
        try:
            while time.monotonic()<deadline:
                readable,_,_=select.select([fd],[],[],0.2)
                if not readable: continue
                try: part=os.read(fd,4096)
                except OSError as exc:
                    if exc.errno==errno.EIO: break
                    raise
                if not part: break
                output.extend(part)
                if b"y/N:" in output and sent_at is None:
                    sent_at=time.monotonic()
                    os.write(fd,answer.encode()+b"\n")
                if b"https://termbin.com/test123" in output and link_at is None:
                    link_at=time.monotonic()
            else:
                os.kill(pid,9)
                raise AssertionError("interactive test timed out")
        finally:
            os.close(fd)
            os.waitpid(pid,0)
        assert sent_at is not None,output
        return output.decode(errors="replace"),sent_at,link_at

    reset()
    result,_,_=interactive("n")
    assert not upload.exists() and not events.exists()
    print("PASS: interactive n does not publish",flush=True)
    reset()
    # Real 15-second wall-clock measurement, with mocked Termbin HTTP responses.
    real_ttl_env=base.copy()
    real_ttl_env.pop("PASTE_TTL")
    # Replace inherited base TTL by an explicit identical default for the test.
    result,start,link=interactive("y",{"PASTE_TTL":"15"})
    ev=event_list()
    assert link is not None and link-start<3, "link not immediate"
    assert upload.read_text()=="redacted test report\n", "wrong payload"
    assert [e["method"] for e in ev]==["POST","GET"], ev
    assert ev[0]["time"]-link>=14.5, ev
    assert ev[0]["time"]-link<19, ev
    assert ev[0]["args"][-1]=="https://termbin.com/delete?slug=test123",ev
    assert ev[1]["args"][-1]=="https://termbin.com/test123",ev
    assert "[OK]" in result and "HTTP 404" in result, result
    print(f"PASS: link after {link-start:.2f}s, delete after {ev[0]['time']-link:.2f}s, confirmed GET 404",flush=True)
    for scenario,expected,number in (("retry","[OK]",4),("failure","НЕ подтверждено",6),("timeout","НЕ подтверждено",6),("gone","HTTP 410",2)):
        reset()
        result,_,_=interactive("y",{"TEST_SCENARIO":scenario})
        ev=event_list()
        assert len(ev)==number,(scenario,ev)
        assert expected in result,(scenario,result)
        if scenario in ("failure","timeout"): assert "[OK]" not in result,result
        print(f"PASS: {scenario} ({len(ev)} HTTP calls)",flush=True)
    reset()
    for extra in ({},{"PASTE":"0"},{"PASTE":"1","SKIP_NET":"1"}):
        run=subprocess.run(["bash",str(script)],env=base|extra,capture_output=True,timeout=5)
        assert run.returncode==0 and not upload.exists() and not events.exists()
    print("PASS: non-interactive default and explicit opt-outs",flush=True)
    reset()
    result,_,_=interactive("y",{"TEST_URL":"https://evil.invalid/slug"})
    assert not events.exists() and "Нет корректной ссылки" in result
    reset()
    result,_,_=interactive("y",{"PASTE_TTL":"0"})
    assert upload.exists() and not events.exists() and "отключено" in result
    print("PASS: invalid response and explicit TTL disable",flush=True)
    reset()
    # Disconnect the waiting process after the detached worker is launched.
    proc=subprocess.Popen(["bash",str(script)],env=base|{"PASTE":"1","PASTE_TTL":"2"},
                          stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
    deadline=time.monotonic()+3
    while not status.exists() and time.monotonic()<deadline: time.sleep(.02)
    assert status.exists(), "worker did not start"
    proc.terminate()
    proc.wait(timeout=4)
    deadline=time.monotonic()+5
    while len(event_list())<2 and time.monotonic()<deadline: time.sleep(.05)
    assert len(event_list())==2,"worker died with parent"
    print("PASS: detached worker continues after parent termination",flush=True)
