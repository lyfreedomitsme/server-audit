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
footer = source.read_text().split("# ---------- Public paste preparation", 1)[1]
definitions = source.read_text().split("audit_number() {", 1)[1].split("\nAUDIT_TIMEOUT=", 1)[0]

with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    report = root / "report"
    report.write_text("redacted test report\nsecond line\n")
    script = root / "footer.sh"
    script.write_text(
        'set -uo pipefail\nhas() { command -v "$1" >/dev/null 2>&1; }\n'
        + "audit_number() {" + definitions
        + '\nFINAL="$TEST_REPORT"\nAUDIT_REPORT_LINES=1\nAUDIT_TMP="$TEST_DIR"\n# ---------- Public paste preparation'
        + footer
    )
    nc = root / "nc"
    nc.write_text('''#!/bin/bash
if [ "$1" = "-h" ]; then printf '%s\\n' ' -N shutdown after EOF' ' -w timeout'; exit 1; fi
printf '%s\\n' "$*" > "$TEST_NC_ARGS"
cat > "$TEST_UPLOAD"
if [ "${TEST_NO_REPLY:-0}" = 1 ]; then echo "fixture connection timeout" >&2; exit 124; fi
printf '%s\\r\\n\\000' "${TEST_URL:-https://termbin.com/test123}"
''')
    nc.chmod(0o700)
    curl = root / "curl"
    curl.write_text("""#!/usr/bin/env python3
import json, os, sys, time
from pathlib import Path
args=sys.argv[1:]
if '%{remote_ip}' in args:
    if os.environ.get('TEST_PREFLIGHT_FAIL') == '1': sys.exit(28)
    assert '-4' in args and '--noproxy' in args and args[-1]=='https://termbin.com/',args
    print('192.0.2.123',end='')
    sys.exit(0)
assert '-4' in args and '--resolve' in args and 'termbin.com:443:192.0.2.123' in args,args
p=Path(os.environ['TEST_EVENTS'])
prev=[json.loads(i) for i in p.read_text().splitlines()] if p.exists() else []
method='POST' if '-X' in args and args[args.index('-X')+1]=='POST' else 'GET'
attempt=1+sum(i['method']==method for i in prev)
scenario=os.environ.get('TEST_SCENARIO','success')
if scenario=='retry':
    code=('503' if method=='POST' else '200') if attempt==1 else ('204' if method=='POST' else '404')
elif scenario=='failure':
    # Real Termbin can refuse deletion while returning a successful HTTP status.
    code='200'
elif scenario=='timeout':
    code='000'
else:
    code='204' if method=='POST' else ('410' if scenario=='gone' else '404')
event={'time':time.monotonic(),'method':method,'attempt':attempt,'code':code,'args':args}
with p.open('a') as f: f.write(json.dumps(event)+'\\n')
if method=='POST':
    # JSON false may be returned with HTTP 200: the GET must decide visibility.
    print(json.dumps({'deleted':code=='204'}))
print(code,end='')
sys.exit(28 if code=='000' else 0)
""")
    curl.chmod(0o700)
    upload = root / "uploaded"
    events = root / "events"
    status = root / "paste-delete-status"
    nc_args = root / "nc-args"
    base = dict(os.environ)
    for key in ("PASTE", "PASTE_TTL", "SKIP_NET"):
        base.pop(key, None)
    base.update(PATH=str(root)+":"+base["PATH"],TEST_REPORT=str(report),TEST_DIR=str(root),
                TEST_UPLOAD=str(upload),TEST_EVENTS=str(events),TEST_NC_ARGS=str(nc_args),PASTE_TTL="1")

    def reset():
        for p in (upload, events, status, nc_args):
            p.unlink(missing_ok=True)
    def event_list():
        return [json.loads(row) for row in events.read_text().splitlines()] if events.exists() else []

    def interactive(answer, extra=None, limit=35, interrupt_on_link=False):
        env=base | (extra or {})
        pid, fd = pty.fork()
        if pid == 0:
            os.execvpe("bash", ["bash", "-c", 'cat "$1" | bash', "bash", str(script)], env)
        output=bytearray()
        answers = [answer] if isinstance(answer, str) else answer
        sent = 0
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
                if output.count(b"y/N:") > sent:
                    assert sent < len(answers), output
                    assert not upload.exists(), "upload before valid confirmation"
                    sent_at=time.monotonic()
                    choice = answers[sent]
                    os.write(fd, b"\x04" if choice is None else choice.encode()+b"\n")
                    sent += 1
                if b"https://termbin.com/test123" in output and link_at is None:
                    link_at=time.monotonic()
                    if interrupt_on_link:
                        assert status.exists() and "DELETE_WORKER_READY" in status.read_text()
                        os.write(fd,b"\x03")
            else:
                os.kill(pid,9)
                raise AssertionError("interactive test timed out")
        finally:
            os.close(fd)
            os.waitpid(pid,0)
        assert sent_at is not None and sent == len(answers),output
        return output.decode(errors="replace"),sent_at,link_at

    reset()
    result,_,_=interactive("n")
    assert not upload.exists() and not events.exists()
    print("PASS: interactive n does not publish",flush=True)
    for answers in (["N"], [""], [None], ["н", "abc", "yes", " ", " y", "n"], ["yY", "no", ""]):
        reset()
        result,_,_=interactive(answers)
        assert not upload.exists() and not events.exists(), result
        assert result.count("y/N:") == len(answers), result
        assert result.count("Введите y или N") == len(answers)-1, result
    print("PASS: malformed inputs re-prompt; n/N, empty Enter and EOF decline",flush=True)
    reset()
    result,_,_=interactive(["н", "wrong", "Y"],{"PASTE_TTL":"1"})
    assert result.count("y/N:") == 3 and upload.exists() and len(event_list()) == 2
    print("PASS: uppercase Y after multiple invalid answers publishes once",flush=True)
    reset()
    # Real 15-second wall-clock measurement, with mocked Termbin HTTP responses.
    real_ttl_env=base.copy()
    real_ttl_env.pop("PASTE_TTL")
    # Replace inherited base TTL by an explicit identical default for the test.
    result,start,link=interactive("y",{"PASTE_TTL":"15"})
    ev=event_list()
    assert link is not None and link-start<3, "link not immediate"
    assert upload.read_text()=="redacted test report\n", "wrong payload"
    assert "-N -w 15 192.0.2.123 9999" in nc_args.read_text()
    assert [e["method"] for e in ev]==["POST","GET"], ev
    assert ev[0]["time"]-link>=14.5, ev
    assert ev[0]["time"]-link<19, ev
    assert ev[0]["args"][-1]=="https://termbin.com/delete?slug=test123",ev
    assert ev[1]["args"][-1]=="https://termbin.com/test123",ev
    assert "[OK]" in result and "HTTP 404" in result and "deleted=true" in result, result
    print(f"PASS: link after {link-start:.2f}s, delete after {ev[0]['time']-link:.2f}s, confirmed GET 404",flush=True)
    for scenario,expected,number in (("retry","[OK]",4),("failure","НЕ подтверждено",6),("timeout","НЕ подтверждено",6),("gone","HTTP 410",2)):
        reset()
        result,_,_=interactive("y",{"TEST_SCENARIO":scenario})
        ev=event_list()
        assert len(ev)==number,(scenario,ev)
        assert expected in result,(scenario,result)
        if scenario in ("failure","timeout"): assert "[OK]" not in result,result
        if scenario=="failure": assert "deleted=false" in result,result
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
    result,_,_=interactive("y",{"TEST_URL":"http://termbin.com/test123","PASTE_TTL":"1"})
    assert "https://termbin.com/test123" in result and len(event_list())==2
    reset()
    result,_,_=interactive("y",{"TEST_NO_REPLY":"1"})
    assert upload.exists() and not events.exists()
    assert "nc exit=124" in result and "ответ=0 байт" in result
    print("PASS: EOF flags, NUL/CRLF response, HTTP URL normalization, timeout evidence",flush=True)
    reset()
    # Big report must become a bounded, marked, still text-readable paste.
    report.write_text("## INCIDENT — WEB STACK / VHOST ROUTING / UPSTREAM HEALTH\n"+ "detail "*2000+"\n"+"FRONT https://example.test/ => HTTP 502 [SERVER ERROR]\n"+"## INCIDENT — BOOT HISTORY / OOM / BEFORE AND AFTER REBOOT\n"+ "line filler "*2000+"\n"+"Out of memory: Killed process 123 (mariadbd)\n")
    # The fixture normally caps one line; increase it for this scenario.
    original_script=script.read_text()
    script.write_text(original_script.replace("AUDIT_REPORT_LINES=1","AUDIT_REPORT_LINES=5000"))
    result,_,_=interactive("y",{"PASTE_MAX_BYTES":"4096","PASTE_TTL":"1"})
    payload=upload.read_text()
    assert len(payload.encode())<=4096 and "[COMPACT TERMBIN REPORT]" in payload
    assert "HTTP_SITE example.test FRONT_https=502" in payload and "Out of memory" in payload
    assert "КОМПАКТНАЯ" in result and len(event_list())==2
    reset()
    run=subprocess.run(["bash",str(script)],env=base|{"PASTE":"1","PASTE_MODE":"full","PASTE_MAX_BYTES":"4096"},capture_output=True,timeout=5)
    assert not upload.exists() and "публикация отменена" in run.stdout.decode()
    print("PASS: oversized report compact/marked; full-only mode refuses without upload",flush=True)
    report.write_text("redacted test report\nsecond line\n")
    script.write_text(original_script)
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
    reset()
    result,_,_=interactive("y",{"TEST_PREFLIGHT_FAIL":"1"})
    assert not upload.exists() and not events.exists() and "IPv4 Termbin" in result
    print("PASS: failed same-destination preflight refuses to upload",flush=True)
    # The link must only become visible after the background worker is running.
    # Test actual terminal Ctrl+C, and simulate a BusyBox-style setsid lacking --wait.
    import shutil
    real_setsid=shutil.which("setsid")
    assert real_setsid
    script.write_text(original_script.replace('AUDIT_TMP="$TEST_DIR"\n',
        """AUDIT_TMP="$TEST_DIR"
trap 'rm -f "$AUDIT_TMP/paste-delete-status"' EXIT
trap 'exit 130' INT
"""))
    for busybox_style in (False,True):
        reset()
        if busybox_style:
            wrapper=root/"setsid"
            wrapper.write_text('#!/bin/bash\nif [ "$1" = "--help" ]; then echo "BusyBox setsid [-c] PROG ARGS"; exit 0; fi\nexec '+real_setsid+' "$@"\n')
            wrapper.chmod(0o700)
        result,_,link=interactive("y",{"PASTE_TTL":"2"},interrupt_on_link=True)
        assert link is not None
        deadline=time.monotonic()+5
        while len(event_list())<2 and time.monotonic()<deadline: time.sleep(.05)
        assert len(event_list())==2,(busybox_style,result,event_list())
        print("PASS: immediate Ctrl+C after displayed URL; worker completed", "BusyBox-style" if busybox_style else "util-linux",flush=True)

