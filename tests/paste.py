#!/usr/bin/env python3
"""Regression test for the interactive upload footer. No real network calls."""
import errno
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
        + "audit_number() {"
        + definitions
        + '\nFINAL="$TEST_REPORT"\nAUDIT_REPORT_LINES=1\n# Optional legacy public paste.'
        + footer
    )
    nc = root / "nc"
    nc.write_text('#!/bin/bash\ncat > "$TEST_UPLOAD"\nprintf "https://termbin.com/test123\\n"\n')
    nc.chmod(0o700)
    curl = root / "curl"
    curl.write_text('#!/bin/bash\nprintf "%s\\n" "$*" >> "$TEST_DELETE"\n')
    curl.chmod(0o700)
    upload = root / "uploaded"
    deleted = root / "deleted"
    env = dict(os.environ)
    for key in ("PASTE", "PASTE_TTL", "SKIP_NET"):
        env.pop(key, None)
    env.update(
        PATH=str(root) + ":" + env["PATH"],
        TEST_REPORT=str(report),
        TEST_UPLOAD=str(upload),
        TEST_DELETE=str(deleted),
        PASTE_TTL="1",
    )

    def interactive(answer):
        """Run with a controlling TTY and script piped into bash, as on SSH."""
        pid, fd = pty.fork()
        if pid == 0:
            os.execvpe("bash", ["bash", "-c", 'cat "$1" | bash', "bash", str(script)], env)
        output = bytearray()
        sent = False
        deadline = time.monotonic() + 10
        try:
            while time.monotonic() < deadline:
                readable, _, _ = select.select([fd], [], [], 0.2)
                if not readable:
                    continue
                try:
                    part = os.read(fd, 4096)
                except OSError as exc:
                    if exc.errno == errno.EIO:
                        break
                    raise
                if not part:
                    break
                output.extend(part)
                if b"y/N:" in output and not sent:
                    os.write(fd, answer.encode() + b"\n")
                    sent = True
            else:
                os.kill(pid, 9)
                raise AssertionError("interactive paste prompt timed out")
        finally:
            os.close(fd)
            os.waitpid(pid, 0)
        assert sent, output
        return output.decode(errors="replace")

    assert "y/N:" in interactive("n")
    assert not upload.exists(), "decline uploaded data"
    result = interactive("y")
    assert "https://termbin.com/test123" in result, result
    assert upload.read_text() == "redacted test report\n", "wrong report uploaded"
    deadline = time.monotonic() + 4
    while not deleted.exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    assert deleted.exists(), "detached delete did not run"
    assert "-X POST https://termbin.com/delete?slug=test123" in deleted.read_text()
    upload.unlink()
    # Non-interactive default and explicit network opt-out must not upload.
    for extra in ({}, {"PASTE": "0"}, {"PASTE": "1", "SKIP_NET": "1"}):
        run = subprocess.run(["bash", str(script)], env=env | extra, capture_output=True, timeout=5)
        assert run.returncode == 0, run.stderr
        assert not upload.exists(), "unexpected public upload"
print("PASS: interactive y/N, capped upload, detached deletion, non-interactive and offline opt-out")
