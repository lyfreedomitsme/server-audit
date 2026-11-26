#!/usr/bin/env python3
"""Loopback integration test: real TCP and HTTPS, real curl, slow delete API.

Only synthetic records; no external network or service. The wrappers point the
hard-coded Termbin endpoints at ephemeral local ports and a test TLS certificate.
Requires Python 3.9+, Bash, curl, openssl, timeout, and setsid/nohup.
"""
import http.server
import json
import os
from pathlib import Path
import select
import shutil
import socketserver
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.parse

source = Path(__file__).resolve().parents[1] / "server_audit.sh"
script_text = source.read_text()
definitions = script_text.split("audit_number() {", 1)[1].split("\nAUDIT_TIMEOUT=", 1)[0]
footer = script_text.split("# ---------- Public paste preparation", 1)[1]
real_curl = shutil.which("curl")
assert real_curl and shutil.which("openssl")
records = {"legacy": b"Synthetic legacy test\n"}
events = []
lock = threading.Lock()
post_delay = 10.0

class PasteTCP(socketserver.StreamRequestHandler):
    def handle(self):
        data = self.rfile.read(4096)
        assert data == b"Synthetic integration test\n", "unexpected payload"
        with lock:
            records["integration"] = data
            events.append(("upload", "integration", time.monotonic()))
        self.wfile.write(b"https://termbin.com/integration\r\n\x00")

class PasteHTTP(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *args):
        pass
    def reply(self, code, body=b""):
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            pass
        self.close_connection = True
    def do_GET(self):
        slug = self.path.lstrip("/")
        with lock:
            data = records.get(slug)
        if self.path == "/":
            self.reply(200, b"Local test service")
        elif data is None:
            self.reply(404)
        else:
            self.reply(200, data)
    def do_POST(self):
        parts = urllib.parse.urlsplit(self.path)
        slug = urllib.parse.parse_qs(parts.query).get("slug", [""])[0]
        assert parts.path == "/delete"
        with lock:
            events.append(("post", slug, time.monotonic()))
        time.sleep(post_delay)
        # Model a slow endpoint which only completes the deletion while the
        # requester is still connected, rather than pretending HTTP 200 is success.
        if select.select([self.connection], [], [], 0)[0]:
            try:
                if not self.connection.recv(1):
                    return
            except (OSError, ssl.SSLError):
                return
        with lock:
            deleted = records.pop(slug, None) is not None
            events.append(("delete", slug, time.monotonic()))
        self.reply(200, json.dumps({"deleted": deleted}).encode())

with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    cert, key = root/"cert.pem", root/"key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", str(key), "-out", str(cert), "-days", "1",
                    "-subj", "/CN=termbin.com", "-addext", "subjectAltName=DNS:termbin.com"],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    tcp = socketserver.ThreadingTCPServer(("127.0.0.1", 0), PasteTCP)
    tcp.daemon_threads = True
    https = http.server.ThreadingHTTPServer(("127.0.0.1", 0), PasteHTTP)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    https.socket = ctx.wrap_socket(https.socket, server_side=True)
    for server in (tcp, https):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    bindir = root/"bin"
    bindir.mkdir()
    nc = bindir/"nc"
    nc.write_text("""#!/usr/bin/env python3
import os, socket, sys
if sys.argv[1] == "-h":
    print(" -N shutdown after EOF\\n -w timeout")
    sys.exit(1)
assert sys.argv[-2:] == ["127.0.0.1", "9999"], sys.argv
with socket.create_connection(("127.0.0.1", int(os.environ["TEST_TCP_PORT"])), timeout=5) as sock:
    sock.sendall(sys.stdin.buffer.read())
    sock.shutdown(socket.SHUT_WR)
    while True:
        data = sock.recv(4096)
        if not data: break
        sys.stdout.buffer.write(data)
""")
    nc.chmod(0o700)
    curl = bindir/"curl"
    curl.write_text("""#!/bin/bash
exec "$REAL_CURL" -q --cacert "$TEST_CERT" --connect-to "termbin.com:443:127.0.0.1:$TEST_HTTPS_PORT" "$@"
""")
    curl.chmod(0o700)
    report = root/"report"
    report.write_text("Synthetic integration test\n")
    script = root/"footer.sh"
    script.write_text('set -uo pipefail\nhas() { command -v "$1" >/dev/null 2>&1; }\n'
                      + "audit_number() {" + definitions
                      + '\nFINAL="$TEST_REPORT"\nAUDIT_REPORT_LINES=10\nAUDIT_TMP="$TEST_DIR"\n'
                      + "# ---------- Public paste preparation" + footer)
    env = dict(os.environ)
    env.update(PATH=str(bindir)+":"+env["PATH"], REAL_CURL=real_curl,
               TEST_CERT=str(cert), TEST_TCP_PORT=str(tcp.server_address[1]),
               TEST_HTTPS_PORT=str(https.server_address[1]), TEST_REPORT=str(report),
               TEST_DIR=str(root), PASTE="1", PASTE_TTL="15", SKIP_NET="0",
               PASTE_MAX_BYTES="30000", PASTE_MODE="compact")
    legacy = subprocess.Popen([str(curl), "-q", "-4", "--noproxy", "*", "--proto", "=https",
                              "--resolve", "termbin.com:443:127.0.0.1",
                              "-sS", "--connect-timeout", "4", "--max-time", "8",
                              "--max-filesize", "4096", "-w", "\n%{http_code}",
                              "-X", "POST", "https://termbin.com/delete?slug=legacy"],
                             env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        run = subprocess.Popen(["bash", str(script)], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        old_stdout, old_stderr = legacy.communicate(timeout=15)
        assert legacy.returncode == 28 and b"timed out" in old_stderr, (old_stdout, old_stderr)
        print("PASS: old 8-second POST times out with real curl (exit 28)", flush=True)
        output = run.communicate(timeout=55)[0].decode(errors="replace")
        assert run.returncode == 0 and "[OK]" in output and "HTTP 404" in output and "deleted=true" in output, output
        with lock:
            timeline = {kind: when for kind, slug, when in events if slug == "integration"}
            assert "integration" not in records and "legacy" in records, records.keys()
        assert timeline["post"]-timeline["upload"] >= 14.5, timeline
        assert timeline["delete"]-timeline["post"] >= 9.8, timeline
        print("PASS: current script uploads synthetic TCP payload, waits 15s, "
              "handles a 10s HTTPS POST with real curl, then confirms HTTP 404", flush=True)
    finally:
        tcp.shutdown()
        https.shutdown()
        tcp.server_close()
        https.server_close()
