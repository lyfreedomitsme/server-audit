#!/usr/bin/env python3
"""Offline compact-report quality regression with synthetic data only."""
import re
import subprocess
import tempfile
from pathlib import Path

source = Path(__file__).resolve().parents[1] / "server_audit.sh"
definition=source.read_text().split("paste_prepare() {",1)[1].split("\npaste_upload() {",1)[0]
filler="\n".join("routine repeated diagnostic detail "+str(i)+" " + "x"*140 for i in range(180))
sections=[
    "SERVER AUDIT REPORT fixture\n",
    "## INCIDENT — BOOT HISTORY / OOM / BEFORE AND AFTER REBOOT\n"
    "--- kernel OOM/errors, boot=0 ---\nOOM kills in retained window (sample):\n"
    "--- system errors, boot=0 ---\n"
    "--- kernel OOM/errors, boot=-1 ---\n"
    "2026-11-26T08:05:00Z kernel: Out of memory: Killed process 123 (mariadbd)\n"
    "OOM kills in retained window (sample):\n 41 mariadbd\n 1 php-fpm\n"
    "--- system errors, boot=-1 ---\n"+filler,
    "## INCIDENT — SERVICES / AUTOSTART / RESTART HISTORY\n"
    "--- httpd.service ---\nActiveState=active\nSubState=running\nResult=success\nNRestarts=0\n"
    "ActiveEnterTimestamp=Thu 2026-11-26 09:11:33 UTC\nUnitFileState=generated\nis-enabled: enabled\n"
    "--- php-fpm.service ---\nActiveState=inactive\nSubState=dead\nResult=oom-kill\n"
    "NRestarts=4\nis-enabled: disabled\n"+filler,
    "## INCIDENT — CONTROL PANEL / HTTP API / TLS\n"
    "PANEL DETECTED FASTPANEL candidate_port=8888 (default/config hint)\n"
    "PANEL FASTPANEL LOCAL https://127.0.0.1:8888/ => HTTP 200 [OK (HTTP response)]\n"
    "PANEL FASTPANEL LOCAL https://127.0.0.1:8888/license/status => HTTP 000 [TIMEOUT]\n"
    "--- PANEL LOG FASTPANEL /var/log/fastpanel2/updater.log ---\n"
    "[ERROR] Number of update exceeded\n"+filler,
    "## INCIDENT — PACKAGE MANAGER / INTERRUPTED UPDATES\n"
    "PACKAGE INSTALLED iU mysql-server-8.0 8.0.45\n"
    "PACKAGE CANDIDATE fastpanel2 installed=1.11 candidate=8.0\n"
    "PACKAGE apt dependency check exit=100\n"
    "Depends: mysql-server-core-8.0 (= 8.0.45) but 8.0.46 is installed\n"+filler,
    "## INCIDENT — FIREWALL / SAVED VS LIVE\n"
    "FIREWALL DRIFT IPv4 saved ACCEPT missing in live ufw-user-input: tcp 8888 src=any dst=any in=any\n"+filler,
    "## INCIDENT — WEB STACK / VHOST ROUTING / UPSTREAM HEALTH\n"
    "/etc/nginx/site.conf:1 server_name main.test city.main.test;\n"
    "SITE main.test\nSITE other.test\nSITE other.test => NOT CHECKED (site probe cap 1)\n"
    "APP_HTACCESS main.test state=empty bytes=0 mode=666\n"
    "APP_ROUTE main.test FRONT https /wp-json/ via=127.0.0.1:443 HTTP 404 type=text/html [NOT FOUND]\n"
    "APP_FINDING main.test FRONT WordPress REST pretty path=404 but query route=200 JSON\n"
    "SITE SUMMARY: discovered=2 selected=1 skipped=1\n"
    "FRONT http://main.test/ via 127.0.0.1:80 => HTTP 301 total=0.012s\n"
    "FRONT https://main.test/ via 127.0.0.1:443 => HTTP 502 total=0.030s [SERVER ERROR]\n"
    "BACKEND https://main.test/ via 127.0.0.1:8290 => NO MATCHING LISTENER\n"
    "PUBLIC https://main.test/ => curl: (28) timeout HTTP 000 total=5.0s [TIMEOUT]\n"+filler,
    "## INCIDENT — WEB / PHP / DB ERROR LOGS\n"
    "--- /var/log/mariadb/error.log ---\n"
    "APP_LOG /var/log/main.test.error.log captcha_signals=2 plugins=ithemes-security-pro (sampled; authentication failure cause unknown)\n"
    "APP_COMPONENT_ERROR source=/var/log/main.test.error.log domain=main.test component=wordpress-plugins/broken-plugin severity=fatal category=dependency_or_compatibility count=1 (log path association; not proven root cause)\n"
    "2026-11-26 9:11:59 [ERROR] Table wp_options is marked as crashed\n"
    "--- /var/log/nginx/error.log ---\n"
    "2026/11/26 09:38:20 [error] upstream timed out, server: main.test\n"
    "[pool www] server reached pm.max_children setting (50)\n"+filler,
    "## INCIDENT — TRAFFIC / BOTS / HTTP STATUS (sampled access logs)\n"
    "At most 12 files, last 2500 lines each; not a full traffic census.\n"
    "IP may be a reverse proxy/CDN; UA may be spoofed; traffic from one IP/UA is not proof of an attack.\n"
    + "\n".join(
        f"--- /var/log/site{i}.test.log ---\n"
        "parsed=2500 unparsed=0 first=25/Nov/2026:10:38:48 +0000 last=26/Nov/2026:09:38:03 +0000\n"
        "STATUS 200 1893\nSTATUS 502 179\nUA_CLASS 47 bot/crawler UA\n"
        "ENDPOINT 1009 xmlrpc.php\n"
        "IP 423 192.0.2.1 (499/5xx=6)\nIP 271 192.0.2.2 (499/5xx=210)\n"
        "Peak sampled requests/min: MINUTE 243 26/Nov/2026:05:15"
        for i in range(1,13)
    )+"\n"+filler,
    "## INCIDENT — CHANGE EVIDENCE (safe excerpts; timestamps may be missing)\n"
    "626: epoch=unknown systemctl disable httpd --now\n"+filler,
    "## INCIDENT — STORAGE / MEMORY PRESSURE\n"
    "[!] filesystem >=90%: /dev/sda1 93% /\n"
    "[!] inode usage >=80%: /dev/sda1 85% /\n"+filler,
]
text="\n".join(sections)+"\n"
with tempfile.TemporaryDirectory() as tmp:
    root=Path(tmp)
    payload=root/"payload"
    payload.write_text(text)
    def run(mode):
        return subprocess.run(
            ["bash","-c", "set -uo pipefail\nAUDIT_TMP=\"$1\"\nAUDIT_DOMAIN=main.test\npaste_prepare() {"+definition+'\npaste_prepare "$2" 30000 "$3"', "bash", str(root), str(payload), str(mode)],
            capture_output=True,text=True,
        )
    result=run("0")
    assert result.returncode==2 and payload.read_text()==text
    result=run("1")
    assert result.returncode==3, (result.stdout,result.stderr)
    output=payload.read_text()
    assert len(output.encode())<=30000
    assert "[COMPACT TERMBIN REPORT]" in output
    assert "/license/status => HTTP 000 [TIMEOUT]" in output
    assert "PACKAGE INSTALLED iU mysql-server-8.0 8.0.45" in output
    assert "PACKAGE apt dependency check exit=100" in output
    assert "FIREWALL DRIFT IPv4 saved ACCEPT missing in live ufw-user-input: tcp 8888" in output
    assert "OOM_COUNT boot=-1 victim=mariadbd kills=41" in output
    assert "OOM_COUNT boot=0 no victim counts printed" in output
    assert re.search(r"^SERVICE httpd\.service .*active=active.*is-enabled=enabled",output,re.M)
    assert re.search(r"^SERVICE php-fpm\.service .*active=inactive.*is-enabled=disabled",output,re.M)
    assert "HTTP_SITE main.test " in output and "FRONT_https=502" in output
    assert "BACKEND_https:8290=NO_LISTENER" in output and "PUBLIC_https=000/TIMEOUT" in output
    assert "APP_HTACCESS main.test state=empty" in output
    assert "APP_ROUTE main.test FRONT https /wp-json/" in output
    assert "APP_FINDING main.test FRONT WordPress REST pretty path=404 but query route=200 JSON" in output
    assert "captcha_signals=2 plugins=ithemes-security-pro" in output
    assert "component=wordpress-plugins/broken-plugin severity=fatal category=dependency_or_compatibility count=1" in output
    assert "SITE SUMMARY: discovered=2 selected=1 skipped=1" in output
    assert "SITE other.test => NOT CHECKED" in output
    assert "systemctl disable httpd --now" in output
    assert "wp_options is marked as crashed" in output and "upstream timed out" in output
    assert "pm.max_children" in output and "filesystem >=90%" in output and "inode usage >=80%" in output
    reports=re.findall(r"^TRAFFIC /var/log/site(\d+)\.test\.log .*$",output,re.M)
    assert sorted(map(int,reports))==list(range(1,13)), reports
    for line in output.splitlines():
        if line.startswith("TRAFFIC /"):
            assert "502:179" in line and "1009 xmlrpc.php" in line
            assert "192.0.2.1" in line and "192.0.2.2" in line
    assert not re.search(r"\([1-9][0-9]* high-priority\)",output)
    print(f"PASS: {len(text.encode())} -> {len(output.encode())} bytes; 12 attributed traffic samples, service/HTTP/OOM evidence preserved")
