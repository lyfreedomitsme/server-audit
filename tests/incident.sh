#!/usr/bin/env bash
# Fixture-only regression tests; no root, network, or real service operations.
set -euo pipefail
cd "$(dirname "$0")/.."
bash -n server_audit.sh
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
# Load definitions without executing main or touching the test host's services.
sed '/^main_audit() {/,$d' server_audit.sh > "$tmp/functions.sh"
source "$tmp/functions.sh"
fail() { echo "FAIL: $*" >&2; exit 1; }
contains() { grep -Fq -- "$2" <<< "$1" || fail "missing '$2'"; }
absent() { if grep -Fq -- "$2" <<< "$1"; then fail "unexpected '$2'"; fi; }
# Reproduce the incident: Nginx -> Apache on 8290, OLS on 8190.
TCP_OK=1
UNIX_OK=1
TCP_LISTEN='LISTEN 0 511 0.0.0.0:8190 0.0.0.0:* users:(("litespeed",pid=1,fd=8))
LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:(("nginx",pid=2,fd=8))'
UNIX_LISTEN='u_str LISTEN 0 128 /tmp/php-cgi-84.sock 123 * 0'
contains "$(audit_upstream 'https://127.0.0.1:8290;')" 'NO MATCHING LISTENER'
contains "$(audit_upstream 'https://127.0.0.1:8190;')" 'LISTENER PRESENT'
contains "$(audit_upstream 'unix:/tmp/php-cgi-84.sock;')" 'UNIX LISTENER PRESENT'
contains "$(audit_upstream 'unix:/tmp/nonexistent-server-audit-test.sock;')" 'NO UNIX SOCKET/LISTENER'
contains "$(audit_upstream 'http://backend;')" 'dynamic/named/remote'
TCP_LISTEN+=$'\nLISTEN 0 511 *:8290 *:* users:(("httpd",pid=3,fd=8))'
contains "$(audit_upstream 'https://127.0.0.1:8290;')" 'LISTENER PRESENT'
TCP_OK=0
contains "$(audit_upstream 'https://127.0.0.1:8290;')" 'UNKNOWN'
config=$(audit_config_lines <<'CONF'
# configuration file /test/site.conf:
server {
  server_name example.test www.example.test;
  # proxy_pass http://127.0.0.1:9999;
  proxy_pass https://127.0.0.1:8290;
  fastcgi_pass unix:/tmp/php-cgi-84.sock;
  proxy_set_header Authorization SecretValue;
}
CONF
)
contains "$config" '/test/site.conf:'
contains "$config" 'server_name example.test'
contains "$config" 'proxy_pass https://127.0.0.1:8290'
absent "$config" '9999'
absent "$config" 'SecretValue'
contains "$(audit_number 0007 1 90)" '7'
contains "$(audit_number '1;touch /tmp/bad' 7 90)" '7'
audit_domain_ok example.test || fail "valid domain"
if audit_domain_ok 'https://example.test/path'; then fail "invalid domain accepted"; fi
traffic=$(audit_access_sample <<'LOG'
192.0.2.1 - - [26/Nov/2026:08:05:01 +0000] "POST /xmlrpc.php?token=secret HTTP/1.1" 502 100 "-" "Go-http-client/1.2"
192.0.2.1 - - [26/Nov/2026:08:05:03 +0000] "POST /wp-json/batch/v1 HTTP/1.1" 503 100 "-" "curl/8"
192.0.2.2 - - [26/Nov/2026:08:05:04 +0000] "GET / HTTP/1.1" 200 100 "-" "Googlebot"
malformed line
LOG
)
contains "$traffic" 'parsed=3 unparsed=1'
contains "$traffic" 'STATUS 502 1'
contains "$traffic" 'IP 2 192.0.2.1 (499/5xx=2)'
contains "$traffic" 'ENDPOINT 1 xmlrpc.php'
contains "$traffic" 'ENDPOINT 1 WordPress REST API'
contains "$traffic" 'UA_CLASS 2 automation/scanner UA'
contains "$traffic" 'Peak sampled requests/min: MINUTE 3'
absent "$traffic" 'secret'
printf '%s\n' 'password="two words"' 'token=private-token' 'GET /?moderation-hash=hiddenvalue HTTP/1.1' 'Authorization: Bearer example-secret' > "$tmp/raw"
redact_file "$tmp/raw" "$tmp/redacted"
for secret in 'two words' private-token hiddenvalue example-secret; do absent "$(cat "$tmp/redacted")" "$secret"; done
# Stub journal so OOM evidence from the prior boot is tested with neither
# retained real logs nor a running systemd required.
audit_cmd() {
  if [ "$1" = journalctl ]; then
    if [[ " $* " == *" --list-boots "* ]]; then echo "-1 previous"; echo "0 current"
    elif [[ " $* " == *" -k -b -1 "* ]]; then
      echo "2026-11-26T08:05:01 kernel: site_total invoked oom-killer"
      echo "2026-11-26T08:05:02 kernel: oom-kill:constraint=CONSTRAINT_NONE,global_oom,task=mariadbd"
      echo "2026-11-26T08:05:03 kernel: Out of memory: Killed process 123 (mariadbd)"
    else echo "-- No entries --"; fi
  elif [ "$1" = dmesg ] || [ "$1" = last ]; then echo "fixture"; else "$@"; fi
}
history=$(audit_boot_history || true)
contains "$history" 'kernel OOM/errors, boot=-1'
contains "$history" 'global_oom'
contains "$history" 'Killed process 123 (mariadbd)'
echo "PASS: config, listeners, bot traffic, redaction, previous-boot OOM"
