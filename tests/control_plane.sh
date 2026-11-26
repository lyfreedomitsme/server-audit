#!/usr/bin/env bash
# Offline fixtures: panel probes, broken package state, firewall drift.
set -euo pipefail
cd "$(dirname "$0")/.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
sed '/^main_audit() {/,$d' server_audit.sh > "$tmp/functions.sh"
source "$tmp/functions.sh"
fail() { echo "FAIL: $*" >&2; exit 1; }
contains() { grep -Fq -- "$2" <<< "$1" || fail "missing '$2'"; }
absent() { if grep -Fq -- "$2" <<< "$1"; then fail "unexpected '$2'"; fi; }

saved=$'-A ufw-user-input -p tcp --dport 8888 -j ACCEPT\n-A ufw-user-input -p tcp --dport 443 -j ACCEPT\n-A ufw-user-input -s 192.0.2.1/32 -p tcp --dport 22222 -j ACCEPT'
live=$'-A ufw-user-input -p tcp -m tcp --dport 443 -j ACCEPT\n-A ufw-user-input -p tcp -m tcp --dport 21 -j ACCEPT\n-A ufw-user-input -s 192.0.2.1/32 -p tcp -m tcp --dport 22222 -j ACCEPT'
drift=$(audit_fw_compare IPv4 ufw-user-input "$saved" "$live")
contains "$drift" 'saved ACCEPT missing in live ufw-user-input: tcp 8888'
contains "$drift" 'live ACCEPT not in saved ufw-user-input: tcp 21'
absent "$drift" 'missing in live ufw-user-input: tcp 443'
absent "$drift" 'missing in live ufw-user-input: tcp 22222'
contains "$(audit_fw_compare IPv4 ufw-user-input "$saved" "$live"$'\n-A ufw-user-input -p tcp -m tcp --dport 8888 -j ACCEPT')" 'no missing simple saved ACCEPT signatures'
signatures=$(audit_fw_allow_signatures ufw-user-input <<'RULES'
-A ufw-user-input ! -s 192.0.2.10 -p tcp --dport 8888 -j ACCEPT
-A ufw-user-input -p tcp --dport 8888 -m conntrack --ctstate NEW -j ACCEPT
-A ufw-user-input -p tcp --dport 8083 -j DROP
-A ufw-user-input -p udp --dport 8888 -j ACCEPT
RULES
)
contains "$signatures" 'udp 8888'
absent "$signatures" 'tcp 8888'
absent "$signatures" '8083'
contains "$(audit_fw_compare IPv6 ufw6-user-input '-A ufw6-user-input -p tcp --dport 8443 -j ACCEPT' '')" 'IPv6 saved ACCEPT missing'
rules=$(audit_firewall_port_rules '8888 8083' <<'RULES'
-A INPUT -p tcp --dport 8888 -j DROP
-A OTHER -p tcp --dport 18888 -j ACCEPT
-A CUSTOM -p tcp -m multiport --dports 8083,8443 -j ACCEPT
table inet filter {
 chain input {
  tcp dport { 80, 8888 } counter drop
 }
}
RULES
)
contains "$rules" 'port=8888 -A INPUT'
contains "$rules" 'port=8083 -A CUSTOM'
contains "$rules" 'chain input'
firewalld=$(audit_firewalld_compare public ports '443/tcp 21/tcp' '8888/tcp 443/tcp')
contains "$firewalld" 'permanent ports missing in runtime: 8888/tcp'
contains "$firewalld" 'runtime-only ports: 21/tcp'

absent "$rules" '18888'
printf "BACKEND_PORT='9443'\n" > "$tmp/config"
[ "$(audit_panel_config_port "$tmp/config")" = 9443 ] || fail 'Hestia config port'
printf 'port=12345\n' > "$tmp/config"
[ "$(audit_panel_config_port "$tmp/config")" = 12345 ] || fail 'custom port'
printf 'port=12345; touch /tmp/unsafe\n' > "$tmp/config"
if audit_panel_config_port "$tmp/config"; then fail 'unsafe config parsed'; fi
audit_panel_port_ok 65535 || fail 'valid port'
if audit_panel_port_ok 65536; then fail 'invalid port'; fi
TCP_OK=1
TCP_LISTEN='LISTEN 0 511 0.0.0.0:8888 0.0.0.0:* users:(("fastpanel2-ngin",pid=1,fd=8))
LISTEN 0 511 127.0.0.1:5501 0.0.0.0:* users:(("fastpanel",pid=2,fd=8))
LISTEN 0 511 0.0.0.0:9443 0.0.0.0:* users:(("miniserv",pid=3,fd=8))
LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:(("nginx",pid=4,fd=8))'
[ "$(audit_panel_listener_ports 'fastpanel2-ngin')" = 8888 ] || fail 'FASTPANEL owned listener'
[ "$(audit_panel_listener_ports 'miniserv|webmin')" = 9443 ] || fail 'Webmin custom listener'
audit_cmd() {
  case "$1" in
    curl)
      [[ " $* " == *" --noproxy * "* && " $* " == *" -o /dev/null "* ]] || fail 'unsafe HTTP probe'
      case "${*: -1}" in
        */license/status) echo 'curl: (28) Operation timed out'; echo 'HTTP 000 total=6s'; return 28;;
        *) echo 'HTTP 200 connect=0.001s ttfb=0.010s total=0.011s bytes=1024';;
      esac;;
    *) fail "unexpected fixture command: $*";;
  esac
}
contains "$(audit_panel_http FASTPANEL https 127.0.0.1 8888 127.0.0.1 / LOCAL)" 'HTTP 200'
contains "$(audit_panel_http FASTPANEL https 127.0.0.1 8888 127.0.0.1 /license/status LOCAL || true)" '[TIMEOUT]'
# Full panel collection uses only local listener connections; no DNS or
# HTTP probes when the associated opt-out is set.
audit_panel_registry() { echo 'FASTPANEL|8888|https|fastpanel2-ngin'; }
audit_panel_hostnames() { echo panel.test; }
audit_panel_logs() { echo "PANEL LOG $1: fixture"; }
has() { case "$1" in curl|ss) return 0;; *) return 1;; esac; }
audit_cmd() {
  case "$1" in
    ss) printf '%s\n' "$TCP_FIXTURE";;
    curl)
      [[ " $* " == *" --connect-to "* ]] || fail 'nonlocal panel probe'
      case "${*: -1}" in
        https://panel.test:8888/) [[ " $* " != *" -k "* ]] || fail 'TLS verification disabled'; echo 'HTTP 000'; return 60;;
        */license/status) echo 'HTTP 000'; return 28;;
        *) echo 'HTTP 200 total=0.01s';;
      esac;;
    *) fail "unexpected command: $*";;
  esac
}
TCP_FIXTURE="$TCP_LISTEN"
SKIP_NET=1 SKIP_HTTP=0
panel=$(audit_panel_health || true)
contains "$panel" 'PANEL FASTPANEL LOCAL https://127.0.0.1:8888/ => HTTP 200'
contains "$panel" 'PANEL FASTPANEL LOCAL https://127.0.0.1:8888/license/status => HTTP 000 [TIMEOUT]'
contains "$panel" 'PANEL FASTPANEL-backend LOCAL http://127.0.0.1:5501/resource/public/settings'
contains "$panel" 'TLS_VERIFY https://panel.test:8888/ => HTTP 000 [TLS FAILURE]'
absent "$panel" 'PANEL DNS'
SKIP_HTTP=1
panel=$(audit_panel_health || true)
contains "$panel" 'PANEL LISTENER FASTPANEL port=8888'
absent "$panel" 'HTTP 200'
SKIP_HTTP=0
# Ensure APT repair is simulation-only and the failed dependency is preserved.
has() { case "$1" in dpkg|apt-get|dpkg-query|apt-cache|apt-mark) return 0;; *) return 1;; esac; }
audit_cmd() {
  case "$1" in
    dpkg) echo 'mysql-server-8.0 unpacked but not configured';;
    dpkg-query) printf 'iU  mysql-server-8.0 8.0.45\nii  mysql-server-core-8.0 8.0.46\nii  fastpanel2 1.11\n';;
    apt-get)
      [[ " $* " == *" -s "* ]] || fail 'real apt invocation'
      if [[ " $* " == *" check "* ]]; then echo 'Depends: mysql-server-core-8.0 (= 8.0.45) but 8.0.46 is installed'; return 100
      else [[ " $* " == *" --no-remove "* ]] || fail 'repair simulation could remove packages'; echo '3 upgraded, 0 newly installed, 0 to remove'; fi;;
    apt-cache) printf 'fastpanel2:\n  Installed: 1.11\n  Candidate: 8.0\n';;
    apt-mark) :;;
    *) fail "unexpected package command: $*";;
  esac
}
packages=$(audit_package_health || true)
contains "$packages" 'PACKAGE dpkg audit (exit=0)'
contains "$packages" 'mysql-server-8.0 unpacked'
contains "$packages" 'PACKAGE apt dependency check exit=100'
contains "$packages" 'Depends: mysql-server-core-8.0'
contains "$packages" '3 upgraded, 0 newly installed, 0 to remove'
contains "$packages" 'PACKAGE CANDIDATE fastpanel2 installed=1.11 candidate=8.0'
echo 'PASS: panel custom ports, HTTP/API timeout, IPv4/IPv6 firewall drift, package audit/simulation'
