#!/usr/bin/env bash
# Fixture-only site discovery, priority, HTTP statuses and probe caps.
set -euo pipefail
cd "$(dirname "$0")/.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
sed '/^main_audit() {/,$d' server_audit.sh > "$tmp/functions.sh"
source "$tmp/functions.sh"
fail() { echo "FAIL: $*" >&2; exit 1; }
contains() { grep -Fq -- "$2" <<< "$1" || fail "missing '$2'"; }
absent() { if grep -Fq -- "$2" <<< "$1"; then fail "unexpected '$2'"; fi; }

for bad in '127.0.0.1' 'localhost' '*.example.test' 'bad..test' '-bad.test' 'bad-.test' 'https://example.test/'; do
  if audit_domain_ok "$bad"; then fail "invalid hostname accepted ($bad)"; fi
done
audit_domain_ok 'xn--e1afmkfd.xn--p1ai'
inventory=$(audit_site_order <<'LIST'
primary 127.0.0.1
primary _
primary www.example.test
alias example.test
alias abc.example.test
primary second.test
primary north.second.test
alias *.wild.test
primary second.test
target ztarget.test
LIST
)
[ "$inventory" = $'ztarget.test\nexample.test\nsecond.test\nnorth.second.test\nwww.example.test\nabc.example.test' ] || fail "inventory order: $inventory"
ng=$(audit_config_lines <<'NGINX'
# configuration file /fixtures/nginx/site.conf:
server_name main.test
    www.main.test # comment
    city.main.test;
proxy_pass https://127.0.0.1:8290;
NGINX
)
records=$(audit_nginx_site_records <<< "$ng")
contains "$records" 'primary main.test'
contains "$records" 'alias city.main.test'
contains "$records" 'alias www.main.test'
apache=$(audit_apache_site_records <<'APACHE'
 default server example.test (/config:2)
 port 443 namevhost apache.test (/config:8)
   alias www.apache.test
   wild alias *.apache.test
APACHE
)
contains "$apache" 'primary apache.test'
contains "$apache" 'alias www.apache.test'
absent "$apache" '*.apache.test'
ols=$(audit_ols_site_records <<'OLS'
map lsws.test lsws.test, www.lsws.test, city.lsws.test
vhDomain another.test
vhAliases www.another.test, alias.another.test
OLS
)
contains "$ols" 'primary lsws.test'
contains "$ols" 'alias city.lsws.test'
contains "$ols" 'primary another.test'
contains "$ols" 'alias alias.another.test'

NGINX_BIN=fake-nginx
APACHE_BIN=fake-apache
OLS_BIN=''
AUDIT_DOMAIN=site2.test
AUDIT_MAX_SITES=5
AUDIT_HTTP_BUDGET=120
SKIP_NET=1
SKIP_HTTP=0
audit_cmd() {
  case "$1" in
    ss)
      if [ "$2" = "-H" ] && [ "$3" = "-lntp" ]; then
        printf '%s\n' 'LISTEN 0 511 0.0.0.0:80 0.0.0.0:*' 'LISTEN 0 511 192.0.2.10:443 0.0.0.0:*'
      fi ;;
    fake-nginx)
      if [ "$2" = "-T" ]; then
        cat <<'NGINX'
# configuration file /fixtures/nginx/site1.conf:
server_name site1.test www.site1.test city.site1.test;
# configuration file /fixtures/nginx/site2.conf:
server_name site2.test www.site2.test;
proxy_pass https://127.0.0.1:8290;
# configuration file /fixtures/nginx/site3.conf:
server_name site3.test;
# configuration file /fixtures/nginx/site4.conf:
server_name site4.test;
# configuration file /fixtures/nginx/site5.conf:
server_name site5.test;
# configuration file /fixtures/nginx/site6.conf:
server_name site6.test;
# configuration file /fixtures/nginx/default.conf:
server_name 127.0.0.1 _;
NGINX
      else echo "fixture nginx"; fi ;;
    fake-apache)
      if [ "$2" = "-S" ]; then
        printf '%s\n' 'port 80 namevhost site2.test (/test:1)' ' alias www.site2.test'
      else echo "fixture apache"; fi ;;
    curl)
      local url="${@: -1}"
      if [ "${TEST_DELAY:-0}" = 1 ] && [ "$url" = "http://site2.test/" ]; then sleep 1.1; fi
      case "$url" in
        *site1.test/*) printf 'HTTP 200 remote=192.0.2.10 connect=0.01s total=0.02s\n';;
        *site2.test/*) printf 'HTTP 502 remote=192.0.2.10 connect=0.01s total=0.02s\n';;
        *site3.test/*) printf 'curl: (28) timeout\nHTTP 000 remote=192.0.2.10 total=5s\n'; return 28;;
        *site4.test/*) printf 'HTTP 403 connect=0.01s total=0.02s\n';;
        *site5.test/*) printf 'HTTP 301 connect=0.01s total=0.02s\n';;
        *) printf 'HTTP 404 connect=0.01s total=0.02s\n';;
      esac ;;
    *) fail "unexpected command $*";;
  esac
}
has() { [ "$1" = curl ] || command -v "$1" >/dev/null 2>&1; }
# audit_web returns an evidence report; no real HTTP requests are issued.
report=$(audit_web)
contains "$report" 'Discovered 9 unique hostnames'
contains "$report" 'FRONT https://site1.test/ via 192.0.2.10:443 => HTTP 200'
contains "$report" '[OK (HTTP response)]'
contains "$report" 'FRONT https://site2.test/ via 192.0.2.10:443 => HTTP 502'
contains "$report" '[SERVER ERROR]'
contains "$report" 'BACKEND https://site2.test/ via 127.0.0.1:8290 => NO MATCHING LISTENER'
contains "$report" '[TIMEOUT]'
contains "$report" '[ACCESS RESTRICTED]'
contains "$report" '[REDIRECT (destination not checked)]'
contains "$report" 'SITE site6.test => NOT CHECKED (site probe cap 5)'
contains "$report" 'SITE www.site1.test => NOT CHECKED'
contains "$report" 'SITE SUMMARY: discovered=9 selected=5 skipped=4'
absent "$report" 'SITE 127.0.0.1'
absent "$report" 'PUBLIC https://'
first=$(grep '^FRONT ' <<< "$report" | head -n1)
contains "$first" 'site2.test'
SKIP_HTTP=1
report=$(audit_web)
contains "$report" 'SITE SUMMARY: discovered=9 selected=0 skipped=9'
absent "$report" 'FRONT http'
SKIP_HTTP=0
SKIP_NET=0
AUDIT_PUBLIC_HTTP=1
AUDIT_MAX_SITES=1
report=$(audit_web)
contains "$report" 'PUBLIC https://site2.test/ => HTTP 502'
absent "$report" 'PUBLIC https://site1.test/'
AUDIT_MAX_SITES=100
AUDIT_HTTP_BUDGET=1
SKIP_NET=1
TEST_DELAY=1
report=$(audit_web)
contains "$report" 'SITE site1.test => NOT CHECKED (HTTP time budget 1s)'
contains "$report" 'SITE SUMMARY: discovered=9 selected=1 skipped=8'
contains "$(audit_http_classify 404 0)" 'NOT FOUND'
contains "$(audit_http_classify 503 0)" 'SERVER ERROR'
contains "$(audit_http_classify 504 0)" 'SERVER ERROR'
contains "$(audit_http_classify 000 7)" 'CONNECT FAILURE'
contains "$(audit_http_classify 000 60)" 'TLS FAILURE'
contains "$(audit_http_classify 000 6)" 'DNS FAILURE'
echo "PASS: site discovery/order/aliases, host-bound front, 2xx/3xx/4xx/5xx, timeout, missing backend, skip/cap/time budget/public opt-in"
