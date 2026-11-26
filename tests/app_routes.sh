#!/usr/bin/env bash
# Offline fixture: multi-IP origin, empty .htaccess, REST routing, CAPTCHA logs.
set -euo pipefail
cd "$(dirname "$0")/.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
sed '/^main_audit() {/,$d' server_audit.sh > "$tmp/functions.sh"
source "$tmp/functions.sh"
fail() { echo "FAIL: $*" >&2; exit 1; }
contains() { grep -Fq -- "$2" <<< "$1" || fail "missing '$2'"; }
absent() { if grep -Fq -- "$2" <<< "$1"; then fail "unexpected '$2'"; fi; }
mkdir -p "$tmp/www/wp-includes"
touch "$tmp/www/wp-includes/version.php" "$tmp/www/wp-load.php" "$tmp/www/index.php" "$tmp/www/.htaccess"
chmod 666 "$tmp/www/.htaccess"
mkdir -p "$tmp/www/wp-content/plugins/broken-plugin" "$tmp/www/wp-content/themes/old-theme" "$tmp/www/wp-content/mu-plugins"
printf '%s\n' '<?php' '/* Plugin Name: Broken Plugin' 'Version: 2.7.1' '*/' 'PRIVATE_VALUE' > "$tmp/www/wp-content/plugins/broken-plugin/broken-plugin.php"
printf '%s\n' '/* Theme Name: Old Theme' 'Version: 1.4.0' '*/' > "$tmp/www/wp-content/themes/old-theme/style.css"
printf '%s\n' '<?php' '/* Plugin Name: Bootstrap' 'Version: 1.0' '*/' > "$tmp/www/wp-content/mu-plugins/bootstrap.php"
printf '%s\n' 'PHP Fatal error: Uncaught Error: Class Missing not found in /www/wp-content/plugins/broken-plugin/init.php:20 token=PRIVATE_VALUE' > "$tmp/www/wp-content/debug.log"
cat > "$tmp/apache.conf" <<APACHE
<VirtualHost 127.0.0.1:8080>
ServerName app.test
DocumentRoot "$tmp/www"
</VirtualHost>
<Directory "$tmp/www">
AllowOverride FileInfo
Options +FollowSymLinks
</Directory>
APACHE
audit_path_ok /hide/
for bad in '//external.test/path' '/x?token=secret' '/foo#fragment' '/../../etc' 'https://app.test/' '/a%20b'; do
  if audit_path_ok "$bad"; then fail "unsafe path accepted: $bad"; fi
done
APACHE_BIN=fake-apache
NGINX_BIN=fake-nginx
OLS_BIN=''
AUDIT_DOMAIN=app.test
AUDIT_PATH=/hide/
AUDIT_MAX_SITES=1
AUDIT_APP_SITES=1
AUDIT_HTTP_BUDGET=60
SKIP_HTTP=0
SKIP_NET=1
audit_cmd() {
  case "$1" in
    ip) printf '%s\n' '1: lo inet 127.0.0.1/8 scope host lo' '2: eth0 inet 192.0.2.10/32 scope global eth0' '2: eth0 inet 198.51.100.9/32 scope global eth0';;
    ss)
      if [ "$3" = -lntp ]; then
        printf '%s\n' 'LISTEN 0 511 0.0.0.0:80 0.0.0.0:*' 'LISTEN 0 511 192.0.2.10:443 0.0.0.0:*' 'LISTEN 0 511 198.51.100.9:443 0.0.0.0:*' 'LISTEN 0 511 127.0.0.1:8080 0.0.0.0:*'
      fi ;;
    fake-nginx)
      if [ "$2" = -T ]; then
        cat <<NGINX
# configuration file /fixtures/app.conf:
server {
server_name app.test www.app.test;
set \$root_path $tmp/www;
root \$root_path;
listen 198.51.100.9:80;
proxy_pass http://127.0.0.1:8080;
}
server {
server_name app.test www.app.test;
set \$root_path $tmp/www;
root \$root_path;
listen 198.51.100.9:443 ssl;
proxy_pass http://127.0.0.1:8080;
}
# configuration file /fixtures/other.conf:
server_name other.test;
listen 192.0.2.10:443 ssl;
NGINX
      fi ;;
    fake-apache)
      case "$2" in
        -S) printf '127.0.0.1:8080 app.test (%s/apache.conf:1)\n' "$tmp";;
        -M) echo ' rewrite_module (shared)';;
      esac ;;
    curl)
      local url="${@: -1}" a route=0
      for a in "$@"; do
        [ "$a" != '%{http_code} %{content_type}' ] || route=1
        if [[ "$a" = *'app.test:443:192.0.2.10:443'* ]]; then fail 'wrong origin'; fi
      done
      if [ "$route" = 1 ]; then
        case "$url" in
          */wp-json/|*/hide/) printf '404 text/html; charset=UTF-8';;
          */index.php\?rest_route=/) printf '200 application/json; charset=UTF-8';;
          *) fail "unexpected path $url";;
        esac
      else printf 'HTTP 200 remote=198.51.100.9 connect=0.01s total=0.02s\n'; fi;;
    *) fail "unexpected command $*";;
  esac
}
has() { [ "$1" = curl ] || [ "$1" = ip ] || command -v "$1" >/dev/null 2>&1; }
report=$(audit_web)
contains "$report" 'APP_CMS app.test WordPress'
contains "$report" 'kind=plugins slug=broken-plugin installed_version=2.7.1 active=unknown'
contains "$report" 'kind=themes slug=old-theme installed_version=1.4.0 active=unknown'
contains "$report" 'kind=mu-plugins slug=bootstrap.php installed_version=1.0 active=unknown'
absent "$report" 'PRIVATE_VALUE'
contains "$report" 'APP_HTACCESS app.test state=empty bytes=0 mode=666'
contains "$report" 'APP_FINDING app.test .htaccess is world-writable'
contains "$report" 'APP_FINDING app.test WordPress .htaccess empty with Apache vhost'
contains "$report" 'AllowOverride FileInfo (candidate; includes/merging not evaluated)'
contains "$report" 'FRONT https://app.test/ via 198.51.100.9:443 => HTTP 200'
contains "$report" 'APP_ROUTE app.test FRONT https /hide/ via=198.51.100.9:443 HTTP 404'
contains "$report" 'APP_ROUTE app.test BACKEND http /wp-json/ via=127.0.0.1:8080 HTTP 404'
contains "$report" 'APP_FINDING app.test FRONT WordPress REST pretty path=404 but query route=200 JSON'
contains "$report" 'APP_FINDING app.test BACKEND WordPress REST pretty path=404 but query route=200 JSON'
absent "$report" 'PUBLIC https://'
SKIP_HTTP=1
report=$(audit_web)
contains "$report" 'APP_HTACCESS app.test state=empty'
absent "$report" 'APP_ROUTE app.test'
printf 'RewriteEngine On\nRewriteRule . /index.php [L]\n# PRIVATE_VALUE\n' > "$tmp/www/.htaccess"
report=$(audit_site_files app.test "$tmp/www" configured 1)
contains "$report" 'state=rewrite-present'
absent "$report" 'PRIVATE_VALUE'
: > "$tmp/www/.htaccess"
report=$(audit_site_files app.test "$tmp/www" configured 0)
contains "$report" 'APP_NOTE app.test'
absent "$report" 'APP_FINDING app.test WordPress'
report=$(audit_app_log_signals /example/app.test.error.log <<'LOG'
PHP Warning: error-codes in /var/www/app/wp-content/plugins/ithemes-security-pro/pro/recaptcha/Provider/Google.php on line 201 secret=PRIVATE_VALUE
WordPress database error Table 'test.wp_audit' doesn't exist
PHP Fatal error: Uncaught Error: Class Missing not found in /www/wp-content/plugins/broken-plugin/init.php:20
PHP Fatal error: Uncaught TypeError: wrong type in /www/wp-content/themes/old-theme/functions.php:24
PHP Fatal error: Allowed memory size of 100 bytes exhausted in /srv/vendor/example/package/lib.php
PHP Warning: Permission denied in /srv/modules/contrib/module_x/load.php
PHP Warning: No space left on device in /srv/components/com_example/models/page.php
PHP Deprecated: example in /srv/wp-content/mu-plugins/bootstrap.php
Error: Cannot find module example from /srv/node_modules/@group/package/index.js
ModuleNotFoundError: No module named example from /srv/site-packages/example/app.py
#1 /srv/wp-content/plugins/other-plugin/include.php(12): trace
LOG
)
contains "$report" 'captcha_signals=1 plugins=ithemes-security-pro'
contains "$report" 'missing_table_signals=1'
contains "$report" 'component=wordpress-plugins/broken-plugin severity=fatal category=dependency_or_compatibility count=1'
contains "$report" 'component=wordpress-themes/old-theme severity=fatal category=type_error count=1'
contains "$report" 'component=composer-vendor/example/package severity=fatal category=memory_exhausted count=1'
contains "$report" 'component=drupal-modules/contrib/module_x severity=error category=permission count=1'
contains "$report" 'component=joomla-components/com_example severity=fatal category=storage_full count=1'
contains "$report" 'component=wordpress-mu-plugins/bootstrap.php severity=notice category=deprecated count=1'
contains "$report" 'component=node-node_modules/@group/package severity=error category=dependency_or_compatibility count=1'
contains "$report" 'component=python-site-packages/example severity=error category=dependency_or_compatibility count=1'
contains "$report" 'component=wordpress-plugins/other-plugin count=1 (stack frame only'
declare -ga AUDIT_APP_LOG_PATHS=()
declare -gA AUDIT_APP_LOG_DOMAIN=()
audit_register_app_logs app.test "$tmp/www"
[ "${AUDIT_APP_LOG_DOMAIN[$tmp/www/wp-content/debug.log]}" = app.test ] || fail 'application debug log not mapped'
AUDIT_DISCOVERED_DOMAINS=(app.test other.test)
[ "$(audit_log_domain /var/www/httpd-logs/app.test.error.log)" = app.test ] || fail 'domain attribution failed'
[ "$(audit_log_domain /var/www/httpd-logs/notapp.test.error.log)" = unknown ] || fail 'wrong log domain guessed'
absent "$report" 'PRIVATE_VALUE'
contains "$(audit_dns_status $'198.51.100.9\n192.0.2.10' $'192.0.2.10\n198.51.100.9')" 'OK ->'
contains "$(audit_dns_status $'198.51.100.9\n203.0.113.8' '198.51.100.9')" 'Часть'
contains "$(audit_dns_status '203.0.113.8' '198.51.100.9')" 'не совпадают'
TCP_OK=1
TCP_LISTEN=$'LISTEN 0 1 0.0.0.0:443 0.0.0.0:*'
AUDIT_LOCAL_IPS=198.51.100.9
if audit_domain_front 443 '/fixtures/stale.conf:1 listen 203.0.113.8:443;' >/dev/null; then fail 'remote IP chosen as local'; fi
directives=$(audit_nginx_domain_directives app.test <<'CONF'
/one.conf:1 server_name app.test;
/one.conf:2 listen 192.0.2.10:443;
/one.conf:3 server_name other.test;
/one.conf:4 listen 198.51.100.9:443;
CONF
)
[ -z "$directives" ] || fail 'ambiguous multi-site config attributed to a domain'
bindings=$(audit_apache_domain_bindings www.app.test <<'APACHE'
192.0.2.10:443 is a NameVirtualHost
         port 443 namevhost other.test (/fixtures/a.conf:1)
198.51.100.9:443 is a NameVirtualHost
         port 443 namevhost app.test (/fixtures/b.conf:1)
                 alias www.app.test
APACHE
)
contains "$bindings" 'listen 198.51.100.9:443'
absent "$bindings" '192.0.2.10'
echo 'PASS: WordPress routing, vhost IP, Apache override, nginx-only caveat, log signals, DNS and safe opt-outs'
