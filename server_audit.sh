#!/usr/bin/env bash
#
# server_audit.sh — диагностика сервера, HMAC-метки секретов и проверяемая очистка Termbin.
#
# Определяет, что установлено на сервере (веб-сервер, БД, панель управления,
# Docker, WireGuard и т.д.), проверяет ресурсы/логи/статус только для того,
# что реально найдено, и в конце печатает в терминал ОДИН структурированный
# текстовый отчёт, готовый для передачи нейросети или инженеру поддержки.
#
# Пока идёт сбор, в терминал выводятся только короткие пометки прогресса
# ("[*] проверяю ..."), чтобы было видно, что скрипт не завис. Сами данные
# показываются один раз — цельным блоком в самом конце.
#
# Скрипт НИЧЕГО не сохраняет на диск сервера: все промежуточные файлы —
# временные, удаляются при штатном выходе и обрабатываемых сигналах.
#
# Запуск:
#   bash server_audit.sh
#   sudo bash server_audit.sh      (рекомендуется — часть проверок требует root)
#
# Переменные окружения:
#   SKIP_NET=1   — пропустить внешние сетевые проверки (ping/traceroute/curl),
#                  полезно на серверах с ограниченным исходящим трафиком.
#
# Отчёт автоматически прогоняется через фильтр, вырезающий похожие на пароли/
# токены/приватные ключи значения (см. redact_file ниже). Это защита "на
# всякий случай", а не гарантия — перед тем как отправлять отчёт куда-то за
# пределы своей команды, всё равно пробегитесь по нему глазами.

set -uo pipefail
# Без -e: часть проверок ожидаемо возвращает ненулевой код (нет пакета,
# сервис не запущен и т.д.), и это не должно останавливать сбор остальной
# диагностики.

# Прогресс во время сбора печатаем в реальный терминал через fd 3 — основной
# stdout в это время уводится в буфер (см. main_audit ниже) и наружу не идёт.
exec 3>&2
export LC_ALL=C
umask 077

if [ "$(id -u)" -ne 0 ]; then
  echo "[!] Скрипт запущен не от root — часть проверок (auth.log, sshd -T, iptables и т.д.) будет пропущена или неполной." >&2
  echo "    Рекомендуется: sudo bash $0" >&2
  echo >&2
fi

has() { command -v "$1" >/dev/null 2>&1; }

# Проверка "сервис запущен" с деградацией по init-системам:
# systemd -> OpenRC -> SysV service -> просто по имени процесса.
svc_active() {
  local name="$1"
  if audit_systemd; then
    systemctl is-active "$name" >/dev/null 2>&1
  elif has rc-service; then
    rc-service "$name" status 2>/dev/null | grep -q started
  elif has service; then
    service "$name" status >/dev/null 2>&1
  else
    pgrep -x "$name" >/dev/null 2>&1
  fi
}
sep() {
  echo "[*] $1..." >&3
  echo; echo "===================================================="; echo "## $1"; echo "===================================================="
}

# Выполняет команду, переданную одной строкой (могут быть пайпы/редиректы).
# Строка всегда задаётся статически внутри этого скрипта, а не приходит
# извне — поэтому использование bash -c здесь безопасно (нет внешнего ввода).
run() { echo "--- \$ $* ---"; audit_cmd bash -c "$*" 2>&1; echo; }

# ---------- Фильтр секретов ----------
# Вырезает из готового отчёта значения, похожие на пароли/токены/ключи,
# которые теоретически могли попасть в crontab, логи ошибок или вывод
# докер-контейнеров.
redact_file() {
  local src="$1" dst="$2"
  # Python is optional: the conservative previous filter is always available.
  # Never show the raw report or leave a partially written output on failure.
  if has python3 && redact_file_hmac "$src" "$dst" 2>/dev/null; then
    return 0
  fi
  # Rewrite from the original, not partially processed output.
  {
    printf '%s\n' '[SECRET MODE] Masking only; comparison unavailable (Python 3 missing or failed).'
    redact_file_mask_only "$src"
  } > "$dst"
}

redact_file_hmac() (
  ulimit -c 0 2>/dev/null || true
  # The random key is generated inside Python and never travels via process
  # arguments, environment, files, network, or report. One key per invocation.
  python3 -I -S - "$1" "$2" <<'PYTHON_SECRET_FILTER'
import hashlib
import hmac
import json
import os
import re
import sys
from urllib.parse import unquote, unquote_plus

key = os.urandom(32)
# 96 bits is ample for matching a bounded log report. Tags are intentionally
# unlinkable between independent audits and are NOT password verifiers.
existing_marker = re.compile(r"\[REDACTED(?:[ _][A-Z0-9_ ]+)?\]")
existing_tag = re.compile(r"\[SECRET:[0-9a-fA-F]{24}\]")

def emit_tag(value):
    if not value:
        return "[REDACTED_EMPTY]"
    if existing_marker.fullmatch(value):
        return value
    if existing_tag.fullmatch(value):
        return "[REDACTED_EXISTING_TAG]"
    if value in ("(hidden)", "(none)"):
        return "[REDACTED]"
    result = "[SECRET:" + hmac.new(
        key, value.encode("utf-8", "surrogateescape"), hashlib.sha256
    ).hexdigest()[:24] + "]"
    return result

secret_name = (
    r"(?:[a-z0-9_.-]*[_-])?"
    r"(?:password|passwd|pwd|pass|passphrase|secret|token|api[_-]?key|"
    r"access[_-]?key|private[_-]?key|client[_-]?secret|session[_-]?id|"
    r"session[_-]?token|auth[_-]?token|access[_-]?token|refresh[_-]?token|"
    r"authorization|credential(?:s)?|requirepass|key|dbpass|dbpassword|"
    r"mysqlpwd|mysql_pwd|secretaccesskey|cookie|set-cookie|proxy-authorization)"
)
secret_field = re.compile(r"^(?:" + secret_name + r")$", re.I)
double = r'"(?:\\.|[^"\\])*"'
single = r"'(?:\\.|[^'\\])*'"
# Malformed quoted values: redact to end of line rather than leaking a suffix.
bare = r"[^\s,;}\"'<>]+"
value_re = r"(?:" + double + "|" + single + "|" + bare + r"|[\"'][^\r\n]*)"
field = re.compile(
    r"(?<![a-z0-9_.?&\[-])(?P<prefix>(?P<name>[\"']?" + secret_name
    + r"[\"']?)[ \t]*[:=][ \t]*)(?P<value>" + value_re + ")", re.I
)
php_define = re.compile(
    r"(?P<prefix>\bdefine[ \t]*\([ \t]*[\"']" + secret_name
    + r"[\"'][ \t]*,[ \t]*)(?P<value>" + value_re + ")", re.I
)
directive = re.compile(
    r"(?P<prefix>(?<!\S)(?:requirepass|masterauth|AuthBasicPassword|"
    r"auth_password|smtp_password|proxy_password)[ \t]+)(?P<value>"
    + value_re + ")", re.I
)
long_arg = re.compile(
    r"(?P<prefix>--(?:password|passwd|passphrase|token|api[-_]key|secret|"
    r"client[-_]secret)[ \t]+)(?P<value>" + value_re + ")", re.I
)
mysql_arg = re.compile(r"(?P<prefix>(?<!\S)-p)(?P<value>" + value_re + ")")
redis_arg = re.compile(r"(?P<prefix>(?<!\S)-a[ \t]+)(?P<value>" + value_re + ")")
curl_user = re.compile(r"(?P<prefix>(?<!\S)(?:-u|--user)[ \t]+)(?P<value>" + value_re + ")")
uri_auth = re.compile(r'([a-zA-Z][a-zA-Z0-9+.-]*://)([^/@\s"<>]+)@')
query = re.compile(r'([?&])([a-zA-Z0-9_.%+~-]+)=([^\s&"<>]*)')
header = re.compile(
    r"(?<![a-z0-9_.?&\[-])(?P<prefix>(?P<name>[\"']?(?:Authorization|"
    r"Proxy-Authorization|Cookie|Set-Cookie|X-API-Key)[\"']?)[ \t]*:[ \t]*)"
    r"(?P<value>" + double + "|" + single + r"|[^\r\n]*)", re.I
)
pem_begin = re.compile(r"-----BEGIN [A-Za-z0-9 -]*PRIVATE KEY-----")
pem_end = re.compile(r"-----END [A-Za-z0-9 -]*PRIVATE KEY-----")
wg_key = re.compile(r"(?P<prefix>(?:private key|preshared key):[ \t]*)(?P<value>[^\r\n]+)", re.I)
auth_scheme = re.compile(r"(?i)(Bearer|Basic)[ \t]+([A-Za-z0-9_.+/=-]{10,})")
known_tokens = [
    re.compile(r"gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}"),
    re.compile(r"(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{12,}"),
    re.compile(r"sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}|sk-ant-[A-Za-z0-9_-]{20,}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{15,}|npm_[A-Za-z0-9]{20,}|AIza[A-Za-z0-9_-]{30,}"),
    re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}"),
]
telegram = re.compile(r"(bot)([0-9]{6,}:[A-Za-z0-9_-]{25,})")

def unwrap(raw, json_value=False):
    # Strip only balanced outer quotes. Decode JSON escapes when the syntax
    # explicitly indicates JSON. Do not evaluate shell/PHP expressions.
    if len(raw) >= 2 and raw[0] in "\"'" and raw[-1] == raw[0]:
        if json_value and raw[0] == '"':
            try:
                data = json.loads(raw)
                if isinstance(data, str):
                    return data, raw[0]
            except (ValueError, TypeError):
                pass
        return raw[1:-1], raw[0]
    return raw, ""

def field_value(match):
    prefix = match.group("prefix")
    name = match.groupdict().get("name") or ""
    name = name.strip("\"'").lower()
    raw = match.group("value")
    is_json = bool(match.groupdict().get("name", "").startswith('"') and ":" in prefix)
    value, quote = unwrap(raw, is_json)
    if name in ("cookie", "set-cookie"):
        tag = "[REDACTED]"
    elif name in ("authorization", "proxy-authorization"):
        parts = value.strip().split(None, 1)
        if len(parts) == 2 and parts[0].lower() in ("bearer", "basic"):
            tag = parts[0] + " " + emit_tag(parts[1])
        else:
            tag = emit_tag(value)
    else:
        tag = emit_tag(value)
    return prefix + quote + tag + quote

def uri_value(match):
    userinfo = match.group(2)
    if ":" in userinfo:
        _, password = userinfo.split(":", 1)
        return match.group(1) + "[REDACTED]:" + emit_tag(unquote(password, errors="surrogateescape")) + "@"
    return match.group(1) + emit_tag(unquote(userinfo, errors="surrogateescape")) + "@"

def query_value(match):
    name = unquote_plus(match.group(2))
    if secret_field.fullmatch(name):
        return match.group(1) + match.group(2) + "=" + emit_tag(unquote_plus(match.group(3), errors="surrogateescape"))
    return match.group(1) + "[REDACTED_QUERY]"

def curl_value(match):
    value, quote = unwrap(match.group("value"))
    if ":" in value:
        _, value = value.split(":", 1)
    return match.group("prefix") + quote + emit_tag(value) + quote

def redact(line):
    # Collect matches on the ORIGINAL text. The leftmost outer match wins;
    # once masked, its contents are never parsed again. This prevents a
    # password containing ?x=y, a URL, or a token-shaped substring from
    # getting modified before its fingerprint is computed.
    rules = [
        (header, field_value),
        (php_define, field_value),
        (directive, field_value),
        (long_arg, field_value),
        (uri_auth, uri_value),
        (query, query_value),
        (wg_key, field_value),
        (field, field_value),
        (auth_scheme, lambda m: m.group(1) + " " + emit_tag(m.group(2))),
        (telegram, lambda m: m.group(1) + emit_tag(m.group(2))),
        (existing_tag, lambda m: "[REDACTED_EXISTING_TAG]"),
    ]
    if re.search(r"\b(?:mysql|mysqldump|mariadb|mariadb-dump)\b", line):
        rules.append((mysql_arg, field_value))
    if re.search(r"\bredis-cli\b", line):
        rules.append((redis_arg, field_value))
    if re.search(r"\bcurl\b", line):
        rules.append((curl_user, curl_value))
    rules.extend((pattern, lambda m: emit_tag(m.group(0))) for pattern in known_tokens)
    matches = []
    for priority, (pattern, replace) in enumerate(rules):
        for match in pattern.finditer(line):
            matches.append((match.start(), priority, match.end(), match, replace))
    matches.sort(key=lambda item: (item[0], item[1]))
    cursor = 0
    parts = []
    for start, _, end, match, replace in matches:
        if start < cursor:
            continue
        parts.append(line[cursor:start])
        parts.append(replace(match))
        cursor = end
    parts.append(line[cursor:])
    return "".join(parts)

with open(sys.argv[1], "r", encoding="utf-8", errors="surrogateescape") as source, \
     open(sys.argv[2], "w", encoding="utf-8", errors="surrogateescape") as target:
    target.write("[SECRET MODE] HMAC-SHA256 tags: equal values match within this report only; not a validity check.\n")
    skip = False
    for line in source:
        if pem_begin.search(line):
            target.write("[REDACTED PRIVATE KEY BLOCK]\n")
            skip = not bool(pem_end.search(line))
            continue
        if pem_end.search(line):
            skip = False
            continue
        if not skip:
            # Preserve original line ending; patterns should not swallow it.
            text = line.rstrip("\r\n")
            target.write(redact(text) + line[len(text):])
PYTHON_SECRET_FILTER
)

redact_file_mask_only() {
  local src="$1"
  # Match named fields in ENV, INI, YAML, JSON and common config formats.
  # Quoted strings (including escapes) must be handled before bare values.
  local secret_name='([a-z0-9_.-]*[_-])?(password|passwd|pwd|pass|passphrase|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|session[_-]?id|session[_-]?token|auth[_-]?token|access[_-]?token|refresh[_-]?token|authorization|credential(s)?|requirepass|key|dbpass|dbpassword|mysqlpwd|mysql_pwd|secretaccesskey)'
  local prefix="((^|[^a-zA-Z0-9_.-])[\"']?${secret_name}[\"']?[[:space:]]*[:=][[:space:]]*)"
  local dq='"([^"\\]|\\.)*"'
  local sq="'([^'\\\\]|\\\\.)*'"
  local bare="[^[:space:],;}\"'<>]+"
  # Strip private-key blocks first; a log can embed the entire PEM on one line.
  # Keep diagnostic lines outside the block and do not depend on Python.
  awk '
    /-----BEGIN [A-Za-z0-9 -]*PRIVATE KEY-----/ {
      print "[REDACTED PRIVATE KEY BLOCK]"
      skip=($0 !~ /-----END [A-Za-z0-9 -]*PRIVATE KEY-----/)
      next
    }
    /-----END [A-Za-z0-9 -]*PRIVATE KEY-----/ {skip=0; next}
    skip {next}
    {print}
  ' "$src" | sed -E \
    -e "s/${prefix}${dq}/\\1\"[REDACTED]\"/gI" \
    -e "s/${prefix}${sq}/\\1'[REDACTED]'/gI" \
    -e "s/${prefix}${bare}/\\1[REDACTED]/gI" \
    -e "s/(define[[:space:]]*\\([[:space:]]*[\"']${secret_name}[\"'][[:space:]]*,[[:space:]]*)(${dq}|${sq})/\\1'[REDACTED]'/gI" \
    -e "s/((^|[[:space:]])(requirepass|masterauth|AuthBasicPassword|auth_password|smtp_password|proxy_password)[[:space:]]+)(${dq}|${sq}|${bare})/\\1[REDACTED]/gI" \
    -e "s/(--(password|passwd|passphrase|token|api[-_]key|secret|client[-_]secret)[[:space:]]+)(${dq}|${sq}|${bare})/\\1[REDACTED]/gI" \
    -e "/\\b(mysql|mysqldump|mariadb|mariadb-dump)\\b/ s/(^|[[:space:]])-p(${dq}|${sq}|${bare})/\\1-p[REDACTED]/g" \
    -e "/\\bredis-cli\\b/ s/(^|[[:space:]])-a[[:space:]]+(${dq}|${sq}|${bare})/\\1-a [REDACTED]/g" \
    -e "/\\bcurl\\b/ s/(^|[[:space:]])(-u|--user)[[:space:]]+(${dq}|${sq}|${bare})/\\1\\2 [REDACTED]/g" \
    -e 's#([a-zA-Z][a-zA-Z0-9+.-]*://)[^/@[:space:]"<>]+@#\1[REDACTED]@#g' \
    -e 's#([?&])[a-zA-Z0-9_.%+~-]+=[^[:space:]&"<>]*#\1[REDACTED_QUERY]#g' \
    -e "s/([\"']?(Authorization|Proxy-Authorization|Cookie|Set-Cookie|X-API-Key)[\"']?[[:space:]]*:[[:space:]]*).*/\\1[REDACTED]/gI" \
    -e 's/(Bearer[[:space:]]+|Basic[[:space:]]+)[A-Za-z0-9_.+\/=-]{10,}/\1[REDACTED]/gI' \
    -e 's/gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}/[REDACTED_GITHUB_TOKEN]/g' \
    -e 's/(AKIA|ASIA)[0-9A-Z]{16}/[REDACTED_AWS_KEY]/g' \
    -e 's/(sk|rk)_(live|test)_[A-Za-z0-9]{12,}/[REDACTED_PAYMENT_KEY]/g' \
    -e 's/(sk-(proj-|svcacct-)?[A-Za-z0-9_-]{20,}|sk-ant-[A-Za-z0-9_-]{20,})/[REDACTED_API_KEY]/g' \
    -e 's/xox[baprs]-[A-Za-z0-9-]{15,}|npm_[A-Za-z0-9]{20,}|AIza[A-Za-z0-9_-]{30,}/[REDACTED_TOKEN]/g' \
    -e 's/bot[0-9]{6,}:[A-Za-z0-9_-]{25,}/bot[REDACTED]/g' \
    -e 's/(private key:[[:space:]]*|preshared key:[[:space:]]*)[^[:space:]].*/\1[REDACTED]/gI' \
    -e 's/eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}/[REDACTED_JWT]/g'
}

# ---------- Incident diagnostics (also works with panel-installed binaries) ----------
# Only read state/config metadata. No restarts, enable/disable, installs, tuning,
# cache removal, or SWAP changes. Never evaluate a string taken from a config.
audit_cmd() {
  if has timeout; then timeout -k 2s "${AUDIT_TIMEOUT}s" "$@"; else "$@"; fi
}
audit_exec() {
  printf '%s' '--- $'; printf ' %q' "$@"; printf ' ---\n'
  audit_cmd "$@"; local rc=$?
  [ "$rc" -eq 0 ] || echo "[exit=$rc]"
  return 0
}
audit_bin() {
  local candidate
  for candidate in "$@"; do
    if has "$candidate"; then command -v "$candidate"; return 0; fi
  done
  return 1
}
audit_number() {
  local value="$1" default="$2" max="$3"
  if [[ "$value" =~ ^[0-9]{1,5}$ ]] && (( 10#$value >= 1 && 10#$value <= max )); then
    echo "$((10#$value))"
  else echo "$default"; fi
}
AUDIT_TIMEOUT=$(audit_number "${AUDIT_TIMEOUT:-12}" 12 120)
AUDIT_HISTORY_DAYS=$(audit_number "${AUDIT_HISTORY_DAYS:-7}" 7 90)
AUDIT_LOG_LINES=$(audit_number "${AUDIT_LOG_LINES:-20}" 20 100)
AUDIT_MAX_SITES=$(audit_number "${AUDIT_MAX_SITES:-30}" 30 100)
AUDIT_HTTP_BUDGET=$(audit_number "${AUDIT_HTTP_BUDGET:-120}" 120 900)
AUDIT_MAX_FILES=$(audit_number "${AUDIT_MAX_FILES:-20}" 20 100)
AUDIT_BOT_FILES=$(audit_number "${AUDIT_BOT_FILES:-12}" 12 60)
AUDIT_BOT_LINES=$(audit_number "${AUDIT_BOT_LINES:-2500}" 2500 10000)
AUDIT_REPORT_LINES=$(audit_number "${AUDIT_REPORT_LINES:-5000}" 5000 20000)
AUDIT_DOMAIN="${AUDIT_DOMAIN:-}"
audit_domain_ok() {
  # HTTP Host/SNI needs an actual DNS hostname, not a wildcard, literal IP,
  # placeholder, regex server_name or path. IDNs use their ASCII punycode form.
  [[ "$1" =~ ^([[:alnum:]]([[:alnum:]-]{0,61}[[:alnum:]])?\.)+[[:alnum:]]([[:alnum:]-]{0,61}[[:alnum:]])?$ &&
     ! "$1" =~ ^[0-9]+(\.[0-9]+){3}$ && ${#1} -le 253 ]]
}
if [ -n "$AUDIT_DOMAIN" ] && ! audit_domain_ok "$AUDIT_DOMAIN"; then
  echo "[!] AUDIT_DOMAIN invalid; use a hostname without scheme, path or port." >&2
  exit 2
fi
AUDIT_DOMAIN=${AUDIT_DOMAIN,,}

audit_site_order() {
  # Read rows "primary name", "alias name", "target name". Deduplicate,
  # put explicit target first, then primary vhosts and shallower names.
  local role name priority labels
  while read -r role name; do
    name=${name%;}
    name=${name#\"}; name=${name%\"}
    name=${name%.}; name=${name,,}
    audit_domain_ok "$name" || continue
    printf '%s %s\n' "$role" "$name"
  done | awk '
    {p=($1=="target"?0:($1=="primary"?1:2)); if(!($2 in rank)||p<rank[$2])rank[$2]=p}
    END{
      for(d in rank) {
        if(d ~ /^www\./ && substr(d,5) in rank && rank[substr(d,5)] > rank[d])
          rank[substr(d,5)]=rank[d]==0?1:rank[d]
      }
      for(d in rank){tmp=d; labels=gsub(/\./,".",tmp); printf "%d\t%d\t%s\n",rank[d],labels,d}
    }' | sort -t $'\t' -k1,1n -k2,2n -k3,3 | cut -f3
}
audit_nginx_site_records() {
  awk '$2=="server_name" {
    found=0
    for(i=3;i<=NF;i++){
      n=$i; ending=(n~/;/); sub(/;.*/,"",n); gsub(/"/,"",n)
      if(n ~ /^[[:alnum:]][[:alnum:].-]*\.[[:alnum:].-]+$/ && n !~ /^[0-9.]+$/)
        print (found++==0?"primary":"alias"),n
      if(ending)break
    }
  }'
}
audit_apache_site_records() {
  awk '{
    for(i=1;i<NF;i++){
      if($i=="namevhost"){print "primary",$(i+1);break}
      if($i=="default" && $(i+1)=="server" && i+2<=NF){print "primary",$(i+2);break}
      if($i=="alias"){print "alias",$(i+1);break}
      if($i=="wild" && $(i+1)=="alias")break
    }
  }'
}
audit_ols_site_records() {
  awk 'tolower($1)=="map" {
    n=0; for(i=3;i<=NF;i++){m=split($i,a,",");for(j=1;j<=m;j++)if(a[j]!="")print (n++==0?"primary":"alias"),a[j]}
  }
  tolower($1)=="vhdomain" {print "primary",$2}
  tolower($1)=="vhaliases" {for(i=2;i<=NF;i++){m=split($i,a,",");for(j=1;j<=m;j++)if(a[j]!="")print "alias",a[j]}}'
}

audit_detect() {
  NGINX_BIN=$(audit_bin /www/server/nginx/sbin/nginx nginx /usr/sbin/nginx || true)
  APACHE_BIN=$(audit_bin /www/server/apache/bin/apachectl /usr/local/apache/bin/apachectl /usr/sbin/apachectl apache2ctl apachectl || true)
  OLS_BIN=$(audit_bin /usr/local/lsws/bin/openlitespeed /usr/local/lsws/bin/lshttpd openlitespeed lshttpd || true)
  MYSQLADMIN_BIN=$(audit_bin /www/server/mysql/bin/mysqladmin /www/server/mysql/bin/mariadb-admin mariadb-admin mysqladmin || true)
}
audit_systemd() {
  has systemctl && [ -d /run/systemd/system ]
}
audit_boot_history() {
  sep "INCIDENT — BOOT HISTORY / OOM / BEFORE AND AFTER REBOOT"
  audit_exec date -u
  audit_exec uptime
  [ -r /proc/sys/kernel/random/boot_id ] && audit_exec cat /proc/sys/kernel/random/boot_id
  if has last; then audit_cmd last -x -F -n 16 2>&1; fi
  if has journalctl; then
    audit_exec journalctl --list-boots --no-pager
    local boot data rc
    for boot in 0 -1; do
      echo "--- kernel OOM/errors, boot=$boot ---"
      data=$(audit_cmd journalctl -k -b "$boot" -n 12000 --since "-${AUDIT_HISTORY_DAYS} days" --no-pager -o short-iso 2>&1); rc=$?
      if [ "$rc" -ne 0 ]; then printf '%s\n' "$data" | tail -n 6; echo "[!] boot $boot unavailable / incomplete (exit=$rc)"; continue; fi
      printf '%s\n' "$data" | awk '
        /oom-kill:constraint=|Out of memory: Killed process|Memory cgroup out of memory|invoked oom-killer|oom_reaper|segfault|I\/O error|EXT4-fs error|XFS.*error/ { print }
      ' | tail -n 65
      echo "OOM kills in retained window (last up to 12000 kernel lines; victim != memory culprit):"
      printf '%s\n' "$data" | sed -nE 's/.*Killed process [0-9]+ \(([^)]+)\).*/\1/p' | sort | uniq -c | sort -nr | head -n 15
      # Kernel OOM task table exposes the overall memory pressure and actual
      # victims. Capture only the most recent event and cap the context.
      printf '%s\n' "$data" | awk '
        /invoked oom-killer/ { n=0; capture=1 }
        capture && n<200 { lines[++n]=$0 }
        /Out of memory: Killed process|Memory cgroup out of memory: Killed process/ { capture=0; last=n; for(i=1;i<=last;i++) saved[i]=lines[i] }
        END { if(last){print "--- most recent OOM context (up to 200 lines) ---"; for(i=1;i<=last;i++) if(i<=10 || i>last-50 || saved[i] ~ /Mem-Info|anon|free:|slab|Killed process|oom-kill:/) print saved[i]} }
      ' | cut -c1-1200 | tail -n 75
      echo "--- system errors, boot=$boot ---"
      audit_cmd journalctl -b "$boot" -p err --since "-${AUDIT_HISTORY_DAYS} days" -n 30 --no-pager -o short-iso 2>&1 | cut -c1-1200
    done
  else echo "journalctl unavailable; previous boot may only exist in rotated syslog."; fi
  echo "--- retained historical resource files (atop/sysstat, metadata only) ---"
  for f in /var/log/atop/atop_* /var/log/sysstat/sa[0-9]* /var/log/sa/sa[0-9]*; do
    [ -f "$f" ] && stat -c '%y %s %n' "$f"
  done | sort -r | head -n 12
  echo "--- dmesg (current boot only) ---"
  audit_cmd dmesg -T 2>&1 | grep -iE 'oom|out of memory|killed process|denied|not permitted|I/O error' | tail -n 25
}
audit_service_inventory() {
  sep "INCIDENT — SERVICES / AUTOSTART / RESTART HISTORY"
  local units=() u state enabled boot data
  if audit_systemd; then
    audit_exec systemctl --failed --no-pager
    # Include inactive/disabled installed units, not merely running services.
    mapfile -t units < <(
      { audit_cmd systemctl list-units --type=service --all --no-legend --plain 2>/dev/null; audit_cmd systemctl list-unit-files --type=service --no-legend 2>/dev/null; } |
      awk '$1 ~ /^(nginx|httpd|apache2|lshttpd|openlitespeed|lsws|litespeed|php.*fpm|mysql|mysqld|mariadb|postgresql|redis|mongod|docker|containerd|caddy|haproxy|traefik|bt|bt-panel|btpanel|ssh|sshd|fail2ban|site_total|lscpd|cyberpanel|hestia|vesta|ispmgr|mgr5|fastpanel|directadmin|sw-cp-server|plesk|cpanel|cpsrvd|webmin|virtualmin|cloudpanel|keyhelp)([-@._0-9a-z]*)\.service$/ {print $1}' |
      sort -u | head -n 60
    )
    for u in "${units[@]}"; do
      echo "--- $u ---"
      state=$(audit_cmd systemctl show "$u" --no-pager -p LoadState -p ActiveState -p SubState -p UnitFileState -p Result -p ExecMainStatus -p NRestarts -p ActiveEnterTimestamp -p InactiveEnterTimestamp -p FragmentPath -p MemoryCurrent -p MemoryPeak -p MemoryMax -p TasksCurrent -p TasksMax 2>&1)
      printf '%s\n' "$state"
      enabled=$(audit_cmd systemctl is-enabled "$u" 2>&1 | tail -n 1)
      echo "is-enabled: $enabled"
      if [ "$enabled" = disabled ] && grep -qx 'ActiveState=active' <<< "$state"; then
        echo "[!] running but disabled: not configured for direct autostart; dependencies or panel may still start it."
      elif [ "$enabled" = disabled ] && grep -qx 'ActiveState=inactive' <<< "$state"; then
        echo "[!] inactive and disabled (may be intentional; compare with configured upstreams)."
      fi
      case "$u" in httpd.service|apache2.service|nginx.service|lshttpd.service|mysql.service|mysqld.service|mariadb.service|php*fpm*.service)
        for boot in 0 -1; do
          echo "recent lifecycle for $u boot=$boot:"
          audit_cmd journalctl -b "$boot" -u "$u" --since "-${AUDIT_HISTORY_DAYS} days" -n 100 --no-pager -o short-iso 2>&1 |
            grep -iE 'starting|started|stopping|stopped|failed|fatal|error|oom|killed|restarting|not found|no journal|boot|permission' | tail -n 8 | cut -c1-800
        done ;;
      esac
    done
    # One journal query per boot for all discovered units, separate time windows.
    local args=()
    for u in "${units[@]}"; do args+=(-u "$u"); done
    if (("${#args[@]}")); then
      for boot in 0 -1; do
        echo "--- service lifecycle/errors boot=$boot, last ${AUDIT_HISTORY_DAYS} days (up to 3000 source lines) ---"
        audit_cmd journalctl -b "$boot" "${args[@]}" -n 3000 --since "-${AUDIT_HISTORY_DAYS} days" --no-pager -o short-iso 2>&1 |
          grep -iE 'starting|started|stopping|stopped|failed|fatal|error|oom|killed|restarting|left-over|segfault|not found|no journal|boot|permission' | tail -n 65 | cut -c1-1200
      done
    fi
  else
    echo "systemd not running or unavailable."
    if has rc-status; then audit_exec rc-status --all; fi
    if has rc-update; then audit_exec rc-update show; fi
  fi
  echo "--- SysV startup link timestamps (K=stop, S=start; mtime is not actor proof) ---"
  local f
  for f in /etc/rc[0-6].d/[KS]*; do
    [ -L "$f" ] || continue
    case "${f##*/}" in *httpd*|*apache*|*nginx*|*lsws*|*lshttpd*|*php*fpm*|*mysql*|*mariadb*) ls -ld --time-style=long-iso "$f" ;; esac
  done | head -n 45
  echo "--- Relevant processes (no raw command arguments) ---"
  ps -eo pid,ppid,user,comm,rss,etimes --sort=-rss | awk 'NR==1 || $4 ~ /nginx|httpd|apache|litespeed|lsphp|php-fpm|mysqld|mariadbd|site_total|caddy|haproxy/' | head -n 35
}
audit_history_evidence() {
  sep "INCIDENT — CHANGE EVIDENCE (safe excerpts; timestamps may be missing)"
  local f
  # Extract only tightly allowlisted commands; do not dump a user's shell history.
  for f in /root/.bash_history /root/.zsh_history; do
    [ -r "$f" ] || continue
    echo "--- $f: selected service operations only ---"
    audit_cmd awk '
      /^#[0-9]+$/ { timestamp=substr($0,2); next }
      {
        line=$0
        if(line ~ /^: [0-9]+:[0-9]+;/){timestamp=line;sub(/^: /,"",timestamp);sub(/:.*/,"",timestamp)}
        sub(/^: [0-9]+:[0-9]+;/,"",line)
        if(line ~ /^(sudo )?systemctl (start|stop|restart|reload|enable|disable|mask|unmask) ( --now |--now )?(httpd|apache2|nginx|lshttpd|lsws|openlitespeed|php[-0-9.]*-?fpm[-0-9.]*|mysql[d]?|mariadb)(\.service)?( --now)?[[:space:]]*$/ ||
           line ~ /^(sudo )?(service|\/etc\/init.d\/(httpd|nginx|apache2|lsws|mysql[d]?)) (httpd |nginx |apache2 |lsws |mysql[d]? )?(start|stop|restart|reload)[[:space:]]*$/ ||
           line ~ /^(sudo )?update-rc.d (httpd|apache2|nginx|lsws|mysql[d]?) (enable|disable|defaults|remove)[[:space:]]*$/)
          print NR ": epoch=" (timestamp?timestamp:"unknown") " " line
        timestamp=""
      }
    ' "$f" | tail -n 30
  done
  if [ -d /www/server/panel ]; then
    echo "--- aaPanel install evidence (filename, time, component only) ---"
    for f in /www/server/panel/logs/installed/*.log; do
      [ -f "$f" ] || continue
      audit_cmd awk '/--[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9:]+--.*\/(openlitespeed|apache|nginx)\.sh/ { match($0,/(openlitespeed|apache|nginx)\.sh/); print FILENAME ":" NR, substr($0,3,19), substr($0,RSTART,RLENGTH) }
        /Created symlink .*multi-user.target.wants\/lshttpd.service/ { print FILENAME ":" NR, "lshttpd enabled (installer evidence)" }' "$f" 2>/dev/null
    done | tail -n 30
    echo "--- aaPanel recent service actions (no request payloads/IP/cookies) ---"
    for f in /www/server/panel/logs/request/*.json; do [ -f "$f" ] && printf '%s\n' "$f"; done |
      sort | tail -n 7 | while IFS= read -r f; do
      audit_cmd awk '
        /ServiceAdmin|switch_webserver|SwitchWebServer/ && /httpd|apache|nginx|openlitespeed|lshttpd/ {
          if(match($0,/"[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9:]+"/)) ts=substr($0,RSTART+1,RLENGTH-2); else ts="unknown"
          svc="unknown"; op="unknown"
          if(match($0,/(httpd|apache|nginx|openlitespeed|lshttpd)/)) svc=substr($0,RSTART,RLENGTH)
          if(match($0,/(restart|reload|start|stop|enable|disable)/)) op=substr($0,RSTART,RLENGTH)
          print FILENAME ":" NR, ts, svc, op, "(request, not proof of success)"
        }' "$f" 2>/dev/null
    done | tail -n 30
  fi
}
audit_disk_pressure() {
  sep "INCIDENT — STORAGE / MEMORY PRESSURE"
  df -P 2>&1 | awk 'NR==1 {print;next} $5+0>=90 {print "[!] filesystem >=90%:",$0}'
  df -Pi 2>&1 | awk 'NR==1 {print;next} $5+0>=80 {print "[!] inode usage >=80%:",$0}'
  if [ -r /proc/pressure/memory ]; then audit_exec cat /proc/pressure/memory; fi
  if [ -r /proc/pressure/io ]; then audit_exec cat /proc/pressure/io; fi
  audit_exec free -h
  audit_exec df -h /
  echo "--- RSS by process name (sum may double-count shared memory) ---"
  ps -eo comm=,rss= | awk '{n[$1]++; r[$1]+=$2} END{for(k in n)printf "%10.1f MiB %5d %s\n",r[k]/1024,n[k],k}' | sort -nr | head -n 20
  if [ "${DEEP_DISK:-0}" = 1 ] || df -P / /www /var 2>/dev/null | awk 'NR>1&&$5+0>=90{found=1} END{exit !found}' || df -Pi / /www /var 2>/dev/null | awk 'NR>1&&$5+0>=80{found=1} END{exit !found}'; then
    local d
    echo "--- bounded du (same filesystem, low priority; partial if timeout) ---"
    for d in / /www /www/server /www/server/nginx/proxy_cache_dir /www/wwwroot /var /var/log; do
      [ -d "$d" ] || continue
      echo "[$d]"
      audit_cmd nice -n 19 du -xhd1 "$d" 2>&1 | sort -hr | head -n 12
      local rc=${PIPESTATUS[0]}
      [ "$rc" -eq 0 ] || echo "[!] du incomplete (exit=$rc)"
    done
  fi
}
audit_local_port_status() {
  # For a loopback endpoint: exact port and matching IPv4/IPv6/wildcard listener.
  # IPv6 wildcard can be v6-only; the optional HTTP probe is stronger evidence.
  local host="$1" port="$2"
  [ "$TCP_OK" = 1 ] || { echo "UNKNOWN (ss unavailable)"; return; }
  local matches
  matches=$(printf '%s\n' "$TCP_LISTEN" | awk -v h="$host" -v p="$port" '
     {a=$4; if(a ~ (":"p"$")) {sub(":"p"$","",a); if(a==h || a=="*" || a=="0.0.0.0" && h !~ /:/ || a=="[::]") print $0}}')
  if [ -n "$matches" ]; then echo "LISTENER PRESENT: $(printf '%s\n' "$matches" | head -n 1 | cut -c1-300)"
  else echo "NO MATCHING LISTENER (likely 502 if this upstream is used)"; fi
}
audit_upstream() {
  local target="$1" host port path
  target="${target%;}"
  case "$target" in
    unix:*|http://unix:*|https://unix:*)
      path="${target#*unix:}"; path="${path%%:*}"
      if [ "$UNIX_OK" != 1 ]; then echo "$target => UNKNOWN (ss unavailable)"
      elif printf '%s\n' "$UNIX_LISTEN" | awk -v p="$path" '{for(i=1;i<=NF;i++)if($i==p)found=1} END{exit !found}'; then echo "$target => UNIX LISTENER PRESENT"
      elif [ -S "$path" ]; then echo "$target => SOCKET EXISTS BUT NOT LISTENING (possibly stale)"
      elif [ -e "$path" ]; then echo "$target => PATH EXISTS BUT IS NOT A SOCKET"
      else echo "$target => NO UNIX SOCKET/LISTENER"; fi ;;
    *)
      if [[ "$target" =~ ^(https?://)?(127\.[0-9]+\.[0-9]+\.[0-9]+|localhost|\[::1\]):([0-9]{1,5})(/.*)?$ ]]; then
        host="${BASH_REMATCH[2]}"; port="${BASH_REMATCH[3]}"
        [ "$host" = localhost ] && host=127.0.0.1
        echo "$target => $(audit_local_port_status "$host" "$port")"
      else echo "$target => dynamic/named/remote upstream; not assumed broken"; fi ;;
  esac
}
audit_http_classify() {
  local code="$1" rc="$2"
  if [ "$rc" != 0 ]; then
    case "$rc" in
      6) echo "DNS FAILURE";; 7) echo "CONNECT FAILURE";;
      28|124|137) echo "TIMEOUT";; 35|51|60) echo "TLS FAILURE";;
      *) echo "TRANSPORT ERROR (curl/timeout exit=$rc)";;
    esac
  else
    case "$code" in
      2??) echo "OK (HTTP response)";;
      3??) echo "REDIRECT (destination not checked)";;
      401|403) echo "ACCESS RESTRICTED";;
      404) echo "NOT FOUND";;
      4??) echo "CLIENT/HTTP ERROR";;
      5??) echo "SERVER ERROR";;
      *) echo "UNKNOWN HTTP STATUS";;
    esac
  fi
}
audit_http() {
  local label="$1" scheme="$2" domain="$3" ip="$4" port="$5"
  local original=80 result rc code
  local args=(curl -q --noproxy '*' -sS --connect-timeout 2 --max-time 5)
  [ "$scheme" = https ] && original=443
  if [ "$label" = PUBLIC ]; then
    # Real DNS/CDN path; verification remains enabled.
    printf '%s %s://%s/ => ' "$label" "$scheme" "$domain"
  else
    # Preserve Host and TLS SNI while testing the local origin.
    args+=(-k --connect-to "$domain:$original:$ip:$port")
    printf '%s %s://%s/ via %s:%s => ' "$label" "$scheme" "$domain" "$ip" "$port"
  fi
  result=$(audit_cmd "${args[@]}" -o /dev/null -w 'HTTP %{http_code} remote=%{remote_ip} connect=%{time_connect}s total=%{time_total}s\n' "$scheme://$domain/" 2>&1); rc=$?
  code=$(printf '%s\n' "$result" | sed -nE 's/^HTTP ([0-9]{3}).*/\1/p' | tail -n1)
  printf '%s [%s]\n' "$(printf '%s' "$result" | tr '\r\n' ' ' | cut -c1-350)" "$(audit_http_classify "${code:-000}" "$rc")"
}
audit_front_address() {
  local port="$1" address
  if [[ "$(audit_local_port_status 127.0.0.1 "$port")" == LISTENER* ]]; then
    echo 127.0.0.1; return 0
  fi
  # Some panels bind public/local interface addresses instead of loopback.
  # Only choose an address reported as a local listener, never DNS resolution.
  address=$(printf '%s\n' "$TCP_LISTEN" | awk -v p="$port" '$4~(":"p"$"){a=$4;sub(":"p"$","",a);if(a!="*"&&a!="0.0.0.0"&&a!="[::]"){print a;exit}}')
  if [[ "$address" =~ ^[0-9]+(\.[0-9]+){3}$ || "$address" =~ ^\[[0-9a-fA-F:]+\]$ ]]; then
    printf '%s\n' "$address"
  else
    return 1
  fi
}

audit_config_lines() {
  # Do not dump whole configs (they can hold secrets). Source markers from
  # nginx -T associate directives with real included files.
  awk '
    /^# configuration file .*:$/ { src=$0; sub(/^# configuration file /,"",src); sub(/:$/,"",src); pending=""; next }
    { line=$0; sub(/^[[:space:]]*/,"",line); if(line ~ /^#/)next
      sub(/[[:space:]]+#.*/,"",line)
      if(pending!=""){ pending=pending " " line; if(pending !~ /;/)next; line=pending; pending="" }
      else if(line ~ /^server_name[[:space:]]/ && line !~ /;/){pending=line;next}
      if(line ~ /^(server_name|listen|proxy_pass|fastcgi_pass|uwsgi_pass|scgi_pass|grpc_pass|upstream|server|error_log|access_log|include|limit_req|limit_req_zone|limit_conn|limit_conn_zone)[[:space:]]/){
        # Strip URL userinfo/query strings; never expose request headers.
        sub(/[[:space:]]+#.*/,"",line); gsub(/\?[^;[:space:]]+/,"?[REDACTED]",line)
        print (src?src:"config") ":" NR " " line
      }
    }'
}
audit_web() {
  sep "INCIDENT — WEB STACK / VHOST ROUTING / UPSTREAM HEALTH"
  TCP_LISTEN=$(audit_cmd ss -H -lntp 2>&1); TCP_OK=$?
  [ "$TCP_OK" = 0 ] && { TCP_OK=1; printf '%s\n' "$TCP_LISTEN" | head -n 70; } || { TCP_OK=0; printf '%s\n' "$TCP_LISTEN" | head -n 3; }
  UNIX_LISTEN=$(audit_cmd ss -H -lxnp 2>&1); UNIX_OK=$?
  [ "$UNIX_OK" = 0 ] && { UNIX_OK=1; printf '%s\n' "$UNIX_LISTEN" | grep -Ei 'php|nginx|apache|httpd|lsws|mysql|redis' | head -n 50; } || { UNIX_OK=0; echo "Unix listeners unavailable"; }
  local ng="" routes="" apache_sites="" records="" f d target s p
  local targets=()
  if [ -n "$NGINX_BIN" ]; then
    audit_exec "$NGINX_BIN" -v
    audit_exec "$NGINX_BIN" -t
    # Config dump kept in memory only and never printed unfiltered.
    ng=$(audit_cmd "$NGINX_BIN" -T 2>/dev/null); local rc=$?
    if [ "$rc" -ne 0 ]; then echo "[!] nginx -T unavailable (exit=$rc); reading known vhost files instead."; fi
    routes=$(printf '%s\n' "$ng" | audit_config_lines)
    if [ -z "$routes" ] || [ "$rc" -ne 0 ]; then
      routes+=$'\n'
      for f in /www/server/panel/vhost/nginx/*.conf /etc/nginx/sites-enabled/* /etc/nginx/conf.d/*.conf; do
        [ -f "$f" ] || continue
        routes+=$( { printf '# configuration file %s:\n' "$f"; cat "$f"; } | audit_config_lines)
        routes+=$'\n'
      done
    fi
    echo "--- nginx on-disk configuration (not necessarily loaded by running master) ---"
    echo "--- selected directives (file and dump line) ---"
    printf '%s\n' "$routes" | head -n 180 | cut -c1-1000
    [ -n "$AUDIT_DOMAIN" ] && { echo "--- target domain configuration ---"; printf '%s\n' "$routes" | grep -F "$AUDIT_DOMAIN" | head -n 30 | cut -c1-1000; }
    echo "--- configured upstream endpoints vs actual listeners ---"
    mapfile -t targets < <(printf '%s\n' "$routes" | awk '$2 ~ /^(proxy_pass|fastcgi_pass|uwsgi_pass|scgi_pass|grpc_pass)$/ {print $3} $2=="server" && $3 ~ /^(127\.|localhost:|\[::1\]:|unix:)/ {print $3}' | sort -u | head -n 100)
    for target in "${targets[@]}"; do
      local endpoint_status
      endpoint_status=$(audit_upstream "$target")
      printf '%s\n' "$endpoint_status"
      # Show where matching endpoints occur, even if the full dump was capped.
      if [[ "$endpoint_status" == *"NO MATCHING LISTENER"* || "$endpoint_status" == *"NO UNIX SOCKET"* ]]; then
        printf '%s\n' "$routes" | awk -v t="$target" '$3==t {print "  referenced:",$0}' | head -n 4 | cut -c1-400
      fi
    done
    records+=$(printf '%s\n' "$routes" | audit_nginx_site_records)
    records+=$'\n'
  fi
  if [ -n "$APACHE_BIN" ]; then
    echo "--- Apache ($APACHE_BIN) ---"
    audit_exec "$APACHE_BIN" -v
    audit_exec "$APACHE_BIN" -t
    apache_sites=$(audit_cmd "$APACHE_BIN" -S 2>&1); local apache_rc=$?
    printf '%s\n' "$apache_sites" | head -n 100 | cut -c1-1000
    records+=$(printf '%s\n' "$apache_sites" | audit_apache_site_records)
    records+=$'\n'
    if [ "$apache_rc" -ne 0 ]; then
      echo "[!] Apache -S incomplete; reading known vhost paths (on-disk candidates)."
      records+=$(for f in /www/server/panel/vhost/apache/*.conf /etc/apache2/sites-enabled/* /etc/httpd/conf.d/*.conf /var/www/vhosts/system/*/conf/httpd.conf /etc/apache2/conf/httpd.conf /usr/local/apache/conf/httpd.conf; do
        [ -f "$f" ] || continue
        awk 'tolower($1)=="servername"{print "primary",$2} tolower($1)=="serveralias"{for(i=2;i<=NF;i++)print "alias",$i}' "$f"
      done)
      records+=$'\n'
    fi
    # Select active config paths only; don't recurse into .bak/original.
    for f in /www/server/apache/conf/httpd.conf /www/server/apache/conf/extra/httpd-mpm.conf /etc/apache2/ports.conf /etc/apache2/mods-enabled/mpm*.conf /etc/httpd/conf/httpd.conf /etc/httpd/conf.modules.d/*mpm*.conf; do
      [ -f "$f" ] || continue
      grep -HiE '^[[:space:]]*(Listen|Include(Optional)?|ErrorLog|MaxRequestWorkers|ServerLimit|ThreadsPerChild|StartServers|MaxConnectionsPerChild)[[:space:]]' "$f" | head -n 30
    done
  fi
  if [ -n "$OLS_BIN" ] || [ -d /usr/local/lsws/conf ]; then
    echo "--- LiteSpeed / OpenLiteSpeed ---"
    [ -n "$OLS_BIN" ] && audit_exec "$OLS_BIN" -v
    for f in /usr/local/lsws/conf/httpd_config.conf /www/server/panel/vhost/openlitespeed/listen/*.conf; do
      [ -f "$f" ] || continue
      grep -HiE '^[[:space:]]*(include|listener|address|secure|map)[[:space:]]' "$f" | head -n 20 | cut -c1-600
    done | head -n 60
    records+=$(for f in /usr/local/lsws/conf/httpd_config.conf /www/server/panel/vhost/openlitespeed/listen/*.conf /www/server/panel/vhost/openlitespeed/detail/*.conf /usr/local/lsws/conf/vhosts/*/vhconf.conf; do
        [ -f "$f" ] && audit_ols_site_records < "$f"
      done)
    records+=$'\n'
    for f in /usr/local/lsws/conf/httpd_config.conf /usr/local/lsws/conf/httpd_config.conf.txt /www/server/panel/vhost/openlitespeed/listen/*.conf; do
      [ -f "$f" ] && stat -c '%y %n' "$f"
    done | head -n 25
  fi
  [ -n "$AUDIT_DOMAIN" ] && records+="target $AUDIT_DOMAIN"$'\n'
  # Retain the same complete inventory for later DNS checks; no second dump.
  mapfile -t AUDIT_DISCOVERED_DOMAINS < <(printf '%s\n' "$records" | audit_site_order)
  echo "--- SITE INVENTORY (configured hostnames, not proof of live DNS) ---"
  printf 'Discovered %s unique hostnames (including explicit target, if set).\n' "${#AUDIT_DISCOVERED_DOMAINS[@]}"
  for d in "${AUDIT_DISCOVERED_DOMAINS[@]}"; do printf 'SITE %s\n' "$d"; done
  echo "--- HTTP GET results (local origin; no redirects; local TLS verification disabled) ---"
  local count=0 skipped=0 start_seconds=$SECONDS front_ip backend_status
  for d in "${AUDIT_DISCOVERED_DOMAINS[@]}"; do
    if [ "${SKIP_HTTP:-0}" = 1 ] || ! has curl; then
      echo "SITE $d => NOT CHECKED (SKIP_HTTP=1 or missing curl)"
    elif [ "$TCP_OK" != 1 ] && { [ "${SKIP_NET:-0}" = 1 ] || { [ "$d" != "$AUDIT_DOMAIN" ] && [ "${AUDIT_PUBLIC_HTTP:-0}" != 1 ]; }; }; then
      echo "SITE $d => NOT CHECKED (ss unavailable; public check disabled)"
    elif ((count >= AUDIT_MAX_SITES)); then
      echo "SITE $d => NOT CHECKED (site probe cap $AUDIT_MAX_SITES)"
    elif ((SECONDS - start_seconds >= AUDIT_HTTP_BUDGET)); then
      echo "SITE $d => NOT CHECKED (HTTP time budget ${AUDIT_HTTP_BUDGET}s)"
    else
      ((count+=1))
      if [ "$TCP_OK" != 1 ]; then
        echo "SITE $d => LOCAL CHECK UNAVAILABLE (ss unavailable)"
      else
        for s in http https; do
          p=80; [ "$s" = https ] && p=443
          if front_ip=$(audit_front_address "$p"); then
            audit_http FRONT "$s" "$d" "$front_ip" "$p"
          else
            echo "FRONT $s://$d/ => NO LOCAL LISTENER on port $p"
          fi
        done
        while IFS= read -r target; do
          if [[ "$target" =~ ^(https?)://(127\.0\.0\.1|localhost):([0-9]{1,5})(/)?\;?$ ]]; then
            s="${BASH_REMATCH[1]}"; p="${BASH_REMATCH[3]}"
            backend_status=$(audit_local_port_status 127.0.0.1 "$p")
            if [[ "$backend_status" == LISTENER* ]]; then audit_http BACKEND "$s" "$d" 127.0.0.1 "$p"
            else echo "BACKEND $s://$d/ via 127.0.0.1:$p => $backend_status"; fi
          fi
        done < <(printf '%s\n' "$routes" | awk -v d="$d" '$2=="server_name" {for(i=3;i<=NF;i++){name=tolower($i);ending=(name~/;/);sub(/;.*/,"",name);gsub(/"/,"",name);sub(/\.$/,"",name);if(name==d){src=$1;sub(/:[0-9]+$/,"",src);files[src]=1}if(ending)break}} $2=="proxy_pass" {src=$1;sub(/:[0-9]+$/,"",src);rows[++n]=src;dest[n]=$3} END{for(i=1;i<=n;i++)if(files[rows[i]])print dest[i]}' | sort -u | head -n 4)
      fi
      if [ "${SKIP_NET:-0}" != 1 ] && { [ "$d" = "$AUDIT_DOMAIN" ] || [ "${AUDIT_PUBLIC_HTTP:-0}" = 1 ]; }; then
        audit_http PUBLIC https "$d" "" 443
      fi
      continue
    fi
    ((skipped+=1))
  done
  echo "SITE SUMMARY: discovered=${#AUDIT_DISCOVERED_DOMAINS[@]} selected=$count skipped=$skipped (HTTP results are point-in-time, not full application health)."
  ((skipped==0)) || echo "[!] Raise AUDIT_MAX_SITES/AUDIT_HTTP_BUDGET or set AUDIT_DOMAIN to prioritize specific names."
  echo "403/redirect/HTTP 200 alone is not proof of backend health; compare routing, logs and application response."

}
audit_logs() {
  sep "INCIDENT — WEB / PHP / DB ERROR LOGS"
  local f source count=0
  local -a files=()
  # Prioritize target's error logs and global service logs.
  if [ -n "$AUDIT_DOMAIN" ]; then
    files+=(/www/wwwlogs/"$AUDIT_DOMAIN".error.log /www/wwwlogs/"$AUDIT_DOMAIN"-error_log /var/log/nginx/"$AUDIT_DOMAIN".error.log /var/log/apache2/"$AUDIT_DOMAIN"-error.log /var/log/nginx/domains/"$AUDIT_DOMAIN".error.log /var/log/apache2/domains/"$AUDIT_DOMAIN".error.log /var/log/httpd/domains/"$AUDIT_DOMAIN".error.log /var/www/httpd-logs/"$AUDIT_DOMAIN".error.log /var/www/*/data/logs/"$AUDIT_DOMAIN".error.log /var/www/vhosts/system/"$AUDIT_DOMAIN"/logs/{proxy_error_log,error_log})
  fi
  files+=(/www/wwwlogs/nginx_error.log /www/server/nginx/logs/error.log /var/log/nginx/error.log /www/server/apache/logs/error_log /www/server/apache/logs/error.log /var/log/apache2/error.log /var/log/httpd/error_log /usr/local/lsws/logs/error.log /www/server/php/*/var/log/php-fpm.log /var/log/php*fpm.log /var/log/php-fpm/error.log /www/server/data/*.err /var/log/mysql/error.log /var/log/mariadb/mariadb.log)
  files+=(/www/wwwlogs/*.error.log /www/wwwlogs/*-error_log /var/log/nginx/*error*.log /var/log/apache2/*error*.log /var/log/httpd/*error* /var/log/php/*fpm*.log /var/log/nginx/domains/*.error.log /var/log/apache2/domains/*.error.log /var/log/httpd/domains/*.error.log /var/www/httpd-logs/*.error.log /var/www/*/data/logs/*.error.log /var/www/vhosts/system/*/logs/{proxy_error_log,error_log} /usr/local/apache/logs/error_log /etc/apache2/logs/error_log /usr/local/lsws/logs/stderr.log)
  declare -A seen=()
  for f in "${files[@]}"; do
    [ -f "$f" ] && [ -r "$f" ] || continue
    [ -z "${seen[$f]+x}" ] || continue; seen["$f"]=1
    if (( count >= AUDIT_MAX_FILES )); then echo "[!] log file cap ($AUDIT_MAX_FILES); use AUDIT_DOMAIN or increase AUDIT_MAX_FILES"; break; fi
    ((count+=1))
    echo "--- $f ($(stat -c 'mtime=%y bytes=%s' "$f" 2>/dev/null)) ---"
    # Bounded tail, then filter; timestamps remain intact. Avoid printing
    # query strings (often moderation tokens), long request bodies or raw configs.
    audit_cmd tail -n 300 "$f" | grep -iE 'error|warn|crit|alert|emerg|fatal|failed|refused|timeout|timed out|denied|oom|killed|max_children|server reached|segfault|shutdown|ready for connections|starting' | tail -n "$AUDIT_LOG_LINES" | cut -c1-1200
  done
  echo "--- recent rotated plain-text service logs (.1; if present) ---"
  for f in /www/wwwlogs/nginx_error.log.1 /var/log/nginx/error.log.1 /var/log/apache2/error.log.1 /var/log/httpd/error_log.1 /usr/local/lsws/logs/error.log.1 /var/log/mysql/error.log.1; do
    [ -r "$f" ] && [ -f "$f" ] || continue
    echo "[$f]"; audit_cmd tail -n 300 "$f" | grep -iE 'error|warn|crit|failed|refused|timeout|oom|killed|shutdown' | tail -n 10 | cut -c1-1000
  done
  echo "--- key upstream failures across site error logs (last 300 lines/file, capped) ---"
  # Bound file count and work; keep source names so the affected vhost is clear.
  count=0
  for f in /www/wwwlogs/*.error.log /var/log/nginx/*error*.log /var/log/nginx/domains/*.error.log /var/www/httpd-logs/*.error.log /var/www/vhosts/system/*/logs/proxy_error_log; do
    [ -r "$f" ] && [ -f "$f" ] || continue
    ((count+=1)); [ "$count" -le 100 ] || { echo "[!] upstream scan limited to 100 logs"; break; }
    audit_cmd tail -n 300 "$f" | grep -iE 'connect\(\) failed|upstream timed out|no live upstreams|upstream prematurely closed|SSL_do_handshake|no such file or directory.*upstream' | tail -n 2 | sed "s|^|$f: |" | cut -c1-900
  done | head -n 60
}
audit_tuning() {
  sep "INCIDENT — PHP POOLS / DB MEMORY LIMITS / PANEL CONFIG METADATA"
  local f
  for f in /www/server/php/*/sbin/php-fpm; do
    [ -x "$f" ] || continue
    echo "--- aaPanel FPM binary $f (version/startup warnings) ---"
    audit_cmd "$f" -v 2>&1 | head -n 8 | cut -c1-1000
  done | head -n 40
  for f in /www/server/php/*/etc/php-fpm.conf /www/server/php/*/etc/php-fpm.d/*.conf /www/server/php/*/etc/pool.d/*.conf /etc/php/*/fpm/php-fpm.conf /etc/php/*/fpm/pool.d/*.conf /etc/php-fpm.conf /etc/php-fpm.d/*.conf /opt/remi/php*/root/etc/php-fpm.d/*.conf /opt/plesk/php/*/etc/php-fpm.d/*.conf /opt/cpanel/ea-php*/root/etc/php-fpm.d/*.conf /usr/local/php*/etc/php-fpm.d/*.conf; do
    [ -f "$f" ] || continue
    grep -HiE '^[[:space:]]*(\[[^]]+\]|(include|listen|pm|pm\.(max_children|start_servers|min_spare_servers|max_spare_servers|max_requests|process_idle_timeout)|process\.max|request_terminate_timeout|request_slowlog_timeout|slowlog|error_log)[[:space:]]*=)' "$f" | head -n 20
  done | head -n 120
  for f in /www/server/php/*/etc/php.ini /etc/php/*/fpm/php.ini /etc/php.ini /opt/plesk/php/*/etc/php.ini /opt/cpanel/ea-php*/root/etc/php.ini /usr/local/php*/lib/php.ini; do
    [ -f "$f" ] || continue
    grep -HiE '^[[:space:]]*(memory_limit|max_execution_time|opcache\.memory_consumption)[[:space:]]*=' "$f"
  done | head -n 40
  for f in /etc/my.cnf /etc/my.cnf.d/*.cnf /etc/mysql/my.cnf /etc/mysql/conf.d/*.cnf /etc/mysql/mariadb.conf.d/*.cnf /etc/mysql/mysql.conf.d/*.cnf /www/server/mysql/my.cnf; do
    [ -f "$f" ] || continue
    grep -HiE '^[[:space:]]*(!include(dir)?[[:space:]]|\[(mysqld|mariadb|server)\]|(max_connections|innodb_buffer_pool_size|key_buffer_size|sort_buffer_size|join_buffer_size|read_buffer_size|read_rnd_buffer_size|tmp_table_size|max_heap_table_size|table_open_cache|thread_cache_size|performance_schema|log_error|socket|port)[[:space:]]*=)' "$f"
  done | head -n 70
  # Per-site script handlers on aaPanel (not the whole application config).
  for f in /www/server/panel/vhost/apache/*.conf /www/server/panel/vhost/openlitespeed/detail/*.conf; do
    [ -f "$f" ] || continue
    grep -HiE '^[[:space:]]*(<VirtualHost|ServerName|SetHandler|scriptHandler|add[[:space:]]+lsapi|extprocessor|path[[:space:]]+/[^[:space:]]*lsphp)' "$f" | head -n 8
  done | head -n 100
  echo "--- web-server configuration timestamps (mtime is not proof of who changed it) ---"
  for f in /www/server/nginx/conf/nginx.conf /www/server/apache/conf/httpd.conf /etc/nginx/nginx.conf /etc/apache2/apache2.conf /etc/httpd/conf/httpd.conf /www/server/apache/conf/extra/badbots.conf /www/server/apache/conf/extra/badbots-test.conf; do
    [ -f "$f" ] && stat -c '%y %n' "$f"
  done
  if [ -n "$AUDIT_DOMAIN" ]; then
    for f in /www/server/panel/vhost/{nginx,apache}/"$AUDIT_DOMAIN".conf /www/server/panel/vhost/openlitespeed/detail/"$AUDIT_DOMAIN".conf; do
      [ -f "$f" ] || continue
      stat -c '%y %n' "$f"
      grep -HiE '^[[:space:]]*(proxy_pass|fastcgi_pass|SetHandler|scriptHandler|extprocessor|address|path[[:space:]]+/[^[:space:]]*lsphp|add[[:space:]]+lsapi|ServerName|server_name|<VirtualHost)' "$f" | head -n 25
    done
  fi
}

# ---------- Bounded access-log analysis (not full traffic accounting) ----------
audit_bot_traffic() {
  sep "INCIDENT — TRAFFIC / BOTS / HTTP STATUS (sampled access logs)"
  local d="$AUDIT_DOMAIN" f count=0
  local -a candidates=()
  if [ -n "$d" ]; then
    candidates+=(/www/wwwlogs/"$d".log /var/log/nginx/domains/"$d".log /var/log/apache2/domains/"$d".log /var/log/httpd/domains/"$d".log /var/www/httpd-logs/"$d".access.log /var/www/vhosts/system/"$d"/logs/{proxy_access_ssl_log,proxy_access_log,access_ssl_log,access_log} /usr/local/apache/domlogs/"$d" /usr/local/apache/domlogs/"$d"-ssl_log /etc/apache2/logs/domlogs/"$d" /var/www/*/data/logs/"$d".access.log)
  fi
  candidates+=(/www/wwwlogs/*.log /var/log/nginx/domains/*.log /var/log/apache2/domains/*.log /var/log/httpd/domains/*.log /var/www/httpd-logs/*.access.log /var/www/*/data/logs/*.access.log /var/www/vhosts/system/*/logs/proxy_access_ssl_log /var/www/vhosts/system/*/logs/proxy_access_log /var/www/vhosts/system/*/logs/access_ssl_log /var/www/vhosts/system/*/logs/access_log /var/log/nginx/*access*.log /var/log/apache2/*access*.log /var/log/httpd/*access* /usr/local/lsws/logs/access.log /usr/local/apache/domlogs/* /etc/apache2/logs/domlogs/*)
  declare -A seen=()
  echo "At most $AUDIT_BOT_FILES files, last $AUDIT_BOT_LINES lines each; not a full traffic census."
  echo "IP may be a reverse proxy/CDN; UA may be spoofed; traffic from one IP/UA is not proof of an attack."
  for f in "${candidates[@]}"; do
    [ -r "$f" ] && [ -f "$f" ] || continue
    case "${f##*/}" in *error*|*err*|*sslcache*|*bytes*|*.gz|*.zip|*.1|*.bak|*.old) continue ;; esac
    [ -z "${seen[$f]+x}" ] || continue; seen["$f"]=1
    if (( count >= AUDIT_BOT_FILES )); then echo "[!] access-log file cap reached; set AUDIT_DOMAIN or raise AUDIT_BOT_FILES"; break; fi
    ((count+=1))
    echo "--- $f ---"
    audit_cmd tail -n "$AUDIT_BOT_LINES" "$f" | audit_access_sample
  done
  [ "$count" -gt 0 ] || echo "No readable known access logs; custom log formats/paths or disabled logging may require manual checks."
}
audit_access_sample() {
  # Common/combined logs: IP ... [date] "METHOD path HTTP/x" status bytes "ref" "UA"
  # Do not emit request query, referrer, cookies or bodies. Classifications are
  # heuristics; public search engines and legitimate APIs can match them.
  awk -F '"' '
    {
      split($1,pre,/ +/); ip=pre[1]
      split($2,r,/ +/); method=r[1]; path=r[2]; sub(/\?.*/,"",path)
      post=$3; sub(/^ +/,"",post); split(post,a,/ +/); code=a[1]
      if(ip !~ /^[0-9a-fA-F:.]+$/ || method !~ /^(GET|HEAD|POST|PUT|DELETE|PATCH|OPTIONS|CONNECT|PROPFIND)$/ || code !~ /^[1-5][0-9][0-9]$/) {bad++;next}
      n++; ips[ip]++; status[code]++
      if(match($1,/\[[^]]+\]/)){ts=substr($1,RSTART+1,RLENGTH-2);if(!first)first=ts;last=ts;minute=substr(ts,1,17);minutes[minute]++}
      ua=tolower($6); label="browser/other"
      if(ua ~ /googlebot|bingbot|yandexbot|duckduckbot|baiduspider/)label="search crawler (unverified)"
      else if(ua ~ /bot|spider|crawler|scrapy|semrush|ahrefs|mj12bot/)label="bot/crawler UA"
      else if(ua ~ /curl|wget|python-requests|go-http-client|httpx|libwww|zgrab|nmap|masscan/)label="automation/scanner UA"
      else if(ua==""||ua=="-")label="empty UA"
      uas[label]++
      if(path ~ /(^|\/)xmlrpc\.php$/)ep["xmlrpc.php"]++
      else if(path ~ /(^|\/)wp-login\.php$/)ep["wp-login.php"]++
      else if(path ~ /(^|\/)wp-json(\/|$)/ || r[2] ~ /[?&]rest_route=/)ep["WordPress REST API"]++
      else if(path ~ /(^|\/)wp-admin(\/|$)/)ep["wp-admin"]++
      else if(path ~ /(^|\/)(\.env|\.git|phpmyadmin|wp-config\.php|\.aws)(\/|$)/)ep["sensitive-path probes"]++
      if(code+0>=500 || code=="499")problem[ip]++
    }
    END{
      printf "parsed=%d unparsed=%d first=%s last=%s\n",n,bad,first,last
      if(!n)exit
      for(k in status)printf "STATUS %s %d\n",k,status[k]
      for(k in uas)printf "UA_CLASS %d %s\n",uas[k],k
      for(k in ep)printf "ENDPOINT %d %s\n",ep[k],k
      for(k in ips)printf "IP %d %s (499/5xx=%d)\n",ips[k],k,problem[k]+0
      for(k in minutes)printf "MINUTE %d %s\n",minutes[k],k
    }' | awk '
      /^IP /{i++;ip[i]=$0;next}
      /^MINUTE /{m++;mins[m]=$0;next}
      {print}
      END{
        for(k=1;k<=10&&k<=i;k++){best=0;v=-1;for(j=1;j<=i;j++)if(ip[j]!=""){split(ip[j],a," ");if(a[2]+0>v){best=j;v=a[2]+0}}if(best){print ip[best];ip[best]=""}}
        best="";v=-1;for(j=1;j<=m;j++){split(mins[j],a," ");if(a[2]+0>v){v=a[2]+0;best=mins[j]}}if(best)print "Peak sampled requests/min:",best
      }'
}

main_audit() {
audit_detect
echo "SERVER AUDIT REPORT v3.2"
echo "History: last $AUDIT_HISTORY_DAYS days, current and previous retained boot; target: ${AUDIT_DOMAIN:-auto}"
echo "Host: $(hostname)   Date: $(date -u +'%Y-%m-%d %H:%M:%S UTC')"
echo "===================================================="

# ---------- 0. СВОДКА: ЧТО НАЙДЕНО НА СЕРВЕРЕ ----------
sep "СВОДКА — что установлено (без подробностей, см. разделы ниже)"
yn() { [ "$2" = "1" ] && echo "  [x] $1" || echo "  [ ] $1"; }
has_dir_or_cmd() { [ -d "$1" ] && return 0; [ -n "${2:-}" ] && has "$2"; }

echo "Панели управления:"
yn "HestiaCP"    "$([ -d /usr/local/hestia ] && echo 1 || echo 0)"
yn "ISPmanager"  "$([ -d /usr/local/mgr5 ] && echo 1 || echo 0)"
yn "FastPanel"   "$([ -d /usr/local/fastpanel2 ] && echo 1 || echo 0)"
yn "DirectAdmin" "$([ -d /usr/local/directadmin ] && echo 1 || echo 0)"
yn "aaPanel"     "$([ -d /www/server/panel ] && echo 1 || echo 0)"
yn "VestaCP"     "$([ -d /usr/local/vesta ] && echo 1 || echo 0)"
yn "Plesk"       "$([ -d /usr/local/psa ] && echo 1 || echo 0)"
yn "cPanel/WHM"  "$([ -d /usr/local/cpanel ] && echo 1 || echo 0)"
yn "CyberPanel"  "$([ -d /usr/local/CyberCP ] && echo 1 || echo 0)"
yn "CloudPanel"  "$( ( [ -d /home/clp ] || [ -d /etc/cloudpanel ] || has clpctl ) && echo 1 || echo 0)"
yn "Webmin/Virtualmin" "$([ -d /etc/webmin ] && echo 1 || echo 0)"
yn "KeyHelp" "$([ -d /home/keyhelp ] && echo 1 || echo 0)"
echo "Веб-серверы / рантаймы:"
yn "nginx"    "$([ -n "$NGINX_BIN" ] && echo 1 || echo 0)"
yn "apache"   "$([ -n "$APACHE_BIN" ] && echo 1 || echo 0)"
yn "OpenLiteSpeed" "$([ -n "$OLS_BIN" ] || [ -d /usr/local/lsws/conf ] && echo 1 || echo 0)"
yn "PHP"      "$( (has php || [ -d /www/server/php ] || [ -d /etc/php ] || [ -d /etc/php-fpm.d ]) && echo 1 || echo 0)"
yn "PM2 (Node.js)" "$(has pm2 && echo 1 || echo 0)"
echo "Базы данных:"
yn "MySQL/MariaDB" "$([ -n "$MYSQLADMIN_BIN" ] || [ -d /www/server/mysql ] && echo 1 || echo 0)"
yn "PostgreSQL"    "$(has psql && echo 1 || echo 0)"
yn "Redis"         "$(has redis-cli && echo 1 || echo 0)"
yn "MongoDB"       "$(has mongod && echo 1 || echo 0)"
echo "Инфраструктура:"
yn "Docker"      "$(has docker && echo 1 || echo 0)"
yn "WireGuard"   "$(has wg && echo 1 || echo 0)"
yn "certbot (SSL)" "$(has certbot && echo 1 || echo 0)"
yn "fail2ban"    "$(has fail2ban-client && echo 1 || echo 0)"
yn "ufw"         "$(has ufw && echo 1 || echo 0)"
yn "firewalld"   "$(has firewall-cmd && echo 1 || echo 0)"
echo "Подробности по каждому пункту — в соответствующих разделах ниже."

# High-priority incident evidence first: it must survive report truncation.
audit_boot_history
audit_service_inventory
audit_web
audit_logs
audit_bot_traffic
audit_tuning
audit_history_evidence
audit_disk_pressure

# ---------- 1. ОС / АРХИТЕКТУРА / ВРЕМЯ РАБОТЫ ----------
sep "OS / UPTIME"
run "cat /etc/os-release | grep -E '^(PRETTY_NAME|ID|ID_LIKE|VERSION)='"
run "uname -a"
run "uptime"
run "who -r"
INIT_SYSTEM="unknown"
if audit_systemd; then
  INIT_SYSTEM="systemd"
elif has rc-status; then
  INIT_SYSTEM="OpenRC"
elif has service; then
  INIT_SYSTEM="SysV (service)"
fi
echo "Init-система: $INIT_SYSTEM"

echo "--- Синхронизация времени ---"
if has timedatectl; then
  run "timedatectl status 2>&1 | grep -iE 'local time|time zone|ntp|synchroni'"
elif has chronyc; then
  run "chronyc tracking 2>&1 | head -n 10"
elif has ntpq; then
  run "ntpq -p 2>&1 | head -n 10"
else
  echo "Нет timedatectl/chronyc/ntpq — проверить синхронизацию времени не удалось."
fi

echo "--- Требуется ли перезагрузка ---"
if [ -f /var/run/reboot-required ]; then
  echo "[!] ТРЕБУЕТСЯ ПЕРЕЗАГРУЗКА (обновлялось ядро/системные библиотеки)"
  [ -f /var/run/reboot-required.pkgs ] && { echo "Пакеты:"; cat /var/run/reboot-required.pkgs; }
elif has needs-restarting; then
  if needs-restarting -r >/dev/null 2>&1; then
    echo "Перезагрузка не требуется (needs-restarting -r)"
  else
    echo "[!] ТРЕБУЕТСЯ ПЕРЕЗАГРУЗКА (needs-restarting -r)"
  fi
else
  echo "Не удалось определить (нет /var/run/reboot-required и needs-restarting) — актуально для Debian/Ubuntu и RHEL/CentOS с yum-utils/dnf-utils соответственно."
fi

echo "--- Обновления пакетов ---"
if has apt; then
  UPD_COUNT=$(apt list --upgradable 2>/dev/null | grep -c upgradable || true)
  echo "apt: доступно обновлений (включая security): $UPD_COUNT"
elif has dnf; then
  UPD_COUNT=$(audit_cmd dnf -C check-update -q 2>/dev/null | grep -cE '^[^ ]+\.' || true)
  echo "dnf: доступно обновлений (локальный кеш, может быть неполным): $UPD_COUNT"
elif has yum; then
  UPD_COUNT=$(audit_cmd yum -C check-update -q 2>/dev/null | grep -cE '^[^ ]+\.' || true)
  echo "yum: доступно обновлений (локальный кеш, может быть неполным): $UPD_COUNT"
elif has apk; then
  run "apk version -l '<' 2>/dev/null | head -n 20"
else
  echo "Не найден apt/dnf/yum/apk — пропущено."
fi

# ---------- 2. CPU / ПАМЯТЬ / SWAP / НАГРУЗКА ----------
sep "CPU / MEMORY / SWAP / LOAD"
run "nproc"
run "cat /proc/loadavg"

echo "--- Лимит открытых файлов (ulimit -n) ---"
ULIMIT_N=$(ulimit -n 2>/dev/null || echo "?")
echo "Текущий процесс: $ULIMIT_N"
if [ "$ULIMIT_N" != "?" ] && [ "$ULIMIT_N" != "unlimited" ] && [ "$ULIMIT_N" -lt 4096 ] 2>/dev/null; then
  echo "[!] ВНИМАНИЕ: лимит открытых файлов низкий (< 4096) — частая причина"
  echo "    ошибок вида 'too many open files' у nginx/докер-контейнеров под нагрузкой."
fi

run "free -h"

echo "--- Memory usage summary ---"
read -r MTOTAL MUSED MFREE MSHARED MBUFF MAVAIL <<EOF
$(free -m | awk '/^Mem:/ {print $2, $3, $4, $5, $6, $7}')
EOF
if [ -n "${MTOTAL:-}" ] && [ "$MTOTAL" -gt 0 ]; then
  MUSED_PCT=$((MUSED * 100 / MTOTAL))
  echo "RAM: занято ${MUSED_PCT}% (${MUSED} MiB из ${MTOTAL} MiB), свободно ${MFREE} MiB, доступно (available) ${MAVAIL:-?} MiB"
  [ "$MUSED_PCT" -ge 90 ] && echo "[!] ВНИМАНИЕ: занято >= 90% RAM"
fi
read -r STOTAL SUSED SFREE <<EOF
$(free -m | awk '/^Swap:/ {print $2, $3, $4}')
EOF
if [ -n "${STOTAL:-}" ] && [ "$STOTAL" -gt 0 ]; then
  SUSED_PCT=$((SUSED * 100 / STOTAL))
  echo "Swap: занято ${SUSED_PCT}% (${SUSED} MiB из ${STOTAL} MiB)"
  [ "$SUSED_PCT" -ge 50 ] && echo "[!] ВНИМАНИЕ: активно используется swap (>= 50%) — возможна нехватка RAM"
else
  echo "Swap: не настроен (0 MiB)"
fi
echo

run "vmstat 1 3"
if has mpstat; then
  echo "--- mpstat (per-CPU utilization, 2 samples) ---"
  mpstat 1 2 2>&1
  echo
fi
if has iostat; then
  echo "--- iostat (disk I/O, 2 samples) ---"
  iostat -xz 1 2 2>&1
  echo
else
  echo "(iostat не установлен — пакет sysstat даст более подробную картину диска/CPU)"
fi
echo "--- Top-10 by RAM ---"
ps -eo pid,ppid,user,comm,%mem,rss,%cpu,etimes --sort=-rss | head -n 16
echo
echo "--- Top-10 by CPU ---"
ps -eo pid,ppid,user,comm,%mem,rss,%cpu,etimes --sort=-%cpu | head -n 16
echo

# ---------- 3. ДИСК / INODE / LVM ----------
sep "DISK / INODES"
run "df -hT"

echo "--- Занятость диска (предупреждение при >= 90%) ---"
df -P 2>/dev/null | awk 'NR>1 && $1 !~ /^(tmpfs|devtmpfs|overlay|shm)$/ {
  pct = $5; sub(/%/, "", pct);
  printf "%-6s%% %-20s %s\n", pct, $6, $1
  if (pct+0 >= 90) print "[!] ВНИМАНИЕ: " $6 " занято на " pct "% (" $1 ")"
}'
echo

run "df -i"
if has lvs; then run "lvs"; run "vgs"; run "pvs"; fi
if has lsblk; then run "lsblk -f"; fi

# ---------- 7. СЕТЬ ----------
sep "NETWORK — INTERFACES / ROUTES / DNS"
run "ip -brief addr"
run "ip route"
run "ip -6 route"
run "ip -6 neigh"
run "cat /etc/resolv.conf"

if [ "${SKIP_NET:-0}" != "1" ]; then
  sep "NETWORK — CONNECTIVITY (ping/DNS/latency)"
  echo "--- Ping (4 packets each) ---"
  for target in "8.8.8.8:Google DNS" "1.1.1.1:Cloudflare DNS" "ya.ru:Yandex" "google.com:Google.com"; do
    ip="${target%%:*}"; label="${target##*:}"
    echo "    ping $label..." >&3
    echo ">> $label ($ip)"
    ping -c 4 -W 2 "$ip" 2>&1 | tail -n 6
    echo
  done

  echo "--- DNS resolution check ---"
  for domain in google.com ya.ru cloudflare.com; do
    if has dig; then
      echo ">> $domain:"; audit_cmd dig +time=2 +tries=1 +short "$domain" | head -n 3
    elif has host; then
      echo ">> $domain:"; audit_cmd host "$domain" | head -n 3
    else
      echo ">> $domain:"; audit_cmd getent hosts "$domain"
    fi
  done
  echo

  echo "    traceroute..." >&3
  echo "--- Traceroute to 8.8.8.8 (first 10 hops) ---"
  if has traceroute; then
    audit_cmd traceroute -m 10 -w 2 8.8.8.8 2>&1
  elif has tracepath; then
    audit_cmd tracepath -m 10 8.8.8.8 2>&1
  else
    echo "traceroute/tracepath не установлены"
  fi
  echo

  echo "--- HTTPS outbound check (curl) ---"
  if has curl; then
    for url in "https://www.google.com" "https://api.telegram.org" "https://github.com"; do
      code=$(curl -q -o /dev/null -s -w "%{http_code} (%{time_total}s)" --max-time 5 "$url")
      echo "$url -> $code"
    done
  else
    echo "curl не установлен"
  fi
  echo
else
  sep "NETWORK — CONNECTIVITY"
  echo "Пропущено (SKIP_NET=1)"
fi

echo "--- MTU / link status ---"
run "ip -s link"

sep "NETWORK — LOCAL PORTS / FIREWALL"
run "ss -tulpn | head -n 60"
if has ufw; then run "ufw status verbose"; fi
if has iptables; then run "iptables -L -n -v | head -n 40"; fi
if has nft; then run "nft list ruleset | head -n 60"; fi
if has firewall-cmd; then run "firewall-cmd --list-all"; fi

# ---------- 7b. SSH ----------
sep "SSH SERVICE"
SSHD_UNIT=""
for u in sshd ssh; do
  if svc_active "$u" 2>/dev/null; then SSHD_UNIT="$u"; break; fi
done
if [ -n "$SSHD_UNIT" ]; then
  echo "status: active ($SSHD_UNIT)"
else
  echo "status: NOT active (проверьте systemctl status sshd/ssh вручную)"
fi
run "sshd -T 2>&1 | grep -iE '^(port|permitrootlogin|passwordauthentication|pubkeyauthentication|maxauthtries|allowusers|allowgroups)'"
echo "--- Config syntax test ---"
run "sshd -t"
echo "--- Listening port(s) ---"
run "ss -tlnp | grep -i ssh"
echo "--- Current sessions (who) ---"
run "who"
echo "--- Active established SSH connections ---"
run "ss -tnp state established '( dport = :22 or sport = :22 )'"
echo "--- Recent auth log: successful/failed logins (last 40) ---"
if [ -f /var/log/auth.log ]; then
  grep -iE 'sshd.*(accepted|failed|invalid user)' /var/log/auth.log | tail -n 40
elif [ -f /var/log/secure ]; then
  grep -iE 'sshd.*(accepted|failed|invalid user)' /var/log/secure | tail -n 40
else
  journalctl -u "$SSHD_UNIT" -S -24h --no-pager 2>/dev/null | grep -iE 'accepted|failed|invalid user' | tail -n 40
fi
echo "--- Failed login attempts count (last 24h) ---"
if [ -f /var/log/auth.log ]; then
  grep -c 'Failed password' /var/log/auth.log
elif [ -f /var/log/secure ]; then
  grep -c 'Failed password' /var/log/secure
fi
if has fail2ban-client; then
  echo "--- fail2ban status ---"
  run "fail2ban-client status"
  run "fail2ban-client status sshd"
fi

# ---------- 8. ПАНЕЛИ УПРАВЛЕНИЯ ----------
sep "CONTROL PANELS"
# Пути логов у панелей не всегда одинаковы между версиями/дистрибутивами —
# пробуем несколько вероятных кандидатов, тихо пропускаем, если не нашли.
panel_status() {
  # panel_status "Имя" unit1 unit2 ...
  local name="$1"; shift
  local u active=""
  for u in "$@"; do
    if svc_active "$u" 2>/dev/null; then active="$u"; break; fi
  done
  [ -n "$active" ] && echo "$name: active ($active)" || echo "$name: сервис не найден активным (проверьте вручную)"
}
panel_log() {
  # panel_log Заголовок file1 file2 ...
  local title="$1"; shift
  local f
  for f in "$@"; do
    if [ -f "$f" ]; then
      echo "--- $title ($f, last 30) ---"
      tail -n 30 "$f"
      return
    fi
  done
}

if [ -d /usr/local/hestia ]; then
  echo "HestiaCP найдена:"
  echo "Full panel configuration omitted (may contain secrets)."
  panel_status "hestia" hestia
  panel_log "HestiaCP log" /usr/local/hestia/log/system.log /usr/local/hestia/log/error/system.log
  echo
fi
if [ -d /usr/local/mgr5 ]; then
  echo "ISPmanager найдена:"
  panel_status "ispmgr" ispmgr
  panel_log "ISPmanager log" /usr/local/mgr5/var/ispmgr.log /var/log/ispmgr.log
  echo
fi
if [ -d /usr/local/fastpanel2 ]; then
  echo "FastPanel найдена:"
  panel_status "fastpanel2" fastpanel2
  panel_log "FastPanel log" /var/log/fastpanel2/fastpanel2.log /var/log/fastpanel2.log
  echo
fi
if [ -d /usr/local/directadmin ]; then
  echo "DirectAdmin найдена:"
  panel_status "directadmin" directadmin
  panel_log "DirectAdmin error log" /var/log/directadmin/error.log
  panel_log "DirectAdmin task queue errors" /var/log/directadmin/errortaskq.log
  echo
fi
if [ -d /www/server/panel ]; then
  echo "aaPanel найдена:"
  panel_status "aaPanel" bt bt-panel btpanel
  panel_log "aaPanel error log" /www/server/panel/logs/error.log
  echo
fi
if [ -d /usr/local/vesta ]; then
  echo "VestaCP найдена:"
  panel_status "vesta" vesta
  panel_log "VestaCP system log" /usr/local/vesta/log/system.log
  echo
fi
if [ -d /usr/local/psa ]; then
  echo "Plesk найдена:"
  run "plesk version 2>/dev/null | head -n 5"
  panel_status "plesk (sw-cp-server)" sw-cp-server psa
  panel_log "Plesk panel log" /var/log/plesk/panel.log
  echo
fi
if [ -d /usr/local/cpanel ]; then
  echo "cPanel/WHM найдена:"
  run "cat /usr/local/cpanel/version 2>/dev/null"
  panel_status "cpanel" cpanel cpsrvd
  panel_log "cPanel error log" /usr/local/cpanel/logs/error_log
  echo
fi

if [ -d /usr/local/CyberCP ]; then
  panel_status "CyberPanel" lscpd cyberpanel
  panel_log "CyberPanel error" /usr/local/lscp/logs/error.log /home/cyberpanel/error-logs.txt
fi
if [ -d /home/clp ] || [ -d /etc/cloudpanel ] || has clpctl; then
  panel_status "CloudPanel" cloudpanel nginx
  panel_log "CloudPanel" /home/clp/logs/error.log /var/log/cloudpanel/error.log
fi
if [ -d /etc/webmin ]; then
  panel_status "Webmin/Virtualmin" webmin
  panel_log "Webmin" /var/webmin/miniserv.error /var/log/webmin/miniserv.error
fi
if [ -d /home/keyhelp ]; then
  panel_status "KeyHelp (web stack)" keyhelp apache2
  panel_log "KeyHelp" /var/log/keyhelp/error.log
fi

# ---------- 10. ДОМЕНЫ / DNS ----------
sep "DOMAINS — DNS POINTING TO THIS SERVER"
if [ "${SKIP_NET:-0}" != "1" ]; then
  SERVER_PUBLIC_IP=""
  if has curl; then
    SERVER_PUBLIC_IP=$(curl -q -s --max-time 5 https://api.ipify.org 2>/dev/null || true)
    [ -z "$SERVER_PUBLIC_IP" ] && SERVER_PUBLIC_IP=$(curl -q -s --max-time 5 https://ifconfig.me 2>/dev/null || true)
  fi
  echo "Внешний IP сервера (определён автоматически): ${SERVER_PUBLIC_IP:-не удалось определить}"
  echo
  if ((${#AUDIT_DISCOVERED_DOMAINS[@]})); then
    echo "DNS проверяет максимум $AUDIT_MAX_SITES имён; отдельно укажите AUDIT_DOMAIN."
    echo "Найдено доменов в конфигах веб-сервера: ${#AUDIT_DISCOVERED_DOMAINS[@]}"
    echo "(если домен идёт через Cloudflare/другой CDN/прокси — несовпадение IP это нормально, не ошибка)"
    echo
    printf '%-35s %-18s %s\n' "DOMAIN" "A-RECORD" "STATUS"
    checked=0
    printf '%s\n' "${AUDIT_DISCOVERED_DOMAINS[@]}" | while IFS= read -r d; do
      audit_domain_ok "$d" || continue
      ((checked+=1)); [ "$checked" -le "$AUDIT_MAX_SITES" ] || break
      if has dig; then
        resolved=$(audit_cmd dig +time=2 +tries=1 +short A "$d" 2>/dev/null | tail -n1)
      elif has getent; then
        resolved=$(audit_cmd getent ahostsv4 "$d" 2>/dev/null | awk '{print $1}' | tail -n1)
      else
        resolved=""
      fi
      if [ -z "$resolved" ]; then
        status="A-запись не получена (проверьте DNS/timeout/NXDOMAIN)"
      elif [ -n "$SERVER_PUBLIC_IP" ] && [ "$resolved" = "$SERVER_PUBLIC_IP" ]; then
        status="OK -> указывает на этот сервер"
      else
        status="указывает на $resolved (не совпадает с этим сервером)"
      fi
      printf '%-35s %-18s %s\n' "$d" "${resolved:--}" "$status"
    done
  else
    echo "Домены в известных конфигах веб-сервера не найдены; нестандартные конфигурации могут требовать отдельной проверки."
  fi
else
  echo "Пропущено (SKIP_NET=1)"
fi

# ---------- 11. PHP-FPM: ВЕРСИИ / ЛИМИТЫ / ПУЛЫ (САЙТЫ) ----------
PHP_FPM_UNITS=""
has systemctl && PHP_FPM_UNITS=$(systemctl list-units --type=service --no-legend 2>/dev/null | awk '{print $1}' | grep -i 'php.*fpm')
PHP_INI_KEYS='^(memory_limit|upload_max_filesize|post_max_size|max_execution_time|max_input_time|max_input_vars|opcache\.enable|opcache\.memory_consumption|display_errors|expose_php)[[:space:]]*='

if has php || [ -n "$PHP_FPM_UNITS" ] || [ -d /etc/php ] || [ -d /etc/php-fpm.d ]; then
  sep "PHP-FPM"
  run "php -v 2>/dev/null | head -n1"
  for u in $PHP_FPM_UNITS; do
    echo "--- $u ---"
    svc_active "$u" && echo "status: active" || echo "status: NOT active"
  done
  [ -z "$PHP_FPM_UNITS" ] && svc_active php-fpm && echo "php-fpm: active"
  echo

  # Debian/Ubuntu-раскладка (Hestia/ISPmanager/FastPanel/VestaCP/DirectAdmin
  # на них обычно и живут): /etc/php/<версия>/fpm/, отдельная версия на сайт.
  PHP_VERSIONS=""
  [ -d /etc/php ] && PHP_VERSIONS=$(find /etc/php -mindepth 1 -maxdepth 1 -type d 2>/dev/null | xargs -n1 basename 2>/dev/null | sort -V)

  if [ -n "$PHP_VERSIONS" ]; then
    for v in $PHP_VERSIONS; do
      echo "--- PHP $v: лимиты и оптимизация ---"
      FPM_BIN=""
      for cand in "php-fpm$v" "php$v-fpm" "/usr/sbin/php-fpm$v"; do
        has "$cand" && { FPM_BIN="$cand"; break; }
      done
      if [ -n "$FPM_BIN" ]; then
        audit_cmd "$FPM_BIN" -i 2>/dev/null | grep -iE "$PHP_INI_KEYS"
      elif [ -f "/etc/php/$v/fpm/php.ini" ]; then
        audit_exec grep -iE "$PHP_INI_KEYS" "/etc/php/$v/fpm/php.ini"
      else
        echo "(не удалось определить: нет бинаря fpm и файла php.ini для этой версии)"
      fi
      POOLDIR="/etc/php/$v/fpm/pool.d"
      if [ -d "$POOLDIR" ]; then
        POOLS=$(find "$POOLDIR" -maxdepth 1 -name '*.conf' 2>/dev/null | xargs -n1 basename 2>/dev/null | sed 's/\.conf$//')
        if [ -n "$POOLS" ]; then
          echo "Сайты/пулы на PHP $v:"
          printf '%s\n' "$POOLS" | sed 's/^/  - /'
        fi
      fi
      for f in "/var/log/php$v-fpm.log" "/var/log/php/$v/fpm.log" "/var/log/php-fpm/$v-error.log"; do
        if [ -f "$f" ]; then
          echo "--- PHP $v FPM error log ($f, last 30) ---"
          tail -n 30 "$f"
          break
        fi
      done
      echo
    done
  elif [ -d /etc/php-fpm.d ]; then
    # RHEL/CentOS-раскладка: обычно одна версия PHP на систему.
    echo "--- PHP: лимиты и оптимизация (RHEL/CentOS layout) ---"
    if has php-fpm; then
      audit_cmd php-fpm -i 2>/dev/null | grep -iE "$PHP_INI_KEYS"
    else
      PHPINI=$(php --ini 2>/dev/null | grep 'Loaded Configuration' | awk '{print $NF}')
      [ -n "$PHPINI" ] && audit_exec grep -iE "$PHP_INI_KEYS" "$PHPINI"
    fi
    POOLS=$(find /etc/php-fpm.d -maxdepth 1 -name '*.conf' 2>/dev/null | xargs -n1 basename 2>/dev/null | sed 's/\.conf$//')
    if [ -n "$POOLS" ]; then
      echo "Сайты/пулы:"
      printf '%s\n' "$POOLS" | sed 's/^/  - /'
    fi
    for f in /var/log/php-fpm/error.log /var/log/php-fpm/www-error.log; do
      if [ -f "$f" ]; then
        echo "--- PHP-FPM error log ($f, last 30) ---"
        tail -n 30 "$f"
        break
      fi
    done
  elif has php; then
    echo "Несколько версий PHP не обнаружено, показываю CLI php.ini:"
    PHPINI=$(php --ini 2>/dev/null | grep 'Loaded Configuration' | awk '{print $NF}')
    [ -n "$PHPINI" ] && audit_exec grep -iE "$PHP_INI_KEYS" "$PHPINI"
  fi
fi

# ---------- 11b. PM2 (Node.js) ----------
if has pm2; then
  sep "PM2 (Node.js process manager)"
  echo "(если приложения запущены под другим пользователем, а скрипт — под root,"
  echo " pm2 может показать пустой список — это ограничение pm2, не ошибка)"
  echo "PM2 process inventory only (pm2 list may start a daemon):"
  ps -eo pid,user,comm | grep -iE "pm2|node" | head -n 30
fi

# ---------- 12. БАЗЫ ДАННЫХ ----------
sep "DATABASES"
if [ -n "$MYSQLADMIN_BIN" ]; then
  echo "--- MySQL/MariaDB ---"
  svc_active mysql 2>/dev/null && echo "status: active (mysql)"
  svc_active mariadb 2>/dev/null && echo "status: active (mariadb)"
  svc_active mysqld 2>/dev/null && echo "status: active (mysqld)"
  audit_exec "$MYSQLADMIN_BIN" --protocol=socket --connect-timeout=3 status
  echo "--- Slow / error log tail ---"
  for f in /var/log/mysql/error.log /var/log/mariadb/mariadb.log; do
    [ -f "$f" ] && { echo "[$f]"; tail -n 30 "$f"; }
  done
fi
if has psql; then
  echo "--- PostgreSQL ---"
  svc_active postgresql && echo "status: active"
  PGLOG=$(find /var/log/postgresql -name '*.log' 2>/dev/null | tail -n1)
  [ -n "$PGLOG" ] && { echo "[$PGLOG]"; tail -n 30 "$PGLOG"; }
fi
if has redis-cli; then
  echo "--- Redis ---"
  svc_active redis-server 2>/dev/null && echo "status: active"
  run "redis-cli info memory 2>&1 | grep -E 'used_memory_human|maxmemory_human'"
fi
if has mongod; then
  echo "--- MongoDB ---"
  svc_active mongod && echo "status: active"
fi

# ---------- 13. DOCKER ----------
# Логи падающих контейнеров жёстко ограничены по объёму: если сервер уходит
# в каскадный краш-луп (много контейнеров рестартует одновременно), отчёт
# всё равно не должен раздуваться на тысячи строк и обрываться в терминале.
DOCKER_LOG_MAX_CONTAINERS=8
DOCKER_LOG_TAIL_LINES=15
if has docker; then
  sep "DOCKER"
  run "docker ps -a --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' | head -n 60"
  echo "--- Restarting/unhealthy containers logs (до $DOCKER_LOG_MAX_CONTAINERS контейнеров, последние $DOCKER_LOG_TAIL_LINES строк каждый) ---"
  PROBLEM_CONTAINERS=$( { docker ps -a --filter "status=restarting" --format '{{.Names}}'; docker ps --filter "health=unhealthy" --format '{{.Names}}'; } 2>/dev/null | sed '/^$/d' | sort -u)
  PROBLEM_TOTAL=$(printf '%s\n' "$PROBLEM_CONTAINERS" | grep -c . || true)
  if [ "$PROBLEM_TOTAL" -gt 0 ]; then
    printf '%s\n' "$PROBLEM_CONTAINERS" | head -n "$DOCKER_LOG_MAX_CONTAINERS" | while IFS= read -r c; do
      [ -z "$c" ] && continue
      echo "[$c]"
      # uniq схлопывает подряд идущие ПОЛНОСТЬЮ одинаковые строки — не спасает
      # от спама с разными таймстампами, но границу по числу строк держит tail.
      docker logs --tail "$DOCKER_LOG_TAIL_LINES" "$c" 2>&1 | uniq
      echo
    done
    if [ "$PROBLEM_TOTAL" -gt "$DOCKER_LOG_MAX_CONTAINERS" ]; then
      echo "... и ещё $((PROBLEM_TOTAL - DOCKER_LOG_MAX_CONTAINERS)) проблемных контейнер(ов) — логи не показаны, чтобы не раздувать отчёт. Проверьте вручную: docker logs <имя>"
    fi
  else
    echo "Нет контейнеров в состоянии restarting/unhealthy."
  fi
  run "docker system df"
fi

# ---------- 14. SSL-СЕРТИФИКАТЫ ----------
if has certbot; then
  sep "SSL CERTIFICATES (certbot)"
  echo "Local certificate metadata (no certbot invocation):"
  for cert in /etc/letsencrypt/live/*/fullchain.pem; do
    [ -r "$cert" ] || continue
    echo "[$cert]"; audit_cmd openssl x509 -in "$cert" -noout -subject -issuer -dates
  done | head -n 60
fi

# ---------- 15. WIREGUARD / ПРОКСИ ----------
if has wg; then
  sep "WIREGUARD"
  # `wg show` по умолчанию маскирует приватный/preshared ключ строкой "(hidden)";
  # redact_file ниже дополнительно подчищает эти строки на случай нестандартной сборки wg.
  run "wg show all"
fi
if has docker && docker ps --format '{{.Names}}' 2>/dev/null | grep -qiE 'mtproxy|3x-ui|hysteria|teamspeak'; then
  sep "PROXY / GAME CONTAINERS (mtproxy/3x-ui/hysteria/teamspeak)"
  docker ps --format '{{.Names}}\t{{.Status}}' | grep -iE 'mtproxy|3x-ui|hysteria|teamspeak'
fi

# ---------- 16. CRON ----------
sep "CRON JOBS (root)"
if has crontab; then
  audit_cmd crontab -l 2>/dev/null | awk '
    /^[[:space:]]*($|#)/ {next}
    /^[[:space:]]*[A-Za-z_][A-Za-z_0-9]*[[:space:]]*=/ {next}
    /^@/ {print $1, "[command omitted]";next}
    NF>=6 {print $1,$2,$3,$4,$5,"[command omitted]"}
  ' | head -n 40
fi

echo
echo "===================================================="
echo "Сбор данных завершён."
echo "===================================================="
}

# ---------- Сбор во временный буфер (удаляется при штатном выходе) ----------
AUDIT_TMP=$(mktemp -d "${TMPDIR:-/tmp}/server-audit.XXXXXXXX") || exit 1
RAW="$AUDIT_TMP/raw"
FINAL="$AUDIT_TMP/final"
cleanup() { rm -f -- "$RAW" "$FINAL" "$AUDIT_TMP/paste-delete-status" "$AUDIT_TMP/paste-payload" "$AUDIT_TMP/paste-compact" "$AUDIT_TMP/paste-response" "$AUDIT_TMP/paste-nc-error" "$AUDIT_TMP/paste-received"; rmdir -- "$AUDIT_TMP" 2>/dev/null || true; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

main_audit > "$RAW" 2>&1
MAIN_RC=$?
if [ "$MAIN_RC" -ne 0 ]; then
  echo "[!] Collection returned exit=$MAIN_RC; report may be incomplete." >> "$RAW"
fi

# Print high-priority incident sections first; explicitly flag truncation.
RAW_LINES=$(wc -l < "$RAW" 2>/dev/null || echo 0)
if [ "$RAW_LINES" -gt "$AUDIT_REPORT_LINES" ]; then
  echo "[!] Report truncated: $RAW_LINES lines collected; showing $AUDIT_REPORT_LINES. Increase AUDIT_REPORT_LINES or narrow AUDIT_DOMAIN." >&3
fi
if ! redact_file "$RAW" "$FINAL"; then
  echo "[!] Report redaction failed; raw report will not be printed." >&2
  exit 1
fi
# Never keep the unfiltered report while waiting for user input or deletion.
rm -f -- "$RAW" || echo "[!] Не удалось сразу удалить временный исходный отчёт." >&2

echo
echo "===================================================="
echo "ГОТОВЫЙ ОТЧЁТ — скопируйте всё, что ниже (до финальной черты), и отправьте"
echo "===================================================="
head -n "$AUDIT_REPORT_LINES" "$FINAL"
if [ "$RAW_LINES" -gt "$AUDIT_REPORT_LINES" ]; then echo "[!] REPORT TRUNCATED: $RAW_LINES collected; $AUDIT_REPORT_LINES displayed."; fi
echo "===================================================="
echo "Конец отчёта. Если терминал обрезает его сверху (маленький буфер"
echo "прокрутки в PuTTY/MobaXterm/Termius) — надёжный способ получить отчёт"
echo "целиком: запустите эту же команду с ЛОКАЛЬНОГО терминала (не внутри"
echo "уже открытой сессии на сервере) с перенаправлением в файл у себя:"
echo "  ssh root@IP_СЕРВЕРА 'curl -fsSL https://raw.githubusercontent.com/lyfreedomitsme/server-audit/main/server_audit.sh | PASTE=0 bash' > report.txt"
echo "Файл report.txt появится у вас на компьютере целиком, без обрезаний."
echo "===================================================="

# ---------- Public paste preparation (local only, before consent) ----------
paste_prepare() {
  local file="$1" cap="$2" compact="$3"
  local size
  size=$(wc -c < "$file")
  [ "$size" -le "$cap" ] && return 0
  [ "$compact" = 1 ] || return 2
  # Keep every section title and prioritize evidence, not just the first N
  # bytes of a large report. LC_ALL=C makes the cap count bytes, not characters.
  # No partial UTF-8 lines: only select complete lines that fit their quota.
  LC_ALL=C awk -v cap="$cap" -v size="$size" -v target="${AUDIT_DOMAIN:-}" '
    function failure_group(x) {
      x=tolower(x)
      if(x ~ /upstream timed out|connection timed out/)return "upstream timeout"
      if(x ~ /connection refused|no matching listener|no unix socket|no local listener/)return "missing upstream"
      if(x ~ /table.*crash|table.*corrupt|wp_options.*crash/)return "database corruption"
      if(x ~ /oom-kill|killed process|out of memory/)return "OOM"
      if(x ~ /max_children|maximum number of processes/)return "PHP capacity"
      if(x ~ /systemctl disable|systemctl stop|disabled|inactive \(dead\)/)return "autostart/stopped"
      if(x ~ /filesystem >=|inode usage|no space/)return "storage pressure"
      if(x ~ /http 5[0-9][0-9]|server error/)return "HTTP 5xx"
      if(x ~ /tls failure|ssl handshake|certificate.*(failed|error)/)return "TLS"
      if(x ~ /dns failure|connect failure|http 000/)return "transport"
      if(x ~ /fatal error|segfault|crash/)return "application failure"
      if(x ~ /error|failed|denied/)return "other error"
      return ""
    }
    function priority(t, x) {
      x=tolower(t)
      if(target!="" && index(x,tolower(target)))return 7
      if(failure_group(x)!="" && failure_group(x)!="other error")return 6
      if(x ~ /oom-kill|killed process|out of memory|connection refused|upstream timed out|no matching listener|no unix socket|no local listener|server error|connect failure|tls failure|dns failure|timeout|timed out|fatal error|crash|corrupt|no space|inode usage|filesystem >=|max_children|http 5[0-9][0-9]|http 000|failed|disabled|inactive \(dead\)|status=exited|systemctl disable|systemctl stop|error:|denied/)return 5
      if(x ~ /site summary|site .*not checked|^front |^backend |^public |^site |^vhost |oom kills|peak sampled|status [45][0-9][0-9]|endpoint .*xmlrpc|endpoint .*wordpress|ip [0-9]+|active:|autostart|is-enabled|service lifecycle|boot=-1|boot=0|sysv startup|^mem:|^swap:|^\/(dev|www|var)\/|load average/)return 4
      if(x ~ /listen|port|server_name|proxy_pass|fastcgi_pass|pm.max_children|memory_limit|server version|installed|uptime|^total|^status |^ua_class|^endpoint|^\[!\]/)return 3
      if(t ~ /^--- / || t ~ /^\[SECRET MODE\]/)return 2
      return 1
    }
    function section_weight(h) {
      if(h ~ /TRAFFIC/)return 11
      if(h ~ /WEB STACK/)return 9
      if(h ~ /SERVICES \/ AUTOSTART/)return 7
      if(h ~ /WEB \/ PHP \/ DB ERROR|BOOT HISTORY/)return 5
      if(h ~ /CHANGE EVIDENCE|STORAGE|PHP POOLS|CPU \/ MEMORY|DATABASES/)return 3
      if(h ~ /DISK|DOMAINS|LOCAL PORTS/)return 2
      return 1
    }
    function add(t, forced, i) {
      if(t=="")return
      i=++n[section]; line[section,i]=t
      rank[section,i]=(forced?forced:priority(t))
      if(target!="" && index(tolower(t),tolower(target)) && rank[section,i]<8)rank[section,i]=8
      if(i<=3 && rank[section,i]<3)rank[section,i]=3
    }
    function flush_service() {
      if(svc!="" && svc_fields!="")add("SERVICE " svc svc_fields,9)
      svc=""; svc_fields=""; life=""
    }
    function flush_traffic(  basic,detail) {
      if(logname=="")return
      # Do not detach the counters from their source logfile/time window.
      basic="TRAFFIC " logname " " sample
      if(http!="")basic=basic " http=" http
      if(endpoints!="")basic=basic " endpoints=" endpoints
      if(peak!="")basic=basic " peak=" peak
      if(botua!="")basic=basic " ua=" botua
      if(firstip!="")basic=basic " top=" firstip
      if(errorip!="" && errorip!=firstip)basic=basic " worst_sampled_errors=" errorip
      add(basic,9)
      detail="TRAFFIC_DETAIL " logname
      if(ua!="")detail=detail " ua=" ua
      if(topip!="")detail=detail " top=" topip
      if(errorip!="")detail=detail " worst_sampled_errors=" errorip
      if(ua!=""||topip!=""||errorip!="")add(detail,7)
      logname="";sample="";http="";endpoints="";peak="";ua="";botua="";firstip="";topip="";ipnum=0;errmax=0;errorip=""
    }
    function add_http(t, a,d,scheme,type,port,code,timing,status,key,part) {
      split(t,a,/[[:space:]]+/)
      type=a[1]; d=a[2]; scheme=(d ~ /^https:\/\//?"https":"http")
      sub(/^https?:\/\//,"",d);sub(/\/.*/,"",d)
      if(d=="")return 0
      if(!(d in hostseen)){hostseen[d]=++hostcount;hostname[hostcount]=d}
      key=type "_" scheme
      if(type=="BACKEND" && a[3]=="via"){port=a[4];sub(/^.*:/,"",port);key=key ":" port}
      code="UNKNOWN"
      if(match(t,/HTTP [0-9][0-9][0-9]/))code=substr(t,RSTART+5,3)
      if(t ~ /NO MATCHING LISTENER|NO LOCAL LISTENER/)code="NO_LISTENER"
      else if(t ~ /TIMEOUT|timed out|curl: \(28\)/)code=code "/TIMEOUT"
      else if(t ~ /CONNECT FAILURE|Connection refused|curl: \(7\)/)code=code "/CONNECT_FAILURE"
      else if(t ~ /TLS FAILURE/)code=code "/TLS_FAILURE"
      else if(t ~ /DNS FAILURE/)code=code "/DNS_FAILURE"
      if(match(t,/total=[0-9.]+s/))code=code "/" sprintf("%.3fs",substr(t,RSTART+6,RLENGTH-7)+0)
      part=key "=" code
      probes[d]=probes[d] (probes[d]!=""?",":"") part
      if(code ~ /^(000|5[0-9][0-9]|NO_LISTENER)|FAILURE|TIMEOUT/)hostbad[d]=1
      return 1
    }
    function flush_http(  i,d) {
      # Error/target hosts before the ordinary successful responses.
      for(i=1;i<=hostcount;i++){
        d=hostname[i]
        add("HTTP_SITE " d " " probes[d],(hostbad[d] || d==target)?10:9)
        delete probes[d];delete hostbad[d];delete hostseen[d];delete hostname[i]
      }
      hostcount=0
    }
    function finish_oom_counts() {
      if(oom_counting && oom_rows==0)add("OOM_COUNT boot=" boot " no victim counts printed (retained sample)",10)
      oom_counting=0;oom_rows=0
    }
    function finish_section() {
      finish_oom_counts();flush_service();flush_traffic();flush_http()
      boot="";error_source="";life=""
    }
    BEGIN {
      section=0; title[0]="## REPORT HEADER"; n[0]=0
      hostcount=0;svc="";logname="";boot=""
    }
    /^## / && length($0)<160 && section<63 {
      finish_section()
      section++; title[section]=$0; n[section]=0; next
    }
    /^[[:space:]]*$/ || /^==+$/ { next }
    {
      t=$0
      if(t ~ /^\[!\] REPORT TRUNCATED:/){add(t,10);next}
      if(title[section] ~ /SERVICES \/ AUTOSTART/){
        if(t ~ /^--- [A-Za-z0-9@_.-]+\.service ---$/){
          flush_service();svc=t;sub(/^--- /,"",svc);sub(/ ---$/,"",svc);next
        }
        if(svc!="" && t ~ /^(LoadState|ActiveState|SubState|Result|NRestarts|ExecMainStatus|UnitFileState|ActiveEnterTimestamp|InactiveEnterTimestamp|MemoryCurrent)=/){
          if(t !~ /=$/){
            sub(/^LoadState=/,"load=",t);sub(/^ActiveState=/,"active=",t);sub(/^SubState=/,"sub=",t)
            sub(/^Result=/,"result=",t);sub(/^NRestarts=/,"restarts=",t);sub(/^ExecMainStatus=/,"exit=",t)
            sub(/^UnitFileState=/,"unit=",t);sub(/^MemoryCurrent=/,"mem=",t)
            sub(/^ActiveEnterTimestamp=/,"started=",t);sub(/^InactiveEnterTimestamp=/,"stopped=",t)
            svc_fields=svc_fields " " t
          }
          next
        }
        if(svc!="" && t ~ /^is-enabled: /){
          sub(/^is-enabled: /,"",t);svc_fields=svc_fields " is-enabled=" t;next
        }
        if(t ~ /^recent lifecycle for /){life=t;add(t,4);next}
        if(t ~ /^--- /){flush_service()}
        if(life!="" && t ~ /^[0-9][0-9][0-9][0-9]-/ && t ~ /Starting|Started|Stopping|Stopped|Failed|failed|oom-kill/){
          add("LIFECYCLE " life " " t,6);next
        }
      }
      if(title[section] ~ /BOOT HISTORY/){
        if(t ~ /^--- kernel OOM\/errors, boot=/){finish_oom_counts();boot=t;sub(/^.*boot=/,"",boot);sub(/ ---$/,"",boot);oom_counting=0;add(t,5);next}
        if(t ~ /^OOM kills in retained window/){oom_counting=1;oom_rows=0;add(t,5);next}
        if(oom_counting && t ~ /^[[:space:]]*[0-9]+[[:space:]]+[^ ]+/){
          oom_rows++;add("OOM_COUNT boot=" boot " victim=" $2 " kills=" $1,10);next
        }
        if(oom_counting && t ~ /^--- /)finish_oom_counts()
        if(t ~ /Out of memory: Killed process/ && boot!=""){add("OOM_EVENT boot=" boot " " t,6);next}
        if(t ~ /^(reboot|shutdown)[[:space:]]/ || t ~ /^[[:space:]]*(-1|0)[[:space:]]+[0-9a-f]+[[:space:]]/){add(t,8);next}
      }
      if(title[section] ~ /WEB STACK/){
        if(t ~ /^(FRONT|BACKEND|PUBLIC) https?:\/\//){if(add_http(t))next}
        if(t ~ /^SITE SUMMARY:/){add(t,10);next}
        if(t ~ /^SITE [^ ]+ => NOT CHECKED/){add(t,8);next}
        if(t ~ /=> (NO MATCHING LISTENER|NO UNIX SOCKET|UNIX LISTENER PRESENT|LISTENER PRESENT|SOCKET EXISTS)/){add(t,8);next}
        if(t ~ /^LISTEN[[:space:]]/){add(t,7);next}
      }
      if(title[section] ~ /TRAFFIC \/ BOTS/){
        if(t ~ /^At most .*not a full traffic census|^IP may be a reverse proxy/){add(t,8);next}
        if(t ~ /^--- \/.* ---$/){
          flush_traffic();logname=t;sub(/^--- /,"",logname);sub(/ ---$/,"",logname);next
        }
        if(logname!=""){
          if(t ~ /^parsed=/){sample=t;next}
          if(t ~ /^STATUS [0-9]/){http=http (http!=""?",":"") $2 ":" $3;next}
          if(t ~ /^ENDPOINT /){v=t;sub(/^ENDPOINT /,"",v);endpoints=endpoints (endpoints!=""?";":"") v;next}
          if(t ~ /^UA_CLASS /){
            v=t;sub(/^UA_CLASS /,"",v);ua=ua (ua!=""?";":"") v
            if(v ~ /bot|crawler|automation|scanner|empty UA/)botua=botua (botua!=""?";":"") v
            next
          }
          if(t ~ /^IP /){
            if(++ipnum<=2){v=t;sub(/^IP /,"",v);topip=topip (topip!=""?";":"") v;if(ipnum==1)firstip=v}
            v=t;sub(/^.*499\/5xx=/,"",v);sub(/\).*$/,"",v)
            if(v ~ /^[0-9]+$/ && v+0>errmax){errmax=v+0;errorip=t;sub(/^IP /,"",errorip)}
            next
          }
          if(t ~ /^Peak sampled requests\/min:/){peak=t;sub(/^Peak sampled requests\/min: /,"",peak);next}
          if(t ~ /^--- /)flush_traffic()
        }
      }
      if(title[section] ~ /WEB \/ PHP \/ DB ERROR/){
        if(t ~ /^--- \/.* ---$/){error_source=t;sub(/^--- /,"",error_source);sub(/ ---$/,"",error_source);add(t,4);next}
        if(t ~ /^--- /)error_source=""
        if(error_source!="" && failure_group(t)!="" && t !~ /^\//){t="LOG " error_source " " t}
      }
      # A giant server_name line can contain dozens of aliases; make the
      # primary vhost explicit without absorbing the whole quota.
      if(t ~ /^[^ ]+:[0-9]+ server_name /){
        split(t,a,/[[:space:]]+/); name=a[3];sub(/;$/,"",name)
        if(name ~ /^[[:alnum:]][[:alnum:].-]*\.[[:alnum:].-]+$/ && name !~ /^[0-9.]+$/){add("VHOST " name,8);next}
      }
      add(t,0)
    }
    END {
      finish_section()
      intro="[COMPACT TERMBIN REPORT] Original displayed report: " size " bytes. Selected evidence from every section; omissions are marked. Full report is in the terminal."
      header_bytes=length(intro)+1
      total_weight=0
      for(s=0;s<=section;s++){
        weight[s]=section_weight(title[s]);total_weight+=weight[s]
        header_bytes+=length(title[s])+2+120
      }
      available=cap-header_bytes
      if(available<0)exit 2
      total_used=0
      for(s=0;s<=section;s++){
        quota=int(available*weight[s]/total_weight)
        used=0; selected=0
        # Prefer compact structured evidence before noisy excerpts. A
        # service state, HTTP result, traffic summary and OOM count keep
        # their attribution even if full logs exceed the cap.
        for(p=10;p>=8;p--){
          for(i=1;i<=n[s];i++){
            if(rank[s,i]!=p)continue
            bytes=length(line[s,i])+1
            if(used+bytes<=quota){keep[s,i]=1;used+=bytes;selected++}
          }
        }
        # Include one recent specimen from distinct severe failure classes.
        for(p=7;p>=5;p--){
          for(i=n[s];i>=1;i--){
            group=failure_group(line[s,i])
            if(rank[s,i]!=p || keep[s,i] || group=="" || seen[s,group])continue
            bytes=length(line[s,i])+1
            if(used+bytes<=quota){keep[s,i]=1;used+=bytes;selected++;seen[s,group]=1}
          }
        }
        # Primary vhost names and the inventory summary are more useful
        # than long repetitive listener/config lines.
        for(i=1;i<=n[s];i++){
          if(keep[s,i] || line[s,i] !~ /^(VHOST |SITE SUMMARY:)/)continue
          bytes=length(line[s,i])+1
          if(used+bytes<=int(quota*0.78)){keep[s,i]=1;used+=bytes;selected++}
        }
        for(p=4;p>=2;p--){
          for(i=1;i<=n[s];i++){
            if(rank[s,i]!=p || keep[s,i])continue
            bytes=length(line[s,i])+1
            if(used+bytes<=int(quota*0.8)){keep[s,i]=1;used+=bytes;selected++}
          }
        }
        for(p=7;p>=1;p--){
          for(i=1;i<=n[s];i++){
            if(rank[s,i]!=p || keep[s,i])continue
            bytes=length(line[s,i])+1
            if(used+bytes<=quota){keep[s,i]=1;used+=bytes;selected++}
          }
        }
        selected_count[s]=selected
        total_used+=used
      }
      # Quotas for small/empty sections may be unused. Reallocate exactly
      # that space to high-priority records which did not fit elsewhere.
      leftover=available-total_used
      for(p=10;p>=8;p--){
        for(s=0;s<=section;s++){
          for(i=1;i<=n[s];i++){
            if(rank[s,i]!=p || keep[s,i])continue
            bytes=length(line[s,i])+1
            if(bytes<=leftover){
              keep[s,i]=1;leftover-=bytes;selected_count[s]++
            }
          }
        }
      }
      print intro
      for(s=0;s<=section;s++){
        print ""; print title[s]
        for(i=1;i<=n[s];i++)if(keep[s,i])print line[s,i]
        essential_omitted=0
        for(i=1;i<=n[s];i++)if(rank[s,i]>=8 && !keep[s,i])essential_omitted++
        if(selected_count[s]<n[s])printf "[COMPACT] %d evidence/detail records omitted (%d high-priority); full report in terminal.\n",n[s]-selected_count[s],essential_omitted
      }
    }' "$file" > "$AUDIT_TMP/paste-compact" || return 1
  size=$(wc -c < "$AUDIT_TMP/paste-compact")
  [ "$size" -le "$cap" ] || return 1
  mv -- "$AUDIT_TMP/paste-compact" "$file"
  return 3
}
paste_upload() {
  local payload="$1" response="$AUDIT_TMP/paste-response" errors="$AUDIT_TMP/paste-nc-error"
  local help rc
  local args=()
  # OpenBSD netcat on Ubuntu/Debian supports -N: half-close the socket
  # after stdin EOF so Fiche does not wait for its receive timeout.
  help=$(timeout 2s nc -h 2>&1 || true)
  if grep -Eq '(^|[[:space:],])-N([[:space:],]|$)' <<< "$help"; then args+=(-N); fi
  if grep -Eq '(^|[[:space:],])-w([[:space:],]|$)' <<< "$help"; then args+=(-w 15); fi
  timeout -k 2s 25s nc "${args[@]}" termbin.com 9999 < "$payload" 2>"$errors" | head -c 2048 > "$response"
  rc=${PIPESTATUS[0]}
  PASTE_NC_RC="$rc"
  PASTE_RESPONSE_BYTES=$(wc -c < "$response")
  # A Fiche response can end in CR/LF and NUL. Accept only a single trusted
  # host/slug, then canonicalize to HTTPS. Never retry an ambiguous upload.
  PASTE_URL=$(tr -d '\000\r' < "$response")
  if [[ "$PASTE_URL" =~ ^https?://termbin\.com/([A-Za-z0-9_-]{1,80})[[:blank:]]*$ ]]; then
    PASTE_URL="https://termbin.com/${BASH_REMATCH[1]}"
    return 0
  fi
  PASTE_URL=""
  return 1
}
# Optional legacy public paste. No upload without explicit opt-in; never
# upload with SKIP_NET=1. Deletion is best-effort, not a privacy guarantee.
DO_PASTE=0
PASTE_READY=0
PASTE_PAYLOAD="$AUDIT_TMP/paste-payload"
if [ "${SKIP_NET:-0}" != 1 ]; then
  case "${PASTE:-}" in
    0|n|N|no|NO) ;;
    *)
      if [[ "${PASTE:-}" =~ ^(1|y|Y|yes|YES)$ ]] || { [ -t 1 ] && ( : </dev/tty ) 2>/dev/null; }; then
        # Fiche upstream defaults to 32KiB; the live public service limit
        # is undocumented. Use a conservative default, with explicit override.
        paste_cap="${PASTE_MAX_BYTES:-30000}"
        if [[ ! "$paste_cap" =~ ^[0-9]{4,7}$ ]] || ((10#$paste_cap<4096 || 10#$paste_cap>1048576)); then paste_cap=30000; fi
        paste_cap=$((10#$paste_cap))
        head -n "$AUDIT_REPORT_LINES" "$FINAL" > "$PASTE_PAYLOAD"
        if [ "${RAW_LINES:-0}" -gt "$AUDIT_REPORT_LINES" ]; then
          printf '[!] REPORT TRUNCATED: %s source lines, %s displayed.\n' "$RAW_LINES" "$AUDIT_REPORT_LINES" >> "$PASTE_PAYLOAD"
        fi
        paste_original_bytes=$(wc -c < "$PASTE_PAYLOAD")
        compact=1
        [ "${PASTE_MODE:-compact}" = full ] && compact=0
        paste_prepare "$PASTE_PAYLOAD" "$paste_cap" "$compact"; prep_rc=$?
        case "$prep_rc" in
          0) PASTE_READY=1; echo "[*] Termbin: полный отчёт ($paste_original_bytes байт)." ;;
          3) PASTE_READY=1; echo "[!] Termbin: полный отчёт $paste_original_bytes байт превышает лимит $paste_cap. Будет опубликована КОМПАКТНАЯ версия ($(wc -c < "$PASTE_PAYLOAD") байт); полный отчёт выше." ;;
          2) echo "[!] Termbin: отчёт $paste_original_bytes байт больше PASTE_MAX_BYTES=$paste_cap; PASTE_MODE=full, публикация отменена." ;;
          *) echo "[!] Не удалось подготовить компактную версию в лимите; публикация отменена." ;;
        esac
        if [ "$PASTE_READY" = 1 ]; then
          case "${PASTE:-}" in
            1|y|Y|yes|YES) DO_PASTE=1 ;;
            *)
              echo "[!] Опубликовать отчёт на termbin.com? Ссылка публичная, без пароля."
              echo "Запланировано удаление и проверка доступности ссылки. Гарантии конфиденциальности нет."
              echo "Отчёт может содержать IP, домены, логи и нераспознанные секреты."
              printf 'y/N: '
              answer=""
              read -r answer </dev/tty || true
              case "$answer" in y|Y|yes|YES) DO_PASTE=1 ;; esac ;;
          esac
        fi
      fi ;;
  esac
fi
if [ "$DO_PASTE" = 1 ]; then
  # Termbin allows self-service deletion for ten minutes. Leave time for retries.
  ttl=$(audit_number "${PASTE_TTL:-15}" 15 540)
  if [ "${PASTE_TTL:-15}" = 0 ]; then ttl=0; fi
  if ! has nc || ! has timeout; then
    echo "[!] nc/timeout unavailable; public upload skipped."
  elif [ "$ttl" != 0 ] && { ! has curl || { ! has setsid && ! has nohup; }; }; then
    echo "[!] Для проверяемого удаления нужны curl и setsid/nohup. Публикация отменена."
  else
    # Only upload the size-checked and redacted payload once.
    if paste_upload "$PASTE_PAYLOAD"; then
      slug="${PASTE_URL##*/}"
      echo "Ссылка: $PASTE_URL"
      echo "[!] Ссылка публичная; данные уже переданы стороннему сервису."
      echo "Ручное удаление (с того же IP):"
      printf '  curl -q --noproxy "*" -fsS -X POST "https://termbin.com/delete?slug=%s"\n' "$slug"
      if [ "$ttl" = 0 ]; then
        echo "[!] Автоматическое удаление отключено (PASTE_TTL=0)."
      else
        echo "[*] Через $ttl сек. начнётся удаление. Откройте ссылку и скопируйте отчёт сейчас."
        # Detached worker: it does not need the raw report, or an open SSH/TTY.
        # Its output is captured privately and displayed by the waiting parent.
        # A GET with 404/410 confirms only that the original URL is unavailable
        # at the moment of the check, not that backups/copies were erased.
        delete_code=$(cat <<'DELETE_WORKER'
set -u
sleep "$1"
slug="$2"
url="https://termbin.com/$slug"
delete_url="https://termbin.com/delete?slug=$slug"
http_code() {
  curl -q --noproxy '*' --proto '=https' -sS --connect-timeout 4 --max-time 8 \
    -o /dev/null -w '%{http_code}' "$@" 2>/dev/null
}
for attempt in 1 2 3; do
  post=$(http_code -X POST "$delete_url") || post=000
  get=$(http_code -H 'Cache-Control: no-cache' -H 'Pragma: no-cache' "$url") || get=000
  case "$get" in
    404|410)
      printf '[OK] Ссылка недоступна (HTTP %s; попытка %s/3, POST %s).\n' "$get" "$attempt" "$post"
      exit 0 ;;
  esac
  printf '[!] Попытка %s/3: POST %s, GET %s.\n' "$attempt" "$post" "$get"
  if [ "$attempt" -lt 3 ]; then sleep "$((attempt * 2))"; fi
done
echo '[!] Удаление НЕ подтверждено. Ссылка может оставаться доступной. Используйте команду ручного удаления выше.'
exit 1
DELETE_WORKER
)
        status_file="$AUDIT_TMP/paste-delete-status"
        if has setsid && setsid --help 2>&1 | grep -q -- '--wait'; then
          setsid --wait bash -c "$delete_code" bash "$ttl" "$slug" </dev/null >"$status_file" 2>&1 &
        elif has nohup; then
          nohup bash -c "$delete_code" bash "$ttl" "$slug" </dev/null >"$status_file" 2>&1 &
        else
          # Some BusyBox versions have setsid but lack --wait. With job
          # control disabled, this child is not a process group leader.
          setsid bash -c "$delete_code" bash "$ttl" "$slug" </dev/null >"$status_file" 2>&1 &
        fi
        delete_pid=$!
        wait "$delete_pid" || true
        if [ -s "$status_file" ]; then cat "$status_file"
        else echo "[!] Не удалось получить результат проверки. Удаление не подтверждено."; fi
      fi
    else
      echo "[!] Нет корректной ссылки от Termbin (nc exit=$PASTE_NC_RC, отправляемый размер=$(wc -c < "$PASTE_PAYLOAD") байт, ответ=$PASTE_RESPONSE_BYTES байт)."
      case "$PASTE_NC_RC" in
        124|137) echo "[!] Истёк таймаут соединения/ответа Termbin." ;;
        *) if [ -s "$AUDIT_TMP/paste-nc-error" ]; then
          echo "[!] Диагностика netcat:"
          LC_ALL=C tr -cd '[:print:]\n' < "$AUDIT_TMP/paste-nc-error" | head -c 300
          echo
        fi ;;
      esac
      echo "[!] Публикация могла состояться; удалить неизвестный URL нельзя. Повтор автоматически не выполняется. Используйте локальный отчёт."
    fi
  fi
fi
