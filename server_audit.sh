#!/usr/bin/env bash
#
# server_audit.sh — универсальный сборщик диагностики сервера.
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
# временные, гарантированно удаляются (shred) при выходе, даже по Ctrl+C.
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
exec 3>&1

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
  if has systemctl; then
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
run() { echo "--- \$ $* ---"; bash -c "$*" 2>&1; echo; }

# ---------- Фильтр секретов ----------
# Вырезает из готового отчёта значения, похожие на пароли/токены/ключи,
# которые теоретически могли попасть в crontab, логи ошибок или вывод
# докер-контейнеров.
redact_file() {
  local src="$1" dst="$2"
  sed -E \
    -e '/\b(mysql|mysqldump|mariadb|mariadb-dump|psql|pg_dump|pg_restore|mongorestore|mongodump)\b/ s/(^|[[:space:]])-p([^[:space:]]{3,})/\1-p[REDACTED]/g' \
    -e 's/((api[_-]?key|access[_-]?key|secret[_-]?key|service[_-]?role[_-]?key|[a-z0-9_]*_key|private[_-]?key|secret|token|passwd|password|pass|pwd)[[:space:]]*[:=][[:space:]]*)[^[:space:]]+/\1[REDACTED]/gI' \
    -e 's#([a-zA-Z][a-zA-Z0-9+.-]*://[^:/@[:space:]]*):[^@/[:space:]]+@#\1:[REDACTED]@#g' \
    -e 's/AKIA[0-9A-Z]{16}/[REDACTED_AWS_KEY]/g' \
    -e 's/(private key:[[:space:]]*)[^[:space:]].*/\1[REDACTED]/gI' \
    -e 's/(preshared key:[[:space:]]*)[^[:space:]].*/\1[REDACTED]/gI' \
    -e 's/(Bearer[[:space:]]+)[A-Za-z0-9_.=-]{10,}/\1[REDACTED]/gI' \
    -e 's/eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}/[REDACTED_JWT]/g' \
    "$src" 2>/dev/null | awk '
      /-----BEGIN [A-Za-z0-9 ]*PRIVATE KEY-----/ { print "[REDACTED PRIVATE KEY BLOCK]"; skip=1; next }
      /-----END [A-Za-z0-9 ]*PRIVATE KEY-----/   { skip=0; next }
      skip { next }
      { print }
    ' > "$dst"
}

main_audit() {
echo "SERVER AUDIT REPORT"
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
echo "Веб-серверы / рантаймы:"
yn "nginx"    "$(has nginx && echo 1 || echo 0)"
yn "apache"   "$( (has apache2 || has httpd) && echo 1 || echo 0)"
yn "PHP"      "$(has php && echo 1 || echo 0)"
yn "PM2 (Node.js)" "$(has pm2 && echo 1 || echo 0)"
echo "Базы данных:"
yn "MySQL/MariaDB" "$( (has mysql || has mariadb) && echo 1 || echo 0)"
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

# ---------- 1. ОС / АРХИТЕКТУРА / ВРЕМЯ РАБОТЫ ----------
sep "OS / UPTIME"
run "cat /etc/os-release | grep -E '^(PRETTY_NAME|ID|ID_LIKE|VERSION)='"
run "uname -a"
run "uptime"
run "who -r"
INIT_SYSTEM="unknown"
if has systemctl; then
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
  UPD_COUNT=$(dnf check-update -q 2>/dev/null | grep -cE '^[^ ]+\.' || true)
  echo "dnf: доступно обновлений: $UPD_COUNT"
elif has yum; then
  UPD_COUNT=$(yum check-update -q 2>/dev/null | grep -cE '^[^ ]+\.' || true)
  echo "yum: доступно обновлений: $UPD_COUNT"
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
ps aux --sort=-%mem | head -n 11
echo
echo "--- Top-10 by CPU ---"
ps aux --sort=-%cpu | head -n 11
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

# ---------- 4. OOM / ОШИБКИ ЯДРА ----------
sep "OOM KILLER / KERNEL ERRORS (dmesg)"
run "dmesg -T 2>/dev/null | grep -iE 'oom|out of memory|killed process' | tail -n 30"
run "dmesg -T 2>/dev/null | grep -iE 'error|fail' | tail -n 30"

# ---------- 5. УПАВШИЕ СЕРВИСЫ ----------
sep "FAILED / STOPPED SERVICES"
if has systemctl; then
  run "systemctl --failed --no-pager"
elif has rc-status; then
  run "rc-status --servicelist 2>&1 | grep -v started"
elif has service; then
  run "service --status-all 2>&1"
else
  echo "Не найден systemctl/rc-status/service — пропущено."
fi

# ---------- 6. ЖУРНАЛ ОШИБОК ЗА 24Ч ----------
sep "ERROR LOG (last 24h, priority err+)"
if has journalctl; then
  run "journalctl -p err -S -24h --no-pager | tail -n 100"
else
  echo "journalctl недоступен (система без systemd) — общие системные ошибки см. в разделе OOM/dmesg выше и в /var/log/messages или /var/log/syslog."
  for f in /var/log/syslog /var/log/messages; do
    [ -f "$f" ] && { echo "--- tail $f (errors) ---"; grep -iE 'error|fail|critical' "$f" | tail -n 100; }
  done
fi

# ---------- 7. СЕТЬ ----------
sep "NETWORK — INTERFACES / ROUTES / DNS"
run "ip -brief addr"
run "ip route"
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
      echo ">> $domain:"; dig +short "$domain" | head -n 3
    elif has host; then
      echo ">> $domain:"; host "$domain" | head -n 3
    else
      echo ">> $domain:"; getent hosts "$domain"
    fi
  done
  echo

  echo "    traceroute..." >&3
  echo "--- Traceroute to 8.8.8.8 (first 10 hops) ---"
  if has traceroute; then
    traceroute -m 10 -w 2 8.8.8.8 2>&1
  elif has tracepath; then
    tracepath -m 10 8.8.8.8 2>&1
  else
    echo "traceroute/tracepath не установлены"
  fi
  echo

  echo "--- HTTPS outbound check (curl) ---"
  if has curl; then
    for url in "https://www.google.com" "https://api.telegram.org" "https://github.com"; do
      code=$(curl -o /dev/null -s -w "%{http_code} (%{time_total}s)" --max-time 5 "$url")
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
run "ss -tulpn | head -n 40"
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
[ -d /usr/local/hestia ] && { echo "HestiaCP найдена:"; run "/usr/local/hestia/bin/v-list-sys-config 2>/dev/null | head -n 20"; }
[ -d /usr/local/mgr5 ] && { echo "ISPmanager найдена"; svc_active ispmgr && echo "ispmgr: active"; }
[ -d /usr/local/fastpanel2 ] && { echo "FastPanel найдена"; svc_active fastpanel2 && echo "fastpanel2: active"; }
[ -d /usr/local/directadmin ] && { echo "DirectAdmin найдена"; svc_active directadmin && echo "directadmin: active"; }
[ -d /www/server/panel ] && echo "aaPanel найдена"
[ -d /usr/local/vesta ] && echo "VestaCP найдена"
[ -d /usr/local/psa ] && { echo "Plesk найдена:"; run "plesk version 2>/dev/null | head -n 5"; }
[ -d /usr/local/cpanel ] && { echo "cPanel/WHM найдена:"; run "cat /usr/local/cpanel/version 2>/dev/null"; }
echo

# ---------- 9. ВЕБ-СЕРВЕРЫ ----------
sep "WEB SERVERS"
if has nginx; then
  echo "--- nginx ---"
  svc_active nginx && echo "status: active" || echo "status: NOT active"
  run "nginx -t"
  run "nginx -v"
  echo "--- nginx error.log (last 40) ---"
  ERRLOG=$(nginx -T 2>/dev/null | grep -m1 'error_log' | awk '{print $2}' | tr -d ';')
  [ -f "${ERRLOG:-/var/log/nginx/error.log}" ] && tail -n 40 "${ERRLOG:-/var/log/nginx/error.log}"
fi
if has apache2 || has httpd; then
  APACHECTL=$(has apache2ctl && echo apache2ctl || echo apachectl)
  echo "--- apache ---"
  svc_active apache2 2>/dev/null && echo "status: active"
  svc_active httpd 2>/dev/null && echo "status: active"
  run "$APACHECTL -t 2>&1"
  run "$APACHECTL -v 2>&1"
  echo "--- apache error log (last 40) ---"
  for f in /var/log/apache2/error.log /var/log/httpd/error_log; do
    [ -f "$f" ] && { echo "[$f]"; tail -n 40 "$f"; }
  done
fi

# ---------- 10. ДОМЕНЫ / DNS ----------
sep "DOMAINS — DNS POINTING TO THIS SERVER"
if [ "${SKIP_NET:-0}" != "1" ]; then
  SERVER_PUBLIC_IP=""
  if has curl; then
    SERVER_PUBLIC_IP=$(curl -s --max-time 5 https://api.ipify.org 2>/dev/null || true)
    [ -z "$SERVER_PUBLIC_IP" ] && SERVER_PUBLIC_IP=$(curl -s --max-time 5 https://ifconfig.me 2>/dev/null || true)
  fi
  echo "Внешний IP сервера (определён автоматически): ${SERVER_PUBLIC_IP:-не удалось определить}"
  echo

  DOMAINS=""
  if has nginx; then
    DOMAINS="$DOMAINS $(nginx -T 2>/dev/null | grep -E '^\s*server_name\s' | sed -E 's/^\s*server_name\s+//; s/;\s*$//' | tr ' ' '\n')"
  fi
  if has apache2ctl || has apachectl; then
    AC=$(has apache2ctl && echo apache2ctl || echo apachectl)
    DOMAINS="$DOMAINS $($AC -S 2>/dev/null | grep -oE 'namevhost [^ ]+' | awk '{print $2}')"
    DOMAINS="$DOMAINS $(grep -rhoE '^\s*ServerAlias\s+.*' /etc/apache2/sites-enabled /etc/httpd/conf.d 2>/dev/null | sed -E 's/^\s*ServerAlias\s+//')"
  fi
  DOMAINS=$(printf '%s\n' $DOMAINS | sed '/^$/d' | grep -vE '^(_|\*|localhost)$' | sort -u)

  if [ -n "$DOMAINS" ]; then
    echo "Найдено доменов в конфигах веб-сервера: $(printf '%s\n' "$DOMAINS" | wc -l)"
    echo "(если домен идёт через Cloudflare/другой CDN/прокси — несовпадение IP это нормально, не ошибка)"
    echo
    printf '%-35s %-18s %s\n' "DOMAIN" "A-RECORD" "STATUS"
    printf '%s\n' "$DOMAINS" | while IFS= read -r d; do
      [ -z "$d" ] && continue
      if has dig; then
        resolved=$(dig +short A "$d" 2>/dev/null | tail -n1)
      elif has getent; then
        resolved=$(getent hosts "$d" 2>/dev/null | awk '{print $1}' | tail -n1)
      else
        resolved=""
      fi
      if [ -z "$resolved" ]; then
        status="нет A-записи / NXDOMAIN"
      elif [ -n "$SERVER_PUBLIC_IP" ] && [ "$resolved" = "$SERVER_PUBLIC_IP" ]; then
        status="OK -> указывает на этот сервер"
      else
        status="указывает на $resolved (не совпадает с этим сервером)"
      fi
      printf '%-35s %-18s %s\n' "$d" "${resolved:--}" "$status"
    done
  else
    echo "Домены в конфигах nginx/apache не найдены (server_name/ServerName не заданы или веб-сервер не установлен)."
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
        run "$FPM_BIN -i 2>/dev/null | grep -iE \"$PHP_INI_KEYS\""
      elif [ -f "/etc/php/$v/fpm/php.ini" ]; then
        run "grep -iE \"$PHP_INI_KEYS\" '/etc/php/$v/fpm/php.ini'"
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
      echo
    done
  elif [ -d /etc/php-fpm.d ]; then
    # RHEL/CentOS-раскладка: обычно одна версия PHP на систему.
    echo "--- PHP: лимиты и оптимизация (RHEL/CentOS layout) ---"
    if has php-fpm; then
      run "php-fpm -i 2>/dev/null | grep -iE \"$PHP_INI_KEYS\""
    else
      PHPINI=$(php --ini 2>/dev/null | grep 'Loaded Configuration' | awk '{print $NF}')
      [ -n "$PHPINI" ] && run "grep -iE \"$PHP_INI_KEYS\" '$PHPINI'"
    fi
    POOLS=$(find /etc/php-fpm.d -maxdepth 1 -name '*.conf' 2>/dev/null | xargs -n1 basename 2>/dev/null | sed 's/\.conf$//')
    if [ -n "$POOLS" ]; then
      echo "Сайты/пулы:"
      printf '%s\n' "$POOLS" | sed 's/^/  - /'
    fi
  elif has php; then
    echo "Несколько версий PHP не обнаружено, показываю CLI php.ini:"
    PHPINI=$(php --ini 2>/dev/null | grep 'Loaded Configuration' | awk '{print $NF}')
    [ -n "$PHPINI" ] && run "grep -iE \"$PHP_INI_KEYS\" '$PHPINI'"
  fi
fi

# ---------- 11b. PM2 (Node.js) ----------
if has pm2; then
  sep "PM2 (Node.js process manager)"
  echo "(если приложения запущены под другим пользователем, а скрипт — под root,"
  echo " pm2 может показать пустой список — это ограничение pm2, не ошибка)"
  run "pm2 list 2>&1"
fi

# ---------- 12. БАЗЫ ДАННЫХ ----------
sep "DATABASES"
if has mysql || has mariadb; then
  echo "--- MySQL/MariaDB ---"
  svc_active mysql 2>/dev/null && echo "status: active (mysql)"
  svc_active mariadb 2>/dev/null && echo "status: active (mariadb)"
  run "mysqladmin status 2>&1"
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
  run "certbot certificates 2>&1"
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
run "crontab -l 2>&1"

echo
echo "===================================================="
echo "Сбор данных завершён."
echo "===================================================="
}

# ---------- Сбор во временный буфер (никогда не остаётся на диске сервера) ----------
RAW="$(mktemp)"
FINAL="$(mktemp)"
chmod 600 "$RAW" "$FINAL"
# gарантированная зачистка временных файлов при любом выходе, включая Ctrl+C
cleanup() { shred -u "$RAW" "$FINAL" 2>/dev/null; rm -f "$RAW" "$FINAL" 2>/dev/null; }
trap cleanup EXIT

main_audit > "$RAW" 2>&1

# Общий предохранитель: если сервер (например, из-за каскадного краш-лупа
# сервисов) выдал аномально много данных, отчёт всё равно не должен
# раздуваться бесконечно и обрываться в терминале пользователя.
MAX_REPORT_LINES=3000
RAW_LINES=$(wc -l < "$RAW" 2>/dev/null || echo 0)
if [ "$RAW_LINES" -gt "$MAX_REPORT_LINES" ]; then
  TRUNCATED=$(head -n "$MAX_REPORT_LINES" "$RAW")
  {
    printf '%s\n' "$TRUNCATED"
    echo
    echo "[!] ОТЧЁТ ОБРЕЗАН: собрано $RAW_LINES строк, показаны первые $MAX_REPORT_LINES."
    echo "    Сервер выдаёт аномально много диагностических данных — это само по"
    echo "    себе симптом (часто: каскадный краш-луп сервисов, спам в логах)."
    echo "    Часть проверок ниже в отчёт не попала."
  } > "$RAW"
fi

redact_file "$RAW" "$FINAL"

echo
echo "===================================================="
echo "ГОТОВЫЙ ОТЧЁТ — скопируйте всё, что ниже (до финальной черты), и отправьте"
echo "===================================================="
cat "$FINAL"
echo "===================================================="
echo "Конец отчёта. Если терминал обрезает его сверху (маленький буфер"
echo "прокрутки в PuTTY/MobaXterm/Termius) — надёжный способ получить отчёт"
echo "целиком: запустите эту же команду с ЛОКАЛЬНОГО терминала (не внутри"
echo "уже открытой сессии на сервере) с перенаправлением в файл у себя:"
echo "  ssh root@${SERVER_PUBLIC_IP:-IP_СЕРВЕРА} 'curl -fsSL https://raw.githubusercontent.com/lyfreedomitsme/server-audit/main/server_audit.sh | bash' > report.txt"
echo "Файл report.txt появится у вас на компьютере целиком, без обрезаний."
echo "===================================================="

PASTE_TTL_DEFAULT=15
DO_PASTE=0
case "${PASTE:-}" in
  1|y|Y|yes|YES) DO_PASTE=1 ;;
  0|n|N|no|NO) DO_PASTE=0 ;;
  *)
    if [ -r /dev/tty ]; then
      echo
      echo "Опубликовать отчёт на termbin.com? Ссылка публичная, без пароля,"
      echo "будет активна ${PASTE_TTL:-$PASTE_TTL_DEFAULT} сек. — скрипт сам её удалит."
      PASTE_ANSWER=""
      read -r -p "y/N: " PASTE_ANSWER 2>/dev/null < /dev/tty || PASTE_ANSWER=""
      case "$PASTE_ANSWER" in
        y|Y|yes|Yes|YES) DO_PASTE=1 ;;
        *) DO_PASTE=0 ;;
      esac
    fi
    ;;
esac

if [ "$DO_PASTE" = "1" ]; then
  PASTE_TTL="${PASTE_TTL:-$PASTE_TTL_DEFAULT}"
  echo
  if has nc; then
    echo "[*] Заливаю отчёт на termbin.com (публичная ссылка, БЕЗ пароля)..."
    PASTE_URL=$(cat "$FINAL" | nc termbin.com 9999 2>/dev/null | tr -d '\0' | tr -d '[:space:]' | tail -c 200)
    if [ -n "$PASTE_URL" ]; then
      PASTE_SLUG="${PASTE_URL##*/}"
      echo "Ссылка: $PASTE_URL"
      echo "[!] Ссылка ПУБЛИЧНАЯ и без пароля — открыть её сможет кто угодно, у кого"
      echo "    она окажется. Пароли/токены/ключи из отчёта уже вырезаны, но хостнеймы,"
      echo "    IP и список софта останутся видны. Не используйте для чувствительных серверов."
      if has curl; then
        echo "Удалить раньше срока можно вручную (первые 10 минут, с этого же IP):"
        echo "  curl -X POST \"https://termbin.com/delete?slug=$PASTE_SLUG\""
        if [ "$PASTE_TTL" -gt 0 ] 2>/dev/null; then
          echo "[*] Удалю ссылку сама через $PASTE_TTL сек. Успейте скопировать/открыть."
          ( sleep "$PASTE_TTL"
            DEL=$(curl -s -X POST "https://termbin.com/delete?slug=$PASTE_SLUG")
            echo "[*] termbin: $DEL" >&3
          ) &
          disown
        fi
      fi
    else
      echo "[!] Не удалось залить на termbin.com (нет сети или сервис недоступен) — используйте текст выше."
    fi
  else
    echo "[!] netcat (nc) не установлен — публикация на termbin.com пропущена."
  fi
fi
