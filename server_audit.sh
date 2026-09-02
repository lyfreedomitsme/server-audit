#!/usr/bin/env bash
#
# server_audit.sh — универсальный сборщик диагностики сервера.
#
# Определяет, что установлено на сервере (веб-сервер, БД, панель управления,
# Docker, WireGuard и т.д.), проверяет ресурсы/логи/статус только для того,
# что реально найдено, и выводит один текстовый отчёт, готовый для передачи
# нейросети или инженеру поддержки для анализа.
#
# Запуск:
#   bash server_audit.sh
#   sudo bash server_audit.sh      (рекомендуется — часть проверок требует root)
#
# Переменные окружения:
#   SKIP_NET=1   — пропустить внешние сетевые проверки (ping/traceroute/curl),
#                  полезно на серверах с ограниченным исходящим трафиком.
#
# Итоговый (уже очищенный от типичных секретов) отчёт сохраняется в:
#   /root/server_audit_<hostname>_<дата>.txt  (или в $HOME, если /root недоступен)
#
# Отчёт автоматически прогоняется через фильтр, вырезающий похожие на пароли/
# токены/приватные ключи значения (см. redact_file ниже). Это защита "на
# всякий случай", а не гарантия — перед тем как отправлять отчёт куда-то за
# пределы своей команды, всё равно пробегитесь по нему глазами.

set -uo pipefail
# Без -e: часть проверок ожидаемо возвращает ненулевой код (нет пакета,
# сервис не запущен и т.д.), и это не должно останавливать сбор остальной
# диагностики.

# ---------- Куда сохранять отчёт ----------
OUTDIR="/root"
[ -w "$OUTDIR" ] || OUTDIR="${HOME:-/tmp}"
HOSTNAME_SHORT="$(hostname -s 2>/dev/null || hostname 2>/dev/null || echo unknown-host)"
OUT="$OUTDIR/server_audit_${HOSTNAME_SHORT}_$(date +%Y%m%d_%H%M%S).txt"

if [ "$(id -u)" -ne 0 ]; then
  echo "[!] Скрипт запущен не от root — часть проверок (auth.log, sshd -T, iptables и т.д.) будет пропущена или неполной." >&2
  echo "    Рекомендуется: sudo bash $0" >&2
  echo >&2
fi

has() { command -v "$1" >/dev/null 2>&1; }
svc_active() { systemctl is-active "$1" >/dev/null 2>&1; }
sep() { echo; echo "===================================================="; echo "## $1"; echo "===================================================="; }

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
    -e 's/((api[_-]?key|access[_-]?key|secret[_-]?key|secret|token|passwd|password|pwd)[[:space:]]*[:=][[:space:]]*)[^[:space:]]+/\1[REDACTED]/gI' \
    -e 's#(https?://[^:/@[:space:]]+):[^@/[:space:]]+@#\1:[REDACTED]@#g' \
    -e 's/AKIA[0-9A-Z]{16}/[REDACTED_AWS_KEY]/g' \
    -e 's/(private key:[[:space:]]*)[^[:space:]].*/\1[REDACTED]/gI' \
    -e 's/(preshared key:[[:space:]]*)[^[:space:]].*/\1[REDACTED]/gI' \
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

# ---------- 1. ОС / ANKETA / LOAD ----------
sep "OS / UPTIME / LOAD"
run "cat /etc/os-release | grep -E '^(PRETTY_NAME|VERSION)='"
run "uname -a"
run "uptime"
run "who -r"

# ---------- 2. CPU / ПАМЯТЬ / SWAP ----------
sep "CPU / MEMORY / SWAP"
run "nproc"
run "free -h"
run "vmstat 1 3"
echo "--- Top-10 by RAM ---"
ps aux --sort=-%mem | head -n 11
echo
echo "--- Top-10 by CPU ---"
ps aux --sort=-%cpu | head -n 11
echo

# ---------- 3. ДИСК / INODE / LVM ----------
sep "DISK / INODES"
run "df -hT"
run "df -i"
if has lvs; then run "lvs"; run "vgs"; run "pvs"; fi
if has lsblk; then run "lsblk -f"; fi

# ---------- 4. OOM / ОШИБКИ ЯДРА ----------
sep "OOM KILLER / KERNEL ERRORS (dmesg)"
run "dmesg -T 2>/dev/null | grep -iE 'oom|out of memory|killed process' | tail -n 30"
run "dmesg -T 2>/dev/null | grep -iE 'error|fail' | tail -n 30"

# ---------- 5. SYSTEMD: УПАВШИЕ ЮНИТЫ ----------
sep "SYSTEMD FAILED UNITS"
run "systemctl --failed --no-pager"

# ---------- 6. ЖУРНАЛ ОШИБОК ЗА 24Ч ----------
sep "JOURNALCTL ERRORS (last 24h, priority err+)"
run "journalctl -p err -S -24h --no-pager | tail -n 100"

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

# ---------- 10. PHP-FPM ----------
if has php || systemctl list-units --type=service 2>/dev/null | grep -q php.*fpm; then
  sep "PHP-FPM"
  run "php -v 2>/dev/null | head -n1"
  for u in $(systemctl list-units --type=service --no-legend 2>/dev/null | awk '{print $1}' | grep -i 'php.*fpm'); do
    echo "--- $u ---"
    svc_active "$u" && echo "status: active" || echo "status: NOT active"
  done
fi

# ---------- 11. БАЗЫ ДАННЫХ ----------
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

# ---------- 12. DOCKER ----------
if has docker; then
  sep "DOCKER"
  run "docker ps -a --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'"
  echo "--- Restarting/unhealthy containers logs (last 20 lines each) ---"
  for c in $(docker ps -a --filter "status=restarting" --format '{{.Names}}') $(docker ps --filter "health=unhealthy" --format '{{.Names}}'); do
    echo "[$c]"
    docker logs --tail 20 "$c" 2>&1
    echo
  done
  run "docker system df"
fi

# ---------- 13. SSL-СЕРТИФИКАТЫ ----------
if has certbot; then
  sep "SSL CERTIFICATES (certbot)"
  run "certbot certificates 2>&1"
fi

# ---------- 14. WIREGUARD / ПРОКСИ ----------
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

# ---------- 15. CRON ----------
sep "CRON JOBS (root)"
run "crontab -l 2>&1"

echo
echo "===================================================="
echo "Сбор данных завершён."
echo "===================================================="
}

# ---------- Сбор в сырой временный файл, затем очистка от секретов ----------
RAW="$(mktemp)"
chmod 600 "$RAW"
main_audit | tee "$RAW"

redact_file "$RAW" "$OUT"
chmod 600 "$OUT"
shred -u "$RAW" 2>/dev/null || rm -f "$RAW"

echo
echo "===================================================="
echo "Итоговый отчёт (с базовой чисткой секретов) сохранён в: $OUT"
echo "Скопируйте текст файла целиком и отправьте нейросети для анализа."
echo "===================================================="
