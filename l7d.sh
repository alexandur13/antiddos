#!/usr/bin/env bash
# l7d.sh   Layer 7 anti ddos detector & mitigator with webhook alerts and dumps
# Usage:
#   l7d.sh run            # start detector/mitigator (foreground)
#   l7d.sh install        # install to /opt/l7d and systemd unit
#   l7d.sh status         # show current blocks and recent actions
#   l7d.sh readme         # print usage
#   l7d.sh dump-latest    # print last incident summary
#
# Requires: jq, nftables, awk, coreutils, tail, logger, curl, tcpdump , nginx 
set -Eeuo pipefail


LOG_FILE="${LOG_FILE:-/var/log/nginx/access_l7.json}"     # JSON access log 
WINDOW_SEC="${WINDOW_SEC:-5}"                              
IP_RPS="${IP_RPS:-150}"                                    # Per-IP average req/s across window to trigger
PATH_RPS="${PATH_RPS:-500}"                                # Per-path global trigger
ERR_RATIO_THRESHOLD="${ERR_RATIO_THRESHOLD:-0.6}"          # 4xx/5xx ratio influences severity (logged)
COOLDOWN_SEC="${COOLDOWN_SEC:-120}"                        # Cooldown per IP between events

# Mitigation: nftables (drop TCP 80/443 from abusive IPs) with escalating TTLs
BAN_TTL_DEFAULT="${BAN_TTL_DEFAULT:-15m}"
BAN_TTL_SECOND="${BAN_TTL_SECOND:-60m}"
BAN_TTL_THIRD="${BAN_TTL_THIRD:-6h}"
BAN_TTL_FOURTH="${BAN_TTL_FOURTH:-24h}"

# Whitelist: exact IPs (one per line). Extend to CIDR using ipset if needed.
WHITELIST_FILE="${WHITELIST_FILE:-/etc/l7d.whitelist}"

# Dumps / incidents
INCIDENTS_DIR="${INCIDENTS_DIR:-/var/log/l7d/incidents}"
CAP_DIR="${CAP_DIR:-/var/log/l7d/pcap}"
DUMP_ON_BAN="${DUMP_ON_BAN:-true}"                          # capture sample.pcap on ban
DUMP_SECONDS="${DUMP_SECONDS:-20}"                          # seconds to capture
IFACE="${IFACE:-eth0}"                                      # interface for tcpdump
SNAP_LEN="${SNAP_LEN:-96}"                                   # bytes per packet

# Runtime / state
STATE_DIR="${STATE_DIR:-/var/lib/l7d}"
RUNTIME_DIR="${RUNTIME_DIR:-/var/run/l7d}"
EVENTS_FILE="${EVENTS_FILE:-$RUNTIME_DIR/events.ndjson}"
ACTIONS_LOG="${ACTIONS_LOG:-$STATE_DIR/actions.log}"
OFFENSE_FILE="${OFFENSE_FILE:-$STATE_DIR/offenders.tsv}"

# nftables
NFT_TABLE="${NFT_TABLE:-inet l7d}"
SET_V4="${SET_V4:-s_black_v4}"
SET_V6="${SET_V6:-s_black_v6}"
PROTECT_TCP_PORTS="${PROTECT_TCP_PORTS:-{80,443}}"

# Webhooks 
WEBHOOK_URL="${WEBHOOK_URL:-}"               # e.g., Slack/Discord/custom
WEBHOOK_FORMAT="${WEBHOOK_FORMAT:-auto}"     # auto|slack|discord|generic
WEBHOOK_TIMEOUT="${WEBHOOK_TIMEOUT:-5}"

LOG_TAG="${LOG_TAG:-l7d}"

# -----------------------------------------------------------------------------------

require() { command -v "$1" >/dev/null 2>&1 || { echo "Missing binary: $1" >&2; exit 2; }; }
need_root() { if [[ $EUID -ne 0 ]]; then echo "[$LOG_TAG] Must run as root."; exit 1; fi; }

mkdir -p "$STATE_DIR" "$RUNTIME_DIR" "$INCIDENTS_DIR" "$CAP_DIR"
touch "$EVENTS_FILE" "$ACTIONS_LOG"
touch "$WHITELIST_FILE" || true

# --------------------------- Helpers ---------------------------
ip_family() { [[ "$1" == *:* ]] && echo "v6" || echo "v4"; }

nft_bootstrap() {
  nft list table $NFT_TABLE >/dev/null 2>&1 && return 0
  logger -t "$LOG_TAG" "Creating nftables table $NFT_TABLE and chains"
  nft -f - <<EOF
table $NFT_TABLE {
  sets {
    $SET_V4 { type ipv4_addr; flags timeout; }
    $SET_V6 { type ipv6_addr; flags timeout; }
  }
  chains {
    input_web {
      type filter hook input priority -10; policy accept;
      tcp dport $PROTECT_TCP_PORTS ip saddr @$SET_V4 drop
      tcp dport $PROTECT_TCP_PORTS ip6 saddr @$SET_V6 drop
    }
  }
}
EOF
}

is_whitelisted() {
  local ip="$1"
  grep -Fqx "$ip" "$WHITELIST_FILE" 2>/dev/null
}

inc_offense() {
  local ip="$1"
  mkdir -p "$(dirname "$OFFENSE_FILE")"; touch "$OFFENSE_FILE"
  local current=0
  if grep -Fq "^$ip	" "$OFFENSE_FILE"; then
    current=$(awk -F'\t' -v i="$ip" '$1==i{print $2}' "$OFFENSE_FILE")
  fi
  current=$(( current + 1 ))
  local tmp; tmp=$(mktemp)
  awk -F'\t' -v i="$ip" -v c="$current" '
    BEGIN{found=0}
    $1==i{print i "\t" c; found=1; next}
    {print}
    END{if(!found) print i "\t" c}
  ' "$OFFENSE_FILE" > "$tmp"
  mv "$tmp" "$OFFENSE_FILE"
  echo "$current"
}

ttl_for_offenses() {
  local n="$1"
  if   (( n==1 )); then echo "$BAN_TTL_DEFAULT"
  elif (( n==2 )); then echo "$BAN_TTL_SECOND"
  elif (( n==3 )); then echo "$BAN_TTL_THIRD"
  else echo "$BAN_TTL_FOURTH"
  fi
}

ban_ip() {
  local ip="$1"
  local offenses ttl fam
  offenses=$(inc_offense "$ip")
  ttl=$(ttl_for_offenses "$offenses")
  fam=$(ip_family "$ip")
  if [[ "$fam" == "v6" ]]; then
    nft add element $NFT_TABLE $SET_V6 { $ip timeout $ttl } 2>/dev/null || nft replace element $NFT_TABLE $SET_V6 { $ip timeout $ttl }
  else
    nft add element $NFT_TABLE $SET_V4 { $ip timeout $ttl } 2>/dev/null || nft replace element $NFT_TABLE $SET_V4 { $ip timeout $ttl }
  fi
  logger -t "$LOG_TAG" "BAN ip=$ip ttl=$ttl offenses=$offenses"
  echo "{\"time\":\"$(date -u +%FT%TZ)\",\"action\":\"BAN\",\"ip\":\"$ip\",\"ttl\":\"$ttl\",\"offenses\":$offenses}" | tee -a "$ACTIONS_LOG" >/dev/null
  echo "$ttl"
}

send_webhook() {
  local payload="$1"
  [[ -z "${WEBHOOK_URL:-}" ]] && return 0
  local fmt="${WEBHOOK_FORMAT:-auto}"
  local data
  case "$fmt" in
    slack|auto)
      # Slack-compatible: {"text":"..."}
      data=$(jq -c --arg text "$payload" '{text:$text}')
      ;;
    discord)
      data=$(jq -c --arg content "$payload" '{content:$content}')
      ;;
    generic|*)
      # Send raw JSON if payload looks like JSON, else wrap in {"message":...}
      if jq -e . >/dev/null 2>&1 <<<"$payload"; then
        data="$payload"
      else
        data=$(jq -c --arg message "$payload" '{message:$message}')
      fi
      ;;
  esac
  curl -sS -m "$WEBHOOK_TIMEOUT" -H "Content-Type: application/json" -X POST -d "$data" "$WEBHOOK_URL" >/dev/null || true
}

human() {
  local ip="$1" rps="$2" path="$3" ttl="$4" efrac="$5"
  printf "L7D BAN: ip=%s rps=%.2f window=%ss path=%s ttl=%s err_ratio=%.2f" "$ip" "$rps" "$WINDOW_SEC" "$path" "$ttl" "$efrac"
}

write_incident() {
  local ip="$1" rps="$2" ts="$3" path="$4" efrac="$5"
  local stamp; stamp="$(date -u "+%Y%m%d-%H%M%S")"
  local incdir="$INCIDENTS_DIR/INCID-${stamp}-${ip//:/_}"
  mkdir -p "$incdir"
  # Save summary
  {
    echo "Incident: $stamp UTC"
    echo "IP: $ip"
    echo "Path (last hit): $path"
    echo "Window: ${WINDOW_SEC}s"
    echo "Observed RPS: $rps"
    echo "Error ratio: $efrac"
    echo "Log file: $LOG_FILE"
  } > "$incdir/SUMMARY.txt"

  # Save raw event
  jq -n --arg time "$(date -u +%FT%TZ)" --arg ip "$ip" --arg path "$path" --argjson rps "$rps" --argjson window "$WINDOW_SEC" --argjson err "$efrac" \
    '{time:$time, ip:$ip, path:$path, rps:$rps, window:$window, err_ratio:$err}' > "$incdir/summary.json"

  # Dump a focused pcap (headers only)
  if [[ "${DUMP_ON_BAN}" == "true" ]]; then
    timeout "$DUMP_SECONDS" tcpdump -i "$IFACE" -n -s "$SNAP_LEN" host "$ip" and tcp and \(port 80 or port 443\) -w "$incdir/sample.pcap" >/dev/null 2>&1 || true
  fi

  # Copy last 1 minute matching log lines for that IP 
  (tail -n 5000 "$LOG_FILE" 2>/dev/null | jq -r --arg ip "$ip" 'select(.remote_addr==$ip) | @json' > "$incdir/log-sample.jsonl" ) || true

  echo "$incdir"
}

status_show() {
  echo "== Current blocked IPv4 =="
  nft list set $NFT_TABLE $SET_V4 2>/dev/null | sed 's/^/  /' || echo "  (none)"
  echo
  echo "== Current blocked IPv6 =="
  nft list set $NFT_TABLE $SET_V6 2>/dev/null | sed 's/^/  /' || echo "  (none)"
  echo
  echo "== Recent actions =="
  tail -n 50 "$ACTIONS_LOG" 2>/dev/null || echo "(no actions logged yet)"
}

dump_latest() {
  local inc
  inc=$(ls -1dt "$INCIDENTS_DIR"/INCID-* 2>/dev/null | head -1 || true)
  if [[ -z "${inc:-}" ]]; then echo "No incidents found in $INCIDENTS_DIR"; exit 1; fi
  cat "$inc/SUMMARY.txt"
  echo
  echo "Artifacts in: $inc"
  ls -1 "$inc" | sed 's/^/  /'
}

# --------------------------- Detector ---------------------------
run_detector() {
  need_root
  require jq; require awk; require tail; require logger; require nft; require curl; require tcpdump

  nft_bootstrap

  echo "[$LOG_TAG] Starting L7D: LOG_FILE=$LOG_FILE WINDOW=$WINDOW_SEC IP_RPS=$IP_RPS PATH_RPS=$PATH_RPS COOLDOWN=$COOLDOWN_SEC" | tee -a "$ACTIONS_LOG"

  # Record last event time per IP (in-memory, resets on restart)
  declare -A LAST_EVT

  # AWK program emits lines: "IP_BAN|<ts>|<ip>|<rps>|<err>|<path>"  or  "PATH_ALERT|<ts>|<path>|<rps>"
  read -r -d '' AWK_PROG <<'AWK'
BEGIN {
  window = WINDOW + 0;
  ip_thr = IP_RPS + 0;
  path_thr = PATH_RPS + 0;
  err_ratio = ERR_RATIO + 0.0;
}
function key_ip(ip, sec) { return ip "|" sec; }
function key_path(path, sec){ return path "|" sec; }
function sum_ip(ip, curr,    s, sum, e4, e5, total) {
  sum=0; e4=0; e5=0; total=0;
  for (s=curr - window + 1; s<=curr; s++) {
    k = ip "|" s;
    if (k in ip_cnt) { sum += ip_cnt[k]; total += ip_cnt[k]; }
    if (k in ip_4xx) { e4 += ip_4xx[k]; }
    if (k in ip_5xx) { e5 += ip_5xx[k]; }
  }
  ip_sum= sum; ip_e4=e4; ip_e5=e5; ip_total=total;
}
function sum_path(path, curr,    s, sum) {
  sum=0;
  for (s=curr - window + 1; s<=curr; s++) {
    k = path "|" s;
    if (k in path_cnt) { sum += path_cnt[k]; }
  }
  return sum;
}
{
  # input format: ts|ip|path|status
  split($0, f, "|");
  ts = int(f[1]+0);
  ip = f[2];
  path = f[3];
  status = int(f[4]+0);

  k = ip "|" ts; ip_cnt[k] += 1;
  if (status >=400 && status < 500) ip_4xx[k] += 1;
  else if (status >=500 && status < 600) ip_5xx[k] += 1;
  k2 = path "|" ts; path_cnt[k2] += 1;

  # compute sums over window
  sum_ip(ip, ts);
  ip_rate = ip_sum / window;
  path_sum = sum_path(path, ts);
  efrac = (ip_total>0) ? ((ip_e4+ip_e5)/ip_total) : 0.0;

  # per-IP trigger
  if (ip_rate >= ip_thr) {
    printf("IP_BAN|%d|%s|%.2f|%.3f|%s\n", ts, ip, ip_rate, efrac, path);
  }

  # per-path global trigger
  if (path_sum >= path_thr) {
    printf("PATH_ALERT|%d|%s|%d\n", ts, path, path_sum/window);
  }
}
AWK

  stdbuf -oL -eL tail -n0 -F "$LOG_FILE" \
    | stdbuf -oL -eL jq -r 'select(.path != null and .remote_addr != null and .time != null and .status != null) | "\((.time|tonumber|floor))|\(.remote_addr)|\(.path)|\(.status)"' \
    | awk -v WINDOW="$WINDOW_SEC" -v IP_RPS="$IP_RPS" -v PATH_RPS="$PATH_RPS" -v ERR_RATIO="$ERR_RATIO_THRESHOLD" "$AWK_PROG" \
    | while IFS='|' read -r kind ts ip rps err path_or_rps; do
        case "$kind" in
          IP_BAN)
            # Cooldown check
            now="$ts"
            last="${LAST_EVT[$ip]:-0}"
            if (( now - last < COOLDOWN_SEC )); then
              continue
            fi
            LAST_EVT[$ip]="$now"

            if is_whitelisted "$ip"; then
              logger -t "$LOG_TAG" "skip-whitelist ip=$ip rps=$rps"
              continue
            fi

            ttl="$(ban_ip "$ip")"
            incdir="$(write_incident "$ip" "$rps" "$ts" "$path_or_rps" "$err")"

            msg="$(human "$ip" "$rps" "$path_or_rps" "$ttl" "$err")"
            echo "$msg | incident=$incdir" | tee -a "$ACTIONS_LOG"
            send_webhook "$msg"
            ;;
          PATH_ALERT)
            pa_path="$ip"   # shifted because of field positions
            pa_rps="$rps"
            echo "{\"time\":\"$(date -u +%FT%TZ)\",\"action\":\"PATH_ALERT\",\"path\":\"$pa_path\",\"rps\":$pa_rps}" | tee -a "$ACTIONS_LOG" >/dev/null
            send_webhook "L7D PATH_ALERT: path=$pa_path rps=$pa_rps window=${WINDOW_SEC}s"
            ;;
        esac
      done
}

# --------------------------- Install / Readme ---------------------------
install_self() {
  need_root
  local dst_dir="/opt/l7d"
  mkdir -p "$dst_dir"
  cp "$0" "$dst_dir/l7d.sh"
  chmod +x "$dst_dir/l7d.sh"
  cat > /etc/systemd/system/l7d.service <<'UNIT'
[Unit]
Description=Single-file L7D (L7 Anti-DDoS) - detector+mitigator
After=network-online.target nginx.service
Wants=network-online.target

[Service]
Type=simple
User=root
Environment="LOG_FILE=/var/log/nginx/access_l7.json"
ExecStart=/opt/l7d/l7d.sh run
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable --now l7d.service
  echo "Installed and started l7d.service. Configure nginx JSON access log and adjust env vars if needed."
}

readme() {
  cat <<'EOF'
Single-file L7 Anti-DDoS (l7d.sh)
---------------------------------
Subcommands:
  run           Start the detector+mitigator in foreground
  install       Install to /opt/l7d and a systemd unit (l7d.service)
  status        Show current blocks and recent actions
  dump-latest   Print the most recent incident summary
  readme        Print this help

Key env vars:
  LOG_FILE                (/var/log/nginx/access_l7.json)
  WINDOW_SEC              (5)
  IP_RPS                  (150)
  PATH_RPS                (500)
  COOLDOWN_SEC            (120)
  ERR_RATIO_THRESHOLD     (0.6)
  WHITELIST_FILE          (/etc/l7d.whitelist)
  WEBHOOK_URL             (empty=disabled)
  WEBHOOK_FORMAT          (auto|slack|discord|generic)
  INCIDENTS_DIR           (/var/log/l7d/incidents)
  DUMP_ON_BAN             (true|false)
  DUMP_SECONDS            (20)
  IFACE                   (eth0)
  SNAP_LEN                (96)

Quick start:
  1) Configure NGINX JSON access log (see nginx-snippet.conf)
  2) sudo ./l7d.sh install
  3) (optional) touch /etc/l7d.whitelist and add IPs to exclude
  4) export WEBHOOK_URL="https://hooks.slack.com/services/..." and restart the service

Status:
  sudo ./l7d.sh status
  sudo journalctl -u l7d.service -f

Safety rails:
  - Whitelist is always honored
  - Cooldown between events per IP
  - Escalating TTLs on repeat offenders
  - Artifacts stored under INCIDENTS_DIR including optional sample.pcap

Disable & cleanup:
  sudo systemctl disable --now l7d.service
  sudo nft delete table inet l7d 2>/dev/null || true
  sudo rm -f /etc/systemd/system/l7d.service
  sudo rm -rf /opt/l7d /var/log/l7d /var/lib/l7d
EOF
}

case "${1:-}" in
  run) run_detector ;;
  install) install_self ;;
  status) status_show ;;
  dump-latest) dump_latest ;;
  readme|-h|--help|"") readme ;;
  *) echo "Unknown subcommand: $1"; exit 2 ;;
esac
