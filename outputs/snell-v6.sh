#!/usr/bin/env bash
#
# Snell v6 one-click installer and updater
# Source of releases: https://kb.nssurge.com/surge-knowledge-base/release-notes/snell
#
# Usage:
#   sudo bash snell-v6.sh install
#   sudo /usr/local/sbin/snell-manager update
#   sudo /usr/local/sbin/snell-manager show
#

set -Eeuo pipefail
IFS=$'\n\t'
umask 077

readonly RELEASE_PAGE="https://kb.nssurge.com/surge-knowledge-base/release-notes/snell.md"
readonly DOWNLOAD_PREFIX="https://dl.nssurge.com/snell/"
readonly BIN_PATH="/usr/local/bin/snell-server"
readonly MANAGER_PATH="/usr/local/sbin/snell-manager"
readonly CONFIG_DIR="/etc/snell-server"
readonly CONFIG_PATH="${CONFIG_DIR}/snell-server.conf"
readonly STATE_DIR="/var/lib/snell-server"
readonly RELEASE_STATE="${STATE_DIR}/release"
readonly HASH_STATE="${STATE_DIR}/sha256"
readonly PORT_STATE="${STATE_DIR}/port"
readonly FIREWALL_STATE="${STATE_DIR}/firewall"
readonly OWNER_STATE="${STATE_DIR}/managed-by"
readonly SERVICE_UNIT="/etc/systemd/system/snell-server.service"
readonly UPDATE_SERVICE_UNIT="/etc/systemd/system/snell-update.service"
readonly UPDATE_TIMER_UNIT="/etc/systemd/system/snell-update.timer"
readonly SERVICE_NAME="snell-server.service"
readonly TIMER_NAME="snell-update.timer"
readonly LOCK_FILE="/run/lock/snell-manager.lock"
readonly SERVICE_MARKER="Managed by snell-v6.sh"

QUIET=0
TMP_DIR=""
LOCK_HELD=0
AUTO_UPDATE="preserve"

log() {
  if [[ "$QUIET" -eq 0 ]]; then
    printf '[snell] %s\n' "$*"
  fi
}

warn() {
  printf '[snell] 警告：%s\n' "$*" >&2
}

die() {
  printf '[snell] 错误：%s\n' "$*" >&2
  exit 1
}

cleanup() {
  if [[ -n "$TMP_DIR" && -d "$TMP_DIR" ]]; then
    rm -rf -- "$TMP_DIR"
  fi
  if [[ "$LOCK_HELD" -eq 1 ]]; then flock -u 9 || true; fi
}
trap cleanup EXIT

require_root() {
  [[ "${EUID}" -eq 0 ]] || die "请使用 root 运行，例如：sudo bash snell-v6.sh install"
}

require_linux_systemd() {
  [[ "$(uname -s)" == "Linux" ]] || die "仅支持 Linux VPS。"
  command -v systemctl >/dev/null 2>&1 || die "未检测到 systemd，本脚本只支持 systemd 系统。"
  [[ -d /run/systemd/system ]] || die "systemd 当前未作为 init 系统运行。"

  if command -v getconf >/dev/null 2>&1; then
    getconf GNU_LIBC_VERSION >/dev/null 2>&1 ||
      die "官方 Snell 二进制依赖 glibc，不支持 Alpine/musl。请改用 Debian、Ubuntu、RHEL 等 glibc 系统。"
  elif command -v ldd >/dev/null 2>&1 && ldd --version 2>&1 | grep -qi musl; then
    die "官方 Snell 二进制依赖 glibc，不支持 Alpine/musl。请改用 Debian、Ubuntu、RHEL 等 glibc 系统。"
  fi
}

acquire_lock() {
  install -d -m 0755 /run/lock
  exec 9>"$LOCK_FILE"
  flock -n 9 || die "已有安装、升级或配置任务正在运行。"
  LOCK_HELD=1
}

install_dependencies() {
  local missing=0
  local cmd
  for cmd in curl unzip sha256sum awk sed grep od ip ss tc sysctl flock timeout getent useradd groupadd; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      missing=1
      break
    fi
  done
  if [[ "$missing" -eq 0 ]] && { [[ -s /etc/ssl/certs/ca-certificates.crt ]] || [[ -s /etc/pki/tls/certs/ca-bundle.crt ]] || [[ -s /etc/ssl/ca-bundle.pem ]]; }; then return 0; fi

  log "安装必要依赖……"
  if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq curl unzip ca-certificates coreutils gawk iproute2 procps util-linux passwd kmod
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y curl unzip ca-certificates coreutils gawk iproute procps-ng util-linux shadow-utils kmod
  elif command -v yum >/dev/null 2>&1; then
    yum install -y curl unzip ca-certificates coreutils gawk iproute procps-ng util-linux shadow-utils kmod
  elif command -v pacman >/dev/null 2>&1; then
    pacman -S --noconfirm --needed curl unzip ca-certificates coreutils gawk iproute2 procps-ng util-linux shadow kmod
  elif command -v zypper >/dev/null 2>&1; then
    zypper --non-interactive install curl unzip ca-certificates coreutils gawk iproute2 procps util-linux shadow kmod
  else
    die "无法识别包管理器，请先安装 curl、unzip、ca-certificates、coreutils 和 awk。"
  fi
}

detect_asset_arch() {
  case "$(uname -m)" in
    x86_64|amd64)
      printf 'amd64\n'
      ;;
    i386|i486|i586|i686)
      printf 'i386\n'
      ;;
    aarch64|arm64)
      printf 'aarch64\n'
      ;;
    *)
      die "Snell v6 官方当前不支持该 CPU 架构：$(uname -m)"
      ;;
  esac
}

version_key() {
  local version="${1#v}" rank=3 suffix=0
  [[ "$version" =~ ^6\.([0-9]{1,6})\.([0-9]{1,6})((beta|rc)([0-9]{0,6}))?$ ]] || return 1
  local minor="${BASH_REMATCH[1]}" patch="${BASH_REMATCH[2]}"
  case "${BASH_REMATCH[4]}" in beta) rank=1 ;; rc) rank=2 ;; esac
  suffix="${BASH_REMATCH[5]:-0}"
  printf '6.%06d.%06d.%d.%06d\n' "$((10#$minor))" "$((10#$patch))" "$rank" "$((10#$suffix))"
}

select_release_url() {
  local asset_arch="$1" url tag key
  while IFS= read -r url; do
    tag="${url##*/snell-server-}"; tag="${tag%-linux-*}"
    key="$(version_key "$tag")" || continue
    printf '%s\t%s\n' "$key" "$url"
  done < <(grep -Eo 'https://[^[:space:]"<>`)]+' | grep -E "^https://dl\\.nssurge\\.com/snell/snell-server-v6\\.[0-9]+\\.[0-9]+((beta|rc)[0-9]*)?-linux-${asset_arch}\\.zip$") |
    LC_ALL=C sort -ru | awk 'NR == 1 { print $2 }'
}

fetch_release_url() {
  local asset_arch="$1"
  local page
  local url

  page="$(curl -fsSL \
    --proto '=https' --proto-redir '=https' --tlsv1.2 \
    --retry 3 --retry-delay 2 \
    --connect-timeout 10 --max-time 40 \
    "$RELEASE_PAGE")" || die "无法读取 Snell 官方发布页面。"

  url="$(
    printf '%s\n' "$page" |
      select_release_url "$asset_arch"
  )"

  [[ -n "$url" ]] || die "官方页面未找到适用于 ${asset_arch} 的 Snell v6 下载地址。"
  [[ "$url" == "${DOWNLOAD_PREFIX}"* ]] || die "发布地址未通过域名白名单校验。"
  printf '%s\n' "$url"
}

release_tag_from_url() {
  local url="$1"
  local filename="${url##*/}"
  local tag
  tag="$(printf '%s\n' "$filename" | sed -n 's/^snell-server-\(v6[^-]*\)-linux-.*\.zip$/\1/p')"
  [[ -n "$tag" ]] || die "无法从官方文件名解析版本号。"
  printf '%s\n' "$tag"
}

download_and_verify_binary() {
  local url="$1"
  local expected_arch="$2"
  local archive="${TMP_DIR}/snell.zip"
  local member
  local member_count
  local version_output

  log "下载官方 Snell v6：${url##*/}"
  curl -fsS \
    --proto '=https' --tlsv1.2 \
    --retry 3 --retry-delay 2 \
    --connect-timeout 10 --max-time 180 \
    -o "$archive" "$url" || die "下载 Snell v6 失败。"

  member="$(
    unzip -Z1 "$archive" |
      awk '
        ($0 == "snell-server" || $0 ~ /\/snell-server$/) && !printed {
          print
          printed = 1
        }
      '
  )"
  member_count="$(
    unzip -Z1 "$archive" |
      awk '$0 == "snell-server" || $0 ~ /\/snell-server$/ { count++ } END { print count + 0 }'
  )"
  [[ "$member_count" -eq 1 ]] || die "官方压缩包中的 snell-server 文件数量异常。"
  [[ "$member" != /* && "$member" != *".."* ]] || die "压缩包成员路径不安全。"

  unzip -p "$archive" "$member" > "${TMP_DIR}/snell-server"
  chmod 0755 "${TMP_DIR}/snell-server"

  version_output="$(timeout 10 "${TMP_DIR}/snell-server" --version 2>&1)" ||
    die "下载的 Snell 二进制无法在当前系统执行。"
  printf '%s\n' "$version_output" | grep -Eq 'snell-server v6\.' ||
    die "下载的文件不是 Snell v6 二进制。"

  case "$expected_arch" in
    amd64)
      printf '%s\n' "$version_output" >/dev/null
      ;;
    i386|aarch64)
      printf '%s\n' "$version_output" >/dev/null
      ;;
  esac
}

atomic_install_binary() {
  local source_binary="$1"
  local staged
  install -d -m 0755 "$(dirname "$BIN_PATH")" || return 1
  staged="$(mktemp "${BIN_PATH}.new.XXXXXX")" || return 1
  if ! install -o root -g root -m 0755 "$source_binary" "$staged" || ! mv -f -- "$staged" "$BIN_PATH"; then
    rm -f -- "$staged"
    return 1
  fi
}

record_release_state() {
  local tag="$1"
  local hash="$2"
  install -d -o root -g root -m 0755 "$STATE_DIR"
  printf '%s\n' "$tag" > "$RELEASE_STATE"
  printf '%s\n' "$hash" > "$HASH_STATE"
  chmod 0644 "$RELEASE_STATE" "$HASH_STATE"
}

service_is_managed() {
  [[ -f "$SERVICE_UNIT" ]] && grep -Fq "$SERVICE_MARKER" "$SERVICE_UNIT"
}

preflight_existing() {
  local fragment process unit
  if [[ -e "$MANAGER_PATH" ]]; then
    grep -Fq '# Snell v6 one-click installer and updater' "$MANAGER_PATH" || die "${MANAGER_PATH} 属于其他工具，停止覆盖。"
  fi
  fragment="$(systemctl show "$SERVICE_NAME" -p FragmentPath --value 2>/dev/null || true)"
  if [[ -n "$fragment" || -e "$SERVICE_UNIT" ]]; then
    service_is_managed || die "检测到其他方式安装的 Snell。请先确认其配置/服务路径；本脚本不自动覆盖或迁移。"
    [[ -z "$fragment" || "$fragment" == "$SERVICE_UNIT" ]] || die "Snell 实际服务来自 ${fragment}，停止覆盖。"
  elif [[ -e "$BIN_PATH" || -f "$CONFIG_PATH" ]]; then
    [[ -f "$OWNER_STATE" && "$(<"$OWNER_STATE")" == 'snell-v6.sh' ]] ||
      die "发现未标记归属的 Snell 程序或配置，停止自动覆盖。"
    log "检测到本工具的未完成安装/保留配置，将继续安装并保留端口和 PSK。"
  fi
  for unit in snell.service snell@.service; do
    fragment="$(systemctl show "$unit" -p FragmentPath --value 2>/dev/null || true)"
    [[ -z "$fragment" ]] || die "发现已有 ${unit}（${fragment}），需要先核对旧安装。"
  done
  if [[ -f /etc/snell-server.conf ]] && ! service_is_managed; then
    die "发现旧配置 /etc/snell-server.conf，已停止安装以免生成另一套端口和密钥。"
  fi
  if command -v pgrep >/dev/null 2>&1; then
    process="$(pgrep -x snell-server || true)"
    if [[ -n "$process" ]] && ! service_is_managed; then die "发现非本脚本管理的运行中 Snell（PID ${process}）。"; fi
  fi
}

restart_and_verify_service() {
  local i port
  port="$(port_from_config)" || return 1
  systemctl restart "$SERVICE_NAME" || return 1
  for ((i = 0; i < 5; i++)); do
    sleep 1
    systemctl is-active --quiet "$SERVICE_NAME" || return 1
  done
  service_listening "$port"
}

service_listening() {
  local port="$1" pid
  pid="$(systemctl show "$SERVICE_NAME" -p MainPID --value)" || return 1
  [[ "$pid" =~ ^[1-9][0-9]*$ ]] || return 1
  ss -H -ltnp | awk -v port="$port" -v pid="$pid" '
    $4 ~ (":" port "$") && index($0, "pid=" pid ",") { found=1 }
    END { exit !found }
  '
}

perform_update() {
  local restart_service="${1:-yes}"
  local asset_arch
  local release_url
  local remote_tag
  local new_hash
  local current_hash=""
  local backup_binary=""
  local current_tag="" remote_key current_key backup_dir

  TMP_DIR="$(mktemp -d /tmp/snell-update.XXXXXX)"
  asset_arch="$(detect_asset_arch)"
  release_url="$(fetch_release_url "$asset_arch")"
  remote_tag="$(release_tag_from_url "$release_url")"
  remote_key="$(version_key "$remote_tag")" || die "无法比较官方版本。"
  if [[ -x "$BIN_PATH" ]]; then
    if [[ -s "$RELEASE_STATE" ]]; then
      current_tag="$(<"$RELEASE_STATE")"
    else
      current_tag="$(timeout 10 "$BIN_PATH" --version 2>&1 | grep -Eo 'v6\.[0-9]+\.[0-9]+((beta|rc)[0-9]*)?' | awk 'NR==1')"
    fi
    current_key="$(version_key "$current_tag")" || die "现有版本无法可靠识别，已停止自动替换。"
    if [[ "$remote_key" < "$current_key" ]]; then
      log "现有版本 ${current_tag} 比官方页面候选 ${remote_tag} 更新，保留当前程序。"
      return 0
    fi
  fi
  download_and_verify_binary "$release_url" "$asset_arch"
  new_hash="$(sha256sum "${TMP_DIR}/snell-server" | awk '{print $1}')"

  if [[ -x "$BIN_PATH" ]]; then
    current_hash="$(sha256sum "$BIN_PATH" | awk '{print $1}')"
  fi

  if [[ -n "$current_hash" && "$current_hash" == "$new_hash" ]]; then
    record_release_state "$remote_tag" "$new_hash"
    log "已是官方当前版本：${remote_tag}"
    return 0
  fi

  if [[ -x "$BIN_PATH" ]]; then
    install -d -m 0700 "${STATE_DIR}/backups"
    backup_dir="$(mktemp -d "${STATE_DIR}/backups/update-$(date +%Y%m%d-%H%M%S).XXXXXX")"
    backup_binary="${backup_dir}/snell-server"
    cp -a -- "$BIN_PATH" "$backup_binary"
    [[ ! -f "$RELEASE_STATE" ]] || cp -a "$RELEASE_STATE" "${backup_dir}/release"
    [[ ! -f "$HASH_STATE" ]] || cp -a "$HASH_STATE" "${backup_dir}/sha256"
    log "旧版本已备份：${backup_dir}"
  fi

  atomic_install_binary "${TMP_DIR}/snell-server" || die "安装新程序失败。"

  if [[ "$restart_service" == "yes" ]] && service_is_managed; then
    if ! restart_and_verify_service; then
      warn "新版本启动失败，正在回滚。"
      if [[ -n "$backup_binary" && -x "$backup_binary" ]]; then
        atomic_install_binary "$backup_binary" || die "恢复旧程序失败：${backup_binary}"
        restart_and_verify_service || die "已恢复旧程序但服务仍异常，请查看 journalctl。"
      fi
      journalctl -u "$SERVICE_NAME" -n 30 --no-pager >&2 || true
      die "升级失败，已尝试恢复旧版本。"
    fi
  fi

  record_release_state "$remote_tag" "$new_hash"
  log "Snell 已升级到官方版本：${remote_tag}"
}

create_service_user() {
  local nologin_shell
  if ! getent group snell >/dev/null 2>&1; then
    groupadd --system snell
  fi
  if ! id -u snell >/dev/null 2>&1; then
    nologin_shell="$(command -v nologin || true)"
    [[ -n "$nologin_shell" ]] || nologin_shell="/usr/sbin/nologin"
    useradd --system \
      --gid snell \
      --home-dir /nonexistent \
      --shell "$nologin_shell" \
      --no-create-home \
      snell
  fi
}

port_in_use() {
  local port="$1"
  local hex_port
  hex_port="$(printf '%04X' "$port")"
  awk -v wanted=":${hex_port}" '
    $2 ~ wanted "$" && $4 == "0A" { found = 1 }
    END { exit(found ? 0 : 1) }
  ' /proc/net/tcp /proc/net/tcp6 2>/dev/null
}

generate_port() {
  local attempt
  local raw
  local port
  for ((attempt = 0; attempt < 200; attempt++)); do
    raw="$(od -An -N2 -tu2 /dev/urandom | tr -d ' ')"
    port=$((10000 + raw % 50001))
    if ! port_in_use "$port"; then
      printf '%s\n' "$port"
      return 0
    fi
  done
  die "尝试 200 次后仍无法找到空闲端口。"
}

generate_psk() {
  od -An -N16 -tx1 /dev/urandom | tr -d ' \n'
  printf '\n'
}

ipv6_available() {
  [[ -s /proc/net/if_inet6 ]] &&
    [[ "$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null || printf '1')" == "0" ]] &&
    ip -6 addr show scope global | grep -q 'inet6 ' &&
    [[ -n "$(ip -6 route show default)" ]]
}

config_value() {
  local key="$1"
  awk -v wanted="$key" '
    /^[[:space:]]*[#;]/ { next }
    {
      line = $0
      sub(/^[[:space:]]*/, "", line)
      if (index(line, wanted) == 1) {
        rest = substr(line, length(wanted) + 1)
        if (rest ~ /^[[:space:]]*=/) {
          sub(/^[[:space:]]*=[[:space:]]*/, "", rest)
          sub(/[[:space:]]*$/, "", rest)
          print rest
          exit
        }
      }
    }
  ' "$CONFIG_PATH"
}

port_from_config() {
  local listen_value
  listen_value="$(config_value listen)"
  printf '%s\n' "$listen_value" |
    grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]{1,5}|\[[^]]+\]:[0-9]{1,5}' |
    sed -n '1 { s/.*://; p; }'
}

ensure_config() {
  local port
  local psk
  local listen_value

  install -d -o root -g snell -m 0750 "$CONFIG_DIR"
  install -d -o root -g root -m 0755 "$STATE_DIR"

  if [[ -f "$CONFIG_PATH" ]]; then
    psk="$(config_value psk || true)"
    port="$(port_from_config || true)"
    [[ ${#psk} -ge 12 && ${#psk} -le 255 ]] ||
      die "现有配置中的 PSK 长度无效；为避免覆盖密钥，脚本已停止。"
    [[ "$port" =~ ^[0-9]+$ && "$port" -ge 1 && "$port" -le 65535 ]] ||
      die "无法从现有配置中读取监听端口；为避免覆盖配置，脚本已停止。"
    log "保留现有端口和 PSK。"
  else
    port="$(generate_port)"
    psk="$(generate_psk)"
    if ipv6_available; then
      listen_value="0.0.0.0:${port},[::]:${port}"
    else
      listen_value="0.0.0.0:${port}"
    fi

    {
      printf '[snell-server]\n'
      printf 'listen = %s\n' "$listen_value"
      printf 'psk = %s\n' "$psk"
      printf 'mode = default\n'
      printf 'dns-ip-preference = default\n'
    } > "$CONFIG_PATH"
    log "已自动生成空闲端口和 32 字符随机 PSK。"
  fi

  chown root:snell "$CONFIG_PATH"
  chmod 0640 "$CONFIG_PATH"
  printf '%s\n' "$port" > "$PORT_STATE"
  chmod 0644 "$PORT_STATE"
}

write_service_units() {
  if [[ -f "$SERVICE_UNIT" ]] && ! service_is_managed; then
    die "检测到非本脚本管理的 ${SERVICE_UNIT}，为避免覆盖已停止。"
  fi

  {
    printf '# %s\n' "$SERVICE_MARKER"
    cat <<'EOF'
[Unit]
Description=Snell v6 Proxy Server
Documentation=https://kb.nssurge.com/surge-knowledge-base/release-notes/snell
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=snell
Group=snell
WorkingDirectory=/var/lib/snell-server
ExecStart=/usr/local/bin/snell-server -c /etc/snell-server/snell-server.conf
Restart=on-failure
RestartSec=3s
LimitNOFILE=1048576
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectHostname=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictRealtime=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
SystemCallArchitectures=native
CapabilityBoundingSet=
AmbientCapabilities=

[Install]
WantedBy=multi-user.target
EOF
  } > "$SERVICE_UNIT"

  cat > "$UPDATE_SERVICE_UNIT" <<'EOF'
[Unit]
Description=Check and install official Snell v6 updates
Documentation=https://kb.nssurge.com/surge-knowledge-base/release-notes/snell
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/snell-manager update --quiet
EOF

  cat > "$UPDATE_TIMER_UNIT" <<'EOF'
[Unit]
Description=Daily Snell v6 update check

[Timer]
OnBootSec=15min
OnUnitActiveSec=24h
RandomizedDelaySec=1h
Unit=snell-update.service

[Install]
WantedBy=timers.target
EOF

  chmod 0644 "$SERVICE_UNIT" "$UPDATE_SERVICE_UNIT" "$UPDATE_TIMER_UNIT"
  systemctl daemon-reload
}

install_manager_copy() {
  local source_path="${BASH_SOURCE[0]:-}"
  install -d -m 0755 "$(dirname "$MANAGER_PATH")"

  if [[ -f "$source_path" ]]; then
    if [[ ! "$source_path" -ef "$MANAGER_PATH" ]]; then
      install -o root -g root -m 0755 "$source_path" "$MANAGER_PATH"
    fi
  elif [[ -n "${SNELL_MANAGER_URL:-}" ]]; then
    curl -fsSL \
      --proto '=https' --proto-redir '=https' --tlsv1.2 \
      --retry 3 --connect-timeout 10 --max-time 60 \
      -o "${MANAGER_PATH}.new" "$SNELL_MANAGER_URL"
    chmod 0755 "${MANAGER_PATH}.new"
    mv -f -- "${MANAGER_PATH}.new" "$MANAGER_PATH"
  else
    die "自动升级需要保存管理脚本。请先把脚本下载为文件，再执行：sudo bash snell-v6.sh install"
  fi
}

open_firewall() {
  local port="$1"
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
    ufw allow "${port}/tcp" comment 'Snell v6' >/dev/null
    printf 'ufw\n' > "$FIREWALL_STATE"
    log "已放行 UFW TCP 端口 ${port}。"
  elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
    firewall-cmd --add-port="${port}/tcp" >/dev/null
    firewall-cmd --permanent --add-port="${port}/tcp" >/dev/null
    printf 'firewalld\n' > "$FIREWALL_STATE"
    log "已放行 firewalld TCP 端口 ${port}。"
  else
    printf 'none\n' > "$FIREWALL_STATE"
    warn "未检测到已启用的 UFW/firewalld。若 VPS 有云防火墙/安全组，请手动放行 TCP ${port}。"
  fi
  chmod 0644 "$FIREWALL_STATE"
}

public_ip() {
  local ip=""
  ip="$(curl -4 -fsS --connect-timeout 3 --max-time 6 https://api.ipify.org 2>/dev/null || true)"
  if [[ ! "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    ip="$(curl -4 -fsS --connect-timeout 3 --max-time 6 https://ifconfig.me/ip 2>/dev/null || true)"
  fi
  if [[ ! "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    ip="$(curl -6 -fsS --connect-timeout 3 --max-time 6 https://api6.ipify.org 2>/dev/null || true)"
    if [[ ! "$ip" =~ ^[0-9a-fA-F:]+$ || "$ip" != *:* ]]; then ip="<你的VPS公网IP或域名>"; fi
  fi
  printf '%s\n' "$ip"
}

show_connection_info() {
  local port
  local psk
  local mode
  local ip
  local endpoint
  local release="unknown"

  [[ -f "$CONFIG_PATH" ]] || die "尚未安装 Snell 配置。"
  port="$(port_from_config)"
  psk="$(config_value psk)"
  mode="$(config_value mode || true)"
  [[ -n "$mode" ]] || mode="default"
  ip="$(public_ip)"
  endpoint="$ip"
  [[ "$ip" != *:* ]] || endpoint="[$ip]"
  [[ -f "$RELEASE_STATE" ]] && release="$(<"$RELEASE_STATE")"

  cat <<EOF

Snell v6 连接信息
  官方包版本：${release}
  服务器：${ip}
  TCP 端口：${port}
  PSK：${psk}
  模式：${mode}

Surge 配置：
Snell-v6 = snell, ${endpoint}, ${port}, psk=${psk}, version=6, mode=${mode}

服务状态：systemctl status snell-server
实时日志：journalctl -u snell-server -f
升级计时器：systemctl status snell-update.timer
EOF
}

install_snell() {
  local port was_installed=0 timer_enabled=0
  require_root
  require_linux_systemd
  preflight_existing
  install_dependencies
  acquire_lock
  # Recheck under the shared lock before creating an ownership marker.
  preflight_existing

  if [[ -f "$SERVICE_UNIT" ]] && ! service_is_managed; then
    die "检测到非本脚本管理的 ${SERVICE_UNIT}，为避免覆盖已停止。"
  fi
  service_is_managed && was_installed=1
  systemctl is-enabled --quiet "$TIMER_NAME" 2>/dev/null && timer_enabled=1

  install -d -o root -g root -m 0755 "$STATE_DIR"
  printf 'snell-v6.sh\n' > "$OWNER_STATE"
  chmod 0644 "$OWNER_STATE"
  create_service_user
  ensure_config
  install_manager_copy
  if [[ "$was_installed" -eq 1 ]]; then perform_update yes; else perform_update no; fi
  write_service_units

  systemctl enable "$SERVICE_NAME"
  if ! restart_and_verify_service; then
    journalctl -u "$SERVICE_NAME" -n 40 --no-pager >&2 || true
    die "Snell 服务未能启动，请查看上方日志。"
  fi
  case "$AUTO_UPDATE" in
    off) systemctl disable --now "$TIMER_NAME" ;;
    on) systemctl enable --now "$TIMER_NAME" ;;
    preserve)
      if [[ "$was_installed" -eq 0 || "$timer_enabled" -eq 1 ]]; then systemctl enable --now "$TIMER_NAME"; fi ;;
  esac

  port="$(port_from_config)"
  open_firewall "$port"
  log "安装完成；自动更新状态：$(systemctl is-enabled "$TIMER_NAME" 2>/dev/null || true)"
  show_connection_info
}

update_snell() {
  require_root
  require_linux_systemd
  install_dependencies
  acquire_lock
  [[ -f "$CONFIG_PATH" ]] || die "尚未安装，请先运行 install。"
  service_is_managed || die "Snell 服务不是由本脚本管理，拒绝自动覆盖。"
  perform_update yes
}

status_snell() {
  require_root
  local release="unknown"
  [[ -f "$RELEASE_STATE" ]] && release="$(<"$RELEASE_STATE")"
  printf '已记录版本：%s\n' "$release"
  printf '服务状态：%s\n' "$(systemctl is-active "$SERVICE_NAME" 2>/dev/null || true)"
  printf '开机启动：%s\n' "$(systemctl is-enabled "$SERVICE_NAME" 2>/dev/null || true)"
  printf '自动升级：%s\n' "$(systemctl is-active "$TIMER_NAME" 2>/dev/null || true)"
  printf '定时计划：\n'
  systemctl list-timers "$TIMER_NAME" --no-pager 2>/dev/null || true
}

remove_firewall_rule() {
  # We cannot prove ownership of pre-existing rules. Never remove shared rules.
  warn "防火墙放行规则已保留；卸载后可手动删除不再使用的 Snell TCP 规则。"
}

uninstall_snell() {
  local purge="${1:-no}"
  require_root
  require_linux_systemd
  acquire_lock

  systemctl disable --now "$TIMER_NAME" >/dev/null 2>&1 || true
  systemctl disable --now "$SERVICE_NAME" >/dev/null 2>&1 || true
  remove_firewall_rule

  rm -f -- "$SERVICE_UNIT" "$UPDATE_SERVICE_UNIT" "$UPDATE_TIMER_UNIT"
  rm -f -- "$BIN_PATH"
  rm -f -- "$MANAGER_PATH"
  systemctl daemon-reload

  if [[ "$purge" == "yes" ]]; then
    rm -rf -- "$CONFIG_DIR" "$STATE_DIR"
    log "已卸载并清除配置、PSK 与状态数据。"
  else
    log "已卸载；配置和 PSK 保留在 ${CONFIG_DIR}。使用 uninstall --purge 可一并清除。"
  fi
}

usage() {
  cat <<'EOF'
Snell v6 一键管理脚本

用法：
  sudo bash snell-v6.sh install       安装或幂等更新（默认命令）
  sudo snell-manager update           立即检查并安装官方 v6 更新
  sudo snell-manager show             显示 Surge 连接配置（包含 PSK）
  sudo snell-manager status           显示服务与自动升级状态
  sudo snell-manager uninstall        卸载程序，保留配置和 PSK
  sudo snell-manager uninstall --purge 卸载并清除配置、PSK 和状态

选项：
  --quiet   减少普通输出，供 systemd 自动升级使用
  --no-auto-update 安装后禁用自动升级
  --auto-update    安装后启用自动升级（默认保留已有开关，新装启用）
  -h        显示帮助
EOF
}

main() {
  local command="${1:-install}"
  local purge="no"
  [[ $# -gt 0 ]] && shift || true

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --quiet)
        QUIET=1
        ;;
      --purge)
        purge="yes"
        ;;
      --no-auto-update) AUTO_UPDATE="off" ;;
      --auto-update) AUTO_UPDATE="on" ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        die "未知参数：$1"
        ;;
    esac
    shift
  done

  case "$command" in
    install)
      install_snell
      ;;
    update)
      update_snell
      ;;
    show)
      require_root
      show_connection_info
      ;;
    status)
      status_snell
      ;;
    uninstall)
      uninstall_snell "$purge"
      ;;
    help|-h|--help)
      usage
      ;;
    *)
      usage
      die "未知命令：$command"
      ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then main "$@"; fi
