#!/usr/bin/env bash
# Conservative, reversible network defaults for a Linux Snell VPS.
# Source this file to test functions; only direct execution runs main.

SNELL_NET_STATE_DIR=${SNELL_NET_STATE_DIR:-/var/lib/snell-net}
SNELL_NET_CONFIG=${SNELL_NET_CONFIG:-/etc/sysctl.d/zzzz-snell-auto-network.conf}
SNELL_NET_PROC=${SNELL_NET_PROC:-/proc}
SNELL_NET_CGROUP=${SNELL_NET_CGROUP:-/sys/fs/cgroup}
SNELL_NET_MARKER='# Managed by snell-net; use snell-net rollback to restore the first backup.'
SNELL_NET_PENDING=0
SNELL_NET_MEMORY_BYTES=0
SNELL_NET_MEMORY_SOURCE=unknown
SNELL_NET_ENVIRONMENT=unknown
SNELL_NET_CAN_APPLY=0
SNELL_NET_REASON='尚未检测'

net_log() { printf '[snell-net] %s\n' "$*"; }
net_warn() { printf '[snell-net] %s\n' "$*" >&2; }
net_read() { sysctl -n "$1" 2>/dev/null | awk '{$1=$1; print}'; }
net_write() { sysctl -q -w "$1=$2" >/dev/null 2>&1; }
net_positive_integer() { [[ "$1" =~ ^[0-9]+$ && ${#1} -le 18 && "$1" != 0 ]]; }

net_supported_key() {
  case "$1" in
    net.ipv4.tcp_congestion_control|net.core.default_qdisc|net.ipv4.tcp_mtu_probing|net.ipv4.tcp_moderate_rcvbuf|net.core.rmem_max|net.core.wmem_max|net.ipv4.tcp_rmem|net.ipv4.tcp_wmem) return 0 ;;
    *) return 1 ;;
  esac
}

net_detect_environment() {
  local container rc vm mapped cap
  SNELL_NET_CAN_APPLY=0
  SNELL_NET_ENVIRONMENT=unknown
  if [[ "$(uname -s)" != Linux ]]; then
    SNELL_NET_REASON='非 Linux 系统，仅提供信息'; return 0
  fi
  if [[ -e /.dockerenv || -e /run/.containerenv || -s /run/systemd/container ]]; then
    SNELL_NET_ENVIRONMENT=container
    SNELL_NET_REASON='检测到容器，跳过可能影响共享内核的 sysctl'; return 0
  fi
  if ! command -v systemd-detect-virt >/dev/null 2>&1; then
    SNELL_NET_REASON='缺少 systemd-detect-virt，无法可靠确认虚拟化边界'; return 0
  fi
  container=$(systemd-detect-virt --container 2>/dev/null); rc=$?
  if [[ "$rc" -eq 0 ]]; then
    SNELL_NET_ENVIRONMENT="container:$container"
    SNELL_NET_REASON='检测到容器/受限环境，跳过 sysctl'; return 0
  elif [[ "$rc" -ne 1 ]]; then
    SNELL_NET_REASON='容器检测失败，不能确认宿主权限'; return 0
  fi
  mapped=$(awk 'NF==3 {print $1 " " $2 " " $3}' "$SNELL_NET_PROC/self/uid_map" 2>/dev/null)
  if [[ "$mapped" != '0 0 4294967295' ]]; then
    SNELL_NET_REASON='用户命名空间不明确或受到限制'; return 0
  fi
  cap=$(awk '/^CapEff:/ {print $2}' "$SNELL_NET_PROC/self/status" 2>/dev/null)
  if [[ ! "$cap" =~ ^[0-9a-fA-F]{1,16}$ ]]; then
    SNELL_NET_REASON='无法读取有效内核权限'; return 0
  fi
  # CAP_NET_ADMIN (bit 12) is needed to change the network namespace defaults.
  if (( (16#$cap & 4096) == 0 )); then
    SNELL_NET_REASON='缺少 CAP_NET_ADMIN，跳过 sysctl'; return 0
  fi
  vm=$(systemd-detect-virt --vm 2>/dev/null); rc=$?
  if [[ "$rc" -eq 0 && -n "$vm" ]]; then
    SNELL_NET_ENVIRONMENT="vm:$vm"
  elif [[ "$rc" -eq 1 ]]; then
    SNELL_NET_ENVIRONMENT=bare-metal
  else
    SNELL_NET_REASON='虚拟机检测失败，无法确认内核控制权限'; return 0
  fi
  SNELL_NET_CAN_APPLY=1
  SNELL_NET_REASON='独立内核环境且具备网络管理权限'
}

net_consider_memory_limit() {
  local path=$1 limit
  [[ -r "$path" ]] || return 0
  read -r limit < "$path" || return 0
  if net_positive_integer "$limit" && (( limit < SNELL_NET_MEMORY_BYTES )); then
    SNELL_NET_MEMORY_BYTES=$limit
    SNELL_NET_MEMORY_SOURCE="cgroup:$path"
  fi
}

net_cgroup_memory_limits() {
  local hierarchy controllers relative root mountpoint kind suffix current limitfile
  [[ -r "$SNELL_NET_PROC/self/cgroup" && -r "$SNELL_NET_PROC/self/mountinfo" ]] || return 0
  while IFS=: read -r hierarchy controllers relative; do
    if [[ "$hierarchy" == 0 && -z "$controllers" ]]; then
      kind=cgroup2; limitfile=memory.max
    elif [[ ",$controllers," == *,memory,* ]]; then
      kind=cgroup; limitfile=memory.limit_in_bytes
    else
      continue
    fi
    while IFS=$'\t' read -r root mountpoint; do
      # Kernel mountinfo uses octal escapes. Decode only the path fields.
      printf -v root '%b' "$root"
      printf -v mountpoint '%b' "$mountpoint"
      [[ "$relative" == /* && "$root" == /* && "$mountpoint" == /* ]] || continue
      # Reject traversal rather than accidentally examining an unrelated path.
      [[ "/$relative/" != */../* ]] || continue
      if [[ "$root" == / ]]; then
        suffix=$relative
      elif [[ "$relative" == "$root" ]]; then
        suffix=''
      elif [[ "$relative" == "$root/"* ]]; then
        suffix=${relative#"$root"}
      else
        # Namespaced cgroups may report / relative to a non-/ mounted root.
        [[ "$relative" == / ]] || continue
        suffix=''
      fi
      current="${mountpoint%/}$suffix"
      current=${current%/}
      [[ -n "$current" ]] || current=/
      while [[ "$current" == "$mountpoint" || "$current" == "$mountpoint/"* ]]; do
        net_consider_memory_limit "$current/$limitfile"
        [[ "$current" != "$mountpoint" ]] || break
        current=${current%/*}
      done
    done < <(awk -v wanted="$kind" '
      {split($0, parts, " - "); split(parts[2], tail, " ")}
      tail[1]==wanted && (wanted=="cgroup2" || tail[3] ~ /(^|,)memory(,|$)/) {print $4 "\t" $5}
    ' "$SNELL_NET_PROC/self/mountinfo")
  done < "$SNELL_NET_PROC/self/cgroup"
}

net_detect_memory() {
  local kib
  kib=$(awk '/^MemTotal:/ {print $2; exit}' "$SNELL_NET_PROC/meminfo" 2>/dev/null)
  if ! net_positive_integer "${kib:-0}"; then
    SNELL_NET_MEMORY_BYTES=0; SNELL_NET_MEMORY_SOURCE=unknown; return 1
  fi
  SNELL_NET_MEMORY_BYTES=$((kib * 1024))
  SNELL_NET_MEMORY_SOURCE=MemTotal
  net_consider_memory_limit "$SNELL_NET_CGROUP/memory.max"
  net_consider_memory_limit "$SNELL_NET_CGROUP/memory/memory.limit_in_bytes"
  net_cgroup_memory_limits
}

net_buffer_target() {
  local bytes=$1
  if (( bytes <= 536870912 )); then printf '4194304\n'
  elif (( bytes <= 1073741824 )); then printf '8388608\n'
  elif (( bytes <= 2147483648 )); then printf '16777216\n'
  else printf '33554432\n'; fi
}

net_show_value() {
  local value
  value=$(net_read "$1") || value='不支持/不可读取'
  printf '  %s = %s\n' "$1" "${value:-不支持/不可读取}"
}

net_diagnose() {
  local name probe=${1:-} key
  net_detect_environment
  name=$(awk -F= '$1=="PRETTY_NAME" {sub(/^[^=]*=/, ""); gsub(/^"|"$/, ""); print; exit}' /etc/os-release 2>/dev/null)
  net_log "系统：${name:-未知} | $(uname -srm)"
  net_log "虚拟化：${SNELL_NET_ENVIRONMENT}；$SNELL_NET_REASON"
  if net_detect_memory; then
    net_log "有效内存上限：$((SNELL_NET_MEMORY_BYTES / 1048576)) MiB（${SNELL_NET_MEMORY_SOURCE}）"
    net_log "缓冲上限建议：$(( $(net_buffer_target "$SNELL_NET_MEMORY_BYTES") / 1048576 )) MiB；保留现有更大值"
  else
    net_warn '无法读取有效内存，不会自动设置缓冲参数'
  fi
  if command -v ip >/dev/null 2>&1; then
    net_log '默认 IPv4 路由：'; ip -4 route show default 2>/dev/null || true
    net_log '默认 IPv6 路由：'; ip -6 route show default 2>/dev/null || true
    net_log '网卡与当前 MTU：'; ip -o link show 2>/dev/null || true
  else
    net_warn '缺少 ip，无法显示路由与 MTU'
  fi
  net_log '实际正在使用的队列（不会替换）：'
  if command -v tc >/dev/null 2>&1; then tc qdisc show 2>/dev/null || true
  else net_warn '缺少 tc，无法读取当前队列'; fi
  for key in net.core.default_qdisc net.ipv4.tcp_available_congestion_control net.ipv4.tcp_congestion_control net.ipv4.tcp_mtu_probing net.ipv4.tcp_moderate_rcvbuf net.core.rmem_max net.core.wmem_max net.ipv4.tcp_rmem net.ipv4.tcp_wmem; do
    net_show_value "$key"
  done
  net_log 'default_qdisc 是新队列的默认值，不代表网卡实际已使用 fq；现有 TCP 连接也不一定采用新拥塞算法。'
  [[ -z "$probe" ]] || net_probe "$probe"
}

net_valid_ip() {
  local octet part
  if [[ "$1" == *:* ]]; then
    [[ "$1" =~ ^[0-9a-fA-F:]+$ && ${#1} -le 39 ]]
    return
  fi
  [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
  local IFS=.
  for part in $1; do
    [[ ${#part} -le 3 ]] || return 1
    octet=$((10#$part)); (( octet <= 255 )) || return 1
  done
}

net_probe() {
  local target=$1
  net_valid_ip "$target" || { net_warn '--probe 仅接受 IPv4/IPv6 地址'; return 1; }
  command -v ping >/dev/null 2>&1 || { net_warn '没有 ping，跳过可选探测'; return 0; }
  net_log "低流量探测 ${target}：4 个 ICMP 包，最多 10 秒。这里只反映 VPS 到该 IP 的路径。"
  if [[ "$target" == *:* ]]; then ping -6 -n -c 4 -W 2 -w 10 "$target" || true
  else ping -4 -n -c 4 -W 2 -w 10 "$target" || true; fi
  net_log 'ICMP 可能被限速/屏蔽；该结果不等同于客户端到 VPS 的吞吐量，也不用于自动调参。'
}

net_plan() {
  local desired_file=$1 previous_file=$2 target key current desired available a b c
  target=$(net_buffer_target "$SNELL_NET_MEMORY_BYTES")
  : > "$desired_file" || return 1
  : > "$previous_file" || return 1
  for key in net.ipv4.tcp_congestion_control net.core.default_qdisc net.ipv4.tcp_mtu_probing net.ipv4.tcp_moderate_rcvbuf net.core.rmem_max net.core.wmem_max net.ipv4.tcp_rmem net.ipv4.tcp_wmem; do
    current=$(net_read "$key") || continue
    [[ -n "$current" ]] || continue
    if [[ -f "$SNELL_NET_STATE_DIR/baseline/values" ]] && ! awk -F '\t' -v key="$key" '$1==key {found=1} END {exit !found}' "$SNELL_NET_STATE_DIR/baseline/values"; then
      net_warn "$key 在首次备份中不存在，保留当前值；先 rollback 后重新 apply 可纳入管理"
      continue
    fi
    desired=$current
    case "$key" in
      net.ipv4.tcp_congestion_control)
        case "$current" in
          bbr|bbr2|bbr3) ;;
          *)
            available=$(net_read net.ipv4.tcp_available_congestion_control) || available=''
            if [[ " $available " != *' bbr '* ]] && command -v modprobe >/dev/null 2>&1; then
              modprobe tcp_bbr >/dev/null 2>&1 || true
              available=$(net_read net.ipv4.tcp_available_congestion_control) || available=''
            fi
            if [[ " $available " == *' bbr '* ]]; then desired=bbr
            else net_log "BBR 不可用，保留拥塞算法 $current"; fi
            ;;
        esac ;;
      net.core.default_qdisc)
        case "$current" in fq|fq_codel|cake) ;; *) desired=fq ;; esac ;;
      net.ipv4.tcp_mtu_probing)
        [[ "$current" =~ ^[012]$ ]] || return 1
        [[ "$current" == 2 ]] || desired=1 ;;
      net.ipv4.tcp_moderate_rcvbuf) desired=1 ;;
      net.core.rmem_max|net.core.wmem_max)
        net_positive_integer "$current" || return 1
        if (( current < target )); then desired=$target
        elif (( current > target )); then net_log "$key 已高于建议上限，保留 $current"; fi ;;
      net.ipv4.tcp_rmem|net.ipv4.tcp_wmem)
        IFS=' ' read -r a b c <<< "$current"
        net_positive_integer "${a:-}" && net_positive_integer "${b:-}" && net_positive_integer "${c:-}" || return 1
        if (( c < target )); then desired="$a $b $target"
        elif (( c > target )); then net_log "$key 已高于建议上限，保留 $c"; fi ;;
    esac
    printf '%s\t%s\n' "$key" "$current" >> "$previous_file" || return 1
    printf '%s\t%s\n' "$key" "$desired" >> "$desired_file" || return 1
  done
  [[ -s "$desired_file" ]]
}

net_require_root() {
  [[ ${EUID:-$(id -u)} -eq 0 ]] || { net_warn '此操作需要 root；请使用 sudo'; return 1; }
}

net_lock() {
  command -v flock >/dev/null 2>&1 || { net_warn '缺少 flock，请安装 util-linux'; return 1; }
  [[ ! -L "$SNELL_NET_STATE_DIR" ]] || { net_warn '状态目录不能是符号链接'; return 1; }
  install -d -m 0700 "$SNELL_NET_STATE_DIR" || return 1
  [[ ! -L "$SNELL_NET_STATE_DIR/lock" ]] || return 1
  exec 9>"$SNELL_NET_STATE_DIR/lock" || return 1
  flock -n 9 || { net_warn '另一个网络优化/回滚任务正在运行'; return 1; }
}

net_safe_config() {
  [[ ! -L "$SNELL_NET_CONFIG" && ( ! -e "$SNELL_NET_CONFIG" || -f "$SNELL_NET_CONFIG" ) ]] || {
    net_warn "拒绝覆盖非普通文件：$SNELL_NET_CONFIG"; return 1;
  }
}

net_snapshot_config() {
  local dir=$1
  net_safe_config || return 1
  if [[ -f "$SNELL_NET_CONFIG" ]]; then
    cp -p -- "$SNELL_NET_CONFIG" "$dir/config" || return 1
    printf 'present\n' > "$dir/config-state"
  else
    printf 'absent\n' > "$dir/config-state"
  fi
}

net_atomic_config_copy() {
  local source=$1 temp
  net_safe_config || return 1
  temp=$(mktemp "${SNELL_NET_CONFIG}.tmp.XXXXXX") || return 1
  if ! cp -p -- "$source" "$temp" || ! mv -f -- "$temp" "$SNELL_NET_CONFIG"; then
    rm -f -- "$temp"
    return 1
  fi
}

net_restore() {
  local dir=$1 key value actual failed=0 config_state
  [[ -f "$dir/values" && -f "$dir/config-state" ]] || { net_warn "备份不完整：$dir"; return 1; }
  read -r config_state < "$dir/config-state"
  case "$config_state" in
    present) net_atomic_config_copy "$dir/config" || failed=1 ;;
    absent) net_safe_config && rm -f -- "$SNELL_NET_CONFIG" || failed=1 ;;
    *) net_warn '备份中的配置状态无效'; failed=1 ;;
  esac
  while IFS=$'\t' read -r key value; do
    net_supported_key "$key" && [[ -n "$value" && "$value" != *$'\n'* ]] || { failed=1; continue; }
    actual=$(net_read "$key") || actual=''
    [[ "$actual" != "$value" ]] || continue
    if ! net_write "$key" "$value"; then
      net_warn "恢复失败：$key"; failed=1; continue
    fi
    actual=$(net_read "$key") || actual=''
    if [[ "$actual" != "$value" ]]; then net_warn "恢复校验失败：$key"; failed=1; fi
  done < "$dir/values"
  [[ "$failed" -eq 0 ]]
}

net_clear_pending() {
  # Delete only our enumerated transaction files, never an arbitrary directory tree.
  rm -f -- "$SNELL_NET_STATE_DIR/pending/values" "$SNELL_NET_STATE_DIR/pending/desired" "$SNELL_NET_STATE_DIR/pending/config" "$SNELL_NET_STATE_DIR/pending/config-state" "$SNELL_NET_STATE_DIR/pending/generated"
  rmdir -- "$SNELL_NET_STATE_DIR/pending"
}

net_clear_preparing() {
  local dir=$1
  [[ "$dir" == "$SNELL_NET_STATE_DIR/preparing."* && ! -L "$dir" ]] || return 1
  rm -f -- "$dir/values" "$dir/desired" "$dir/config" "$dir/config-state"
  rmdir -- "$dir"
}

net_abort() {
  if [[ "$SNELL_NET_PENDING" -eq 1 ]]; then
    # Commit may already have moved/removed the directory just before a signal.
    [[ -d "$SNELL_NET_STATE_DIR/pending" ]] || { SNELL_NET_PENDING=0; return 0; }
    net_warn '正在恢复本次操作前的参数……'
    if net_restore "$SNELL_NET_STATE_DIR/pending"; then
      net_clear_pending || return 1
      SNELL_NET_PENDING=0
      net_warn '本次变更已回滚'
    else
      net_warn "自动回滚未完全成功，备份保留在 $SNELL_NET_STATE_DIR/pending；请运行 snell-net rollback 重试"
      return 1
    fi
  fi
}

net_recover_pending() {
  if [[ -e "$SNELL_NET_STATE_DIR/pending" ]]; then
    net_warn '发现未完成事务，先恢复该事务之前的状态'
    [[ -d "$SNELL_NET_STATE_DIR/pending" && ! -L "$SNELL_NET_STATE_DIR/pending" ]] || return 1
    SNELL_NET_PENDING=1
    net_abort || return 1
  fi
}

net_apply() {
  local transaction staging key desired actual config_dir
  net_require_root || return 1
  [[ "$(uname -s)" == Linux ]] || { net_warn '仅支持 Linux'; return 1; }
  net_detect_environment
  if [[ "$SNELL_NET_CAN_APPLY" -ne 1 ]]; then
    net_log "SKIPPED：${SNELL_NET_ENVIRONMENT}；${SNELL_NET_REASON}。Snell 安装可继续。"
    return 0
  fi
  net_detect_memory || { net_warn '无法确定有效内存，停止优化'; return 1; }
  net_lock || return 1
  net_recover_pending || return 1
  net_safe_config || return 1
  config_dir=${SNELL_NET_CONFIG%/*}
  [[ -d "$config_dir" ]] || { net_warn "配置目录不存在：$config_dir"; return 1; }
  # A pre-existing baseline is kept intact across all later successful applies.
  [[ ! -L "$SNELL_NET_STATE_DIR/baseline" ]] || return 1
  if [[ -e "$SNELL_NET_STATE_DIR/baseline" && ( ! -f "$SNELL_NET_STATE_DIR/baseline/values" || ! -f "$SNELL_NET_STATE_DIR/baseline/config-state" ) ]]; then
    net_warn '首次备份不完整，停止覆盖'; return 1
  fi
  transaction="$SNELL_NET_STATE_DIR/pending"
  staging=$(mktemp -d "$SNELL_NET_STATE_DIR/preparing.XXXXXX") || return 1
  if ! net_snapshot_config "$staging" || ! net_plan "$staging/desired" "$staging/values"; then
    net_warn '建立优化计划失败，未修改 sysctl'
    net_clear_preparing "$staging" || true
    return 1
  fi
  # An interrupted preparation is harmless; only complete snapshots become pending.
  mv -- "$staging" "$transaction" || { net_clear_preparing "$staging" || true; return 1; }
  SNELL_NET_PENDING=1
  while IFS=$'\t' read -r key desired; do
    actual=$(net_read "$key") || actual=''
    if [[ "$actual" != "$desired" ]]; then
      net_log "${key}：$actual → $desired"
      if ! net_write "$key" "$desired"; then
        net_warn "写入失败：$key"
        net_abort || true
        return 1
      fi
    fi
    actual=$(net_read "$key") || actual=''
    if [[ "$actual" != "$desired" ]]; then
      net_warn "读回校验失败：$key"
      net_abort || true
      return 1
    fi
  done < "$transaction/desired"
  {
    printf '%s\n' "$SNELL_NET_MARKER"
    printf '# Memory-based defaults; existing larger buffers are preserved.\n'
    while IFS=$'\t' read -r key desired; do printf '%s = %s\n' "$key" "$desired"; done < "$transaction/desired"
  } > "$transaction/generated" || { net_abort || true; return 1; }
  chmod 0644 "$transaction/generated" || { net_abort || true; return 1; }
  if ! cmp -s "$transaction/generated" "$SNELL_NET_CONFIG"; then
    net_atomic_config_copy "$transaction/generated" || { net_abort || true; return 1; }
  fi
  if [[ ! -e "$SNELL_NET_STATE_DIR/baseline" ]]; then
    mv -- "$transaction" "$SNELL_NET_STATE_DIR/baseline" || { net_abort || true; return 1; }
  else
    net_clear_pending || { net_warn '参数已生效，但事务文件清理失败'; return 1; }
  fi
  SNELL_NET_PENDING=0
  net_log "已逐项写入并校验，持久配置：$SNELL_NET_CONFIG"
  net_log '新的默认队列不替换网卡正在使用的队列；已有连接可能继续使用原拥塞算法。'
  net_log '不修改路由、MTU、DNS、IPv6、SSH、防火墙或内核；不重启。回滚命令：snell-net rollback'
  net_log '这是按资源与内核能力选择的保守参数，不代表实测最优；需要客户端到 VPS 双向测试才能判断收益。'
}

net_rollback() {
  local archive
  net_require_root || return 1
  net_detect_environment
  if [[ "$SNELL_NET_CAN_APPLY" -ne 1 ]]; then
    net_warn "无法安全执行回滚：${SNELL_NET_REASON}；备份未修改"
    return 1
  fi
  net_lock || return 1
  net_recover_pending || return 1
  if [[ ! -d "$SNELL_NET_STATE_DIR/baseline" || -L "$SNELL_NET_STATE_DIR/baseline" ]]; then
    net_log '没有首次优化备份；没有执行参数恢复'
    return 0
  fi
  if ! net_restore "$SNELL_NET_STATE_DIR/baseline"; then
    net_warn '回滚未完全成功；备份已保留，可修复权限后重新执行 rollback'
    return 1
  fi
  archive=$(mktemp -d "$SNELL_NET_STATE_DIR/restored.XXXXXX") || return 1
  if ! mv -- "$SNELL_NET_STATE_DIR/baseline" "$archive/baseline"; then
    rmdir -- "$archive" || true
    net_warn '参数已恢复，但备份归档失败；原备份仍在'
    return 1
  fi
  net_log "已恢复首次优化前的真实参数与配置文件；备份归档：$archive/baseline"
}

net_status() {
  local key line
  net_log "持久配置：$SNELL_NET_CONFIG"
  if [[ -f "$SNELL_NET_CONFIG" ]]; then
    while IFS= read -r line; do printf '  %s\n' "$line"; done < "$SNELL_NET_CONFIG"
  else net_log '尚无本脚本的持久配置'; fi
  [[ ! -e "$SNELL_NET_STATE_DIR/pending" ]] || net_warn '有未完成事务，运行 snell-net rollback 可尝试恢复'
  if [[ -d "$SNELL_NET_STATE_DIR/baseline" ]]; then net_log '首次参数备份存在，可执行 rollback'
  else net_log '未保存首次参数备份'; fi
  net_log '当前实时值：'
  for key in net.ipv4.tcp_congestion_control net.core.default_qdisc net.ipv4.tcp_mtu_probing net.ipv4.tcp_moderate_rcvbuf net.core.rmem_max net.core.wmem_max net.ipv4.tcp_rmem net.ipv4.tcp_wmem; do net_show_value "$key"; done
  net_log '当前真实网卡队列：'
  if command -v tc >/dev/null 2>&1; then tc qdisc show 2>/dev/null || true; fi
}

net_help() {
  printf '%s\n' \
    '用法：snell-net diagnose [--probe IP] | apply | rollback | status | help' \
    '  diagnose  只读检测系统、权限、内存、路由、MTU、实际队列及 TCP 参数' \
    '  --probe   可选发送 4 个 ICMP 包；不会据此自动调参' \
    '  apply     按内存和内核能力应用保守参数；失败自动恢复本次变更' \
    '  rollback  恢复首次成功优化前的真实参数及本脚本管理的配置文件' \
    '  status    对照持久配置、当前参数和实际网卡队列' \
    '保留更大的现有缓冲上限及已有 BBR/BBR2/BBR3、fq/fq_codel/cake。' \
    '容器、权限不确定时跳过优化；不安装内核、不测速开放端口、不重启。'
}

net_main() {
  local action=${1:-diagnose} probe=''
  [[ $# -eq 0 ]] || shift
  if [[ "$action" == diagnose && $# -eq 2 && "$1" == --probe ]]; then probe=$2; shift 2; fi
  [[ $# -eq 0 ]] || { net_help; return 2; }
  case "$action" in
    diagnose) net_diagnose "$probe" ;;
    apply) net_apply ;;
    rollback) net_rollback ;;
    status) net_status ;;
    help|-h|--help) net_help ;;
    *) net_help; return 2 ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  set -uo pipefail
  umask 077
  trap 'net_abort || true' EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  net_main "$@"
fi
