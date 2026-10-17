#!/usr/bin/env bash
# Conservative host hardening for snell-auto. Safe to source for offline tests.

SNELL_SECURITY_STATE=${SNELL_SECURITY_STATE:-/var/lib/snell-security}
SNELL_SECURITY_SYSCTL=${SNELL_SECURITY_SYSCTL:-/etc/sysctl.d/zzzz-snell-auto-security.conf}
SNELL_SECURITY_SSH=${SNELL_SECURITY_SSH:-/etc/ssh/sshd_config.d/00-snell-auto-security.conf}
SNELL_SECURITY_JAIL=${SNELL_SECURITY_JAIL:-/etc/fail2ban/jail.d/snell-auto-sshd.local}
SNELL_SECURITY_APT_PERIODIC=${SNELL_SECURITY_APT_PERIODIC:-/etc/apt/apt.conf.d/99snell-auto-periodic}
SNELL_SECURITY_APT_REBOOT=${SNELL_SECURITY_APT_REBOOT:-/etc/apt/apt.conf.d/99zz-snell-auto-no-reboot}
SNELL_SECURITY_PROC=${SNELL_SECURITY_PROC:-/proc}
SNELL_SECURITY_MARKER='# Managed by snell-security; rollback with snell-security rollback.'
SNELL_SECURITY_TRANSACTION=''
SNELL_SECURITY_NO_PACKAGES=0
SNELL_SECURITY_MASKED=0
SNELL_SECURITY_SSHD=''
SNELL_SECURITY_SSH_UNIT=''
SNELL_SECURITY_CLIENT=''
SNELL_SECURITY_PORTS=''
SNELL_SECURITY_CONTEXT=''
SNELL_SECURITY_REPORT=''

sec_log() { printf '[snell-security] %s\n' "$*"; [[ -z "$SNELL_SECURITY_REPORT" ]] || printf '%s\n' "$*" >> "$SNELL_SECURITY_REPORT"; }
sec_warn() { printf '[snell-security] %s\n' "$*" >&2; [[ -z "$SNELL_SECURITY_REPORT" ]] || printf '%s\n' "$*" >> "$SNELL_SECURITY_REPORT"; }
sec_keys() {
  printf '%s\n' fs.protected_hardlinks fs.protected_symlinks fs.protected_fifos fs.protected_regular kernel.kptr_restrict kernel.dmesg_restrict net.ipv4.tcp_syncookies
}
sec_target() {
  case "$1" in
    sysctl) printf '%s\n' "$SNELL_SECURITY_SYSCTL" ;;
    ssh) printf '%s\n' "$SNELL_SECURITY_SSH" ;;
    jail) printf '%s\n' "$SNELL_SECURITY_JAIL" ;;
    periodic) printf '%s\n' "$SNELL_SECURITY_APT_PERIODIC" ;;
    reboot) printf '%s\n' "$SNELL_SECURITY_APT_REBOOT" ;;
    *) return 1 ;;
  esac
}
sec_owned() { [[ -f "$1" && ! -L "$1" ]] && { grep -Fqx "$SNELL_SECURITY_MARKER" "$1" || grep -Fqx "// ${SNELL_SECURITY_MARKER#\# }" "$1"; }; }
sec_file_id() {
  local id
  for id in sysctl ssh jail periodic reboot; do [[ "$(sec_target "$id")" != "$1" ]] || { printf '%s\n' "$id"; return 0; }; done
  return 1
}
sec_fingerprint() {
  [[ ! -L "$1" ]] || return 1
  if [[ ! -e "$1" ]]; then printf 'absent\n'; return 0; fi
  [[ -f "$1" ]] || return 1
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}'
  else return 1; fi
}
sec_metadata() {
  local target=$1 value=$2 temporary
  mkdir -p "$(dirname "$target")" || return 1
  temporary=$(mktemp "${target}.tmp.XXXXXX") || return 1
  printf '%s\n' "$value" > "$temporary" && chmod 600 "$temporary" && mv -f "$temporary" "$target" || { rm -f "$temporary"; return 1; }
}
sec_matches_expected() {
  local id=$1 current expected
  current=$(sec_fingerprint "$(sec_target "$id")") || return 1
  if [[ -f "$SNELL_SECURITY_STATE/expected.$id" ]]; then
    read -r expected < "$SNELL_SECURITY_STATE/expected.$id" || return 1
    [[ "$current" == "$expected" ]]
  else [[ "$current" == absent ]]; fi
}
sec_can_write() {
  local id
  id=$(sec_file_id "$1") || return 1
  [[ ! -L "$1" ]] && { [[ ! -e "$1" ]] || sec_owned "$1"; } && sec_matches_expected "$id"
}
sec_write_file() {
  local target=$1 input=$2 temporary marker=$SNELL_SECURITY_MARKER id fingerprint
  sec_can_write "$target" || { sec_warn "拒绝覆盖非本脚本管理文件：$target"; return 1; }
  mkdir -p "$(dirname "$target")" || return 1
  temporary=$(mktemp "${target}.tmp.XXXXXX") || return 1
  if [[ "$target" == "$SNELL_SECURITY_APT_PERIODIC" || "$target" == "$SNELL_SECURITY_APT_REBOOT" ]]; then marker="// ${SNELL_SECURITY_MARKER#\# }"; fi
  if ! { printf '%s\n' "$marker"; cat "$input"; } > "$temporary" || ! chmod 644 "$temporary"; then
    rm -f "$temporary"; return 1
  fi
  id=$(sec_file_id "$target") && fingerprint=$(sec_fingerprint "$temporary") || { rm -f "$temporary"; return 1; }
  # Persist expected content before rename, so a kill -9 between rename and ledger
  # update can be recovered without mistaking our own write for a user's edit.
  if [[ -n "$SNELL_SECURITY_TRANSACTION" ]]; then sec_metadata "$SNELL_SECURITY_TRANSACTION/planned.$id" "$fingerprint" || { rm -f "$temporary"; return 1; }; fi
  mv -f "$temporary" "$target" && sec_metadata "$SNELL_SECURITY_STATE/expected.$id" "$fingerprint"
}
sec_snapshot() {
  local directory=$1 id target value key unit enabled active
  mkdir -p "$directory/files" || return 1
  chmod 700 "$directory" "$directory/files" || return 1
  for id in sysctl ssh jail periodic reboot; do
    target=$(sec_target "$id") || return 1
    if [[ -e "$target" || -L "$target" ]]; then
      [[ -f "$target" && ! -L "$target" ]] || return 1
      cp -p "$target" "$directory/files/$id" || return 1
      printf 'present\n' > "$directory/$id.state" || return 1
    else printf 'absent\n' > "$directory/$id.state" || return 1; fi
  done
  : > "$directory/values" || return 1
  while IFS= read -r key; do
    value=$(sysctl -n "$key" 2>/dev/null) || continue
    [[ "$value" =~ ^[0-9]+$ ]] || continue
    printf '%s\t%s\n' "$key" "$value" >> "$directory/values" || return 1
  done < <(sec_keys)
  : > "$directory/services" || return 1
  for unit in fail2ban.service apt-daily.timer apt-daily-upgrade.timer; do
    enabled=$(systemctl is-enabled "$unit" 2>/dev/null) || true
    active=$(systemctl is-active "$unit" 2>/dev/null) || true
    printf '%s\t%s\t%s\n' "$unit" "${enabled:-not-found}" "${active:-inactive}" >> "$directory/services" || return 1
  done
}
sec_restore_file() {
  local directory=$1 id=$2 target state temporary current planned='' original=absent
  target=$(sec_target "$id") || return 1
  [[ -r "$directory/$id.state" ]] || return 1
  read -r state < "$directory/$id.state" || return 1
  current=$(sec_fingerprint "$target") || return 1
  if [[ "$state" == present ]]; then original=$(sec_fingerprint "$directory/files/$id") || return 1; fi
  [[ ! -f "$directory/planned.$id" ]] || read -r planned < "$directory/planned.$id"
  if ! sec_matches_expected "$id" && [[ "$current" != "$planned" && "$current" != "$original" ]]; then
    sec_warn "恢复已跳过：$target 内容校验不匹配，保留用户后续修改"; return 1
  fi
  if [[ -e "$target" || -L "$target" ]]; then
    if ! sec_owned "$target"; then
      if [[ "$state" == present ]] && cmp -s "$target" "$directory/files/$id"; then return 0; fi
      sec_warn "恢复已跳过：$target 已由其他程序修改或不属于本脚本"; return 1
    fi
  fi
  if [[ "$state" == present ]]; then
    mkdir -p "$(dirname "$target")" || return 1
    temporary=$(mktemp "${target}.restore.XXXXXX") || return 1
    cp -p "$directory/files/$id" "$temporary" && mv -f "$temporary" "$target" || { rm -f "$temporary"; return 1; }
  elif [[ "$state" == absent ]]; then
    [[ ! -e "$target" ]] || rm -f "$target" || return 1
  else return 1; fi
  sec_metadata "$SNELL_SECURITY_STATE/expected.$id" "$original"
}
sec_restore_services() {
  local directory=$1 unit enabled active result=0
  while IFS=$'\t' read -r unit enabled active; do
    case "$unit" in fail2ban.service|apt-daily.timer|apt-daily-upgrade.timer) ;; *) return 1;; esac
    if [[ "$unit" == fail2ban.service ]]; then [[ -e "$directory/touched.fail2ban" ]] || continue
    else [[ -e "$directory/touched.updates" ]] || continue; fi
    # A package may remain installed; restore only its prior runtime/enable state.
    case "$enabled" in
      enabled) systemctl enable "$unit" >/dev/null 2>&1 || result=1 ;;
      enabled-runtime)
        systemctl disable "$unit" >/dev/null 2>&1 || result=1
        systemctl enable --runtime "$unit" >/dev/null 2>&1 || result=1
        ;;
      disabled|not-found|'')
        if systemctl is-enabled "$unit" 2>/dev/null | grep -Eq '^enabled(-runtime)?$'; then
          systemctl disable "$unit" >/dev/null 2>&1 || result=1
          if systemctl is-enabled "$unit" 2>/dev/null | grep -Eq '^enabled(-runtime)?$'; then result=1; fi
        fi
        ;;
      masked|masked-runtime|static|indirect|generated|alias|linked|linked-runtime) ;;
      *) sec_warn "未知原始服务状态 $unit=${enabled}；未修改启用状态" ;;
    esac
    if [[ "$active" == active ]]; then
      if [[ "$unit" == fail2ban.service ]] && systemctl is-active --quiet "$unit"; then
        systemctl reload "$unit" >/dev/null 2>&1 || result=1
      elif ! systemctl is-active --quiet "$unit"; then systemctl start "$unit" >/dev/null 2>&1 || result=1; fi
    elif systemctl is-active --quiet "$unit"; then systemctl stop "$unit" >/dev/null 2>&1 || result=1; fi
  done < "$directory/services"
  return "$result"
}
sec_restore_allowed() {
  local directory=$1 id=$2 target state current original=absent planned=''
  target=$(sec_target "$id") && read -r state < "$directory/$id.state" || return 1
  current=$(sec_fingerprint "$target") || return 1
  if [[ "$state" == present ]]; then original=$(sec_fingerprint "$directory/files/$id") || return 1; fi
  [[ ! -f "$directory/planned.$id" ]] || read -r planned < "$directory/planned.$id"
  if ! sec_matches_expected "$id" && [[ "$current" != "$original" && "$current" != "$planned" ]]; then
    sec_warn "恢复冲突：$target 内容已变更；保留文件及运行状态"; return 1
  fi
  [[ "$current" == absent || "$current" == "$original" ]] || sec_owned "$target"
}
sec_restore() {
  local directory=$1 id key value result=0 kernel_ok=1 ssh_ok=1
  [[ -d "$directory/files" && -f "$directory/values" && -f "$directory/services" ]] || return 1
  # Preflight all targets before touching runtime state. If a user has edited a
  # managed file, a partial rollback must not pair it with older running values.
  for id in sysctl ssh jail periodic reboot; do
    [[ ! -e "$directory/touched.$id" ]] || sec_restore_allowed "$directory" "$id" || return 1
  done
  # Stop our newly started Fail2ban before removing its safe jail/ignoreip.
  if [[ -e "$directory/touched.fail2ban" ]] && ! awk -F '\t' '$1=="fail2ban.service" && $3=="active" {found=1} END {exit !found}' "$directory/services"; then
    sec_stop_fail2ban || return 1
  fi
  for id in sysctl ssh jail periodic reboot; do
    if [[ -e "$directory/touched.$id" ]] && ! sec_restore_file "$directory" "$id"; then
      result=1
      [[ "$id" != sysctl ]] || kernel_ok=0
      [[ "$id" != ssh ]] || ssh_ok=0
    fi
  done
  if [[ -e "$directory/touched.sysctl" && "$kernel_ok" == 1 ]]; then
    while IFS=$'\t' read -r key value; do
      sec_keys | grep -Fqx "$key" || { result=1; continue; }
      [[ "$value" =~ ^[0-9]+$ ]] || { result=1; continue; }
      [[ "$(sysctl -n "$key" 2>/dev/null)" == "$value" ]] || sysctl -q -w "$key=$value" >/dev/null 2>&1 || result=1
    done < "$directory/values"
  fi
  sec_find_sshd
  if [[ -e "$directory/touched.ssh" && "$ssh_ok" == 1 && -n "$SNELL_SECURITY_SSHD" && -n "$SNELL_SECURITY_SSH_UNIT" ]]; then
    "$SNELL_SECURITY_SSHD" -t && systemctl reload "$SNELL_SECURITY_SSH_UNIT" || result=1
  fi
  sec_restore_services "$directory" || result=1
  return "$result"
}
sec_package() {
  local package=$1
  if (( SNELL_SECURITY_NO_PACKAGES )); then sec_warn "--no-packages：不安装 $package"; return 1; fi
  if command -v apt-get >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=60 -o Acquire::Retries=1 -o Acquire::http::Timeout=20 -o Acquire::https::Timeout=20 update &&
      DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=60 -o Dpkg::Options::=--force-confold install -y --no-install-recommends "$package"
  elif command -v dnf >/dev/null 2>&1; then dnf -y --setopt=timeout=20 --setopt=retries=1 install "$package"
  elif command -v yum >/dev/null 2>&1; then yum -y --setopt=timeout=20 --setopt=retries=1 install "$package"
  else sec_warn '没有支持的软件包管理器'; return 1; fi
}
sec_kernel_safe() {
  local result mapping caps
  [[ ! -e /.dockerenv && ! -e /run/.containerenv && ! -s /run/systemd/container ]] || return 1
  command -v systemd-detect-virt >/dev/null 2>&1 || return 1
  systemd-detect-virt --container >/dev/null 2>&1; result=$?
  [[ "$result" -eq 1 ]] || return 1
  mapping=$(awk 'NF==3 {print $1 " " $2 " " $3}' "$SNELL_SECURITY_PROC/self/uid_map" 2>/dev/null)
  [[ "$mapping" == '0 0 4294967295' ]] || return 1
  caps=$(awk '/^CapEff:/ {print $2}' "$SNELL_SECURITY_PROC/self/status" 2>/dev/null)
  [[ "$caps" =~ ^[0-9a-fA-F]{1,16}$ ]] || return 1
  # CAP_SYS_ADMIN and CAP_NET_ADMIN: fail closed in restricted namespaces.
  (( (16#$caps & 2097152) != 0 && (16#$caps & 4096) != 0 ))
}
sec_sysctl() {
  local directory=$1 key current target result=0
  if ! sec_kernel_safe; then sec_warn '内核加固 skipped：容器或内核管理权限不明确'; return 0; fi
  : > "$directory/kernel-plan" || return 1
  while IFS= read -r key; do
    current=$(sysctl -n "$key" 2>/dev/null) || continue
    [[ "$current" =~ ^[0-9]+$ ]] || continue
    if [[ -f "$SNELL_SECURITY_STATE/baseline/values" ]] && ! awk -F '\t' -v wanted="$key" '$1==wanted {found=1} END {exit !found}' "$SNELL_SECURITY_STATE/baseline/values"; then continue; fi
    target=1
    case "$key" in fs.protected_fifos|fs.protected_regular|kernel.kptr_restrict) target=2;; esac
    (( current > target )) && target=$current
    printf '%s = %s\n' "$key" "$target" >> "$directory/kernel-plan" || return 1
  done < <(sec_keys)
  [[ -s "$directory/kernel-plan" ]] || { sec_warn '内核加固 skipped：没有可管理参数'; return 0; }
  : > "$directory/touched.sysctl" || return 1
  sec_write_file "$SNELL_SECURITY_SYSCTL" "$directory/kernel-plan" || return 1
  while read -r key _ target; do
    if ! sysctl -q -w "$key=$target" >/dev/null 2>&1 || [[ "$(sysctl -n "$key" 2>/dev/null)" != "$target" ]]; then result=1; break; fi
  done < "$directory/kernel-plan"
  if (( result )); then
    sec_restore_file "$directory" sysctl || return 1
    while IFS=$'\t' read -r key current; do sysctl -q -w "$key=$current" >/dev/null 2>&1 || return 1; done < "$directory/values"
    sec_warn '内核加固 skipped：写入/验证失败，已恢复本次参数'; return 0
  fi
  sec_log '内核加固已验证：链接/临时文件保护、内核信息访问限制、SYN cookies；保留已有更严格值'
}
sec_valid_ip() {
  local ip=$1 part
  if command -v python3 >/dev/null 2>&1; then
    python3 -c 'import ipaddress,sys; ipaddress.ip_address(sys.argv[1])' "$ip" >/dev/null 2>&1; return
  fi
  [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
  local IFS=.
  for part in $ip; do [[ ${#part} -le 3 ]] && (( 10#$part <= 255 )) || return 1; done
}
sec_valid_port() { [[ "$1" =~ ^[0-9]{1,5}$ ]] && (( 10#$1 >= 1 && 10#$1 <= 65535 )); }
sec_find_sshd() {
  local unit
  SNELL_SECURITY_SSHD=$(command -v sshd 2>/dev/null || true)
  [[ -n "$SNELL_SECURITY_SSHD" ]] || { [[ ! -x /usr/sbin/sshd ]] || SNELL_SECURITY_SSHD=/usr/sbin/sshd; }
  SNELL_SECURITY_SSH_UNIT=''
  for unit in ssh.service sshd.service; do
    if systemctl is-active --quiet "$unit"; then SNELL_SECURITY_SSH_UNIT=$unit; break; fi
  done
}
sec_ssh_default_service() {
  local command_line pid running
  [[ -n "$SNELL_SECURITY_SSH_UNIT" ]] || return 1
  command_line=$(systemctl show "$SNELL_SECURITY_SSH_UNIT" -p ExecStart --value 2>/dev/null) || return 1
  [[ -n "$command_line" ]] || return 1
  # systemd renders argv and environment variable references; unresolved arguments
  # cannot be safely interpreted as the same /etc/ssh/sshd_config checked below.
  [[ "$command_line" == *"path=$SNELL_SECURITY_SSHD ;"* ]] || return 1
  if [[ "$command_line" =~ (^|[[:space:]])-[fo] ]]; then return 1; fi
  pid=$(systemctl show "$SNELL_SECURITY_SSH_UNIT" -p MainPID --value 2>/dev/null) || return 1
  [[ "$pid" =~ ^[0-9]+$ && "$pid" -gt 1 && -r "$SNELL_SECURITY_PROC/$pid/cmdline" ]] || return 1
  running=$(tr '\0' ' ' < "$SNELL_SECURITY_PROC/$pid/cmdline") || return 1
  # Debian/Ubuntu default units include $SSHD_OPTS. Validate the actually expanded
  # listener argv instead of rejecting every default unit with that placeholder.
  [[ "$running" == *"$SNELL_SECURITY_SSHD"* ]] || return 1
  [[ ! "$running" =~ (^|[[:space:]])-[fo] ]]
}
sec_connection() {
  local source source_port local_ip local_port extra user
  SNELL_SECURITY_CLIENT=''; SNELL_SECURITY_CONTEXT=''
  [[ -n "${SSH_CONNECTION:-}" ]] || return 1
  read -r source source_port local_ip local_port extra <<< "$SSH_CONNECTION"
  [[ -z "$extra" ]] && sec_valid_ip "$source" && sec_valid_ip "$local_ip" && sec_valid_port "$source_port" && sec_valid_port "$local_port" || return 1
  user=${SUDO_USER:-root}
  [[ "$user" =~ ^[a-zA-Z0-9_.@-]+$ ]] || return 1
  SNELL_SECURITY_CLIENT=$source
  SNELL_SECURITY_CONTEXT="user=$user,addr=$source,laddr=$local_ip,lport=$local_port"
}
sec_ssh_auth_view() {
  # Compare every effective value other than the four intentionally hardened keys.
  awk '$1!="permitemptypasswords" && $1!="x11forwarding" && $1!="logingracetime" && $1!="loglevel"' "$1" | LC_ALL=C sort
}
sec_ssh_value() { awk -v key="$2" '$1==key {print $2; exit}' "$1"; }
sec_ssh_targets_ok() {
  local before=$1 after=$2 old_time time old_log log
  [[ "$(sec_ssh_value "$after" permitemptypasswords)" == no && "$(sec_ssh_value "$after" x11forwarding)" == no ]] || return 1
  old_time=$(sec_ssh_value "$before" logingracetime); time=$(sec_ssh_value "$after" logingracetime)
  [[ "$old_time" =~ ^[0-9]+$ && "$time" =~ ^[0-9]+$ ]] || return 1
  (( time > 0 && time <= 120 )) || return 1
  (( old_time == 0 || time <= old_time )) || return 1
  old_log=$(sec_ssh_value "$before" loglevel); log=$(sec_ssh_value "$after" loglevel)
  case "$old_log" in DEBUG*) [[ "$log" == "$old_log" ]] ;; *) [[ "$log" == VERBOSE || "$log" == DEBUG* ]] ;; esac
}
sec_ssh_restore_reload() {
  sec_restore_file "$1" ssh && "$SNELL_SECURITY_SSHD" -t && systemctl reload "$SNELL_SECURITY_SSH_UNIT"
}
sec_ssh() {
  local directory=$1 grace log result=0 context=0
  sec_find_sshd
  if [[ -z "$SNELL_SECURITY_SSHD" || -z "$SNELL_SECURITY_SSH_UNIT" ]]; then sec_warn 'SSH 加固 skipped：未发现活动 ssh/sshd 服务'; return 0; fi
  if ! sec_ssh_default_service; then sec_warn 'SSH 加固 skipped：服务启动参数不是可验证的默认配置，可能使用自定义 -f/-o/环境参数'; return 0; fi
  if ! "$SNELL_SECURITY_SSHD" -t || ! "$SNELL_SECURITY_SSHD" -T > "$directory/ssh-before"; then sec_warn 'SSH 加固 skipped：现有配置校验失败'; return 0; fi
  if [[ -n "${SSH_CONNECTION:-}" ]]; then
    if ! sec_connection || ! "$SNELL_SECURITY_SSHD" -T -C "$SNELL_SECURITY_CONTEXT" > "$directory/ssh-context-before"; then
      sec_warn 'SSH 加固 skipped：无法验证当前 SSH 会话上下文'; return 0
    fi
    context=1
  fi
  grace=$(sec_ssh_value "$directory/ssh-before" logingracetime)
  [[ "$grace" =~ ^[0-9]+$ ]] || { sec_warn 'SSH 加固 skipped：LoginGraceTime 无法解析'; return 0; }
  (( grace > 0 && grace < 120 )) || grace=120
  log=$(sec_ssh_value "$directory/ssh-before" loglevel)
  case "$log" in DEBUG*) ;; *) log=VERBOSE;; esac
  printf 'PermitEmptyPasswords no\nX11Forwarding no\nLoginGraceTime %s\nLogLevel %s\n' "$grace" "$log" > "$directory/ssh-plan" || return 1
  : > "$directory/touched.ssh" || return 1
  sec_write_file "$SNELL_SECURITY_SSH" "$directory/ssh-plan" || return 1
  "$SNELL_SECURITY_SSHD" -t && "$SNELL_SECURITY_SSHD" -T > "$directory/ssh-after" || result=1
  if (( result == 0 )); then
    cmp -s <(sec_ssh_auth_view "$directory/ssh-before") <(sec_ssh_auth_view "$directory/ssh-after") && sec_ssh_targets_ok "$directory/ssh-before" "$directory/ssh-after" || result=1
  fi
  if (( context && result == 0 )); then
    "$SNELL_SECURITY_SSHD" -T -C "$SNELL_SECURITY_CONTEXT" > "$directory/ssh-context-after" &&
      cmp -s <(sec_ssh_auth_view "$directory/ssh-context-before") <(sec_ssh_auth_view "$directory/ssh-context-after") &&
      sec_ssh_targets_ok "$directory/ssh-context-before" "$directory/ssh-context-after" || result=1
  fi
  if (( result )); then
    sec_restore_file "$directory" ssh || return 1
    sec_warn 'SSH 加固 skipped：Include 未生效、Match 覆盖或认证/转发设置变化；已还原文件，未 reload'; return 0
  fi
  if ! systemctl reload "$SNELL_SECURITY_SSH_UNIT" || ! systemctl is-active --quiet "$SNELL_SECURITY_SSH_UNIT"; then
    sec_ssh_restore_reload "$directory" || { sec_warn 'SSH reload 和恢复校验失败，请检查现有 SSH 服务'; return 1; }
    sec_warn 'SSH 加固 skipped：reload 失败，已恢复'; return 0
  fi
  sec_log 'SSH 加固生效；已验证认证方式、端口及转发不变，只执行 reload'
}
sec_collect_ports() {
  local directory=$1 port line listener source sport local_ip local_port extra
  SNELL_SECURITY_PORTS=''
  [[ -n "$SNELL_SECURITY_SSHD" ]] || return 1
  "$SNELL_SECURITY_SSHD" -T > "$directory/ssh-ports" || return 1
  : > "$directory/ports" || return 1
  while read -r port; do
    sec_valid_port "$port" || return 1
    printf '%s\n' "$((10#$port))" >> "$directory/ports"
  done < <(awk '$1=="port" {print $2}' "$directory/ssh-ports")
  command -v ss >/dev/null 2>&1 || return 1
  ss -H -lntp > "$directory/listeners" 2>/dev/null || return 1
  while read -r line; do
    [[ "$line" == *'"sshd"'* || "$line" == *'"sshd-session"'* ]] || continue
    listener=$(awk '{print $4}' <<< "$line"); port=${listener##*:}
    sec_valid_port "$port" || return 1
    printf '%s\n' "$((10#$port))" >> "$directory/ports"
  done < "$directory/listeners"
  read -r source sport local_ip local_port extra <<< "$SSH_CONNECTION"
  sec_valid_port "$local_port" || return 1
  printf '%s\n' "$((10#$local_port))" >> "$directory/ports"
  SNELL_SECURITY_PORTS=$(LC_ALL=C sort -nu "$directory/ports" | paste -sd, -)
  [[ -n "$SNELL_SECURITY_PORTS" ]]
}
sec_unmask_install() {
  if (( SNELL_SECURITY_MASKED )); then
    systemctl unmask --runtime fail2ban.service >/dev/null 2>&1 || return 1
    SNELL_SECURITY_MASKED=0
    [[ -z "$SNELL_SECURITY_TRANSACTION" ]] || rm -f "$SNELL_SECURITY_TRANSACTION/mask-owned" || return 1
  fi
}
sec_journal_backend() { command -v python3 >/dev/null 2>&1 && python3 -c 'from systemd import journal' >/dev/null 2>&1; }
sec_install_fail2ban_packages() {
  (( SNELL_SECURITY_NO_PACKAGES == 0 )) || return 1
  sec_package fail2ban || return 1
  if ! sec_journal_backend; then
    sec_package python3-systemd || sec_warn '现有软件源未能安装 python3-systemd；稍后按后端实际可用性决定是否启用'
  fi
}
sec_stop_fail2ban() {
  if systemctl is-active --quiet fail2ban.service; then
    systemctl stop fail2ban.service >/dev/null 2>&1 || { sec_warn 'Fail2ban 无法停止，保留 jail 与白名单'; return 1; }
    if systemctl is-active --quiet fail2ban.service; then sec_warn 'Fail2ban 仍在运行，保留 jail 与白名单'; return 1; fi
  fi
}
sec_fail2ban() {
  local directory=$1 action='' enabled
  if systemctl is-active --quiet fail2ban.service; then sec_log 'Fail2ban 已运行：保留现有配置与封禁规则，不接管'; return 0; fi
  if command -v fail2ban-client >/dev/null 2>&1 && ! sec_owned "$SNELL_SECURITY_JAIL"; then sec_log 'Fail2ban 已安装：保留现有配置，不自动启动或接管'; return 0; fi
  sec_find_sshd
  if ! sec_ssh_default_service || ! sec_connection || ! sec_collect_ports "$directory"; then
    sec_warn 'Fail2ban skipped：无法可靠验证当前 SSH 来源/全部监听端口；请从 SSH 会话运行'; return 0
  fi
  if ! command -v fail2ban-client >/dev/null 2>&1; then
    (( SNELL_SECURITY_NO_PACKAGES == 0 )) || { sec_warn 'Fail2ban skipped：--no-packages 且未安装'; return 0; }
    enabled=$(systemctl is-enabled fail2ban.service 2>/dev/null || true)
    case "$enabled" in masked*) sec_warn 'Fail2ban skipped：服务已被管理员 mask'; return 0;; esac
    : > "$directory/touched.fail2ban" || return 1
    : > "$directory/mask-owned" || return 1
    SNELL_SECURITY_MASKED=1
    if ! systemctl mask --runtime fail2ban.service >/dev/null 2>&1; then sec_unmask_install || return 1; sec_warn 'Fail2ban skipped：无法阻止包安装时自动启动'; return 0; fi
    enabled=$(systemctl is-enabled fail2ban.service 2>/dev/null || true)
    if [[ "$enabled" != masked-runtime && "$enabled" != masked ]]; then
      sec_unmask_install || return 1
      sec_warn 'Fail2ban skipped：临时 mask 未实际生效，未安装包'; return 0
    fi
    if ! sec_install_fail2ban_packages; then sec_unmask_install && sec_restore_services "$directory" || return 1; sec_warn 'Fail2ban skipped：现有软件源安装失败'; return 0; fi
    sec_unmask_install || return 1
  fi
  if ! sec_journal_backend; then
    sec_restore_services "$directory" || return 1
    sec_warn 'Fail2ban skipped：缺少 systemd journal Python 后端'; return 0
  fi
  if command -v nft >/dev/null 2>&1 && [[ -f /etc/fail2ban/action.d/nftables-multiport.conf ]] && nft list ruleset >/dev/null 2>&1; then action=nftables-multiport
  elif command -v iptables >/dev/null 2>&1 && [[ -f /etc/fail2ban/action.d/iptables-multiport.conf ]] && iptables -L -n >/dev/null 2>&1; then
    if ! command -v ip6tables >/dev/null 2>&1 || ! ip6tables -L -n >/dev/null 2>&1; then
      sec_restore_services "$directory" || return 1
      sec_warn 'Fail2ban skipped：IPv6 防护 action 不可用'; return 0
    fi
    action=iptables-multiport
  else sec_restore_services "$directory" || return 1; sec_warn 'Fail2ban skipped：没有可验证的 nftables/iptables action'; return 0; fi
  printf '[sshd]\nenabled = false\n\n[snell-auto-sshd]\nenabled = true\nfilter = sshd\nbackend = systemd\nport = %s\nprotocol = tcp\nbanaction = %s\nmaxretry = 8\nfindtime = 10m\nbantime = 15m\nusedns = no\nignoreip = 127.0.0.0/8 ::1 %s\n' "$SNELL_SECURITY_PORTS" "$action" "$SNELL_SECURITY_CLIENT" > "$directory/jail-plan" || return 1
  : > "$directory/touched.jail" || return 1
  : > "$directory/touched.fail2ban" || return 1
  sec_write_file "$SNELL_SECURITY_JAIL" "$directory/jail-plan" || return 1
  if ! fail2ban-client -t > "$directory/fail2ban-test" 2>&1 || ! fail2ban-client -d > "$directory/fail2ban-plan" 2>&1; then
    sec_restore_file "$directory" jail || return 1
    sec_restore_services "$directory" || return 1
    sec_warn 'Fail2ban skipped：jail 配置验证失败，已恢复文件'; return 0
  fi
  # Do not activate any unrelated jail left by a package or administrator.
  if ! command -v python3 >/dev/null 2>&1 || ! python3 - "$directory/fail2ban-plan" "$SNELL_SECURITY_CLIENT" <<'PY'
import ast, sys
jails, ignored = [], []
for line in open(sys.argv[1]):
    try:
        cmd = ast.literal_eval(line.strip())
    except (ValueError, SyntaxError):
        continue
    if not isinstance(cmd, (list, tuple)):
        continue
    if len(cmd) >= 2 and cmd[0] == 'add':
        jails.append(cmd[1])
    if len(cmd) >= 4 and cmd[:3] == ['set', 'snell-auto-sshd', 'addignoreip']:
        ignored.extend(cmd[3:])
sys.exit(0 if jails == ['snell-auto-sshd'] and sys.argv[2] in ignored else 1)
PY
  then
    sec_restore_file "$directory" jail || return 1
    sec_restore_services "$directory" || return 1
    sec_warn 'Fail2ban skipped：发现其他启用 jail 或来源白名单未确认；未启动服务'; return 0
  fi
  if ! systemctl enable --now fail2ban.service || ! sec_fail2ban_ready; then
    sec_stop_fail2ban || return 1
    sec_restore_file "$directory" jail && sec_restore_services "$directory" || return 1
    sec_warn 'Fail2ban skipped：启动/验证失败，已恢复'; return 0
  fi
  sec_log "Fail2ban 已启用：TCP ${SNELL_SECURITY_PORTS}；10 分钟失败 8 次封禁 15 分钟；当前 SSH 来源已加入白名单"
}
sec_fail2ban_ready() {
  local attempt
  for attempt in 1 2 3 4 5; do
    if systemctl is-active --quiet fail2ban.service && fail2ban-client status snell-auto-sshd >/dev/null 2>&1; then return 0; fi
    [[ "$attempt" == 5 ]] || sleep 1
  done
  return 1
}
sec_apt_read() {
  local value
  value=$(apt-config shell SNELL_APT_VALUE "$1" 2>/dev/null) || return 1
  # apt-config's quoted numeric/boolean output only; never eval configuration.
  printf '%s\n' "$value" | sed -n "s/^SNELL_APT_VALUE='\([^']*\)'$/\1/p"
}
sec_updates() {
  local directory=$1 distro current key result=0 policy=0
  distro=$(awk -F= '$1=="ID" {gsub(/"/, "", $2); print $2; exit}' /etc/os-release 2>/dev/null)
  if [[ "$distro" != debian && "$distro" != ubuntu ]] || ! command -v apt-config >/dev/null 2>&1; then
    sec_warn '自动安全更新 skipped：仅自动配置 Debian/Ubuntu；其他系统保留原策略'; return 0
  fi
  for key in APT::Periodic::Enable APT::Periodic::Update-Package-Lists APT::Periodic::Unattended-Upgrade; do
    current=$(sec_apt_read "$key") || { sec_warn '自动安全更新 skipped：无法读取现有 APT 策略'; return 0; }
    if [[ "$current" == 0 || "$current" == false ]]; then
      sec_warn "自动安全更新 skipped：管理员已有禁用策略 $key=$current"; return 0
    fi
  done
  # Installing this package can create distro-owned 20auto-upgrades or trigger
  # post-install policy outside our rollback scope. Manage only an existing install.
  command -v unattended-upgrade >/dev/null 2>&1 || { sec_warn '自动安全更新 skipped：尚未安装 unattended-upgrades；包安装会创建额外系统策略，请由管理员单独安装'; return 0; }
  apt-config dump > "$directory/apt-effective" || return 1
  # Package defaults supply distro security origins; do not invent or replace origins.
  if ! grep -Eq 'Unattended-Upgrade::(Allowed-Origins|Origins-Pattern)::.*(security|Security)' "$directory/apt-effective"; then
    sec_warn '自动安全更新 skipped：未发现安全更新来源，保留现有源与策略'; return 0
  fi
  : > "$directory/periodic-plan" || return 1
  for key in APT::Periodic::Update-Package-Lists APT::Periodic::Unattended-Upgrade; do
    current=$(sec_apt_read "$key") || return 1
    if [[ -z "$current" ]]; then
      printf '%s "1";\n' "$key" >> "$directory/periodic-plan" || return 1
    elif sec_owned "$SNELL_SECURITY_APT_PERIODIC"; then
      # Effective value may originate from our previous apply. Keep our setting
      # instead of deleting it and accidentally disabling scheduling on reruns.
      awk -v key="$key" '$1==key {print}' "$SNELL_SECURITY_APT_PERIODIC" >> "$directory/periodic-plan" || return 1
    fi
  done
  printf 'Unattended-Upgrade::Automatic-Reboot "false";\n' > "$directory/reboot-plan" || return 1
  : > "$directory/touched.updates" || return 1
  : > "$directory/touched.periodic" || return 1
  : > "$directory/touched.reboot" || return 1
  sec_write_file "$SNELL_SECURITY_APT_PERIODIC" "$directory/periodic-plan" && sec_write_file "$SNELL_SECURITY_APT_REBOOT" "$directory/reboot-plan" || return 1
  [[ "$(sec_apt_read Unattended-Upgrade::Automatic-Reboot)" == false ]] || result=1
  for key in APT::Periodic::Update-Package-Lists APT::Periodic::Unattended-Upgrade; do
    current=$(sec_apt_read "$key")
    [[ -n "$current" && "$current" != 0 && "$current" != false ]] || result=1
  done
  if (( result )); then
    sec_restore_file "$directory" periodic && sec_restore_file "$directory" reboot || return 1
    sec_warn '自动安全更新 skipped：有效配置校验失败，已恢复'; return 0
  fi
  # Timers schedule future work; no upgrade or apt-daily service is run here.
  for key in apt-daily.timer apt-daily-upgrade.timer; do
    current=$(systemctl is-enabled "$key" 2>/dev/null || true)
    case "$current" in masked*) sec_warn "保留管理员 mask：$key"; continue;; esac
    if ! systemctl enable "$key" >/dev/null 2>&1; then sec_warn "$key 无法启用；请检查系统更新定时器"; policy=1; fi
  done
  sec_log 'APT 自动更新沿用现有 Allowed-Origins/Origins-Pattern（可能不限于安全更新）、排除/周期；禁止自动重启，未运行升级任务'
  sec_log '已有活动更新 timer 保持运行；新启用的非活动 timer 下次开机开始调度'
  (( policy == 0 )) || sec_warn '自动更新调度未完全启用，请查看 status'
}
sec_firewall() {
  sec_log '防火墙审计（仅查看，不启用/重置或改变默认策略）：'
  if command -v ufw >/dev/null 2>&1; then ufw status 2>/dev/null || true; fi
  if command -v firewall-cmd >/dev/null 2>&1; then firewall-cmd --state 2>/dev/null || true; fi
  if command -v nft >/dev/null 2>&1; then
    if nft list tables 2>/dev/null; then :; else sec_warn 'nftables 状态不可读'; fi
  fi
  if command -v iptables >/dev/null 2>&1; then iptables -S INPUT 2>/dev/null || true; fi
  if command -v ss >/dev/null 2>&1; then sec_log '当前 TCP 监听端口：'; ss -H -lnt 2>/dev/null || true; fi
}
sec_status() {
  local key value
  [[ ! -d "$SNELL_SECURITY_STATE/baseline" ]] || sec_log "首次基线备份：$SNELL_SECURITY_STATE/baseline"
  for key in sysctl ssh jail periodic reboot; do
    value=$(sec_target "$key")
    if sec_owned "$value"; then sec_log "${key}：本脚本管理 ($value)"; else sec_log "${key}：未管理"; fi
  done
  sec_log '实际内核参数：'
  while IFS= read -r key; do value=$(sysctl -n "$key" 2>/dev/null) || value=unsupported; printf '  %s = %s\n' "$key" "$value"; done < <(sec_keys)
  for key in fail2ban.service apt-daily.timer apt-daily-upgrade.timer; do
    value=$(systemctl is-active "$key" 2>/dev/null || true); sec_log "${key}：active=${value:-unknown}, enabled=$(systemctl is-enabled "$key" 2>/dev/null || true)"
  done
  if [[ -f "$SNELL_SECURITY_STATE/latest" ]]; then
    read -r value < "$SNELL_SECURITY_STATE/latest"
    if [[ "$value" == "$SNELL_SECURITY_STATE/transaction."* && -f "$value/report" ]]; then sec_log '最近一次执行报告：'; cat "$value/report"; fi
  fi
  [[ ! -f "$SNELL_SECURITY_STATE/pending" ]] || sec_warn '检测到未完成事务；下次 apply/rollback 将先尝试恢复'
  sec_firewall
}
sec_recover_pending() {
  local directory suffix
  [[ -f "$SNELL_SECURITY_STATE/pending" ]] || return 0
  read -r directory < "$SNELL_SECURITY_STATE/pending" || return 1
  suffix=${directory#"$SNELL_SECURITY_STATE/transaction."}
  [[ "$directory" == "$SNELL_SECURITY_STATE/transaction."* && "$suffix" =~ ^[a-zA-Z0-9]+$ && -d "$directory" && ! -L "$directory" ]] || { sec_warn 'pending 事务路径无效，停止以保护现有配置'; return 1; }
  sec_warn "恢复上次未完成事务：$directory"
  if [[ -f "$directory/mask-owned" ]]; then
    SNELL_SECURITY_MASKED=1
    sec_unmask_install || return 1
  fi
  sec_restore "$directory" || return 1
  rm -f "$SNELL_SECURITY_STATE/pending" || return 1
}
sec_abort() {
  local result=$?
  trap - EXIT INT TERM
  sec_unmask_install || result=1
  if [[ -n "$SNELL_SECURITY_TRANSACTION" && -d "$SNELL_SECURITY_TRANSACTION" ]]; then
    sec_warn '操作未完成，正在恢复本次变更'
    if sec_restore "$SNELL_SECURITY_TRANSACTION"; then rm -f "$SNELL_SECURITY_STATE/pending" || result=1
    else sec_warn "自动恢复有未完成项，保留备份：$SNELL_SECURITY_TRANSACTION"; result=1; fi
  fi
  exit "$result"
}
sec_apply() {
  local id target directory baseline_new=0
  for id in sysctl ssh jail periodic reboot; do
    target=$(sec_target "$id")
    sec_can_write "$target" || { sec_warn "拒绝覆盖未标记文件：$target"; return 1; }
  done
  [[ ! -L "$SNELL_SECURITY_STATE" ]] || return 1
  mkdir -p "$SNELL_SECURITY_STATE" || return 1
  chmod 700 "$SNELL_SECURITY_STATE" || return 1
  directory=$(mktemp -d "$SNELL_SECURITY_STATE/transaction.XXXXXX") || return 1
  sec_snapshot "$directory" || return 1
  SNELL_SECURITY_TRANSACTION=$directory
  SNELL_SECURITY_REPORT="$directory/report"
  sec_metadata "$SNELL_SECURITY_STATE/pending" "$directory" || return 1
  if [[ ! -d "$SNELL_SECURITY_STATE/baseline" ]]; then baseline_new=1; fi
  sec_sysctl "$directory" && sec_ssh "$directory" && sec_fail2ban "$directory" && sec_updates "$directory" || return 1
  if (( baseline_new )); then
    target=$(mktemp -d "$SNELL_SECURITY_STATE/baseline-new.XXXXXX") || return 1
    cp -a "$directory/." "$target/" && mv "$target" "$SNELL_SECURITY_STATE/baseline" || return 1
  else
    for id in sysctl ssh jail periodic reboot fail2ban updates; do
      [[ ! -e "$directory/touched.$id" ]] || : > "$SNELL_SECURITY_STATE/baseline/touched.$id" || return 1
    done
  fi
  SNELL_SECURITY_TRANSACTION=''
  rm -f "$SNELL_SECURITY_STATE/pending" || return 1
  printf '%s\n' "$directory" > "$SNELL_SECURITY_STATE/latest" || return 1
  sec_firewall
  sec_log '基础加固流程完成；skipped 项未启用。rollback 恢复首次基线，不卸载新装软件包，也无法撤销已发生的软件更新。'
}
sec_require_host() {
  [[ "$EUID" -eq 0 ]] || { sec_warn '请使用 root 或 sudo'; return 1; }
  [[ "$(uname -s)" == Linux && -d /run/systemd/system ]] || { sec_warn '需要 Linux + systemd'; return 1; }
  local command
  for command in systemctl sysctl flock awk sed grep sort cmp mktemp; do command -v "$command" >/dev/null 2>&1 || { sec_warn "缺少依赖：$command"; return 1; }; done
}
sec_help() {
  printf '%s\n' '用法：snell-security apply [--no-packages] | status | rollback | help' \
    'apply：可回滚的内核/SSH 基础加固，条件允许时配置 Fail2ban 和 Debian/Ubuntu 自动安全更新。' \
    '--no-packages：只使用已安装组件，不访问软件源。' \
    'status：只读审计。rollback：恢复第一次成功 apply 前的文件、参数及服务状态。' \
    '不修改 SSH 端口/密码登录/root 登录，不启用全局防火墙，不重启 VPS。'
}
sec_main() {
  local action=${1:-apply}
  [[ $# -eq 0 ]] || shift
  case "$action" in help|-h|--help) [[ $# -eq 0 ]] || return 2; sec_help; return 0;; apply|status|rollback) ;; *) sec_warn "未知命令：$action"; sec_help; return 2;; esac
  if [[ "$action" == apply && $# -eq 1 && "$1" == --no-packages ]]; then SNELL_SECURITY_NO_PACKAGES=1; shift; fi
  [[ $# -eq 0 ]] || { sec_warn '参数错误'; return 2; }
  sec_require_host || return 1
  if [[ "$action" == status ]]; then sec_status; return; fi
  [[ ! -L "$SNELL_SECURITY_STATE" ]] || return 1
  mkdir -p "$SNELL_SECURITY_STATE" && chmod 700 "$SNELL_SECURITY_STATE" || return 1
  exec 9> "$SNELL_SECURITY_STATE/lock" || return 1
  flock -n 9 || { sec_warn '另一个安全管理任务正在运行'; return 1; }
  sec_recover_pending || return 1
  trap sec_abort EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  case "$action" in
    apply) sec_apply ;;
    status) sec_status ;;
    rollback)
      [[ -d "$SNELL_SECURITY_STATE/baseline" ]] || { sec_warn '没有可回滚的首次基线'; return 1; }
      if sec_restore "$SNELL_SECURITY_STATE/baseline"; then
        mv "$SNELL_SECURITY_STATE/baseline" "$SNELL_SECURITY_STATE/restored-$(date +%Y%m%d%H%M%S)" || return 1
        sec_log '已恢复首次基线；已安装软件包及已执行的软件更新保留'
      else sec_warn '部分回滚失败，保留基线以便排查'; return 1; fi
      ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  set -uo pipefail
  sec_main "$@"
fi
