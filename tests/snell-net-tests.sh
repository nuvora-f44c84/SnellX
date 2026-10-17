#!/usr/bin/env bash
# Portable mock tests: no real sysctl, network, root access or Linux required.
set -uo pipefail
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$script_dir/../outputs/snell-net.sh"
fixture=$(mktemp -d "${TMPDIR:-/tmp}/snell-net-test.XXXXXX") || exit 1
trap 'rm -rf -- "$fixture"' EXIT
failures=0
checks=0
assert_equal() {
  checks=$((checks + 1))
  if [[ "$1" != "$2" ]]; then
    printf 'FAIL %s: expected <%s>, got <%s>\n' "$3" "$2" "$1" >&2
    failures=$((failures + 1))
  fi
}
assert_ok() {
  checks=$((checks + 1))
  "$@" || { printf 'FAIL command: %s\n' "$*" >&2; failures=$((failures + 1)); }
}

assert_equal "$(net_buffer_target 536870912)" 4194304 '512 MiB boundary'
assert_equal "$(net_buffer_target 536870913)" 8388608 'above 512 MiB'
assert_equal "$(net_buffer_target 1073741824)" 8388608 '1 GiB boundary'
assert_equal "$(net_buffer_target 2147483648)" 16777216 '2 GiB boundary'
assert_equal "$(net_buffer_target 2147483649)" 33554432 'above 2 GiB'
assert_ok net_valid_ip 192.0.2.5
assert_ok net_valid_ip 2001:db8::1
if net_valid_ip 256.1.1.1 || net_valid_ip '--help' || net_valid_ip example.org; then
  printf 'FAIL invalid probe IP accepted\n' >&2; failures=$((failures + 1))
fi

# cgroup v2: both the current process cgroup and its parents constrain memory.
SNELL_NET_PROC="$fixture/proc"
SNELL_NET_CGROUP="$fixture/cgroup"
mkdir -p "$SNELL_NET_PROC/self" "$SNELL_NET_CGROUP/parent/child"
printf 'MemTotal:       8388608 kB\n' > "$SNELL_NET_PROC/meminfo"
printf '0::/parent/child\n' > "$SNELL_NET_PROC/self/cgroup"
printf '25 22 0:24 / %s rw - cgroup2 cgroup rw\n' "$SNELL_NET_CGROUP" > "$SNELL_NET_PROC/self/mountinfo"
printf 'max\n' > "$SNELL_NET_CGROUP/memory.max"
printf '536870912\n' > "$SNELL_NET_CGROUP/parent/memory.max"
printf '1073741824\n' > "$SNELL_NET_CGROUP/parent/child/memory.max"
assert_ok net_detect_memory
assert_equal "$SNELL_NET_MEMORY_BYTES" 536870912 'v2 parent limit wins'

# cgroup v1: mounted subtree root maps to the corresponding process path.
printf '4:memory:/guest/parent/child\n' > "$SNELL_NET_PROC/self/cgroup"
printf '25 22 0:24 /guest %s rw - cgroup cgroup rw,memory\n' "$SNELL_NET_CGROUP" > "$SNELL_NET_PROC/self/mountinfo"
printf '9223372036854771712\n' > "$SNELL_NET_CGROUP/memory.limit_in_bytes"
printf '268435456\n' > "$SNELL_NET_CGROUP/parent/memory.limit_in_bytes"
printf '1073741824\n' > "$SNELL_NET_CGROUP/parent/child/memory.limit_in_bytes"
assert_ok net_detect_memory
assert_equal "$SNELL_NET_MEMORY_BYTES" 268435456 'v1 ancestor limit wins, huge unlimited ignored'

# Override privileged/platform interfaces; filesystem state is a private fixture.
SNELL_NET_STATE_DIR="$fixture/state"
SNELL_NET_CONFIG="$fixture/etc/network.conf"
mock_values="$fixture/sysctl"
mkdir -p "$SNELL_NET_STATE_DIR" "$fixture/etc" "$mock_values"
FAIL_KEY=''
CORRUPT_KEY=''
net_require_root() { return 0; }
net_lock() { return 0; }
uname() { printf 'Linux\n'; }
net_detect_environment() { SNELL_NET_CAN_APPLY=1; SNELL_NET_ENVIRONMENT=vm:kvm; SNELL_NET_REASON=mock; }
net_detect_memory() { SNELL_NET_MEMORY_BYTES=2147483648; SNELL_NET_MEMORY_SOURCE=mock; }
net_read() { [[ -f "$mock_values/$1" ]] && command cat "$mock_values/$1"; }
net_write() {
  printf '%s\n' "$1" >> "$fixture/writes"
  if [[ "$1" == "$FAIL_KEY" && ! -e "$fixture/failure-used" ]]; then
    : > "$fixture/failure-used"; return 1
  fi
  if [[ "$1" == "$CORRUPT_KEY" && ! -e "$fixture/failure-used" ]]; then
    : > "$fixture/failure-used"
    printf 'mismatch\n' > "$mock_values/$1"
    return 0
  fi
  printf '%s\n' "$2" > "$mock_values/$1"
}
reset_values() {
  printf 'cubic\n' > "$mock_values/net.ipv4.tcp_congestion_control"
  printf 'reno cubic bbr\n' > "$mock_values/net.ipv4.tcp_available_congestion_control"
  printf 'pfifo_fast\n' > "$mock_values/net.core.default_qdisc"
  printf '0\n' > "$mock_values/net.ipv4.tcp_mtu_probing"
  printf '0\n' > "$mock_values/net.ipv4.tcp_moderate_rcvbuf"
  printf '212992\n' > "$mock_values/net.core.rmem_max"
  printf '212992\n' > "$mock_values/net.core.wmem_max"
  printf '4096 131072 6291456\n' > "$mock_values/net.ipv4.tcp_rmem"
  printf '4096 16384 4194304\n' > "$mock_values/net.ipv4.tcp_wmem"
  : > "$fixture/writes"
  rm -f -- "$fixture/failure-used"
}
reset_values
printf '# previous owned-path file\n' > "$SNELL_NET_CONFIG"
assert_ok net_apply
assert_equal "$(net_read net.ipv4.tcp_congestion_control)" bbr 'BBR selection'
assert_equal "$(net_read net.ipv4.tcp_rmem)" '4096 131072 16777216' 'preserve first two buffer values'
assert_equal "$(net_read net.core.rmem_max)" 16777216 'core buffer maximum'
baseline_hash=$(cksum "$SNELL_NET_STATE_DIR/baseline/values")
writes_before=$(wc -l < "$fixture/writes")
assert_ok net_apply
assert_equal "$(wc -l < "$fixture/writes")" "$writes_before" 'repeat apply performs no redundant sysctl writes'
assert_equal "$(cksum "$SNELL_NET_STATE_DIR/baseline/values")" "$baseline_hash" 'repeat preserves original backup'
printf 'cubic\n' > "$mock_values/net.ipv4.tcp_congestion_control"
printf '0\n' > "$mock_values/net.ipv4.tcp_mtu_probing"
config_hash=$(cksum "$SNELL_NET_CONFIG")
FAIL_KEY=net.ipv4.tcp_mtu_probing
if net_apply; then printf 'FAIL repeated apply failure reported success\n' >&2; failures=$((failures + 1)); fi
assert_equal "$(net_read net.ipv4.tcp_congestion_control)" cubic 'failed repeat restores its own immediate snapshot'
assert_equal "$(cksum "$SNELL_NET_CONFIG")" "$config_hash" 'failed repeat restores previous managed file'
assert_equal "$(cksum "$SNELL_NET_STATE_DIR/baseline/values")" "$baseline_hash" 'failed repeat preserves first baseline'
FAIL_KEY=''
assert_ok net_rollback
assert_equal "$(net_read net.ipv4.tcp_congestion_control)" cubic 'rollback original congestion'
assert_equal "$(net_read net.ipv4.tcp_rmem)" '4096 131072 6291456' 'rollback exact TCP vector'
assert_equal "$(cat "$SNELL_NET_CONFIG")" '# previous owned-path file' 'restore original persistence file'
assert_ok test ! -d "$SNELL_NET_STATE_DIR/baseline"

# A failed write must revert preceding writes and leave no persistent config.
reset_values
rm -f -- "$SNELL_NET_CONFIG"
FAIL_KEY=net.ipv4.tcp_mtu_probing
if net_apply; then printf 'FAIL write failure reported success\n' >&2; failures=$((failures + 1)); fi
assert_equal "$(net_read net.ipv4.tcp_congestion_control)" cubic 'failed apply restores earlier congestion change'
assert_equal "$(net_read net.core.default_qdisc)" pfifo_fast 'failed apply restores earlier qdisc default'
assert_ok test ! -f "$SNELL_NET_CONFIG"
assert_ok test ! -d "$SNELL_NET_STATE_DIR/pending"
assert_ok test ! -d "$SNELL_NET_STATE_DIR/baseline"
FAIL_KEY=''

# A write that reports success but reads back wrong must also revert.
reset_values
CORRUPT_KEY=net.core.rmem_max
if net_apply; then printf 'FAIL readback mismatch reported success\n' >&2; failures=$((failures + 1)); fi
assert_equal "$(net_read net.core.rmem_max)" 212992 'readback failure restores original buffer'
assert_equal "$(net_read net.ipv4.tcp_congestion_control)" cubic 'readback failure rolls whole transaction back'
assert_ok test ! -f "$SNELL_NET_CONFIG"
CORRUPT_KEY=''

# Atomic config install failure after all sysctls changed must undo all of them.
reset_values
eval "$(declare -f net_atomic_config_copy | sed '1s/net_atomic_config_copy/net_atomic_config_copy_original/')"
net_atomic_config_copy() { return 1; }
if net_apply; then printf 'FAIL persistence failure reported success\n' >&2; failures=$((failures + 1)); fi
assert_equal "$(net_read net.ipv4.tcp_congestion_control)" cubic 'persistence failure restores runtime defaults'
assert_equal "$(net_read net.ipv4.tcp_wmem)" '4096 16384 4194304' 'persistence failure restores last changed key'
assert_ok test ! -f "$SNELL_NET_CONFIG"
assert_ok test ! -d "$SNELL_NET_STATE_DIR/pending"
net_atomic_config_copy() { net_atomic_config_copy_original "$@"; }

# Without a BBR implementation the existing controller remains intact.
reset_values
printf 'reno cubic\n' > "$mock_values/net.ipv4.tcp_available_congestion_control"
modprobe() { return 1; }
assert_ok net_apply
assert_equal "$(net_read net.ipv4.tcp_congestion_control)" cubic 'unavailable BBR keeps existing controller'
assert_ok net_rollback

# Conservative choices preserve explicit existing settings above heuristics.
reset_values
printf 'bbr3\n' > "$mock_values/net.ipv4.tcp_congestion_control"
printf 'cake\n' > "$mock_values/net.core.default_qdisc"
printf '2\n' > "$mock_values/net.ipv4.tcp_mtu_probing"
printf '67108864\n' > "$mock_values/net.core.rmem_max"
printf '4096 131072 67108864\n' > "$mock_values/net.ipv4.tcp_rmem"
assert_ok net_apply
assert_equal "$(net_read net.ipv4.tcp_congestion_control)" bbr3 'preserve BBR3'
assert_equal "$(net_read net.core.default_qdisc)" cake 'preserve cake default'
assert_equal "$(net_read net.ipv4.tcp_mtu_probing)" 2 'preserve MTU probing 2'
assert_equal "$(net_read net.core.rmem_max)" 67108864 'do not shrink existing core maximum'
assert_equal "$(net_read net.ipv4.tcp_rmem)" '4096 131072 67108864' 'do not shrink existing TCP maximum'

# Rollback must surface errors and retain the baseline for a later retry.
printf 'cubic\n' > "$mock_values/net.ipv4.tcp_congestion_control"
FAIL_KEY=net.ipv4.tcp_congestion_control
rm -f -- "$fixture/failure-used"
if net_rollback; then printf 'FAIL failed rollback reported success\n' >&2; failures=$((failures + 1)); fi
assert_ok test -d "$SNELL_NET_STATE_DIR/baseline"
FAIL_KEY=''
assert_ok net_rollback
assert_equal "$(net_read net.ipv4.tcp_congestion_control)" bbr3 'retry restores baseline'

# Simulate process termination with a complete pending snapshot: recovery first.
reset_values
mkdir "$SNELL_NET_STATE_DIR/pending"
net_plan "$SNELL_NET_STATE_DIR/pending/desired" "$SNELL_NET_STATE_DIR/pending/values"
net_snapshot_config "$SNELL_NET_STATE_DIR/pending"
printf 'bbr\n' > "$mock_values/net.ipv4.tcp_congestion_control"
assert_ok net_recover_pending
assert_equal "$(net_read net.ipv4.tcp_congestion_control)" cubic 'recover interrupted transaction'
assert_ok test ! -d "$SNELL_NET_STATE_DIR/pending"

net_detect_environment() { SNELL_NET_CAN_APPLY=0; SNELL_NET_ENVIRONMENT=container; SNELL_NET_REASON=mock; }
writes_before=$(wc -l < "$fixture/writes")
assert_ok net_apply
assert_equal "$(wc -l < "$fixture/writes")" "$writes_before" 'container never modifies sysctl'

printf 'Checks: %s; failures: %s\n' "$checks" "$failures"
[[ "$failures" -eq 0 ]]
