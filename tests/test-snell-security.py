#!/usr/bin/env python3
"""Offline tests for security helpers. No root, network, or real daemon changes.

Paths are relocated to TemporaryDirectory and systemctl/sysctl/sshd are mocked.
These regression checks do not replace Linux VM/real SSH connectivity testing.
"""
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[1]
MODULE = REPO / "outputs" / "snell-security.sh"
MARKER = "# Managed by snell-security; rollback with snell-security rollback."
KEYS = {
    "fs.protected_hardlinks": "0", "fs.protected_symlinks": "1",
    "fs.protected_fifos": "0", "fs.protected_regular": "2",
    "kernel.kptr_restrict": "1", "kernel.dmesg_restrict": "1",
    "net.ipv4.tcp_syncookies": "2",
}


class SecurityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="snell-security-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.bash = shutil.which("bash")
        self.module = self.root / "security.sh"
        source = MODULE.read_text()
        source = re.sub(r"/(?:etc|var/lib|proc|run|usr/sbin)/",
                        lambda m: str(self.root) + m.group(), source)
        self.module.write_text(source)
        self.helper = self.root / "mock.py"
        self.helper.write_text(MOCK_PYTHON)
        self.data = self.root / "data.json"
        self.data.write_text(json.dumps({"sysctl": KEYS.copy(), "calls": [], "services": {
            "ssh.service": ["enabled", "active"],
            "sshd.service": ["not-found", "inactive"],
            "fail2ban.service": ["not-found", "inactive"],
            "apt-daily.timer": ["enabled", "active"],
            "apt-daily-upgrade.timer": ["enabled", "active"],
        }}))
        self.ssh = self.root / "etc/ssh/sshd_config.d/00-snell-auto-security.conf"
        self.kernel = self.root / "etc/sysctl.d/zzzz-snell-auto-security.conf"
        self.jail = self.root / "etc/fail2ban/jail.d/snell-auto-sshd.local"
        self.apt_periodic = self.root / "etc/apt/apt.conf.d/99snell-auto-periodic"
        self.apt_reboot = self.root / "etc/apt/apt.conf.d/99zz-snell-auto-no-reboot"
        self.env = os.environ.copy()
        for name in list(self.env):
            if name.startswith("BASH_FUNC_") or name in ("BASH_ENV", "ENV", "SSH_CONNECTION", "SUDO_USER"):
                del self.env[name]
        self.env.update({"TEST_ROOT": str(self.root), "TEST_HELPER": str(self.helper),
                         "TEST_DATA": str(self.data), "TEST_PYTHON": sys.executable,
                         "TEST_SSH": str(self.ssh)})

    def run_shell(self, code, overrides="", **environment):
        script = f"set -uo pipefail\nsource {shlex.quote(str(self.module))}\n" + MOCK_SHELL + "\n" + overrides + "\n" + code
        env = self.env | environment
        return subprocess.run([self.bash, "--noprofile", "--norc", "-c", script],
                              text=True, capture_output=True, env=env, timeout=20)

    def assert_ok(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def state(self):
        return json.loads(self.data.read_text())

    def change_state(self, mutate):
        state = self.state()
        mutate(state)
        self.data.write_text(json.dumps(state))

    def test_source_has_no_effect_and_unknown_command_fails(self):
        self.assert_ok(self.run_shell("sec_main help"))
        result = self.run_shell("sec_main typo")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(self.state()["calls"], [])

    def test_apply_refuses_unowned_target_before_snapshot(self):
        self.ssh.parent.mkdir(parents=True)
        self.ssh.write_text("# administrator file\nX11Forwarding yes\n")
        result = self.run_shell("sec_apply")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("拒绝覆盖", result.stderr)
        self.assertEqual(self.ssh.read_text(), "# administrator file\nX11Forwarding yes\n")

    def test_foreign_symlink_target_refused(self):
        self.ssh.parent.mkdir(parents=True)
        original = self.root / "original"
        original.write_text("safe")
        self.ssh.symlink_to(original)
        result = self.run_shell('sec_can_write "$SNELL_SECURITY_SSH"')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(original.read_text(), "safe")

    def test_sysctl_preserves_stricter_values_and_rolls_back(self):
        result = self.run_shell('''
sec_snapshot "$TEST_ROOT/snapshot" || exit 10
sec_sysctl "$TEST_ROOT/snapshot" || exit 11
[[ $(sysctl -n net.ipv4.tcp_syncookies) == 2 ]] || exit 12
[[ $(sysctl -n fs.protected_fifos) == 2 ]] || exit 13
sec_restore "$TEST_ROOT/snapshot"
''', overrides="sec_kernel_safe() { return 0; }")
        self.assert_ok(result)
        self.assertEqual(self.state()["sysctl"], KEYS)
        self.assertFalse(self.kernel.exists())
        self.assertFalse(any("reload" in c for c in self.state()["calls"]))

    def test_sysctl_write_failure_restores_prior_values(self):
        result = self.run_shell('''
sec_snapshot "$TEST_ROOT/snapshot" || exit 10
sec_sysctl "$TEST_ROOT/snapshot"
''', overrides="sec_kernel_safe() { return 0; }", TEST_FAIL_SYSCTL="kernel.kptr_restrict=2")
        self.assert_ok(result)
        self.assertEqual(self.state()["sysctl"], KEYS)
        self.assertFalse(self.kernel.exists())
        self.assertIn("skipped", result.stderr)

    def test_existing_owned_file_and_service_restore(self):
        self.ssh.parent.mkdir(parents=True)
        previous = MARKER + "\nLoginGraceTime 30\n"
        self.ssh.write_text(previous)
        result = self.run_shell('''
sec_metadata "$SNELL_SECURITY_STATE/expected.ssh" "$(sec_fingerprint "$SNELL_SECURITY_SSH")" || exit 9
sec_snapshot "$TEST_ROOT/snapshot" || exit 10
printf 'PermitEmptyPasswords no\n' > "$TEST_ROOT/new"
sec_write_file "$SNELL_SECURITY_SSH" "$TEST_ROOT/new" || exit 11
: > "$TEST_ROOT/snapshot/touched.ssh"
sec_restore "$TEST_ROOT/snapshot"
''')
        self.assert_ok(result)
        self.assertEqual(self.ssh.read_text(), previous)
        self.assertIn(["systemctl", "reload", "ssh.service"], self.state()["calls"])

    def test_restore_refuses_external_replacement(self):
        result = self.run_shell('''
sec_snapshot "$TEST_ROOT/snapshot" || exit 10
mkdir -p "$(dirname "$SNELL_SECURITY_SSH")"
printf 'administrator replacement\n' > "$SNELL_SECURITY_SSH"
sec_restore_file "$TEST_ROOT/snapshot" ssh
''')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.ssh.read_text(), "administrator replacement\n")

    def test_ssh_applies_preserving_short_grace_debug_and_auth(self):
        result = self.run_shell('''
sec_snapshot "$TEST_ROOT/snapshot" || exit 10
sec_ssh "$TEST_ROOT/snapshot"
''', TEST_GRACE="30", TEST_LOG="DEBUG2", SSH_CONNECTION="198.51.100.4 12345 203.0.113.5 49764")
        self.assert_ok(result)
        text = self.ssh.read_text()
        self.assertIn("LoginGraceTime 30", text)
        self.assertIn("LogLevel DEBUG2", text)
        self.assertNotRegex(text, r"(?mi)^(Port|PasswordAuthentication|PermitRootLogin|AllowTcpForwarding)\b")
        calls = self.state()["calls"]
        self.assertIn(["systemctl", "reload", "ssh.service"], calls)
        self.assertFalse(any("restart" in c for c in calls))

    def test_ssh_include_ignored_is_not_reported_success(self):
        result = self.run_shell('sec_snapshot "$TEST_ROOT/s" && sec_ssh "$TEST_ROOT/s"', TEST_IGNORE_DROPIN="1")
        self.assert_ok(result)
        self.assertFalse(self.ssh.exists())
        self.assertIn("skipped", result.stderr)
        self.assertNotIn(["systemctl", "reload", "ssh.service"], self.state()["calls"])

    def test_ssh_authentication_change_is_rejected(self):
        result = self.run_shell('sec_snapshot "$TEST_ROOT/s" && sec_ssh "$TEST_ROOT/s"', TEST_AUTH_CHANGE="1")
        self.assert_ok(result)
        self.assertFalse(self.ssh.exists())
        self.assertIn("认证", result.stderr)
        self.assertNotIn(["systemctl", "reload", "ssh.service"], self.state()["calls"])

    def test_ssh_match_context_change_is_rejected(self):
        result = self.run_shell('sec_snapshot "$TEST_ROOT/s" && sec_ssh "$TEST_ROOT/s"',
                                TEST_CONTEXT_AUTH_CHANGE="1", SSH_CONNECTION="198.51.100.4 12345 203.0.113.5 49764")
        self.assert_ok(result)
        self.assertFalse(self.ssh.exists())
        self.assertIn("skipped", result.stderr)

    def test_ssh_failed_reload_restores_and_reloads_original(self):
        result = self.run_shell('sec_snapshot "$TEST_ROOT/s" && sec_ssh "$TEST_ROOT/s"', TEST_FAIL_RELOAD_ONCE="1")
        self.assert_ok(result)
        self.assertFalse(self.ssh.exists())
        reloads = [c for c in self.state()["calls"] if c == ["systemctl", "reload", "ssh.service"]]
        self.assertEqual(len(reloads), 2)
        self.assertIn("已恢复", result.stderr)

    def test_invalid_current_ip_skips_ssh_and_fail2ban(self):
        result = self.run_shell('sec_snapshot "$TEST_ROOT/s" && sec_ssh "$TEST_ROOT/s" && sec_fail2ban "$TEST_ROOT/s"',
                                SSH_CONNECTION="999.1.1.1 12345 203.0.113.5 49764")
        self.assert_ok(result)
        self.assertFalse(self.ssh.exists())
        self.assertFalse(self.jail.exists())
        self.assertNotIn("PACKAGE", result.stdout)

    def test_existing_active_fail2ban_is_untouched(self):
        self.change_state(lambda state: state["services"].update({"fail2ban.service": ["enabled", "active"]}))
        result = self.run_shell('sec_snapshot "$TEST_ROOT/s" && sec_fail2ban "$TEST_ROOT/s"')
        self.assert_ok(result)
        self.assertIn("保留现有", result.stdout)
        self.assertFalse(self.jail.exists())
        self.assertFalse(any(c[1] in {"start", "stop", "reload", "mask", "enable"} for c in self.state()["calls"] if c[0] == "systemctl"))

    def test_existing_inactive_fail2ban_is_not_started(self):
        result = self.run_shell('sec_snapshot "$TEST_ROOT/s" && sec_fail2ban "$TEST_ROOT/s"',
                                overrides="fail2ban-client() { return 0; }")
        self.assert_ok(result)
        self.assertIn("已安装", result.stdout)
        self.assertFalse(self.jail.exists())
        self.assertNotIn("PACKAGE", result.stdout)

    def test_new_fail2ban_stopped_before_jail_removed_on_rollback(self):
        result = self.run_shell('''
sec_snapshot "$TEST_ROOT/s" || exit 10
printf '[snell-auto-sshd]\nenabled=true\n' > "$TEST_ROOT/jail"
sec_write_file "$SNELL_SECURITY_JAIL" "$TEST_ROOT/jail" || exit 11
: > "$TEST_ROOT/s/touched.jail"
: > "$TEST_ROOT/s/touched.fail2ban"
systemctl enable --now fail2ban.service
sec_restore "$TEST_ROOT/s"
''')
        self.assert_ok(result)
        self.assertFalse(self.jail.exists())
        self.assertEqual(self.state()["services"]["fail2ban.service"], ["disabled", "inactive"])
        self.assertFalse(any(c == ["systemctl", "start", "fail2ban.service"] for c in self.state()["calls"]))

    def test_no_packages_does_not_call_package_managers(self):
        result = self.run_shell('SNELL_SECURITY_NO_PACKAGES=1; real_sec_package fail2ban',
                                overrides="apt-get() { echo PACKAGE; return 99; }")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("PACKAGE", result.stdout)

    def test_new_fail2ban_installs_journal_dependency_if_needed(self):
        result = self.run_shell('sec_install_fail2ban_packages', overrides='''
sec_package() { printf 'install:%s\n' "$1"; return 0; }
sec_journal_backend() { return 1; }
''')
        self.assert_ok(result)
        self.assertEqual(result.stdout.splitlines(), ["install:fail2ban", "install:python3-systemd"])

    def test_fail2ban_stop_failure_keeps_safe_jail(self):
        result = self.run_shell('''
sec_snapshot "$TEST_ROOT/s" || exit 10
printf '[snell-auto-sshd]\nenabled=true\n' > "$TEST_ROOT/jail"
sec_write_file "$SNELL_SECURITY_JAIL" "$TEST_ROOT/jail" || exit 11
: > "$TEST_ROOT/s/touched.jail"
: > "$TEST_ROOT/s/touched.fail2ban"
systemctl enable --now fail2ban.service
sec_restore "$TEST_ROOT/s"
''', TEST_FAIL_STOP="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(self.jail.exists())
        self.assertIn("保留 jail", result.stderr)

    def test_apt_files_use_valid_comment_prefix(self):
        result = self.run_shell('''
printf 'Unattended-Upgrade::Automatic-Reboot "false";\n' > "$TEST_ROOT/apt"
sec_write_file "$SNELL_SECURITY_APT_REBOOT" "$TEST_ROOT/apt" && sec_owned "$SNELL_SECURITY_APT_REBOOT"
''')
        self.assert_ok(result)
        self.assertTrue(self.apt_reboot.read_text().startswith("// Managed by snell-security"))

    def test_apt_missing_package_is_not_installed_implicitly(self):
        release = self.root / "etc/os-release"
        release.parent.mkdir(parents=True)
        release.write_text('ID=debian\n')
        result = self.run_shell('sec_snapshot "$TEST_ROOT/s" && sec_updates "$TEST_ROOT/s"',
                                overrides='apt-config() { "$TEST_PYTHON" "$TEST_HELPER" apt "$@"; }')
        self.assert_ok(result)
        self.assertFalse(self.apt_periodic.exists())
        self.assertNotIn("PACKAGE", result.stdout)
        self.assertIn("尚未安装", result.stderr)

    def test_apt_respects_existing_explicit_disabled_policy(self):
        release = self.root / "etc/os-release"
        release.parent.mkdir(parents=True)
        release.write_text('ID=ubuntu\n')
        result = self.run_shell('sec_snapshot "$TEST_ROOT/s" && sec_updates "$TEST_ROOT/s"',
                                overrides='apt-config() { "$TEST_PYTHON" "$TEST_HELPER" apt "$@"; }; unattended-upgrade() { return 0; }',
                                TEST_APT_VALUES=json.dumps({"APT::Periodic::Unattended-Upgrade": "0"}))
        self.assert_ok(result)
        self.assertFalse(self.apt_periodic.exists())
        self.assertIn("已有禁用策略", result.stderr)

    def test_apt_repeated_apply_and_rollback_no_immediate_upgrade(self):
        release = self.root / "etc/os-release"
        release.parent.mkdir(parents=True)
        release.write_text('ID=ubuntu\n')
        result = self.run_shell('''
sec_snapshot "$TEST_ROOT/s" || exit 10
sec_updates "$TEST_ROOT/s" || exit 11
sec_snapshot "$TEST_ROOT/t" || exit 12
sec_updates "$TEST_ROOT/t" || exit 13
[[ $(sec_apt_read APT::Periodic::Unattended-Upgrade) == 1 ]] || exit 14
[[ $(sec_apt_read Unattended-Upgrade::Automatic-Reboot) == false ]] || exit 15
sec_restore "$TEST_ROOT/s" || exit 16
[[ $(sec_apt_read Unattended-Upgrade::Automatic-Reboot) == true ]]
''', overrides='apt-config() { "$TEST_PYTHON" "$TEST_HELPER" apt "$@"; }; unattended-upgrade() { return 99; }',
                                TEST_APT_VALUES=json.dumps({"Unattended-Upgrade::Automatic-Reboot": "true"}))
        self.assert_ok(result)
        self.assertFalse(self.apt_periodic.exists())
        self.assertFalse(self.apt_reboot.exists())
        self.assertFalse(any(c[0] == "systemctl" and c[1] == "start" for c in self.state()["calls"]))

    def test_repeated_apply_preserves_first_baseline(self):
        result = self.run_shell('''
sec_apply || exit 10
sec_apply || exit 11
sec_restore "$SNELL_SECURITY_STATE/baseline"
''', overrides="""
sec_kernel_safe() { return 0; }
sec_ssh() { return 0; }
sec_fail2ban() { return 0; }
sec_updates() { return 0; }
sec_firewall() { return 0; }
""")
        self.assert_ok(result)
        self.assertEqual(self.state()["sysctl"], KEYS)
        self.assertFalse(self.kernel.exists())

    def test_preserves_user_edits_even_with_ownership_marker(self):
        result = self.run_shell('''
sec_snapshot "$TEST_ROOT/s" || exit 10
SNELL_SECURITY_TRANSACTION="$TEST_ROOT/s"
sec_sysctl "$TEST_ROOT/s" || exit 11
printf '# user edit\n' >> "$SNELL_SECURITY_SYSCTL"
sec_restore "$TEST_ROOT/s"
''', overrides="sec_kernel_safe() { return 0; }")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("user edit", self.kernel.read_text())
        self.assertEqual(self.state()["sysctl"]["fs.protected_hardlinks"], "1")
        self.assertIn("保留文件及运行状态", result.stderr)

    def test_recovers_pending_before_next_apply(self):
        result = self.run_shell('''
mkdir -p "$SNELL_SECURITY_STATE"
transaction=$(mktemp -d "$SNELL_SECURITY_STATE/transaction.XXXXXX")
sec_snapshot "$transaction" || exit 10
SNELL_SECURITY_TRANSACTION="$transaction"
sec_metadata "$SNELL_SECURITY_STATE/pending" "$transaction" || exit 11
sec_sysctl "$transaction" || exit 12
SNELL_SECURITY_TRANSACTION=''
sec_recover_pending
''', overrides="sec_kernel_safe() { return 0; }")
        self.assert_ok(result)
        self.assertFalse(self.kernel.exists())
        self.assertEqual(self.state()["sysctl"], KEYS)
        self.assertFalse((self.root / "var/lib/snell-security/pending").exists())

    def test_planned_hash_recovers_crash_before_expected_update(self):
        result = self.run_shell('''
sec_snapshot "$TEST_ROOT/s" || exit 10
SNELL_SECURITY_TRANSACTION="$TEST_ROOT/s"
sec_sysctl "$TEST_ROOT/s" || exit 11
rm -f "$SNELL_SECURITY_STATE/expected.sysctl"
sec_restore "$TEST_ROOT/s"
''', overrides="sec_kernel_safe() { return 0; }")
        self.assert_ok(result)
        self.assertFalse(self.kernel.exists())
        self.assertEqual(self.state()["sysctl"], KEYS)

    def test_status_does_not_create_state_directory(self):
        result = self.run_shell('sec_main status', overrides="sec_require_host() { return 0; }; sec_firewall() { return 0; }")
        self.assert_ok(result)
        self.assertFalse((self.root / "var/lib/snell-security").exists())

    def test_port_collection_includes_config_listeners_and_session(self):
        result = self.run_shell('''
mkdir -p "$TEST_ROOT/s"
sec_find_sshd
sec_connection && sec_collect_ports "$TEST_ROOT/s" && printf 'PORTS=%s\n' "$SNELL_SECURITY_PORTS"
''', SSH_CONNECTION="198.51.100.4 12345 203.0.113.5 49764",
                                overrides="ss() { printf '%s\\n' 'LISTEN 0 128 0.0.0.0:2222 0.0.0.0:* users:((\"sshd\",pid=99,fd=3))'; }")
        self.assert_ok(result)
        self.assertIn("PORTS=22,2222,49764", result.stdout)


    def test_sudo_recovers_ssh_connection_from_parent_session(self):
        result = self.run_shell(r"""
SNELL_SECURITY_PROC="$TEST_ROOT/proc"
mkdir -p "$SNELL_SECURITY_PROC/$$" "$SNELL_SECURITY_PROC/777"
printf 'Name:\tbash\nPPid:\t777\n' > "$SNELL_SECURITY_PROC/$$/status"
printf 'Name:\tbash\nPPid:\t1\n' > "$SNELL_SECURITY_PROC/777/status"
printf 'HOME=/root\0SSH_CONNECTION=198.51.100.4 50000 203.0.113.5 22\0' > "$SNELL_SECURITY_PROC/777/environ"
sec_inherit_ssh_connection
printf 'GOT=%s\n' "$SSH_CONNECTION"
sec_connection && printf 'CLIENT=%s\n' "$SNELL_SECURITY_CLIENT"
""", SUDO_USER="admin")
        self.assert_ok(result)
        self.assertIn("GOT=198.51.100.4 50000 203.0.113.5 22", result.stdout)
        self.assertIn("CLIENT=198.51.100.4", result.stdout)

    def test_existing_session_value_is_not_replaced(self):
        result = self.run_shell(r"""
sec_inherit_ssh_connection
printf 'GOT=%s\n' "$SSH_CONNECTION"
""", SSH_CONNECTION="192.0.2.9 1 203.0.113.5 22")
        self.assert_ok(result)
        self.assertIn("GOT=192.0.2.9 1 203.0.113.5 22", result.stdout)

    def _owned_active_jail(self, ignore):
        self.change_state(lambda state: state["services"].update({"fail2ban.service": ["enabled", "active"]}))
        self.jail.parent.mkdir(parents=True)
        body = ("[sshd]\nenabled = false\n\n[snell-auto-sshd]\nenabled = true\nport = 22\n"
                f"ignoreip = {ignore}\n")
        result = self.run_shell(r"""
printf '%s' "$BODY" > "$TEST_ROOT/plan"
sec_write_file "$SNELL_SECURITY_JAIL" "$TEST_ROOT/plan"
""", BODY=body)
        self.assert_ok(result)

    def test_owned_fail2ban_whitelist_adds_new_ssh_source(self):
        self._owned_active_jail("127.0.0.0/8 ::1 192.0.2.1")
        result = self.run_shell(
            'sec_snapshot "$TEST_ROOT/s" && sec_fail2ban "$TEST_ROOT/s"',
            overrides='fail2ban-client() { printf "F2B %s\\n" "$*" >> "$TEST_ROOT/f2b"; }',
            SSH_CONNECTION="198.51.100.4 12345 203.0.113.5 22")
        self.assert_ok(result)
        self.assertIn("ignoreip = 127.0.0.0/8 ::1 192.0.2.1 198.51.100.4\n", self.jail.read_text())
        self.assertIn("F2B reload snell-auto-sshd", (self.root / "f2b").read_text())
        self.assertTrue((self.root / "s/touched.jail").exists())

    def test_owned_fail2ban_whitelist_keeps_five_recent_sources(self):
        self._owned_active_jail("127.0.0.0/8 ::1 192.0.2.1 192.0.2.2 192.0.2.3 192.0.2.4 192.0.2.5")
        result = self.run_shell(
            'sec_snapshot "$TEST_ROOT/s" && sec_fail2ban "$TEST_ROOT/s"',
            overrides='fail2ban-client() { return 0; }',
            SSH_CONNECTION="198.51.100.4 12345 203.0.113.5 22")
        self.assert_ok(result)
        self.assertIn("ignoreip = 127.0.0.0/8 ::1 192.0.2.2 192.0.2.3 192.0.2.4 192.0.2.5 198.51.100.4\n",
                      self.jail.read_text())

    def test_owned_fail2ban_reload_failure_restores_jail(self):
        self._owned_active_jail("127.0.0.0/8 ::1 192.0.2.1")
        before = self.jail.read_text()
        result = self.run_shell(
            'sec_snapshot "$TEST_ROOT/s" && sec_fail2ban "$TEST_ROOT/s"',
            overrides='fail2ban-client() { [[ "$1" != reload ]]; }',
            SSH_CONNECTION="198.51.100.4 12345 203.0.113.5 22")
        self.assert_ok(result)
        self.assertEqual(self.jail.read_text(), before)
        self.assertIn("已恢复原 jail", result.stderr)


MOCK_SHELL = r'''
eval "$(declare -f sec_package | sed '1s/sec_package/real_sec_package/')"
# Dependency presence is a fixture, not a property of the CI runner's packages.
command() {
  if [[ "${1:-}" == -v ]]; then
    case "${2:-}" in
      fail2ban-client|unattended-upgrade) declare -F "$2" >/dev/null || return 1 ;;
    esac
  fi
  builtin command "$@"
}
sysctl() { "$TEST_PYTHON" "$TEST_HELPER" sysctl "$@"; }
systemctl() { "$TEST_PYTHON" "$TEST_HELPER" systemctl "$@"; }
mock_sshd() { "$TEST_PYTHON" "$TEST_HELPER" sshd "$@"; }
sec_find_sshd() { SNELL_SECURITY_SSHD=mock_sshd; SNELL_SECURITY_SSH_UNIT=ssh.service; }
sec_ssh_default_service() { return 0; }
sec_package() { printf 'PACKAGE %s\n' "$*"; return 99; }
'''

MOCK_PYTHON = r'''
import json, os, re, sys
from pathlib import Path
path = Path(os.environ["TEST_DATA"])
data = json.loads(path.read_text())
tool, *args = sys.argv[1:]
data["calls"].append([tool] + args)
result = 0
output = ""
if tool == "sysctl":
    if args[0] == "-n":
        output = data["sysctl"].get(args[1], "")
        result = 0 if output else 1
    elif args[:2] == ["-q", "-w"]:
        key, value = args[2].split("=", 1)
        if args[2] == os.environ.get("TEST_FAIL_SYSCTL"):
            result = 1
        else:
            data["sysctl"][key] = value
    else:
        result = 99
elif tool == "systemctl":
    unit = args[-1]
    state = data["services"].setdefault(unit, ["not-found", "inactive"])
    if args[0] == "is-active":
        result = 0 if state[1] == "active" else 3
        if "--quiet" not in args: output = state[1]
    elif args[0] == "is-enabled":
        result = 0 if state[0] in ["enabled", "enabled-runtime", "static"] else 1
        output = state[0]
    elif args[0] == "reload":
        if os.environ.get("TEST_FAIL_RELOAD_ONCE") and not data.get("failed_reload"):
            data["failed_reload"] = True
            result = 1
    elif args[0] in ["start", "stop"]:
        if args[0] == "stop" and os.environ.get("TEST_FAIL_STOP"):
            result = 1
        else:
            state[1] = "active" if args[0] == "start" else "inactive"
    elif args[0] in ["enable", "disable"]:
        state[0] = "enabled" if args[0] == "enable" else "disabled"
        if "--now" in args: state[1] = "active" if args[0] == "enable" else "inactive"
    elif args[0] not in ["mask", "unmask"]:
        result = 99
elif tool == "apt":
    values = json.loads(os.environ.get("TEST_APT_VALUES", "{}"))
    directory = Path(os.environ["TEST_ROOT"]) / "etc/apt/apt.conf.d"
    if directory.exists():
        for file in sorted(directory.iterdir()):
            for line in file.read_text().splitlines():
                match = re.fullmatch(r'([^ ]+) "([^\"]*)";', line)
                if match: values[match[1]] = match[2]
    if args[0] == "shell":
        key = args[2]
        if key in values: output = f"{args[1]}='{values[key]}'"
    elif args[0] == "dump":
        output = 'Unattended-Upgrade::Allowed-Origins:: "${distro_id}:${distro_codename}-security";'
    else: result = 99
elif tool == "sshd":
    if args[0] == "-t":
        pass
    elif args[0] == "-T":
        values = {
            "port": "22", "listenaddress": "[::]:22", "passwordauthentication": "yes",
            "pubkeyauthentication": "yes", "permitrootlogin": "prohibit-password",
            "authenticationmethods": "any", "kbdinteractiveauthentication": "no",
            "allowtcpforwarding": "yes", "clientaliveinterval": "0", "usepam": "yes",
            "permitemptypasswords": "yes", "x11forwarding": "yes",
            "logingracetime": os.environ.get("TEST_GRACE", "180"),
            "loglevel": os.environ.get("TEST_LOG", "INFO"),
        }
        file = Path(os.environ["TEST_SSH"])
        if file.exists() and not os.environ.get("TEST_IGNORE_DROPIN"):
            for line in file.read_text().splitlines():
                if line.startswith("#") or not line.strip(): continue
                key, value = line.split(None, 1)
                values[key.lower()] = value
            if os.environ.get("TEST_AUTH_CHANGE") or (os.environ.get("TEST_CONTEXT_AUTH_CHANGE") and "-C" in args):
                values["passwordauthentication"] = "no"
        output = "\n".join(f"{key} {value}" for key, value in values.items())
    else:
        result = 99
else:
    result = 99
path.write_text(json.dumps(data))
if output: print(output)
sys.exit(result)
'''


if __name__ == "__main__":
    unittest.main(verbosity=2)
