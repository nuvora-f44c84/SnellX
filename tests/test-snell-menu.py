#!/usr/bin/env python3
"""Offline menu regression tests using temporary files and mocked Linux tools.

Runs without root on macOS. Real Bash menu/config-editing code is exercised;
systemd, sockets, ownership, locks, firewall and external HTTP are simulated.
It does not verify that Linux services or firewall rules work on a live VPS.
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
MENU = REPO / "outputs" / "snellx"

MOCK_COMMANDS = r'''
require_root() { return 0; }
mock_tool() { "$TEST_PYTHON" "$TEST_HELPER" "$@"; }
systemctl() { mock_tool systemctl "$@"; }
ss() { mock_tool ss "$@"; }
chown() { mock_tool chown "$@"; }
flock() { mock_tool flock "$@"; }
curl() { mock_tool curl "$@"; }
ufw() { mock_tool ufw "$@"; }
firewall-cmd() { mock_tool firewall-cmd "$@"; }
install() { mock_tool install "$@"; }
sleep() { mock_tool sleep "$@"; }
sysctl() { mock_tool forbidden-sysctl "$@"; }
modprobe() { mock_tool forbidden-modprobe "$@"; }
'''

HELPER = r'''
import json
import os
from pathlib import Path
import re
import sys

root = Path(os.environ["TEST_ROOT"])
config = Path(os.environ["TEST_CONFIG"])
tool, *args = sys.argv[1:]
entry = {"tool": tool, "args": args}
if tool == "systemctl" and args and args[0] == "restart":
    entry["config"] = config.read_text()
with Path(os.environ["TEST_CALLS"]).open("a") as stream:
    stream.write(json.dumps(entry) + "\n")

def value(key):
    match = re.search(r"^\s*" + re.escape(key) + r"\s*=\s*(.*?)\s*$",
                      config.read_text(), re.MULTILINE)
    return match.group(1) if match else ""

if tool == "systemctl":
    action = args[0] if args else ""
    if action == "restart":
        counter = root / "restart-count"
        count = int(counter.read_text()) + 1 if counter.exists() else 1
        counter.write_text(str(count))
        if os.environ.get("TEST_FAIL_FIRST_RESTART") == "1" and count == 1:
            sys.exit(1)
        sys.exit(int(os.environ.get("TEST_RESTART_EXIT", "0")))
    if action == "is-active":
        active = os.environ.get("TEST_ACTIVE", "1") == "1"
        if "--quiet" not in args:
            print("active" if active else "failed")
        sys.exit(0 if active else 3)
    if action == "show":
        print(os.environ.get("TEST_MAIN_PID", "42"))
        sys.exit(0)
    if action == "cat":
        print("# Managed by snell-v6.sh\n[Service]\n")
        sys.exit(0)
    sys.exit(97)
elif tool == "ss":
    if os.environ.get("TEST_SS_FAIL") == "1":
        sys.exit(1)
    port = os.environ.get("TEST_SOCKET_PORT")
    if not port:
        match = re.search(r":([0-9]+)(?:,|$)", value("listen"))
        port = match.group(1) if match else "20992"
    pid = os.environ.get("TEST_SOCKET_PID", "42")
    print(f'LISTEN 0 4096 0.0.0.0:{port} 0.0.0.0:* users:(("snell-server",pid={pid},fd=5))')
    sys.exit(0)
elif tool == "ufw":
    rules_file = root / "ufw-rules.json"
    rules = json.loads(rules_file.read_text()) if rules_file.exists() else ["20992/tcp"]
    if args and args[0] == "status":
        print("Status: active\n")
        for rule in rules:
            print(f"{rule} ALLOW Anywhere")
        sys.exit(0)
    if args and args[0] == "allow":
        if os.environ.get("TEST_UFW_ALLOW_FAIL") == "1":
            sys.exit(1)
        if args[1] not in rules:
            rules.append(args[1])
        rules_file.write_text(json.dumps(rules))
        sys.exit(0)
    if len(args) > 3 and args[:3] == ["--force", "delete", "allow"]:
        rules = [rule for rule in rules if rule != args[3]]
        rules_file.write_text(json.dumps(rules))
        sys.exit(0)
    sys.exit(97)
elif tool == "install":
    # Only directory creation occurs on the exercised menu paths. Ignore
    # root ownership flags and create directories below the fixture root.
    if "-d" not in args:
        sys.exit(97)
    target = Path(args[-1])
    if not target.is_relative_to(root):
        sys.exit(97)
    target.mkdir(parents=True, exist_ok=True)
    sys.exit(0)
elif tool == "curl":
    print("198.51.100.20")
    sys.exit(0)
elif tool in ("chown", "flock", "sleep"):
    sys.exit(0)
elif tool == "firewall-cmd":
    sys.exit(1)
elif tool == "network":
    print("mock network: " + " ".join(args))
    sys.exit(int(os.environ.get("TEST_NETWORK_EXIT", "0")))
elif tool == "security":
    print("mock security: " + " ".join(args))
    sys.exit(int(os.environ.get("TEST_SECURITY_EXIT", "0")))
elif tool == "manager":
    print("mock manager: " + " ".join(args))
    sys.exit(int(os.environ.get("TEST_MANAGER_EXIT", "0")))
else:
    print("blocked unexpected tool: " + tool, file=sys.stderr)
    sys.exit(97)
'''


class MenuTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="snell-menu-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.bash = shutil.which("bash")
        self.assertIsNotNone(self.bash, "bash is required")
        self.relocated = self.root / "menu.sh"
        original = MENU.read_text(encoding="utf-8")
        relocated = re.sub(
            r"/(?:usr/local|etc|var/lib|run)/",
            lambda match: str(self.root) + match.group(),
            original,
        )
        self.relocated.write_text(relocated, encoding="utf-8")
        self.config = self.root / "etc/snell-server/snell-server.conf"
        self.state = self.root / "var/lib/snell-server"
        self.port_state = self.state / "port"
        self.network = self.root / "usr/local/sbin/snell-net"
        self.security = self.root / "usr/local/sbin/snell-security"
        self.binary = self.root / "usr/local/bin/snell-server"
        for directory in (
            self.config.parent, self.state, self.network.parent,
            self.binary.parent, self.root / "run/systemd/system",
            self.root / "run/lock",
        ):
            directory.mkdir(parents=True, exist_ok=True)
        self.original_config = (
            "# fixture only; no production secret\n"
            "[snell-server]\n"
            "listen = 0.0.0.0:20992,[::]:20992\n"
            "psk = original-unit-test-psk\n"
            "ipv6 = true\n"
        ).encode("utf-8")
        self.config.write_bytes(self.original_config)
        self.config.chmod(0o640)
        self.port_state.write_text("20992\n")
        self.binary.write_text("#!/bin/sh\nexit 0\n")
        self.binary.chmod(0o755)
        self.calls = self.root / "calls.jsonl"
        self.calls.touch()
        self.helper = self.root / "mock-helper.py"
        self.helper.write_text(HELPER, encoding="utf-8")
        self.network.write_text(
            '#!/bin/sh\nexec "$TEST_PYTHON" "$TEST_HELPER" network "$@"\n',
            encoding="utf-8",
        )
        self.network.chmod(0o755)
        self.security.write_text(
            '#!/bin/sh\nexec "$TEST_PYTHON" "$TEST_HELPER" security "$@"\n',
            encoding="utf-8",
        )
        self.security.chmod(0o755)
        self.env = os.environ.copy()
        for name in list(self.env):
            if name.startswith("BASH_FUNC_") or name in ("BASH_ENV", "ENV"):
                del self.env[name]
        self.env.update({
            "TEST_ROOT": str(self.root),
            "TEST_CONFIG": str(self.config),
            "TEST_CALLS": str(self.calls),
            "TEST_HELPER": str(self.helper),
            "TEST_PYTHON": sys.executable,
        })

    def run_bash(self, body, *, stdin=None, env=None):
        script = (
            f"source {shlex.quote(str(self.relocated))}\n"
            + MOCK_COMMANDS + "\n" + body
        )
        environment = self.env.copy()
        if env:
            environment.update(env)
        return subprocess.run(
            [self.bash, "--noprofile", "--norc", "-c", script],
            input=stdin, text=True, capture_output=True,
            cwd=self.root, env=environment, timeout=20,
        )

    def assert_success(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def events(self, tool=None):
        entries = [json.loads(line) for line in self.calls.read_text().splitlines()]
        return [item for item in entries if tool is None or item["tool"] == tool]

    def backup_files(self):
        return list(self.config.parent.glob("snell-server.conf.bak.*"))

    def test_source_guard_does_not_execute_menu_or_privileged_tools(self):
        result = self.run_bash("declare -F main change_psk change_port >/dev/null\nprintf 'sourced\\n'\n")
        self.assert_success(result)
        self.assertEqual(result.stdout, "sourced\n")
        self.assertEqual(result.stderr, "")
        self.assertEqual(self.events(), [])
        self.assertEqual(self.config.read_bytes(), self.original_config)

    def test_random_psk_generator_returns_independent_128_bit_hex_values(self):
        result = self.run_bash("generate_psk\ngenerate_psk\n")
        self.assert_success(result)
        keys = result.stdout.splitlines()
        self.assertEqual(len(keys), 2)
        for key in keys:
            self.assertRegex(key, r"^[0-9a-f]{32}$")
        self.assertNotEqual(keys[0], keys[1])
        self.assertEqual(self.events(), [])

    def test_random_psk_change_backs_up_restarts_and_verifies_owner(self):
        result = self.run_bash("main psk\n", stdin="1\ny\n")
        self.assert_success(result)
        config = self.config.read_text()
        self.assertRegex(config, r"(?m)^psk = [0-9a-f]{32}$")
        self.assertIn("listen = 0.0.0.0:20992,[::]:20992", config)
        backups = self.backup_files()
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_bytes(), self.original_config)
        self.assertEqual(self.port_state.read_text(), "20992\n")
        self.assertTrue(any(item["args"][0] == "show" for item in self.events("systemctl")))
        self.assertTrue(any("-ltnp" in item["args"] for item in self.events("ss")))
        self.assertTrue(self.events("flock"))

    def test_failed_psk_restart_restores_exact_original_and_restarts_again(self):
        result = self.run_bash(
            "main psk\n", stdin="1\ny\n", env={"TEST_FAIL_FIRST_RESTART": "1"},
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("已自动回滚", result.stderr)
        self.assertEqual(self.config.read_bytes(), self.original_config)
        self.assertEqual(self.port_state.read_text(), "20992\n")
        restarts = [event for event in self.events("systemctl") if event["args"][0] == "restart"]
        self.assertEqual(len(restarts), 2)
        self.assertNotIn("original-unit-test-psk", restarts[0]["config"])
        self.assertEqual(restarts[1]["config"].encode(), self.original_config)
        self.assertEqual(self.backup_files()[0].read_bytes(), self.original_config)

    def test_failed_port_change_restores_dual_stack_config_and_port_state(self):
        result = self.run_bash(
            "main port\n", stdin="34567\ny\n", env={"TEST_FAIL_FIRST_RESTART": "1"},
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("已恢复旧配置", result.stderr)
        self.assertEqual(self.config.read_bytes(), self.original_config)
        self.assertEqual(self.port_state.read_text(), "20992\n")
        restarts = [event for event in self.events("systemctl") if event["args"][0] == "restart"]
        self.assertEqual(len(restarts), 2)
        self.assertIn("listen = 0.0.0.0:34567,[::]:34567", restarts[0]["config"])
        self.assertEqual(restarts[1]["config"].encode(), self.original_config)
        firewall_calls = [item["args"] for item in self.events("ufw")]
        self.assertIn(["allow", "34567/tcp", "comment", "Snell v6"], firewall_calls)
        self.assertFalse(any("delete" in args for args in firewall_calls))
        self.assertIn("新端口防火墙规则已保留", result.stderr)

    def test_port_change_does_not_edit_config_if_firewall_allow_fails(self):
        result = self.run_bash(
            "main port\n", stdin="34567\ny\n", env={"TEST_UFW_ALLOW_FAIL": "1"},
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("防火墙放行失败", result.stderr)
        self.assertEqual(self.config.read_bytes(), self.original_config)
        self.assertEqual(self.port_state.read_text(), "20992\n")
        self.assertFalse(any(event["args"][0] == "restart" for event in self.events("systemctl")))

    def test_socket_must_belong_to_exact_main_pid(self):
        for main_pid, socket_pid, expected in (
            ("42", "42", 0), ("42", "99", 1), ("42", "142", 1),
            ("0", "0", 1), ("not-a-pid", "42", 1),
        ):
            with self.subTest(main_pid=main_pid, socket_pid=socket_pid):
                result = self.run_bash(
                    "port_is_listening 20992\n",
                    env={"TEST_MAIN_PID": main_pid, "TEST_SOCKET_PID": socket_pid},
                )
                self.assertEqual(result.returncode, expected, result.stdout + result.stderr)

    def test_restart_refuses_success_if_another_process_owns_port(self):
        result = self.run_bash("main restart\n", env={"TEST_SOCKET_PID": "99"})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("重启后服务未监听", result.stderr)
        self.assertNotIn("[成功]", result.stdout)
        self.assertEqual(self.config.read_bytes(), self.original_config)

    def test_network_wrapper_preserves_arguments_and_exit_status(self):
        for status in (0, 17):
            with self.subTest(status=status):
                result = self.run_bash(
                    "network_command diagnose --probe 198.51.100.1\n",
                    env={"TEST_NETWORK_EXIT": str(status)},
                )
                self.assertEqual(result.returncode, status, result.stdout + result.stderr)
                self.assertEqual(self.events("network")[-1]["args"], ["diagnose", "--probe", "198.51.100.1"])

    def test_network_cli_dispatch_and_failure_statuses(self):
        for command, expected_args, child_exit, expected_exit in (
            ("diagnose --probe 198.51.100.1", ["diagnose", "--probe", "198.51.100.1"], 0, 0),
            ("diagnose", ["diagnose"], 17, 17),
            ("rollback-network", ["rollback"], 0, 0),
            ("rollback-network", ["rollback"], 23, 23),
            ("optimize", ["apply"], 0, 0),
            ("optimize", ["apply"], 17, 1),
        ):
            with self.subTest(command=command, child_exit=child_exit):
                result = self.run_bash(
                    f"main {command}\n", env={"TEST_NETWORK_EXIT": str(child_exit)},
                )
                self.assertEqual(result.returncode, expected_exit, result.stdout + result.stderr)
                self.assertEqual(self.events("network")[-1]["args"], expected_args)
                if command == "optimize" and child_exit:
                    self.assertNotIn("网络参数已检查", result.stdout)

    def test_missing_network_module_reports_failure(self):
        self.network.unlink()
        result = self.run_bash("main diagnose\n")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("未安装网络模块", result.stderr)
        self.assertEqual(self.events("network"), [])

    def test_security_cli_dispatch_preserves_arguments_and_exit_codes(self):
        for command, expected in (
            ("security", ["apply"]),
            ("security --no-packages", ["apply", "--no-packages"]),
            ("security-status", ["status"]),
            ("rollback-security", ["rollback"]),
        ):
            for status in (0, 19):
                with self.subTest(command=command, status=status):
                    result = self.run_bash(
                        f"main {command}\n", env={"TEST_SECURITY_EXIT": str(status)},
                    )
                    self.assertEqual(result.returncode, status, result.stdout + result.stderr)
                    self.assertEqual(self.events("security")[-1]["args"], expected)
                    self.assertEqual(self.config.read_bytes(), self.original_config)

    def test_missing_security_module_reports_failure(self):
        self.security.unlink()
        result = self.run_bash("main security\n")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("未安装安全模块", result.stderr)
        self.assertEqual(self.events("security"), [])


    def test_menu_returns_to_menu_after_invalid_input(self):
        # Mismatched manual PSK, then a privileged port: both used to exit the
        # whole menu because die() calls exit inside "action || true".
        result = self.run_bash(
            "clear() { :; }\ninteractive_menu\nprintf 'MENU-STILL-RUNNING\\n'\n",
            stdin="5\n2\nabcdefghijklm\nDIFFERENT\n6\n80\n 0 \n",
        )
        self.assert_success(result)
        self.assertIn("两次输入不一致", result.stderr)
        self.assertIn("端口范围必须是", result.stderr)
        self.assertEqual(result.stderr.count("已返回菜单"), 2)
        self.assertIn("MENU-STILL-RUNNING", result.stdout)
        self.assertEqual(self.config.read_bytes(), self.original_config)
        self.assertFalse(any(e["args"][:1] == ["restart"] for e in self.events("systemctl")))

    def test_rollback_commands_work_after_snell_is_uninstalled(self):
        self.binary.unlink()
        result = self.run_bash("main rollback-network\n")
        self.assert_success(result)
        self.assertEqual(self.events("network")[-1]["args"], ["rollback"])
        result = self.run_bash("main rollback-security\n")
        self.assert_success(result)
        self.assertEqual(self.events("security")[-1]["args"], ["rollback"])
        result = self.run_bash("main status\n")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("未找到 Snell 程序", result.stderr)

    def _uninstall_fixture(self):
        manager = self.root / "usr/local/sbin/snell-manager"
        manager.write_text('#!/bin/sh\nexec "$TEST_PYTHON" "$TEST_HELPER" manager "$@"\n')
        manager.chmod(0o755)
        self.network.write_text(
            '#!/bin/sh\n# zzzz-snell-auto-network.conf\nexec "$TEST_PYTHON" "$TEST_HELPER" network "$@"\n')
        self.security.write_text(
            '#!/bin/sh\n# Managed by snell-security\nexec "$TEST_PYTHON" "$TEST_HELPER" security "$@"\n')
        (self.root / "var/lib/snell-net/baseline").mkdir(parents=True)
        (self.root / "var/lib/snell-security/baseline").mkdir(parents=True)

    def test_uninstall_rolls_back_before_removing_snell_and_tools(self):
        self._uninstall_fixture()
        result = self.run_bash("main uninstall --yes\n")
        self.assert_success(result)
        order = [e["tool"] for e in self.events() if e["tool"] in ("security", "network", "manager")]
        self.assertEqual(order, ["security", "network", "manager"])
        self.assertEqual(self.events("manager")[-1]["args"], ["uninstall"])
        self.assertFalse(self.network.exists())
        self.assertFalse(self.security.exists())
        self.assertEqual(self.config.read_bytes(), self.original_config)

    def test_uninstall_stops_when_security_rollback_fails(self):
        self._uninstall_fixture()
        result = self.run_bash("main uninstall --yes\n", env={"TEST_SECURITY_EXIT": "1"})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("已停止卸载", result.stderr)
        self.assertEqual(self.events("network"), [])
        self.assertEqual(self.events("manager"), [])
        self.assertTrue(self.network.exists())
        self.assertTrue(self.security.exists())

    def test_uninstall_requires_confirmation(self):
        self._uninstall_fixture()
        result = self.run_bash("main uninstall\n", stdin="n\n")
        self.assert_success(result)
        self.assertEqual(self.events("security") + self.events("manager"), [])

    def test_generated_port_avoids_ephemeral_range(self):
        result = self.run_bash(
            "ephemeral_port_range() { printf '32768 60999\\n'; }\n"
            "port_is_free() { return 0; }\n"
            "for i in $(seq 1 300); do generate_port; done\n")
        self.assert_success(result)
        ports = [int(x) for x in result.stdout.split()]
        self.assertEqual(len(ports), 300)
        for port in ports:
            self.assertTrue(10000 <= port <= 65000, port)
            self.assertFalse(32768 <= port <= 60999, port)


if __name__ == "__main__":
    unittest.main(verbosity=2)
