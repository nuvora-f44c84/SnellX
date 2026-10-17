#!/usr/bin/env python3
"""Offline, unprivileged tests of the self-contained Snell distribution.

No server connection or Linux machine is needed. The real bundle is used for
source guards, extraction and CLI checks. Conflict-check paths alone are
relocated under TemporaryDirectory; write/network commands are blocked.
These tests do not establish that Snell or sysctl work on a real Linux VPS.
"""

import hashlib
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[1]
BUNDLE = REPO / "outputs" / "snell-auto.sh"
PAYLOADS = {
    "installer": REPO / "outputs" / "snell-v6.sh",
    "menu": REPO / "outputs" / "snellx",
    "network": REPO / "outputs" / "snell-net.sh",
    "security": REPO / "outputs" / "snell-security.sh",
}
MENU_MARKER = (
    "# snellx - interactive manager for the Snell v6 installation "
    "created by snell-v6.sh"
)


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="snell-bundle-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.bash = shutil.which("bash")
        self.assertIsNotNone(self.bash, "bash is required")
        self.bin = self.root / "mock-bin"
        self.bin.mkdir()
        self.calls = self.root / "calls.log"
        self.calls.touch()
        self.env = os.environ.copy()
        for key in list(self.env):
            if key.startswith("BASH_FUNC_") or key in ("BASH_ENV", "ENV"):
                del self.env[key]
        self.env.update({
            "PATH": f"{self.bin}:/usr/bin:/bin:/usr/sbin:/sbin",
            "TEST_CALLS": str(self.calls),
            "TEST_UNAME": "Darwin",
        })
        # An accidentally reached privileged/network command fails before doing
        # any work. uname is a controlled read-only platform fixture.
        self.write_mock(
            "uname",
            'printf "uname\\n" >> "$TEST_CALLS"\n'
            'printf "%s\\n" "$TEST_UNAME"\n',
        )
        for name in (
            "mktemp", "install", "cp", "mv", "rm", "mkdir", "chmod",
            "chown", "sysctl", "systemctl", "modprobe", "curl", "wget",
            "apt", "apt-get", "dnf", "yum", "apk", "pacman", "zypper",
            "ufw", "firewall-cmd", "reboot", "shutdown", "useradd",
        ):
            self.write_mock(
                name,
                f'printf "BLOCKED {name}\\n" >> "$TEST_CALLS"\n'
                f'printf "unexpected command: {name}\\n" >&2\nexit 97\n',
            )
        self.relocated = self.root / "bundle-relocated.sh"
        original = BUNDLE.read_text(encoding="utf-8")
        # Only paths used by auto_check_tool_conflicts need relocation. One pass
        # prevents re-matching a /tmp prefix inside the temporary root itself.
        relocated = re.sub(
            r"/usr/local/",
            lambda match: str(self.root) + match.group(),
            original,
        )
        self.relocated.write_text(relocated, encoding="utf-8")
        self.sbin = self.root / "usr/local/sbin"
        self.local_bin = self.root / "usr/local/bin"
        self.sbin.mkdir(parents=True)
        self.local_bin.mkdir(parents=True)

    def write_mock(self, name, body):
        path = self.bin / name
        path.write_text("#!/bin/sh\n" + body, encoding="utf-8")
        path.chmod(0o755)

    def run_bash(self, body, *, relocated=False):
        path = self.relocated if relocated else BUNDLE
        script = f"source {shlex.quote(str(path))}\n" + body
        return subprocess.run(
            [self.bash, "--noprofile", "--norc", "-c", script],
            cwd=self.root,
            env=self.env,
            capture_output=True,
            timeout=15,
        )

    def run_cli(self, *args):
        return subprocess.run(
            [self.bash, "--noprofile", "--norc", str(BUNDLE), *args],
            cwd=self.root,
            env=self.env,
            capture_output=True,
            timeout=15,
        )

    def assert_success(self, result):
        self.assertEqual(
            result.returncode, 0,
            (result.stdout + result.stderr).decode("utf-8", errors="replace"),
        )

    def tree_snapshot(self):
        return {
            str(path.relative_to(self.root)): path.read_bytes()
            for path in self.root.rglob("*")
            if path.is_file() and path != self.calls
        }

    def test_sourcing_defines_functions_without_running_any_command(self):
        before = self.tree_snapshot()
        result = self.run_bash(
            "declare -F auto_main write_installer write_menu write_network write_security "
            "auto_check_tool_conflicts >/dev/null\n"
            "printf 'source-safe\\n'\n"
        )
        self.assert_success(result)
        self.assertEqual(result.stdout, b"source-safe\n")
        self.assertEqual(result.stderr, b"")
        self.assertEqual(self.calls.read_text(), "")
        self.assertEqual(self.tree_snapshot(), before)

    def test_embedded_payloads_are_byte_identical_to_source_files(self):
        before = self.tree_snapshot()
        for name, source in PAYLOADS.items():
            with self.subTest(payload=name):
                result = self.run_bash(f"write_{name}\n")
                self.assert_success(result)
                self.assertEqual(result.stderr, b"")
                self.assertEqual(result.stdout, source.read_bytes())
        self.assertEqual(self.calls.read_text(), "")
        self.assertEqual(self.tree_snapshot(), before)

    def test_help_works_without_linux_or_root_or_side_effects(self):
        before = self.tree_snapshot()
        for option in ("--help", "-h", "help"):
            with self.subTest(option=option):
                result = self.run_cli(option)
                self.assert_success(result)
                text = result.stdout.decode("utf-8")
                self.assertIn("Snell v6", text)
                self.assertIn("--network off", text)
                self.assertIn("rollback-network", text)
                self.assertIn("rollback-security", text)
                self.assertIn("--security off", text)
                self.assertEqual(result.stderr, b"")
        self.assertEqual(self.calls.read_text(), "")
        self.assertEqual(self.tree_snapshot(), before)

    def test_non_linux_install_stops_before_extraction_or_writes(self):
        before = self.tree_snapshot()
        for args in ((), ("install",), ("install", "--network", "off")):
            with self.subTest(args=args):
                self.calls.write_text("")
                result = self.run_cli(*args)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("当前系统不是 Linux", result.stderr.decode("utf-8"))
                self.assertEqual(result.stdout, b"")
                self.assertEqual(self.calls.read_text(), "uname\n")
                self.assertEqual(self.tree_snapshot(), before)

    def test_security_dispatch_preserves_arguments_and_exit_status(self):
        extracted = self.root / "extracted"
        extracted.mkdir()
        for command, action, extra, exit_code in (
            ("security", "apply", "--no-packages", 0),
            ("security-status", "status", "", 0),
            ("rollback-security", "rollback", "", 19),
        ):
            with self.subTest(command=command):
                result = self.run_bash(
                    "uname() { printf 'Linux\\n'; }\n"
                    f"mktemp() {{ printf '%s\\n' {shlex.quote(str(extracted))}; }}\n"
                    "rm() { :; }\n"
                    f"bash() {{ printf '%s\\n' \"$@\"; return {exit_code}; }}\n"
                    f"auto_main {command} {extra}\n"
                )
                self.assertEqual(result.returncode, exit_code, result.stderr)
                expected = [str(extracted / "snell-security"), action]
                if extra:
                    expected.append(extra)
                self.assertEqual(result.stdout.decode().splitlines(), expected)
                self.assertEqual(self.calls.read_text(), "")
                self.assertEqual(
                    (extracted / "snell-security").read_bytes(),
                    PAYLOADS["security"].read_bytes(),
                )

    def test_third_party_snellx_rejected_in_both_path_locations(self):
        for directory in (self.sbin, self.local_bin):
            with self.subTest(directory=str(directory)):
                target = directory / "snellx"
                third_party = b"#!/bin/sh\n# third party manager; do not replace\n"
                target.write_bytes(third_party)
                before = self.tree_snapshot()
                result = self.run_bash("auto_check_tool_conflicts\n", relocated=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("其他管理脚本", result.stderr.decode("utf-8"))
                self.assertIn(str(target), result.stderr.decode("utf-8"))
                self.assertEqual(target.read_bytes(), third_party)
                self.assertEqual(self.calls.read_text(), "")
                self.assertEqual(self.tree_snapshot(), before)
                target.unlink()

    def test_owned_tool_markers_pass_conflict_check_without_mutation(self):
        for directory in (self.sbin, self.local_bin):
            (directory / "snellx").write_text(MENU_MARKER + "\n", encoding="utf-8")
        (self.sbin / "snell-net").write_text(
            "# zzzz-snell-auto-network.conf\n", encoding="utf-8",
        )
        (self.sbin / "snell-auto").write_text(
            "# snell-auto: self-contained Linux Snell v6 installer\n",
            encoding="utf-8",
        )
        (self.sbin / "snell-security").write_text(
            "# Managed by snell-security\n", encoding="utf-8",
        )
        before = self.tree_snapshot()
        result = self.run_bash("auto_check_tool_conflicts\n", relocated=True)
        self.assert_success(result)
        self.assertEqual(result.stdout + result.stderr, b"")
        self.assertEqual(self.calls.read_text(), "")
        self.assertEqual(self.tree_snapshot(), before)

    def test_foreign_network_and_launcher_tools_are_not_overwritten(self):
        for name in ("snell-net", "snell-auto", "snell-security"):
            with self.subTest(tool=name):
                target = self.sbin / name
                target.write_text("# unrelated existing tool\n", encoding="utf-8")
                before = self.tree_snapshot()
                result = self.run_bash("auto_check_tool_conflicts\n", relocated=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("已存在且不是本工具", result.stderr.decode("utf-8"))
                self.assertEqual(self.tree_snapshot(), before)
                self.assertEqual(self.calls.read_text(), "")
                target.unlink()

    def test_distributable_checksum_matches_bundle(self):
        checksum = BUNDLE.with_name(BUNDLE.name + ".sha256")
        fields = checksum.read_text(encoding="utf-8").split()
        self.assertEqual(len(fields), 2)
        self.assertEqual(fields[1], BUNDLE.name)
        self.assertEqual(fields[0], hashlib.sha256(BUNDLE.read_bytes()).hexdigest())


if __name__ == "__main__":
    unittest.main(verbosity=2)
