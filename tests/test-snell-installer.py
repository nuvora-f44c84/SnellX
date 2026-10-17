#!/usr/bin/env python3
"""Unprivileged, offline installer tests; works on macOS without Docker.

Only the sourced installer's pure helpers and explicitly mocked update path run.
All installer paths are relocated into TemporaryDirectory; privileged/network
commands are intercepted. This does not test a real Linux/systemd deployment.
"""

import hashlib
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
INSTALLER = REPO / "outputs" / "snell-v6.sh"
BASE_URL = "https://dl.nssurge.com/snell/"


def asset(version, arch="amd64"):
    return f"{BASE_URL}snell-server-{version}-linux-{arch}.zip"


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="snell-test-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.bash = shutil.which("bash")
        self.assertIsNotNone(self.bash, "bash is required")
        self.relocated = self.root / "installer.sh"
        source = INSTALLER.read_text(encoding="utf-8")
        # One pass avoids re-relocating paths when the temporary root is /tmp.
        # Generated unit strings are relocated as well.
        source = re.sub(r"/(?:usr/local|etc|var/lib|run|tmp)/",
                        lambda match: str(self.root) + match.group(), source)
        self.relocated.write_text(source, encoding="utf-8")
        self.bin = self.root / "usr/local/bin/snell-server"
        self.state = self.root / "var/lib/snell-server"
        self.release = self.state / "release"
        self.hash_file = self.state / "sha256"
        self.config = self.root / "etc/snell-server/snell-server.conf"
        for directory in (self.bin.parent, self.state, self.config.parent,
                          self.root / "etc/systemd/system", self.root / "tmp"):
            directory.mkdir(parents=True, exist_ok=True)
        self.calls = self.root / "calls.log"
        self.calls.touch()
        self.page = self.root / "release-page.txt"
        self.page.write_text("", encoding="utf-8")
        self.helper = self.root / "safe-helper.py"
        self.helper.write_text(SAFE_HELPER, encoding="utf-8")
        self.env = os.environ.copy()
        self.env.update({
            "TEST_ROOT": str(self.root),
            "TEST_PYTHON": sys.executable,
            "TEST_HELPER": str(self.helper),
            "TEST_CALLS": str(self.calls),
            "TEST_PAGE": str(self.page),
            "TEST_REMOTE_URL": asset("v6.0.0rc2"),
            "TEST_MAIN_PID": "42",
            "TEST_SOCKET_PID": "42",
            "TEST_SOCKET_PORT": "20992",
        })
        # Do not allow exported shell functions or startup files to affect tests.
        for name in list(self.env):
            if name.startswith("BASH_FUNC_") or name in ("BASH_ENV", "ENV"):
                del self.env[name]

    def run_bash(self, body, *, stdin=None, overrides="", env=None):
        script = (
            "set -Eeuo pipefail\n"
            + f"source {shlex.quote(str(self.relocated))}\n"
            + MOCK_COMMANDS
            + "\n" + overrides + "\n" + body
        )
        environment = self.env.copy()
        if env:
            environment.update(env)
        return subprocess.run(
            [self.bash, "--noprofile", "--norc", "-c", script],
            input=stdin, text=True, capture_output=True, cwd=self.root,
            env=environment, timeout=15,
        )

    def assert_success(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def seed_installation(self, tag="v6.0.0rc"):
        binary = b"#!/bin/sh\n# old-working-binary\nprintf 'snell-server v6.0.0\\n'\n"
        self.bin.write_bytes(binary)
        self.bin.chmod(0o755)
        self.release.write_text(tag + "\n", encoding="utf-8")
        self.hash_file.write_text(hashlib.sha256(binary).hexdigest() + "\n")
        self.config.write_text(
            "[snell-server]\nlisten = 0.0.0.0:20992,[::]:20992\n"
            "psk = unit-test-key-not-a-real-secret\nmode = default\n",
            encoding="utf-8",
        )
        (self.root / "etc/systemd/system/snell-server.service").write_text(
            "# Managed by snell-v6.sh\n[Service]\n", encoding="utf-8",
        )
        self.new_binary = self.root / "candidate-snell-server"
        self.new_binary.write_text(
            "#!/bin/sh\n# new-broken-binary\nprintf 'snell-server v6.0.0rc2\\n'\n",
            encoding="utf-8",
        )
        self.new_binary.chmod(0o755)
        self.env["TEST_NEW_BINARY"] = str(self.new_binary)
        return binary

    def test_source_does_not_run_installation(self):
        result = self.run_bash("printf 'source-only-ok\\n'")
        self.assert_success(result)
        self.assertEqual(result.stdout, "source-only-ok\n")
        self.assertEqual(self.calls.read_text(), "")
        self.assertFalse(self.bin.exists())

    def test_release_order_is_numeric_and_ignores_page_order(self):
        cases = (
            (["v6.0.0rc2", "v6.0.0rc", "v6.0.0rc10"], "v6.0.0rc10"),
            (["v6.0.0rc", "v6.0.0beta99", "v6.0.0beta"], "v6.0.0rc"),
            (["v6.0.0rc10", "v6.0.0", "v6.0.0beta99"], "v6.0.0"),
            (["v6.2.0", "v6.10.0beta2", "v6.9.99"], "v6.10.0beta2"),
            (["v6.0.9", "v6.0.10rc", "v6.0.2"], "v6.0.10rc"),
        )
        for versions, expected in cases:
            for ordered in (versions, list(reversed(versions))):
                with self.subTest(versions=ordered):
                    result = self.run_bash(
                        'select_release_url "amd64"',
                        stdin="\n".join(asset(v) for v in ordered) + "\n",
                    )
                    self.assert_success(result)
                    self.assertEqual(result.stdout.strip(), asset(expected))

    def test_version_key_rejects_unsupported_and_malformed_tags(self):
        for version in ("v5.0.1", "v7.0.0", "v6.0", "v6.0.0;id",
                        "v6.0.0rc-2", "v6.0.0preview1", "v6.1234567.0"):
            with self.subTest(version=version):
                result = self.run_bash("version_key " + shlex.quote(version))
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")

    def test_release_selection_filters_wrong_architecture_and_major(self):
        page = "\n".join((asset("v6.0.0rc2", "amd64"),
                          asset("v6.1.0", "aarch64"),
                          asset("v7.0.0", "amd64")))
        result = self.run_bash('select_release_url "amd64"', stdin=page)
        self.assert_success(result)
        self.assertEqual(result.stdout.strip(), asset("v6.0.0rc2"))

    def test_fetch_fails_if_no_supported_release_exists(self):
        for page in ("no release here", asset("v5.0.1"), asset("v6.0.0", "armv7l")):
            with self.subTest(page=page):
                self.page.write_text(page, encoding="utf-8")
                result = self.run_bash('fetch_release_url "amd64"')
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")

    def test_malicious_urls_are_not_accepted_as_release_candidates(self):
        bad_urls = (
            "http://dl.nssurge.com/snell/snell-server-v6.9.0-linux-amd64.zip",
            "https://dl.nssurge.com.evil.example/snell/snell-server-v6.9.0-linux-amd64.zip",
            "https://evil.example/?next=" + asset("v6.9.0"),
            asset("v6.9.0") + ".exe",
            asset("v6.9.0") + "/payload",
        )
        for url in bad_urls:
            with self.subTest(url=url):
                result = self.run_bash('select_release_url "amd64"', stdin=url + "\n")
                self.assertEqual(result.stdout.strip(), "", result.stdout + result.stderr)

    def test_downgrade_is_rejected_before_download(self):
        for current, remote in (("v6.0.0rc10", "v6.0.0rc2"),
                                ("v6.0.0", "v6.0.0rc10"),
                                ("v6.1.0", "v6.0.99")):
            with self.subTest(current=current, remote=remote):
                original = self.seed_installation(current)
                self.calls.write_text("")
                original_state = (self.release.read_bytes(), self.hash_file.read_bytes())
                result = self.run_bash(
                    "perform_update yes", overrides=UPDATE_MOCKS,
                    env={"TEST_REMOTE_URL": asset(remote)},
                )
                self.assert_success(result)
                self.assertEqual(self.bin.read_bytes(), original)
                self.assertEqual((self.release.read_bytes(), self.hash_file.read_bytes()),
                                 original_state)
                self.assertNotIn("download", self.calls.read_text())
                self.assertNotIn("systemctl", self.calls.read_text())

    def test_failed_new_binary_restores_binary_and_preserves_state(self):
        original = self.seed_installation()
        original_state = (self.release.read_bytes(), self.hash_file.read_bytes())
        result = self.run_bash("perform_update yes", overrides=UPDATE_MOCKS)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.bin.read_bytes(), original)
        self.assertEqual((self.release.read_bytes(), self.hash_file.read_bytes()), original_state)
        log = self.calls.read_text()
        self.assertEqual(log.count("download\n"), 1, log)
        self.assertIn("restart-new-failed", log)
        self.assertIn("restart-old-working", log)
        backups = list((self.state / "backups").glob("update-*/snell-server"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_bytes(), original)

    def test_atomic_install_failure_preserves_binary_and_does_not_use_old_stage(self):
        original = self.seed_installation()
        stale_stage = Path(str(self.bin) + ".new")
        stale_stage.write_bytes(b"stale-stage-must-never-be-installed\n")
        original_state = (self.release.read_bytes(), self.hash_file.read_bytes())
        # Run the function in a conditional, as perform_update does: this turns
        # off Bash errexit inside the function and exercises explicit checks.
        result = self.run_bash(
            'if atomic_install_binary "$TEST_NEW_BINARY"; then exit 99; fi\n'
            "printf 'atomic-failure-detected\\n'",
            overrides=r'''
install() {
  if [[ "$1" == -d ]]; then
    "$TEST_PYTHON" "$TEST_HELPER" install "$@"
    return
  fi
  local destination
  for destination; do :; done
  printf 'partial-copy\n' > "$destination"
  return 1
}
''',
        )
        self.assert_success(result)
        self.assertEqual(result.stdout, "atomic-failure-detected\n")
        self.assertEqual(self.bin.read_bytes(), original)
        self.assertEqual(stale_stage.read_bytes(), b"stale-stage-must-never-be-installed\n")
        self.assertEqual(list(self.bin.parent.glob("snell-server.new.*")), [])
        self.assertEqual((self.release.read_bytes(), self.hash_file.read_bytes()), original_state)

    def test_owned_retained_config_allows_retry_without_existing_service(self):
        original = b"[snell-server]\nlisten = 0.0.0.0:20992\npsk = retained-unit-test-key\n"
        self.config.write_bytes(original)
        (self.state / "managed-by").write_text("snell-v6.sh\n", encoding="utf-8")
        result = self.run_bash("preflight_existing", overrides=PREFLIGHT_MOCKS)
        self.assert_success(result)
        self.assertEqual(self.config.read_bytes(), original)
        self.assertFalse(self.bin.exists())

    def test_unowned_retained_config_is_rejected(self):
        original = b"[snell-server]\nlisten = 0.0.0.0:20992\npsk = third-party-test-key\n"
        self.config.write_bytes(original)
        for owner in (None, "another-installer\n"):
            with self.subTest(owner=owner):
                owner_path = self.state / "managed-by"
                if owner is not None:
                    owner_path.write_text(owner, encoding="utf-8")
                result = self.run_bash("preflight_existing", overrides=PREFLIGHT_MOCKS)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(self.config.read_bytes(), original)
                self.assertFalse(self.bin.exists())

    def test_third_party_manager_is_rejected_even_with_ownership_marker(self):
        manager = self.root / "usr/local/sbin/snell-manager"
        manager.parent.mkdir(parents=True, exist_ok=True)
        original = b"#!/bin/sh\n# unrelated manager; must not be overwritten\n"
        manager.write_bytes(original)
        manager.chmod(0o755)
        for owned in (False, True):
            with self.subTest(owned=owned):
                if owned:
                    (self.state / "managed-by").write_text("snell-v6.sh\n", encoding="utf-8")
                result = self.run_bash("preflight_existing", overrides=PREFLIGHT_MOCKS)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(manager.read_bytes(), original)
                self.assertFalse(self.bin.exists())

    def test_matching_main_pid_and_port_are_required(self):
        cases = (("42", "42", "20992", True),
                 ("42", "142", "20992", False),
                 ("42", "42", "20993", False),
                 ("0", "42", "20992", False),
                 ("unknown", "42", "20992", False))
        for main, socket, port, expected in cases:
            with self.subTest(main=main, socket=socket, port=port):
                result = self.run_bash('service_listening "20992"', env={
                    "TEST_MAIN_PID": main, "TEST_SOCKET_PID": socket,
                    "TEST_SOCKET_PORT": port,
                })
                self.assertEqual(result.returncode == 0, expected,
                                 result.stdout + result.stderr)

    def test_active_service_with_other_process_listener_fails_health_verification(self):
        self.seed_installation()
        result = self.run_bash("restart_and_verify_service", env={"TEST_SOCKET_PID": "142"})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("restart-old-working", self.calls.read_text())


    def test_stable_channel_ignores_prereleases(self):
        page = "\n".join(asset(v) for v in ("v6.0.0rc2", "v6.1.0beta1", "v6.0.1", "v6.0.0"))
        result = self.run_bash('select_release_url "amd64" stable', stdin=page)
        self.assert_success(result)
        self.assertEqual(result.stdout.strip(), asset("v6.0.1"))
        result = self.run_bash('select_release_url "amd64" stable', stdin=asset("v6.0.0rc2"))
        self.assert_success(result)
        self.assertEqual(result.stdout.strip(), "")

    def test_auto_update_skips_when_only_prereleases_exist(self):
        original = self.seed_installation("v6.0.0rc")
        self.page.write_text(asset("v6.0.0rc2") + "\n", encoding="utf-8")
        result = self.run_bash(
            "UPDATE_MODE=auto\nperform_update yes",
            overrides="detect_asset_arch() { printf 'amd64\\n'; }\n"
                      "download_and_verify_binary() { printf 'download\\n' >> \"$TEST_CALLS\"; return 1; }",
        )
        self.assert_success(result)
        self.assertEqual(self.bin.read_bytes(), original)
        self.assertNotIn("download", self.calls.read_text())
        self.assertNotIn("systemctl", self.calls.read_text())

    def test_prerelease_channel_and_manual_update_still_take_prereleases(self):
        for setup in ("UPDATE_MODE=manual", "UPDATE_MODE=auto\nprintf 'prerelease\\n' > \"$CHANNEL_STATE\""):
            with self.subTest(setup=setup):
                self.seed_installation("v6.0.0rc")
                self.calls.write_text("")
                self.page.write_text(asset("v6.0.0rc2") + "\n", encoding="utf-8")
                result = self.run_bash(
                    setup + "\nperform_update no",
                    overrides="detect_asset_arch() { printf 'amd64\\n'; }\n"
                              "download_and_verify_binary() { printf 'download\\n' >> \"$TEST_CALLS\"; "
                              "cp \"$TEST_NEW_BINARY\" \"$TMP_DIR/snell-server\"; }",
                )
                self.assert_success(result)
                self.assertIn("download", self.calls.read_text())
                self.assertEqual(self.release.read_text().strip(), "v6.0.0rc2")

    def test_elf_check_matches_architecture(self):
        def elf(machine):
            data = bytearray(64)
            data[0:4] = b"\x7fELF"
            data[18:20] = machine.to_bytes(2, "little")
            return bytes(data)
        cases = ((elf(62), "amd64", True), (elf(183), "aarch64", True), (elf(3), "i386", True),
                 (elf(183), "amd64", False), (elf(62), "aarch64", False),
                 (b"#!/bin/sh\necho snell-server v6.0.0\n", "amd64", False))
        for content, arch, expected in cases:
            with self.subTest(arch=arch, expected=expected):
                target = self.root / "candidate"
                target.write_bytes(content)
                result = self.run_bash(f'elf_matches_arch "{target}" {arch}')
                self.assertEqual(result.returncode == 0, expected, result.stderr)

    def test_generated_port_avoids_ephemeral_range(self):
        result = self.run_bash(
            "ephemeral_port_range() { printf '32768 60999\\n'; }\n"
            "port_in_use() { return 1; }\n"
            "for i in $(seq 1 300); do generate_port; done")
        self.assert_success(result)
        ports = [int(x) for x in result.stdout.split()]
        self.assertEqual(len(ports), 300)
        self.assertTrue(all(10000 <= x <= 65000 and not 32768 <= x <= 60999 for x in ports))

    def test_old_update_backups_are_pruned(self):
        backups = self.state / "backups"
        for minute in range(8):
            (backups / f"update-20261017-1200{minute}0.abc{minute}").mkdir(parents=True)
        result = self.run_bash('prune_backups "$STATE_DIR/backups" "update-*"')
        self.assert_success(result)
        remaining = sorted(path.name for path in backups.iterdir())
        self.assertEqual(remaining, [f"update-20261017-1200{m}0.abc{m}" for m in range(3, 8)])


MOCK_COMMANDS = r'''
QUIET=1
install() { "$TEST_PYTHON" "$TEST_HELPER" install "$@"; }
sha256sum() { "$TEST_PYTHON" "$TEST_HELPER" hash "$@"; }
sleep() { :; }
timeout() { shift; "$@"; }
curl() { printf 'curl\n' >> "$TEST_CALLS"; cat "$TEST_PAGE"; }
journalctl() { printf 'journalctl\n' >> "$TEST_CALLS"; }
systemctl() {
  printf 'systemctl %s\n' "$*" >> "$TEST_CALLS"
  case "$1" in
    show) printf '%s\n' "$TEST_MAIN_PID" ;;
    is-active) return 0 ;;
    restart)
      if grep -q new-broken-binary "$BIN_PATH"; then
        printf 'restart-new-failed\n' >> "$TEST_CALLS"
        return 1
      fi
      printf 'restart-old-working\n' >> "$TEST_CALLS"
      ;;
    *) printf 'BLOCKED unexpected systemctl command\n' >&2; return 97 ;;
  esac
}
ss() {
  printf 'LISTEN 0 128 0.0.0.0:%s 0.0.0.0:* users:(("snell-server",pid=%s,fd=3))\n' \
    "$TEST_SOCKET_PORT" "$TEST_SOCKET_PID"
}
apt-get() { return 97; }
dnf() { return 97; }
yum() { return 97; }
pacman() { return 97; }
zypper() { return 97; }
useradd() { return 97; }
groupadd() { return 97; }
ufw() { return 97; }
firewall-cmd() { return 97; }
sysctl() { return 97; }
'''

UPDATE_MOCKS = r'''
detect_asset_arch() { printf 'amd64\n'; }
fetch_release_url() { printf '%s\n' "$TEST_REMOTE_URL"; }
download_and_verify_binary() {
  printf 'download\n' >> "$TEST_CALLS"
  cp "$TEST_NEW_BINARY" "$TMP_DIR/snell-server"
  chmod 0755 "$TMP_DIR/snell-server"
}
'''

PREFLIGHT_MOCKS = r'''
systemctl() {
  [[ "$1" == show && "$*" == *FragmentPath* ]] || return 97
  return 0
}
pgrep() { return 1; }
'''

SAFE_HELPER = r'''
import hashlib
import os
from pathlib import Path
import shutil
import sys

root = Path(os.environ["TEST_ROOT"]).resolve()

def checked(name):
    path = Path(name).resolve()
    if path != root and root not in path.parents:
        raise SystemExit("Refusing test filesystem access outside temporary root: " + str(path))
    return path

command, *args = sys.argv[1:]
if command == "hash":
    for name in args:
        path = checked(name)
        print(hashlib.sha256(path.read_bytes()).hexdigest() + "  " + str(path))
elif command == "install":
    directories = False
    mode = 0o755
    files = []
    while args:
        arg = args.pop(0)
        if arg == "-d":
            directories = True
        elif arg in ("-o", "-g"):
            args.pop(0)  # Intentionally never chown on an unprivileged host.
        elif arg == "-m":
            mode = int(args.pop(0), 8)
        elif arg == "--":
            files.extend(args)
            break
        elif arg.startswith("-"):
            raise SystemExit("Unsupported test install option: " + arg)
        else:
            files.append(arg)
    if directories:
        for name in files:
            path = checked(name)
            path.mkdir(mode=mode, parents=True, exist_ok=True)
    else:
        if len(files) != 2:
            raise SystemExit("Expected source and destination for test install")
        source, destination = map(checked, files)
        shutil.copyfile(source, destination)
        destination.chmod(mode)
else:
    raise SystemExit("Unknown test helper operation")
'''


if __name__ == "__main__":
    unittest.main(verbosity=2)
