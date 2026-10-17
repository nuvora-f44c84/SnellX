#!/usr/bin/env python3
"""Offline tests for the pinned GitHub release bootstrap.

All network/platform/root checks are fixtures. The payload is a harmless local
script; neither a real Snell installation nor a privileged command is executed.
"""

import hashlib
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[1]
TEMPLATE = REPO / "scripts" / "snell-release-install.sh"


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="snell-bootstrap-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.bash = shutil.which("bash")
        self.assertIsNotNone(self.bash)
        self.mock_bin = self.root / "bin"
        self.mock_bin.mkdir()
        self.calls = self.root / "calls"
        self.calls.touch()
        self.run_record = self.root / "executed"
        self.payload = self.root / "fixture.sh"
        self.environment = os.environ.copy()
        for key in list(self.environment):
            if key.startswith("BASH_FUNC_") or key in ("BASH_ENV", "ENV"):
                del self.environment[key]
        self.environment.update({
            "PATH": f"{self.mock_bin}:/usr/bin:/bin:/usr/sbin:/sbin",
            "TEST_CALLS": str(self.calls),
            "TEST_PAYLOAD": str(self.payload),
            "TEST_RUN_RECORD": str(self.run_record),
            "TEST_ROOT": str(self.root),
            "TEST_OS": "Linux",
            "TEST_IS_ROOT": "1",
            "TEST_DOWNLOAD_EXIT": "0",
            "TEST_PAYLOAD_EXIT": "0",
        })
        self.mock("curl", r'''
printf 'curl' >> "$TEST_CALLS"
for arg in "$@"; do printf ' <%s>' "$arg" >> "$TEST_CALLS"; done
printf '\n' >> "$TEST_CALLS"
[ "$TEST_DOWNLOAD_EXIT" = 0 ] || exit "$TEST_DOWNLOAD_EXIT"
output=''
while [ "$#" -gt 0 ]; do
  if [ "$1" = --output ]; then output="$2"; shift; fi
  shift
done
[ -n "$output" ] || exit 96
cp "$TEST_PAYLOAD" "$output"
''')
        self.mock("uname", 'printf "uname\\n" >> "$TEST_CALLS"\nprintf "%s\\n" "$TEST_OS"\n')
        self.write_payload()

    def mock(self, name, contents):
        path = self.mock_bin / name
        path.write_text("#!/bin/sh\n" + contents, encoding="utf-8")
        path.chmod(0o755)

    def write_payload(self, contents=None):
        if contents is None:
            contents = r'''#!/usr/bin/env bash
printf 'executed\n' > "$TEST_RUN_RECORD"
printf 'argument=<%s>\n' "$@" >> "$TEST_RUN_RECORD"
if IFS= read -r line; then printf 'stdin=<%s>\n' "$line" >> "$TEST_RUN_RECORD"; fi
exit "$TEST_PAYLOAD_EXIT"
'''
        self.payload.write_text(contents, encoding="utf-8")
        self.digest = hashlib.sha256(self.payload.read_bytes()).hexdigest()

    def render(self, *, digest=None, repository="example-owner/snell-auto", tag="v1.2.3"):
        body = TEMPLATE.read_text(encoding="utf-8")
        body = body.replace("__GITHUB_REPOSITORY__", repository)
        body = body.replace("__RELEASE_TAG__", tag)
        body = body.replace("__BUNDLE_SHA256__", digest or self.digest)
        output = self.root / "install.sh"
        output.write_text(body, encoding="utf-8")
        return output

    def run_bootstrap(self, *args, digest=None, extra_setup="", source=None, stdin=""):
        script = source or self.render(digest=digest)
        # Functions permit root/platform fixtures without requiring sudo. The
        # private temporary directory is redirected into this test's own root.
        wrapper = f"source {shlex.quote(str(script))}\n" + r'''
snell_release_is_root() {
  printf 'root-check\n' >> "$TEST_CALLS"
  [[ "$TEST_IS_ROOT" == 1 ]]
}
mktemp() {
  /usr/bin/mktemp -d "$TEST_ROOT/download.XXXXXXXX"
}
''' + extra_setup + "\nsnell_release_main \"$@\"\n"
        return subprocess.run(
            [self.bash, "--noprofile", "--norc", "-c", wrapper, "bootstrap-test", *args],
            cwd=self.root, env=self.environment, input=stdin, text=True,
            capture_output=True, timeout=15,
        )

    def assert_success(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def assert_not_executed(self):
        self.assertFalse(self.run_record.exists())

    def assert_cleaned(self):
        self.assertEqual(list(self.root.glob("download.*")), [])

    def test_template_and_rendered_shell_syntax(self):
        for path in (TEMPLATE, self.render()):
            result = subprocess.run([self.bash, "-n", str(path)], capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_source_has_no_side_effects(self):
        result = subprocess.run(
            [self.bash, "--noprofile", "--norc", "-c", f"source {shlex.quote(str(TEMPLATE))}"],
            env=self.environment, capture_output=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.calls.read_text(), "")
        self.assert_not_executed()

    def test_help_on_mac_without_root_does_not_check_or_download(self):
        self.environment.update(TEST_OS="Darwin", TEST_IS_ROOT="0")
        for args in (("--help",), ("-h",), ("help",), ("install", "--help")):
            with self.subTest(args=args):
                result = self.run_bootstrap(*args, source=TEMPLATE)
                self.assert_success(result)
                self.assertIn("SHA-256", result.stdout)
                self.assertEqual(self.calls.read_text(), "")
        self.assert_not_executed()
        self.assert_cleaned()

    def test_rejects_non_linux_before_download(self):
        self.environment["TEST_OS"] = "Darwin"
        result = self.run_bootstrap()
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("curl", self.calls.read_text())
        self.assert_not_executed()

    def test_install_requires_root_before_download(self):
        self.environment["TEST_IS_ROOT"] = "0"
        for args in ((), ("install",), ("security",), ("security-status",), ("rollback-security",)):
            with self.subTest(args=args):
                result = self.run_bootstrap(*args)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("curl", self.calls.read_text())
        self.assert_not_executed()

    def test_diagnose_allows_non_root_and_preserves_arguments(self):
        self.environment["TEST_IS_ROOT"] = "0"
        result = self.run_bootstrap("diagnose", "--probe", "203.0.113.9")
        self.assert_success(result)
        self.assertNotIn("root-check", self.calls.read_text())
        self.assertEqual(self.run_record.read_text(),
                         "executed\nargument=<diagnose>\nargument=<--probe>\nargument=<203.0.113.9>\n")
        self.assert_cleaned()

    def test_empty_arguments_default_to_install_and_stdin_survives(self):
        result = self.run_bootstrap(stdin="keep my input\n")
        self.assert_success(result)
        self.assertEqual(self.run_record.read_text(),
                         "executed\nargument=<install>\nstdin=<keep my input>\n")
        self.assert_cleaned()

    def test_arguments_and_exit_status_are_preserved(self):
        self.environment["TEST_PAYLOAD_EXIT"] = "37"
        result = self.run_bootstrap("install", "--network", "off", "spaces ; $(false)", "")
        self.assertEqual(result.returncode, 37, result.stdout + result.stderr)
        self.assertEqual(self.run_record.read_text(),
                         "executed\nargument=<install>\nargument=<--network>\nargument=<off>\n"
                         "argument=<spaces ; $(false)>\nargument=<>\n")
        self.assert_cleaned()

    def test_download_is_fixed_https_release_with_no_environment_override(self):
        self.environment.update(SNELL_DOWNLOAD_URL="http://malicious.invalid/payload",
                                GITHUB_REPOSITORY="malicious/repo", RELEASE_TAG="latest")
        result = self.run_bootstrap("diagnose")
        self.assert_success(result)
        calls = self.calls.read_text()
        self.assertIn("<https://github.com/example-owner/snell-auto/releases/download/v1.2.3/snell-auto.sh>", calls)
        self.assertIn("<--proto> <=https>", calls)
        self.assertIn("<--proto-redir> <=https>", calls)
        self.assertIn("<--fail>", calls)
        self.assertNotIn("malicious", calls)
        self.assert_cleaned()

    def test_hash_mismatch_fails_closed_and_cleans(self):
        result = self.run_bootstrap(digest="0" * 64)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SHA-256 不匹配", result.stderr)
        self.assert_not_executed()
        self.assert_cleaned()

    def test_download_failure_fails_closed_and_cleans(self):
        self.environment["TEST_DOWNLOAD_EXIT"] = "22"
        result = self.run_bootstrap()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("下载失败", result.stderr)
        self.assert_not_executed()
        self.assert_cleaned()

    def test_valid_hash_with_invalid_shell_syntax_is_not_executed(self):
        self.write_payload('printf "executed" > "$TEST_RUN_RECORD"\nif then\n')
        result = self.run_bootstrap()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("语法检查失败", result.stderr)
        self.assert_not_executed()
        self.assert_cleaned()

    def test_unrendered_template_is_rejected_without_downloading(self):
        result = self.run_bootstrap(source=TEMPLATE)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("curl", self.calls.read_text())
        self.assert_not_executed()

    def test_failed_checksum_program_is_not_treated_as_a_match(self):
        result = self.run_bootstrap(extra_setup='sha256sum() { return 43; }\n')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("无法计算", result.stderr)
        self.assert_not_executed()
        self.assert_cleaned()

    def test_sha256sum_is_preferred_when_available(self):
        result = self.run_bootstrap(extra_setup=r'''
sha256sum() {
  printf 'sha256sum-selected\n' >> "$TEST_CALLS"
  /usr/bin/shasum -a 256 "$@"
}
''')
        self.assert_success(result)
        self.assertIn("sha256sum-selected", self.calls.read_text())
        self.assertTrue(self.run_record.exists())
        self.assert_cleaned()

    def test_malformed_pinned_metadata_fails_before_download(self):
        for repository, tag in (("example/repo/../../other", "v1"),
                                ("example/repo", "v1?redirect=elsewhere")):
            with self.subTest(repository=repository, tag=tag):
                result = self.run_bootstrap(source=self.render(repository=repository, tag=tag))
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("curl", self.calls.read_text())
                self.assert_not_executed()

    def test_shasum_fallback(self):
        # Override discovery only for sha256sum. Real shasum hashes the fixture.
        result = self.run_bootstrap(extra_setup=r'''
command() {
  if [[ "$#" == 2 && "$1" == -v && "$2" == sha256sum ]]; then return 1; fi
  builtin command "$@"
}
''')
        self.assert_success(result)
        self.assertTrue(self.run_record.exists())
        self.assert_cleaned()

    def test_missing_hash_tool_fails_before_download(self):
        result = self.run_bootstrap(extra_setup=r'''
command() {
  if [[ "$#" == 2 && "$1" == -v && ( "$2" == sha256sum || "$2" == shasum ) ]]; then return 1; fi
  builtin command "$@"
}
''')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("curl", self.calls.read_text())
        self.assert_not_executed()

    def test_missing_curl_fails_before_download(self):
        result = self.run_bootstrap(extra_setup=r'''
command() {
  if [[ "$#" == 2 && "$1" == -v && "$2" == curl ]]; then return 1; fi
  builtin command "$@"
}
''')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("curl", self.calls.read_text())
        self.assert_not_executed()

    def test_direct_executable_help_needs_no_fixture(self):
        result = subprocess.run([self.bash, str(TEMPLATE), "--help"],
                                env=self.environment, capture_output=True, text=True)
        self.assert_success(result)
        self.assertEqual(self.calls.read_text(), "")


if __name__ == "__main__":
    unittest.main(verbosity=2)
