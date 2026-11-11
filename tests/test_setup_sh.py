"""Exercise bootstrap order and failure handling without downloading or starting VMs."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        shutil.copy(ROOT / "setup.sh", self.repo / "setup.sh")
        (self.repo / "docker").mkdir()
        (self.repo / "docker/.env").write_text("ELASTIC_PASSWORD=test-only\n")
        self.bin = self.repo / "bin"
        self.bin.mkdir()
        for name in ("bash", "dirname", "grep", "curl", "cat", "tr", "cut", "date", "mkdir", "tee", "mktemp", "rm", "mv", "touch"):
            target = shutil.which(name)
            if target:
                (self.bin / name).symlink_to(target)
        self.stub("timeout", 'shift 2; exec "$@"')
        self.stub("sleep", 'exit 0')
        self.stub("uname", 'if [ "$1" = -s ]; then echo Linux; else echo "${TEST_ARCH:-x86_64}"; fi')
        self.stub("df", 'echo "Filesystem 1024-blocks Used Available Capacity Mounted"; echo "disk 900000000 0 900000000 0% /"')
        self.stub("awk", 'if [ "${2:-}" = /proc/meminfo ]; then echo 64000; else exec ' + shutil.which("awk") + ' "$@"; fi')
        self.stub("systemctl", "exit 0")
        self.stub("vmrun", "exit 0")
        self.stub("vagrant", '''echo "$*" >> calls.txt
case "$1" in
 --version) echo 'Vagrant 2.4.9';;
 plugin) printf 'other-plugin (1.0)\\nvagrant-vmware-desktop (3.0.5)\\n';;
 validate) exit 0;;
 reload) exit 0;;
 ssh) [ "${FAIL_READINESS:-}" != yes ] || exit 1;;
 up)
  if [ "$2" = "${DOWNLOAD_FAIL_VM:-}" ] && [ ! -f download-retried ]; then
   touch download-retried
   echo 'An error occurred while downloading the remote file.'
   exit 1
  fi
  if [ "$2" = "${WINRM_FAIL_VM:-}" ] && [ ! -f winrm-retried ]; then
   touch winrm-retried
   echo 'Vagrant timed out while attempting to connect via WinRM.'
   exit 1
  fi
  [ "$2" != "${FAIL_VM:-}" ] || exit 42
  if [ "$2" = docker-host ] && [ "${SKIP_ARTIFACT:-}" != yes ]; then
   echo elastic:test-only > elastic-credentials.txt
   echo token-test-only > fleet-enrollment-token.txt
  fi
  if [ "$2" = win-dc ]; then printf 'DOMAIN=lab.local\\nNETBIOS=LAB\\n' > domain-info.txt; fi
  ;;
 *) exit 91;;
esac''')
        self.env = {**os.environ, "PATH": str(self.bin)}

    def stub(self, name, body):
        path = self.bin / name
        if path.is_symlink():
            path.unlink()
        path.write_text("#!/bin/sh\n" + body + "\n")
        path.chmod(0o755)

    def run_setup(self, args=(), **env):
        result = subprocess.run(["bash", "setup.sh", *args], cwd=self.repo,
                                env={**self.env, **env}, text=True, capture_output=True)
        calls = (self.repo / "calls.txt").read_text() if (self.repo / "calls.txt").exists() else ""
        return result, calls

    def test_vmware_selected_and_dependencies_start_in_order(self):
        result, calls = self.run_setup()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([x for x in calls.splitlines() if x.startswith("up ")], [
            f"up {name} --provider vmware_desktop --provision"
            for name in ("docker-host", "win-dc", "win-server", "win11-victim")])
        self.assertIn("VM provisioning and core readiness checks passed", result.stdout)

    def test_failed_dc_stops_before_domain_members(self):
        result, calls = self.run_setup(FAIL_VM="win-dc")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("up win-server", calls)
        self.assertNotIn("up win11-victim", calls)
        self.assertEqual(calls.count("up win-dc"), 1)
        self.assertIn("exit 42", result.stderr)
        self.assertIn("bash setup.sh --from win-dc", result.stderr)

    def test_missing_shared_artifacts_stops_before_windows(self):
        result, calls = self.run_setup(SKIP_ARTIFACT="yes")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("up win-dc", calls)
        self.assertIn("did not produce", result.stderr)

    def test_unsupported_arch_stops_before_vagrant(self):
        result, calls = self.run_setup(TEST_ARCH="arm64")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls, "")

    def test_download_failure_retries_same_machine(self):
        result, calls = self.run_setup(DOWNLOAD_FAIL_VM="win11-victim")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls.count("up win11-victim"), 2)
        self.assertEqual(calls.count("up docker-host"), 1)

    def test_winrm_failure_reloads_before_retry(self):
        result, calls = self.run_setup(WINRM_FAIL_VM="win11-victim")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls.count("up win11-victim"), 2)
        self.assertEqual(calls.count("reload win11-victim"), 1)

    def test_resume_skips_completed_machines(self):
        for name in ("elastic-credentials.txt", "fleet-enrollment-token.txt", "domain-info.txt"):
            (self.repo / name).write_text("test-only")
        result, calls = self.run_setup(args=("--from", "win11-victim"))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("up docker-host", calls)
        self.assertNotIn("up win-dc", calls)
        self.assertIn("up win11-victim", calls)

    def test_failed_readiness_is_not_success(self):
        result, calls = self.run_setup(FAIL_READINESS="yes")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("core readiness checks passed", result.stdout)
        self.assertEqual(calls.count("ssh docker-host"), 5)

    def test_timeout_stops_with_resume_instruction(self):
        self.stub("timeout", "exit 124")
        result, calls = self.run_setup()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("bash setup.sh --from docker-host", result.stderr)
        self.assertNotIn("up win-dc", calls)

    def prepare_missing_vagrant(self):
        (self.bin / "vagrant").rename(self.bin / "vagrant-pending")
        self.stub("dpkg", "exit 0")
        self.stub("sudo", 'exec "$@"')
        self.stub("curl", '''while [ "$#" -gt 0 ]; do
 if [ "$1" = -o ]; then shift; printf test-package > "$1"; fi
 shift
done''')
        self.stub("sha256sum", 'cat >/dev/null; [ "${BAD_CHECKSUM:-}" != yes ]')
        self.stub("apt-get", '''echo "$*" >> install-calls.txt
[ "${FAIL_INSTALL:-}" != yes ] || exit 100
mv bin/vagrant-pending bin/vagrant''')

    def test_missing_vagrant_installed_before_build(self):
        self.prepare_missing_vagrant()
        result, calls = self.run_setup()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("vagrant_2.4.9-1_amd64.deb", (self.repo / "install-calls.txt").read_text())
        self.assertIn("up docker-host", calls)

    def test_bad_download_never_installs_or_builds(self):
        self.prepare_missing_vagrant()
        result, calls = self.run_setup(BAD_CHECKSUM="yes")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("checksum verification", result.stderr)
        self.assertFalse((self.repo / "install-calls.txt").exists())
        self.assertEqual(calls, "")

    def test_failed_vagrant_install_stops_build(self):
        self.prepare_missing_vagrant()
        result, calls = self.run_setup(FAIL_INSTALL="yes")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls, "")


if __name__ == "__main__":
    unittest.main()
