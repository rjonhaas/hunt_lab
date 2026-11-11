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
 up)
  [ "$2" != "${FAIL_VM:-}" ] || exit 42
  if [ "$2" = docker-host ] && [ "${SKIP_ARTIFACT:-}" != yes ]; then
   echo elastic:test-only > elastic-credentials.txt
   echo token-test-only > fleet-enrollment-token.txt
  fi
  if [ "$2" = win-dc ]; then printf 'DOMAIN=lab.local\\nNETBIOS=LAB\\n' > domain-info.txt; fi
  ;;
 *) exit 91;;
esac''')
        self.env = {**os.environ, "PATH": str(self.bin) + os.pathsep + os.environ["PATH"]}

    def stub(self, name, body):
        path = self.bin / name
        path.write_text("#!/bin/sh\n" + body + "\n")
        path.chmod(0o755)

    def run_setup(self, **env):
        result = subprocess.run(["bash", "setup.sh"], cwd=self.repo,
                                env={**self.env, **env}, text=True, capture_output=True)
        calls = (self.repo / "calls.txt").read_text() if (self.repo / "calls.txt").exists() else ""
        return result, calls

    def test_vmware_selected_and_dependencies_start_in_order(self):
        result, calls = self.run_setup()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([x for x in calls.splitlines() if x.startswith("up ")], [
            f"up {name} --provider vmware_desktop --provision"
            for name in ("docker-host", "win-dc", "win-server", "win11-victim")])
        self.assertIn("VM provisioning finished", result.stdout)

    def test_failed_dc_stops_before_domain_members(self):
        result, calls = self.run_setup(FAIL_VM="win-dc")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("up win-server", calls)
        self.assertNotIn("up win11-victim", calls)

    def test_missing_shared_artifacts_stops_before_windows(self):
        result, calls = self.run_setup(SKIP_ARTIFACT="yes")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("up win-dc", calls)
        self.assertIn("did not produce", result.stderr)

    def test_unsupported_arch_stops_before_vagrant(self):
        result, calls = self.run_setup(TEST_ARCH="arm64")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls, "")

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
