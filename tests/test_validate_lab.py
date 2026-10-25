"""Regression checks for stale/duplicate enrollment falsely passing readiness."""
import importlib.util
from datetime import datetime, timedelta, timezone
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("readiness", Path(__file__).resolve().parents[1] / "scripts/validate_lab.py")
lab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab)


class ReadinessTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 10, 25, 16, tzinfo=timezone.utc)

    def agent(self, host, trusted=True, age=0):
        return {"host": host, "trusted": trusted,
                "last_seen": (self.now - timedelta(minutes=age)).isoformat()}

    def test_duplicate_agents_do_not_replace_missing_hosts(self):
        agents = [self.agent("win-dc") for _ in range(4)]
        self.assertEqual(lab.missing_hosts(lab.live_caldera_hosts(agents, self.now)), ["win-server", "win11-victim"])

    def test_stale_and_untrusted_agents_do_not_pass(self):
        agents = [self.agent("win-dc"), self.agent("win-server", age=20), self.agent("win11-victim", trusted=False)]
        self.assertEqual(lab.missing_hosts(lab.live_caldera_hosts(agents, self.now)), ["win-server", "win11-victim"])

    def test_current_hosts_pass_regardless_of_operation_group(self):
        agents = [self.agent(h.upper() + ".lab.local") for h in lab.EXPECTED_HOSTS]
        agents[0]["group"] = "war-wagon-demo"
        self.assertEqual(lab.missing_hosts(lab.live_caldera_hosts(agents, self.now)), [])

    def test_fleet_duplicates_and_offline_members(self):
        agents = [{"status": "online", "local_metadata": {"host": {"hostname": "win-dc"}}}] * 4
        agents += [{"status": "offline", "local_metadata": {"host": {"hostname": "win-server"}}}]
        self.assertEqual(lab.missing_hosts(lab.online_fleet_hosts(agents)), ["win-server", "win11-victim"])

    def test_invalid_and_future_timestamps_fail(self):
        for stamp in (None, "invalid", "2027-01-01T00:00:00Z"):
            self.assertFalse(lab.recent(stamp, self.now))


if __name__ == "__main__":
    unittest.main()
