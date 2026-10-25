"""Check the on-disk contract with Filebeat without connecting to Docker."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch


class CloudTrailOutputTests(unittest.TestCase):
    def test_complete_newline_delimited_records_and_error_status(self):
        source = Path(__file__).resolve().parents[1] / "docker/bootstrap/cloudtrail_tailer.py"
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict(os.environ, {"CLOUDTRAIL_LOG_DIR": directory}), patch.dict(
                sys.modules, {"docker": types.ModuleType("docker")}
            ):
                spec = importlib.util.spec_from_file_location("tailer_under_test", source)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                module.emit_event("s3", "PutObject", 200)
                module.emit_event("iam", "CreateAccessKey", 403)
            files = list(Path(directory).glob("*.json"))
            self.assertEqual(len(files), 2)
            self.assertEqual(list(Path(directory).glob("*.tmp")), [])
            records = {}
            for path in files:
                raw = path.read_bytes()
                self.assertTrue(raw.endswith(b"\n"), "Filebeat needs the final newline")
                self.assertEqual(len(raw.splitlines()), 1)
                event = json.loads(raw.splitlines()[0])
                records[event["eventName"]] = event
                self.assertIn(event["eventID"], path.name)
            self.assertNotIn("errorCode", records["PutObject"])
            self.assertEqual(records["CreateAccessKey"]["errorCode"], "HTTP_403")
            self.assertNotEqual(records["PutObject"]["eventID"], records["CreateAccessKey"]["eventID"])


if __name__ == "__main__":
    unittest.main()
