"""Cloud lab telemetry provenance and safe endpoint flag configuration."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]

class CloudWorkshopTests(unittest.TestCase):
    def test_tailer_emits_one_json_line_without_inventing_identity(self):
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, {'CLOUDTRAIL_LOG_DIR': folder}), patch.dict(sys.modules, {'docker': types.ModuleType('docker')}):
            spec = importlib.util.spec_from_file_location('tailer_test', ROOT/'docker/bootstrap/cloudtrail_tailer.py')
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            module.emit_event('s3', 'PutObject', 403)
            lines = next(Path(folder).glob('*.json')).read_text().splitlines()
            self.assertEqual(len(lines), 1)
            event = json.loads(lines[0])
            self.assertEqual(event['eventName'], 'PutObject')
            self.assertEqual(event['event']['outcome'], 'failure')
            self.assertTrue(event['labels']['simulated'])
            self.assertNotIn('userIdentity', event)
            self.assertNotIn('sourceIPAddress', event)

    def test_flag_validation_and_staging_command(self):
        code = "import scripts.caldera_ransomhub_setup as r; a=next(a for a in r.abilities if a['ability_id']=='rh-08-tool-stage-artifacts'); assert r.CTF_FLAG+'.txt' in a['executors'][0]['command']"
        for value, good in [('{RH_TEST_2026}', True), ('RH_TEST_2026', False), ("{x';whoami}", False), ('{../x}', False)]:
            with self.subTest(flag=value):
                result = subprocess.run([sys.executable, '-c', code], cwd=ROOT, env={**os.environ, 'RH_CTF_FLAG':value}, capture_output=True)
                self.assertEqual(result.returncode == 0, good)

if __name__ == '__main__':
    unittest.main()
