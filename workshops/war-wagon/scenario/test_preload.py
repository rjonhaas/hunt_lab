import copy
import json
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch
import build
import preload

class PreloadTests(unittest.TestCase):
    def setUp(self):
        self.package = build.build({'run_label':'test-01', 'discovery_flag':'{WW_PRACTICE_DISCOVERY}', 'staging_flag':'{WW_PRACTICE_STAGING}'})
        self.state = {'abilities':{}, 'adversaries':{}}
        self.posts = []

    def api(self, url, key, method, path, body=None):
        kind, _, ident = path.partition('/')
        self.assertIn(kind, self.state, 'Preload must never access operation endpoints')
        if method == 'GET':
            return copy.deepcopy(self.state[kind][ident] if ident else list(self.state[kind].values()))
        self.assertEqual(method, 'POST')
        id_key = 'ability_id' if kind == 'abilities' else 'adversary_id'
        self.state[kind][body[id_key]] = copy.deepcopy(body)
        self.posts.append(kind)
        return body

    def run_preload(self):
        with patch.object(preload, 'api', self.api):
            preload.ensure_package(self.package, 'http://example.invalid', 'unused')

    def test_private_config_overrides_practice(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(preload, 'ROOT', root):
                self.assertEqual(preload.configuration()['run_label'], 'practice-01')
                (root / '.war-wagon').mkdir()
                config = {'run_label':'conference-01', 'discovery_flag':'{WW_TEST_DISCOVERY}', 'staging_flag':'{WW_TEST_STAGING}'}
                (root / '.war-wagon/config.json').write_text(json.dumps(config), encoding='utf-8-sig')
                self.assertEqual(preload.configuration(), config)
                (root / '.war-wagon/config.json').write_text('invalid json')
                with self.assertRaises(ValueError):preload.configuration()

    def test_first_run_and_idempotent_rerun(self):
        self.run_preload()
        self.assertEqual(self.posts, ['abilities'] * 4 + ['adversaries'])
        self.posts.clear()
        self.run_preload()
        self.assertEqual(self.posts, [])

    def test_partial_import_resumes(self):
        ability = self.package['abilities'][0]
        self.state['abilities'][ability['ability_id']] = copy.deepcopy(ability)
        self.run_preload()
        self.assertEqual(self.posts, ['abilities'] * 3 + ['adversaries'])

    def test_changed_command_stops_before_writes(self):
        ability = copy.deepcopy(self.package['abilities'][-1])
        ability['executors'][0]['command'] = 'different command'
        self.state['abilities'][ability['ability_id']] = ability
        with self.assertRaises(RuntimeError):self.run_preload()
        self.assertEqual(self.posts, [])

    def test_reordered_profile_stops_before_writes(self):
        adv = copy.deepcopy(self.package['adversary'])
        adv['atomic_ordering'].reverse()
        self.state['adversaries'][adv['adversary_id']] = adv
        with self.assertRaises(RuntimeError):self.run_preload()
        self.assertEqual(self.posts, [])

    def test_readback_mismatch_is_failure(self):
        def altered(*args, **kwargs):
            obj = self.api(*args, **kwargs)
            if args[2] == 'GET' and args[3].startswith('abilities/'):
                obj['executors'][0]['command'] = 'different'
            return obj
        with patch.object(preload, 'api', altered):
            with self.assertRaises(RuntimeError):
                preload.ensure_package(self.package, 'http://example.invalid', 'unused')
        self.assertNotIn('adversaries', self.posts)

if __name__ == '__main__':unittest.main()
