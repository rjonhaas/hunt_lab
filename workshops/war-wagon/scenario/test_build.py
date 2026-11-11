import copy
import unittest
import build

class PackageSafetyTests(unittest.TestCase):
    def setUp(self):
        self.config={'run_label':'practice-01','discovery_flag':'{WW_PRACTICE_DISCOVERY}','staging_flag':'{WW_PRACTICE_STAGING}'}

    def test_rejects_command_and_path_injection(self):
        for key, bad in [('run_label','../other'),('run_label',"x';whoami"),('discovery_flag','WW_ABC & whoami'),('staging_flag','WW_X/../../x')]:
            with self.subTest(key=key,bad=bad):
                config=dict(self.config);config[key]=bad
                with self.assertRaises(ValueError):build.build(config)

    def test_requires_one_pair_of_braces_and_safe_content(self):
        for bad in ['WW_PRACTICE_DISCOVERY', '{flag', 'flag}', '{{flag}}', '{}', '{x & whoami}', "{x';whoami}", '{../file}']:
            with self.subTest(flag=bad):
                with self.assertRaises(ValueError):
                    build.build(dict(self.config, discovery_flag=bad))
        package = build.build(dict(self.config, discovery_flag='{discovery_2026}'))
        self.assertIn('echo {discovery_2026} & whoami.exe', package['abilities'][0]['executors'][0]['command'])
        self.assertIn("'{WW_PRACTICE_STAGING}.txt'", package['abilities'][3]['executors'][0]['command'])

    def test_different_runs_cannot_overwrite_same_ids(self):
        first=build.build(self.config)
        other=dict(self.config,run_label='practice-02')
        second=build.build(other)
        a={x['ability_id'] for x in first['abilities']}
        b={x['ability_id'] for x in second['abilities']}
        self.assertFalse(a & b)
        self.assertNotEqual(first['adversary']['adversary_id'],second['adversary']['adversary_id'])

    def test_import_collision_refuses_before_any_write(self):
        pkg=build.build(self.config);calls=[];original=build.api
        def fake(url,key,method,path,body=None):
            calls.append(method)
            return pkg['abilities'] if path=='abilities' else []
        build.api=fake
        try:
            with self.assertRaises(ValueError):build.import_package(pkg,'http://example.invalid','unused')
            self.assertEqual(calls,['GET','GET'])
        finally:build.api=original

    def test_equal_flags_rejected(self):
        self.config['staging_flag']=self.config['discovery_flag']
        with self.assertRaises(ValueError):build.build(self.config)

if __name__=='__main__':unittest.main()
