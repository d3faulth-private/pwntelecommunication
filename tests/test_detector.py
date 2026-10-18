import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('analyzer', ROOT / 'detection/analyze.py')
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)
FIX = ROOT / 'detection/fixtures'


class DetectorTests(unittest.TestCase):
    def setUp(self):
        self.policy = json.loads((FIX / 'policy.json').read_text())
        self.good = [json.loads(x) for x in (FIX / 'good.jsonl').read_text().splitlines()]

    def run_events(self, events, policy=None):
        return a.analyze(('\n'.join(json.dumps(e) for e in events)).encode(), self.policy if policy is None else policy)

    def test_good(self):
        r = self.run_events(self.good)
        self.assertEqual(r['verdict'], 'NO_ALERTS')
        self.assertFalse(r['enforcement'])
        self.assertEqual(r['unsupported_rules'], ['MAP-02'])

    def test_anomalies(self):
        r = a.analyze((FIX / 'anomalies.jsonl').read_bytes(), self.policy)
        self.assertEqual(r['alert_counts'], {'SIG-01': 1, 'SIG-02': 1, 'MAP-01': 3, 'MAP-03': 1})

    def test_tuple_not_independent_fields(self):
        self.good[1]['point_code'] = '3.3.3'
        self.good[1]['routing_context'] = 3
        self.assertEqual(self.run_events(self.good)['alert_counts'], {'SIG-02': 1})

    def test_unknown_peer_alias(self):
        self.good[0]['peer_id'] = 'unknown'
        self.assertEqual(self.run_events(self.good)['alert_counts'], {'SIG-01': 1})

    def test_map_context_mismatch(self):
        self.good[2]['application_context'] = 'wrong-context'
        self.assertEqual(self.run_events(self.good)['alert_counts'], {'MAP-01': 1})

    def test_unconfigured_policy(self):
        self.policy['map_allowed_tuples'] = []
        self.policy['rate_limit_per_peer_operation_60s'] = None
        r = self.run_events(self.good)
        self.assertEqual(r['verdict'], 'BLOCKED')
        self.assertEqual(len(r['blocked']), 2)

    def test_duplicate_not_counted(self):
        r = self.run_events(self.good + [self.good[-1]] * 5)
        self.assertEqual(r['duplicates_skipped'], 5)
        self.assertEqual(r['verdict'], 'NO_ALERTS')

    def test_reused_id_inconsistent(self):
        e = copy.deepcopy(self.good[-1]); e['destination_alias'] = 'changed'
        self.assertEqual(self.run_events(self.good + [e])['verdict'], 'INCONCLUSIVE')

    def test_window_boundary(self):
        first = self.good[-1]
        second = copy.deepcopy(first); second['event_id'] = 'second'; second['timestamp_utc'] = '2026-01-01T00:01:03Z'
        self.policy['rate_limit_per_peer_operation_60s'] = 1
        self.assertEqual(self.run_events([first, second])['verdict'], 'NO_ALERTS')
        second['timestamp_utc'] = '2026-01-01T00:01:02Z'
        self.assertEqual(self.run_events([first, second])['alert_counts'], {'MAP-03': 1})

    def test_out_of_order(self):
        self.assertEqual(self.run_events(list(reversed(self.good)))['verdict'], 'INCONCLUSIVE')

    def test_missing_field(self):
        del self.good[0]['source_ip']
        self.assertEqual(self.run_events(self.good)['verdict'], 'INCONCLUSIVE')

    def test_no_raw_sensitive_content_in_output(self):
        self.good[0]['subscriber_secret'] = 'PRIVATE_SENTINEL'
        r = self.run_events(self.good)
        self.assertEqual(r['verdict'], 'INCONCLUSIVE')
        self.assertNotIn('PRIVATE_SENTINEL', json.dumps(r))

    def test_empty_is_not_pass(self):
        self.assertEqual(self.run_events([])['verdict'], 'NOT_TESTED')

    def test_bad_policy(self):
        for value in (0, -1, True, '50'):
            self.policy['rate_limit_per_peer_operation_60s'] = value
            with self.assertRaises(ValueError):
                self.run_events(self.good)

    def test_invalid_json(self):
        r = a.analyze(b'{invalid}\n', self.policy)
        self.assertEqual(r['verdict'], 'INCONCLUSIVE')

    def test_unsupported_dialogue_event(self):
        self.good[-1]['kind'] = 'map_result'
        self.assertEqual(self.run_events(self.good)['verdict'], 'INCONCLUSIVE')

    def test_cli_permissions_hashes_exit_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / 'report.json'
            cmd = [sys.executable, str(ROOT / 'detection/analyze.py'), '--events', str(FIX / 'good.jsonl'), '--policy', str(FIX / 'policy.json'), '--output', str(out)]
            result = subprocess.run(cmd, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(out.stat().st_mode & 0o777, 0o600)
            r = json.loads(out.read_text())
            self.assertEqual(len(r['manifest']['events_sha256']), 64)
            self.assertEqual(len(r['manifest']['config_sha256']), 8)
            before = out.read_bytes()
            self.assertEqual(subprocess.run(cmd, capture_output=True).returncode, 2)
            self.assertEqual(out.read_bytes(), before)
            cmd[3] = str(FIX / 'anomalies.jsonl'); cmd[-1] = str(Path(d) / 'bad.json')
            self.assertEqual(subprocess.run(cmd, capture_output=True).returncode, 1)


class RepositoryTests(unittest.TestCase):
    def test_config_warnings_and_preserved_topology(self):
        for p in (ROOT / 'configs').glob('*/*.cfg'):
            self.assertIn('LAB-ONLY', p.read_text().splitlines()[0])
        for name in ('osmobsc', 'osmohlr'):
            self.assertEqual((ROOT / f'configs/baseline/{name}.cfg').read_bytes(), (ROOT / f'configs/hardened/{name}.cfg').read_bytes())

    def test_capture_rejects_invalid_args(self):
        for args in (['baseline','0'], ['baseline','301'], ['other'], ['baseline','-1']):
            self.assertEqual(subprocess.run(['bash', str(ROOT / 'scripts/capture.sh'), *args], capture_output=True).returncode, 2)

    def test_diff_expected_changes_not_failure(self):
        r = subprocess.run(['bash', str(ROOT / 'scripts/diff-configs.sh')], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0)
        self.assertIn('+ authentication required', r.stdout)
        self.assertIn('+  accept-asp-connections pre-configured', r.stdout)


if __name__ == '__main__':
    unittest.main()
