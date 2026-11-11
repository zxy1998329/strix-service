import json
import unittest
from pathlib import Path

import runtime_config
import service
import test_service


class ModelStatsTests(unittest.TestCase):
    setUp = test_service.ServiceTests.setUp
    tearDown = test_service.ServiceTests.tearDown
    zip_bytes = test_service.ServiceTests.zip_bytes
    submit = test_service.ServiceTests.submit

    def test_task_stats_are_numeric_only_and_owner_scoped(self):
        task = self.submit().json()
        path = service.job_dir(task['id']) / 'model_metrics.json'
        path.write_text(json.dumps({
            'total_input_tokens': 1234,
            'total_output_tokens': 56,
            'peak_minute_input_tokens': 1000,
            'peak_minute_output_tokens': 40,
            'max_input_tokens': 700,
            'max_output_tokens': 30,
            'max_concurrency': 3,
            'requests': 7,
            'rate_limit_retries': 2,
            'unknown_usage_requests': 1,
            'api_key': 'must-never-be-exposed',
        }))
        endpoint = '/v1/scans/' + task['id']
        response = self.client.get(endpoint, headers=self.auth)
        self.assertEqual(response.status_code, 200, response.text)
        stats = response.json()['model_metrics']
        self.assertEqual(stats['total_input_tokens'], 1234)
        self.assertEqual(stats['peak_minute_output_tokens'], 40)
        self.assertEqual(stats['max_concurrency'], 3)
        self.assertEqual(stats['rate_limit_retries'], 2)
        self.assertNotIn('must-never-be-exposed', response.text)
        self.assertEqual(self.client.get(endpoint, headers={
            'Authorization': 'Bearer ' + 'b' * 40}).status_code, 404)

        path.write_text(json.dumps({'total_input_tokens': True,
                                    'total_output_tokens': -5,
                                    'max_input_tokens': '<script>alert(1)</script>',
                                    'max_concurrency': 2.5,
                                    'requests': 4}))
        stats = self.client.get(endpoint, headers=self.auth).json()['model_metrics']
        self.assertEqual(stats, {'requests': 4})

    def test_legacy_and_missing_metrics_have_no_fabricated_peaks(self):
        task = self.submit().json()
        root = service.job_dir(task['id'])
        self.assertIsNone(service.model_metrics(root))
        run = root / 'strix_runs' / 'legacy'
        run.mkdir(parents=True)
        (run / 'run.json').write_text(json.dumps({'llm_usage': {
            'input_tokens': 500, 'output_tokens': 25, 'requests': 2}}))
        stats = service.model_metrics(root, run)
        self.assertEqual(stats, {'total_input_tokens': 500,
                                 'total_output_tokens': 25,
                                 'source': 'engine_totals'})
        self.assertNotIn('max_concurrency', stats)
        self.assertNotIn('peak_minute_input_tokens', stats)
        path = root / 'model_metrics.json'
        path.write_text('{incomplete JSON')
        self.assertEqual(service.model_metrics(root, run), stats)
        path.unlink()
        path.symlink_to(run / 'run.json')
        self.assertEqual(service.model_metrics(root, run), stats)

    def test_old_limit_settings_are_hidden_and_no_longer_configurable(self):
        value = runtime_config.defaults()
        value.update({'rate_requests': 5, 'rate_input_tokens': 400000,
                      'rate_output_tokens': 10000})
        encrypted = runtime_config.cipher().encrypt(json.dumps(value).encode()).decode()
        with service.database() as conn:
            runtime_config.tables(conn)
            conn.execute('INSERT INTO portal_settings (id, encrypted) VALUES (1, ?)', (encrypted,))
        public = runtime_config.public_settings()
        for key in ('rate_requests', 'rate_input_tokens', 'rate_output_tokens'):
            self.assertNotIn(key, public)
            self.assertNotIn(key, runtime_config.defaults())
        configured = runtime_config.save_settings({'rate_requests': 1})
        self.assertEqual(configured['rate_requests'], 5)
        paths = {getattr(route, 'path', '') for route in service.app.routes}
        self.assertNotIn('/web/admin/rate-limits', paths)
