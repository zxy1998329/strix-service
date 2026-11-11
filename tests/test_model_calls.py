"""Regression coverage for direct model retry and per-task usage accounting."""
import io
import json
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch

import model_calls


class ModelCallTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def snapshot(self):
        return json.loads((self.root / 'model_metrics.json').read_text())

    def test_metrics_usage_totals_peaks_and_overlapping_requests(self):
        metrics = model_calls.Metrics(self.root)
        with patch('model_calls.time.time', return_value=100):
            first = metrics.start(10)
        with patch('model_calls.time.time', return_value=101):
            second = metrics.start(20)
        with patch('model_calls.time.time', return_value=102):
            metrics.finish(first, {'usage': {'prompt_tokens': 9, 'completion_tokens': 4}})
        with patch('model_calls.time.time', return_value=103):
            metrics.finish(second, {'usage': {'input_tokens': 18, 'output_tokens': 6}})
        value = self.snapshot()
        self.assertEqual(value['total_input_tokens'], 27)
        self.assertEqual(value['total_output_tokens'], 10)
        self.assertEqual(value['max_input_tokens'], 18)
        self.assertEqual(value['max_output_tokens'], 6)
        self.assertEqual(value['peak_minute_input_tokens'], 27)
        self.assertEqual(value['peak_minute_output_tokens'], 10)
        self.assertEqual(value['max_concurrency'], 2)
        self.assertEqual(value['requests'], 2)
        self.assertEqual(value['unknown_usage_requests'], 0)

    def test_metrics_minute_peak_is_rolling_not_lifetime_total(self):
        metrics = model_calls.Metrics(self.root)
        with patch('model_calls.time.time', return_value=100):
            first = metrics.start(40)
            metrics.finish(first, {'usage': {'input_tokens': 40, 'output_tokens': 8}})
        with patch('model_calls.time.time', return_value=200):
            second = metrics.start(60)
            metrics.finish(second, {'usage': {'input_tokens': 60, 'output_tokens': 7}})
        value = self.snapshot()
        self.assertEqual(value['total_input_tokens'], 100)
        self.assertEqual(value['total_output_tokens'], 15)
        self.assertEqual(value['peak_minute_input_tokens'], 60)
        self.assertEqual(value['peak_minute_output_tokens'], 8)
        self.assertEqual(value['max_concurrency'], 1)

    def test_rate_limited_attempt_has_no_fabricated_token_charge(self):
        metrics = model_calls.Metrics(self.root)
        ticket = metrics.start(1000)
        metrics.finish(ticket, status=432)
        value = self.snapshot()
        self.assertEqual(value['requests'], 1)
        self.assertEqual(value['rate_limit_retries'], 1)
        self.assertEqual(value['total_input_tokens'], 0)
        self.assertEqual(value['total_output_tokens'], 0)

    def test_missing_usage_is_explicitly_marked_unknown(self):
        metrics = model_calls.Metrics(self.root)
        ticket = metrics.start(12)
        metrics.finish(ticket, {'choices': [{'message': {'content': ''}}]})
        value = self.snapshot()
        self.assertEqual(value['unknown_usage_requests'], 1)
        self.assertEqual(value['total_input_tokens'], 0)
        self.assertEqual(value['total_output_tokens'], 0)

    def test_direct_http_rate_limits_wait_sixty_seconds_without_retry_cap(self):
        statuses = [429, 432, 433, 429, 432]
        class Opener:
            count = 0
            def open(self, request, **kwargs):
                self.count += 1
                if self.count <= len(statuses):
                    code = statuses[self.count - 1]
                    raise urllib.error.HTTPError(request.full_url, code, 'limited', {}, io.BytesIO(b'{"error":"limited"}'))
                return io.BytesIO(b'{"choices":[],"usage":{"prompt_tokens":2,"completion_tokens":1}}')
        opener = Opener()
        request = urllib.request.Request('https://model.example/v1/chat/completions', data=b'{"messages":[{"role":"user","content":"hello"}]}')
        with patch('model_calls.time.sleep') as sleep:
            result = model_calls.read_json(request, {}, opener=opener, timeout=25)
        self.assertEqual(result['usage']['prompt_tokens'], 2)
        self.assertEqual(opener.count, 6)
        self.assertEqual(sleep.call_count, 5)
        self.assertTrue(all(call.args == (60,) for call in sleep.call_args_list))
        self.assertEqual(request.full_url, 'https://model.example/v1/chat/completions')

    def test_non_rate_limit_errors_are_not_retried(self):
        class Opener:
            def open(self, request, **kwargs):
                raise urllib.error.HTTPError(request.full_url, 401, 'invalid key', {}, io.BytesIO(b'{}'))
        request = urllib.request.Request('https://model.example/v1/chat/completions', data=b'{"messages":[]}')
        with patch('model_calls.time.sleep') as sleep:
            with self.assertRaises(urllib.error.HTTPError):
                model_calls.read_json(request, {}, opener=Opener())
        sleep.assert_not_called()

    def test_keyboard_interrupt_during_rate_limit_wait_propagates(self):
        class Opener:
            def open(self, request, **kwargs):
                raise urllib.error.HTTPError(request.full_url, 433, 'limited', {}, io.BytesIO(b'{}'))
        request = urllib.request.Request('https://model.example/v1/chat/completions', data=b'{"messages":[]}')
        with patch('model_calls.time.sleep', side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                model_calls.read_json(request, {}, opener=Opener())

class HttpxEntryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_stats_write_failure_does_not_hide_original_network_error(self):
        import httpx
        original_sync = httpx.Client.send
        original_async = httpx.AsyncClient.send
        def handler(request):
            raise httpx.ConnectError('original-network-error', request=request)
        with patch.object(httpx.Client, 'send', original_sync), patch.object(httpx.AsyncClient, 'send', original_async):
            metrics = model_calls.install_httpx(self.root)
            with patch.object(metrics, '_save', side_effect=[None, OSError('disk-full')]):
                with httpx.Client(transport=httpx.MockTransport(handler)) as client:
                    with self.assertRaisesRegex(httpx.ConnectError, 'original-network-error'):
                        client.post('https://company.example/v1/chat/completions',
                            json={'model': 'test', 'messages': [{'role': 'user', 'content': 'hi'}]})
            self.assertEqual(metrics.active, {})

    def test_sync_sdk_entry_retries_provider_limits_without_proxy(self):
        import httpx
        original_sync = httpx.Client.send
        original_async = httpx.AsyncClient.send
        seen = []
        replies = [429, 432, 433, {'code': 432}, {'error': {'code': '433'}},
                   {'choices': [{'message': {'content': 'ok'}}],
                    'usage': {'prompt_tokens': 21, 'completion_tokens': 7}}]
        def handler(request):
            seen.append(request)
            reply = replies[len(seen) - 1]
            return httpx.Response(reply if isinstance(reply, int) else 200,
                                  json={'error': 'limited'} if isinstance(reply, int) else reply)
        with patch.object(httpx.Client, 'send', original_sync), patch.object(httpx.AsyncClient, 'send', original_async):
            model_calls.install_httpx(self.root)
            with patch('model_calls.time.sleep') as sleep:
                with httpx.Client(transport=httpx.MockTransport(handler)) as client:
                    response = client.post('https://company.example/llm/test/v1/chat/completions',
                        headers={'Authorization': 'Bearer upstream-company-key', 'X-Session-Id': 'session-123'},
                        json={'model': 'test', 'stream': False,
                              'messages': [{'role': 'user', 'content': 'hello'}]})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(sleep.call_count, 5)
            self.assertTrue(all(call.args == (60,) for call in sleep.call_args_list))
        self.assertEqual(httpx.Client.send, original_sync)
        self.assertEqual(httpx.AsyncClient.send, original_async)
        self.assertEqual(len(seen), 6)
        for request in seen:
            self.assertEqual(str(request.url), 'https://company.example/llm/test/v1/chat/completions')
            self.assertEqual(request.headers['Authorization'], 'Bearer upstream-company-key')
            self.assertEqual(request.headers['X-Session-Id'], 'session-123')
            body = json.loads(request.content)
            self.assertFalse(body['stream'])
            self.assertNotIn('stream_options', body)
        value = json.loads((self.root / 'model_metrics.json').read_text())
        self.assertEqual(value['requests'], 6)
        self.assertEqual(value['rate_limit_retries'], 5)
        self.assertEqual(value['total_input_tokens'], 21)
        self.assertEqual(value['total_output_tokens'], 7)
        self.assertEqual(value['max_concurrency'], 1)



class AsyncHttpxEntryTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    async def test_async_sdk_entry_retries_all_provider_rate_codes(self):
        import httpx
        from unittest.mock import AsyncMock
        original_sync = httpx.Client.send
        original_async = httpx.AsyncClient.send
        seen = []
        replies = [429, 432, 433, {'code': '432'},
                   {'usage': {'input_tokens': 13, 'output_tokens': 5}, 'content': []}]
        async def handler(request):
            seen.append(request)
            reply = replies[len(seen) - 1]
            return httpx.Response(reply if isinstance(reply, int) else 200,
                                  json={'error': 'limited'} if isinstance(reply, int) else reply)
        with patch.object(httpx.Client, 'send', original_sync), patch.object(httpx.AsyncClient, 'send', original_async):
            model_calls.install_httpx(self.root)
            with patch('model_calls.asyncio.sleep', new_callable=AsyncMock) as sleep:
                async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                    response = await client.post('https://company.example/llm/test/v1/messages',
                        headers={'x-api-key': 'actual-key', 'anthropic-version': '2023-06-01'},
                        json={'model': 'test', 'messages': [{'role': 'user', 'content': 'hello'}], 'stream': False})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(sleep.await_count, 4)
            self.assertTrue(all(call.args == (60,) for call in sleep.call_args_list))
        self.assertEqual(httpx.Client.send, original_sync)
        self.assertEqual(httpx.AsyncClient.send, original_async)
        for request in seen:
            self.assertEqual(str(request.url), 'https://company.example/llm/test/v1/messages')
            self.assertEqual(request.headers['x-api-key'], 'actual-key')
            self.assertFalse(json.loads(request.content)['stream'])
        value = json.loads((self.root / 'model_metrics.json').read_text())
        self.assertEqual(value['requests'], 5)
        self.assertEqual(value['rate_limit_retries'], 4)
        self.assertEqual(value['total_input_tokens'], 13)
        self.assertEqual(value['total_output_tokens'], 5)

    async def test_overlapping_sdk_requests_measure_actual_max_concurrency(self):
        import asyncio
        import httpx
        original_sync = httpx.Client.send
        original_async = httpx.AsyncClient.send
        ready = asyncio.Event()
        entered = 0
        async def handler(request):
            nonlocal entered
            entered += 1
            if entered == 2:
                ready.set()
            await ready.wait()
            return httpx.Response(200, json={'usage': {'prompt_tokens': 10, 'completion_tokens': 3}})
        with patch.object(httpx.Client, 'send', original_sync), patch.object(httpx.AsyncClient, 'send', original_async):
            metrics = model_calls.install_httpx(self.root)
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                body = {'model': 'test', 'messages': [{'role': 'user', 'content': 'hi'}]}
                responses = await asyncio.wait_for(asyncio.gather(
                    client.post('https://company.example/v1/chat/completions', json=body),
                    client.post('https://company.example/v1/chat/completions', json=body)), timeout=5)
            self.assertTrue(all(response.status_code == 200 for response in responses))
            self.assertEqual(metrics.active, {})
        value = json.loads((self.root / 'model_metrics.json').read_text())
        self.assertEqual(value['requests'], 2)
        self.assertEqual(value['max_concurrency'], 2)
        self.assertEqual(value['total_input_tokens'], 20)
        self.assertEqual(value['total_output_tokens'], 6)

    async def test_cancelled_sdk_call_releases_active_measurement(self):
        import asyncio
        import httpx
        original_sync = httpx.Client.send
        original_async = httpx.AsyncClient.send
        async def handler(request):
            raise asyncio.CancelledError()
        with patch.object(httpx.Client, 'send', original_sync), patch.object(httpx.AsyncClient, 'send', original_async):
            metrics = model_calls.install_httpx(self.root)
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                with self.assertRaises(asyncio.CancelledError):
                    await client.post('https://company.example/v1/chat/completions',
                        json={'model': 'test', 'messages': [{'role': 'user', 'content': 'hi'}]})
            self.assertEqual(metrics.active, {})
        value = json.loads((self.root / 'model_metrics.json').read_text())
        self.assertEqual(value['requests'], 1)
        self.assertEqual(value['total_input_tokens'], 0)
        self.assertEqual(value['total_output_tokens'], 0)

    async def test_cancellation_during_backoff_does_not_issue_another_attempt(self):
        import asyncio
        import httpx
        from unittest.mock import AsyncMock
        original_sync = httpx.Client.send
        original_async = httpx.AsyncClient.send
        calls = 0
        async def handler(request):
            nonlocal calls
            calls += 1
            return httpx.Response(432, json={'error': 'limited'})
        with patch.object(httpx.Client, 'send', original_sync), patch.object(httpx.AsyncClient, 'send', original_async):
            metrics = model_calls.install_httpx(self.root)
            with patch('model_calls.asyncio.sleep', new_callable=AsyncMock, side_effect=asyncio.CancelledError):
                async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                    with self.assertRaises(asyncio.CancelledError):
                        await client.post('https://company.example/v1/chat/completions',
                            json={'model': 'test', 'messages': [{'role': 'user', 'content': 'hi'}]})
            self.assertEqual(metrics.active, {})
        self.assertEqual(calls, 1)
        value = json.loads((self.root / 'model_metrics.json').read_text())
        self.assertEqual(value['requests'], 1)
        self.assertEqual(value['rate_limit_retries'], 1)
