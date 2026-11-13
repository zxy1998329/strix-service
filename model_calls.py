"""Direct model HTTP calls: reactive retry and per-task usage metrics.

There is no HTTP listener, proxy URL or proactive per-minute quota in this module.
"""
import asyncio
from collections import deque
import json
import os
from pathlib import Path
import threading
import time
import urllib.error
import urllib.request
import uuid


RATE_CODES = {429, 432, 433}
WAIT_SECONDS = 60


def rate_code(status, value=None):
    if status in RATE_CODES:
        return status
    if isinstance(value, dict):
        candidates = [value.get('code')]
        if isinstance(value.get('error'), dict):
            candidates.append(value['error'].get('code'))
        for candidate in candidates:
            if str(candidate) in ('429', '432', '433'):
                return int(candidate)
    return None


def _token_value(value):
    return value if type(value) is int and value >= 0 else None


class Metrics:
    def __init__(self, root):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()
        self.active = {}
        self.window = deque()
        self.window_input = 0
        self.window_output = 0
        self.values = dict.fromkeys((
            'total_input_tokens', 'total_output_tokens', 'peak_minute_input_tokens',
            'peak_minute_output_tokens', 'max_input_tokens', 'max_output_tokens',
            'max_concurrency', 'requests', 'rate_limit_retries', 'unknown_usage_requests'), 0)
        self._save()

    def _save(self):
        temporary = self.root / ('model_metrics.' + uuid.uuid4().hex + '.tmp')
        with temporary.open('x', encoding='utf-8') as stream:
            os.chmod(temporary, 0o600)
            json.dump(self.values, stream)
        os.replace(temporary, self.root / 'model_metrics.json')

    def start(self, input_tokens=None):
        ticket = uuid.uuid4().hex
        with self.lock:
            self.active[ticket] = (time.time(), input_tokens)
            self.values['requests'] += 1
            self.values['max_concurrency'] = max(self.values['max_concurrency'], len(self.active))
            self._save()
        return ticket

    def finish(self, ticket, response_dict=None, status=None):
        with self.lock:
            active = self.active.pop(ticket, None)
            if active is None:
                return
            now = time.time()
            started, _ = active
            limited = rate_code(status, response_dict)
            if limited:
                self.values['rate_limit_retries'] += 1
            response_dict = response_dict if isinstance(response_dict, dict) else None
            usage = (response_dict or {}).get('usage') or {}
            usage = usage if isinstance(usage, dict) else {}
            incoming = _token_value(usage.get('prompt_tokens', usage.get('input_tokens')))
            outgoing = _token_value(usage.get('completion_tokens', usage.get('output_tokens')))
            if incoming is not None:
                for key in ('cache_creation_input_tokens', 'cache_read_input_tokens'):
                    incoming += _token_value(usage.get(key)) or 0
            if incoming is None or outgoing is None:
                self.values['unknown_usage_requests'] += 1
            recorded_input = incoming or 0
            recorded_output = outgoing or 0
            self.values['total_input_tokens'] += recorded_input
            self.values['total_output_tokens'] += recorded_output
            self.values['max_input_tokens'] = max(self.values['max_input_tokens'], recorded_input)
            self.values['max_output_tokens'] = max(self.values['max_output_tokens'], recorded_output)
            self.window.append((now, recorded_input, recorded_output))
            self.window_input += recorded_input
            self.window_output += recorded_output
            while self.window and self.window[0][0] <= now-60:
                _, old_input, old_output = self.window.popleft()
                self.window_input -= old_input
                self.window_output -= old_output
            self.values['peak_minute_input_tokens'] = max(self.values['peak_minute_input_tokens'], self.window_input)
            self.values['peak_minute_output_tokens'] = max(self.values['peak_minute_output_tokens'], self.window_output)
            event = {'id':ticket, 'started':started, 'finished':now, 'status':status,
                     'input_tokens':incoming, 'output_tokens':outgoing, 'usage_known':incoming is not None and outgoing is not None,
                     'rate_limit':limited}
            event_path = self.root / 'model_calls.jsonl'
            with event_path.open('a', encoding='utf-8') as stream:
                os.chmod(event_path, 0o600)
                stream.write(json.dumps(event) + '\n')
            self._save()


def read_json(request, config, opener=None, timeout=25):
    """Direct urllib calls for the administrator's model connection test."""
    if opener is None:
        from portal import NoRedirect
        opener = urllib.request.build_opener(NoRedirect)
    while True:
        try:
            with opener.open(request, timeout=timeout) as response:
                value = json.loads(response.read(32*1024*1024+1))
            code = rate_code(200, value)
            if code is None:
                return value
        except urllib.error.HTTPError as error:
            code = rate_code(error.code)
            if code is None:
                raise
            error.close()
        print(f'[模型调用] 模型返回限流 {code}，等待 60 秒后重试。', flush=True)
        time.sleep(WAIT_SECONDS)


def _model_payload(request):
    if request.method != 'POST':
        return None
    try:
        body = json.loads(request.content)
    except (ValueError, UnicodeError, TypeError):
        return None
    if not isinstance(body, dict) or not body.get('model'):
        return None
    if not any(key in body for key in ('messages', 'input')):
        return None
    if not request.url.path.rstrip('/').endswith(('/chat/completions', '/responses', '/messages')):
        return None
    return body


def install_httpx(root, router=None, guard=None):
    """Instrument SDK clients inside the Strix process.

    Without a router requests go directly upstream as before.  With a router a
    failed primary request is retried once against the configured backup model.
    With a guard, consecutive failure streaks are counted, the job is paused at
    the configured threshold, and the call blocks until the API resumes it.
    """
    import httpx
    from model_failover import failure_reason
    metrics = Metrics(root)
    from call_details import CallDetails, sanitize
    details = CallDetails(root)
    original_async = httpx.AsyncClient.send
    original_sync = httpx.Client.send

    def model_name(request, target):
        if target and target.get('model_name'):
            return target['model_name']
        body = _model_payload(request) or {}
        return str(body.get('model') or '')

    def failure_message(value, error, status):
        if error is not None:
            text = f'{type(error).__name__}: {error}'
        elif isinstance(value, dict):
            error_value = value.get('error')
            if isinstance(error_value, dict):
                text = error_value.get('message') or error_value.get('code') or error_value.get('type') or ''
            elif isinstance(error_value, str):
                text = error_value
            else:
                text = ''
            if not text:
                text = value.get('message') or value.get('detail') or value.get('raw_text') or ''
            if not text and status:
                text = 'HTTP ' + str(status)
        else:
            text = 'HTTP ' + str(status) if status else ''
        return sanitize(str(text), details.secrets)[:800]

    def note_attempt(ticket, target, outbound, status, error_name, value, error, started):
        if guard is None:
            return
        guard.note_attempt(ticket, (target or {}).get('role', 'primary'), model_name(outbound, target),
                           status, error_name, failure_message(value, error, status), started, time.time())

    async def send_async(client, request, *args, **kwargs):
        if _model_payload(request) is None:
            return await original_async(client, request, *args, **kwargs)
        while True:
            target = None
            outbound = request
            if router is not None:
                target = router.active()
                if target and target.get('role') == 'backup':
                    try:
                        outbound = router.rewrite(request, target)
                    except Exception as rewrite_error:
                        print(f'[模型调用] 备用模型请求改写失败（{type(rewrite_error).__name__}）。', flush=True)
                        outbound = request
            started = time.time()
            ticket = metrics.start()
            value, status, response = None, None, None
            detail_handle = None
            error_name = None
            error_object = None
            failure = None
            try:
                try:
                    detail_handle = details.start(ticket, outbound, (target or {}).get('role'))
                except Exception as detail_error:
                    print(f'[模型调用] 明细记录失败（{type(detail_error).__name__}）。', flush=True)
                response = await original_async(client, outbound, *args, **kwargs)
                status = response.status_code
                await response.aread()
                try:
                    value = response.json()
                except ValueError:
                    value = {'raw_text': response.text}
                failure = failure_reason(status, value)
            except asyncio.CancelledError:
                raise
            except Exception as error:
                error_object = error
                error_name = type(error).__name__
                failure = failure_reason(None, None, error)
            finally:
                if detail_handle is not None:
                    try:
                        details.finish(detail_handle, value, status, error_name)
                    except Exception as detail_error:
                        print(f'[模型调用] 明细记录失败（{type(detail_error).__name__}）。', flush=True)
                try:
                    metrics.finish(ticket, value, status)
                except Exception as metrics_error:
                    print(f'[模型调用] 警告：调用统计写入失败（{type(metrics_error).__name__}）。', flush=True)
            if failure is None:
                if guard is not None:
                    guard.note_success()
                return response

            # The attempt failed.  Record it for the pause page, then decide.
            note_attempt(ticket, target, outbound, status, error_name, value, error_object, started)
            role = (target or {}).get('role', 'primary')
            if role == 'primary' and router is not None and router.backup:
                router.note_failure(failure)
                if response is not None:
                    await response.aclose()
                continue

            if guard is not None:
                count = guard.note_logical_failure(failure)
                if count >= guard.threshold:
                    guard.pause(f'主备模型均不可用，连续 {count} 次失败：{failure}')
                    guard.wait()
                    continue
                if response is not None:
                    await response.aclose()
                print(f'[模型调用] 连续失败 {count}/{guard.threshold} 次，等待 60 秒后重试。', flush=True)
                await asyncio.sleep(WAIT_SECONDS)
                continue

            # Legacy behavior without a pause guard: keep the original failover
            # and rate-limit retry semantics.
            if response is not None and rate_code(status, value):
                await response.aclose()
                print(f'[模型调用] 模型返回限流 {rate_code(status, value)}，等待 60 秒后重试。', flush=True)
                await asyncio.sleep(WAIT_SECONDS)
                continue
            if response is not None:
                return response
            if error_object is not None:
                raise error_object

    def send_sync(client, request, *args, **kwargs):
        if _model_payload(request) is None:
            return original_sync(client, request, *args, **kwargs)
        while True:
            target = None
            outbound = request
            if router is not None:
                target = router.active()
                if target and target.get('role') == 'backup':
                    try:
                        outbound = router.rewrite(request, target)
                    except Exception as rewrite_error:
                        print(f'[模型调用] 备用模型请求改写失败（{type(rewrite_error).__name__}）。', flush=True)
                        outbound = request
            started = time.time()
            ticket = metrics.start()
            value, status, response = None, None, None
            detail_handle = None
            error_name = None
            error_object = None
            failure = None
            try:
                try:
                    detail_handle = details.start(ticket, outbound, (target or {}).get('role'))
                except Exception as detail_error:
                    print(f'[模型调用] 明细记录失败（{type(detail_error).__name__}）。', flush=True)
                response = original_sync(client, outbound, *args, **kwargs)
                status = response.status_code
                response.read()
                try:
                    value = response.json()
                except ValueError:
                    value = {'raw_text': response.text}
                failure = failure_reason(status, value)
            except Exception as error:
                error_object = error
                error_name = type(error).__name__
                failure = failure_reason(None, None, error)
            finally:
                if detail_handle is not None:
                    try:
                        details.finish(detail_handle, value, status, error_name)
                    except Exception as detail_error:
                        print(f'[模型调用] 明细记录失败（{type(detail_error).__name__}）。', flush=True)
                try:
                    metrics.finish(ticket, value, status)
                except Exception as metrics_error:
                    print(f'[模型调用] 警告：调用统计写入失败（{type(metrics_error).__name__}）。', flush=True)
            if failure is None:
                if guard is not None:
                    guard.note_success()
                return response

            note_attempt(ticket, target, outbound, status, error_name, value, error_object, started)
            role = (target or {}).get('role', 'primary')
            if role == 'primary' and router is not None and router.backup:
                router.note_failure(failure)
                if response is not None:
                    response.close()
                continue

            if guard is not None:
                count = guard.note_logical_failure(failure)
                if count >= guard.threshold:
                    guard.pause(f'主备模型均不可用，连续 {count} 次失败：{failure}')
                    guard.wait()
                    continue
                if response is not None:
                    response.close()
                print(f'[模型调用] 连续失败 {count}/{guard.threshold} 次，等待 60 秒后重试。', flush=True)
                time.sleep(WAIT_SECONDS)
                continue

            if response is not None and rate_code(status, value):
                response.close()
                print(f'[模型调用] 模型返回限流 {rate_code(status, value)}，等待 60 秒后重试。', flush=True)
                time.sleep(WAIT_SECONDS)
                continue
            if response is not None:
                return response
            if error_object is not None:
                raise error_object

    httpx.AsyncClient.send = send_async
    httpx.Client.send = send_sync
    return metrics
