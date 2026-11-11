"""Real Strix binary + Docker sandbox, local fake model. No vulnerability or paid API test."""
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import sys

sys.path.insert(0, '/app')
import service
import worker
import runtime_config


class Model(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        payload = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        names = {item.get('function', {}).get('name') for item in payload.get('tools', [])}
        message = {'role': 'assistant', 'content': 'Local mock response, no security assessment.'}
        if 'finish_scan' in names:
            args = {key: 'Integration smoke only. No actual vulnerability assessment performed.' for key in
                    ('executive_summary', 'methodology', 'technical_analysis', 'recommendations')}
            message['content'] = None
            message['tool_calls'] = [{'id': 'call_smoke', 'type': 'function',
                'function': {'name': 'finish_scan', 'arguments': json.dumps(args)}}]
        response = {'id': 'chatcmpl-local-smoke', 'object': 'chat.completion', 'created': 1,
                    'model': payload.get('model', 'local-smoke'),
                    'choices': [{'index': 0, 'message': message, 'finish_reason': 'tool_calls' if 'tool_calls' in message else 'stop'}],
                    'usage': {'prompt_tokens': 10, 'completion_tokens': 10, 'total_tokens': 20}}
        body = json.dumps(response).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


server = ThreadingHTTPServer(('127.0.0.1', 0), Model)
threading.Thread(target=server.serve_forever, daemon=True).start()
key_file = Path('/dev/shm/strix-local-dummy-key')
key_file.write_text('dummy-integration-only-not-a-real-key')
os.environ.update(ENABLE_SCANS='true', EGRESS_POLICY_ACK='true', STRIX_LLM='openai/local-smoke',
                  LLM_API_BASE=f'http://127.0.0.1:{server.server_port}/v1', LLM_API_KEY_FILE=str(key_file),
                  SCAN_TIMEOUT_SECONDS='90', SCAN_MAX_TURNS='3')
if os.environ.get('SMOKE_WEB_CONFIG') == 'true':
    value = runtime_config.defaults()
    value.update(model='openai/local-smoke', api_base=f'http://127.0.0.1:{server.server_port}/v1',
                 api_type='chat_completions', api_key='dummy-integration-only-not-a-real-key',
                 enabled=True, timeout=90, max_turns=3)
    runtime_config.save_settings(value)
job_id = 'f' * 32
root = service.job_dir(job_id)
(root / 'source').mkdir(parents=True, exist_ok=True)
(root / 'source/app.py').write_text('print("Synthetic smoke fixture")')
service.enqueue(job_id, 'integration', 'whitebox', 'local-mock-smoke', str(root / 'source'))
job = worker.claim_job()
try:
    worker.run_job(job)
    state = service.owned_job(job_id, 'integration')
    print('Job status:', state['status'])
    print('Report generated:', (root / 'report.md').exists())
    if state['status'] != 'completed':
        print((root / 'worker.log').read_text()[-6000:])
        raise SystemExit(1)
    assert json.loads((root / 'report.json').read_text())['review_required'] is True
    print('PASS: real Strix, real Docker sandbox, local fake model, normalized report; no paid API call')
finally:
    server.shutdown()
    key_file.unlink(missing_ok=True)
