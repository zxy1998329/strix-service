"""Offline smoke test through the real source engine and SDK, without a paid model."""
import asyncio
import json
import os
from pathlib import Path
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

os.environ.update(STRIX_LLM='openai/test-model', LLM_API_KEY='synthetic',
                  STRIX_API_TYPE='chat_completions', LLM_DISABLE_STREAMING='true',
                  LITELLM_LOCAL_MODEL_COST_MAP='True', STRIX_MODEL_RATE_RETRY='true',
                  LLM_PREFLIGHT_TIMEOUT='1', STRIX_TELEMETRY='false')
observed=[]

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        body=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        observed.append((self.path,body))
        status=[429,432,433,200][min(len(observed)-1,3)]
        value={'error':{'message':'limited','code':status}} if status!=200 else {
            'id':'chatcmpl-synthetic','object':'chat.completion','created':1,'model':'test-model',
            'choices':[{'index':0,'message':{'role':'assistant','content':'OK'},'finish_reason':'stop'}],
            'usage':{'prompt_tokens':11,'completion_tokens':1,'total_tokens':12}}
        data=json.dumps(value).encode()
        self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
    def log_message(self,*args):pass

server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
os.environ['LLM_API_BASE']=f'http://127.0.0.1:{server.server_port}/v1'

import sys
sys.path.insert(0,'/opt/strix-engine')
import model_calls
from strix.interface.scan_setup import preflight_model_connection

async def check():
    original_sleep=asyncio.sleep
    waits=[]
    async def fast_sleep(seconds,*args,**kwargs):
        if seconds==60:
            waits.append(seconds)
            return await original_sleep(0.4)
        return await original_sleep(seconds,*args,**kwargs)
    with tempfile.TemporaryDirectory() as directory:
        model_calls.install_httpx(directory)
        with patch('model_calls.asyncio.sleep',side_effect=fast_sleep):
            await preflight_model_connection('openai/test-model')
        metrics=json.loads((Path(directory)/'model_metrics.json').read_text())
        assert waits==[60,60,60],waits
        assert metrics['requests']==4,metrics
        assert metrics['rate_limit_retries']==3,metrics
        assert metrics['total_input_tokens']==11 and metrics['total_output_tokens']==1,metrics
        assert all(path=='/v1/chat/completions' for path,_ in observed),observed
        assert all(body.get('stream',False) is False for _,body in observed),observed
        print('ENGINE SDK SMOKE PASSED',json.dumps(metrics))
try:
    asyncio.run(check())
finally:
    server.shutdown();server.server_close();thread.join()
