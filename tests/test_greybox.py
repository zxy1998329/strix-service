import json
import socket
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import patch
import test_service
import service
import greybox
import runtime_config
import worker
import os


class GreyboxTests(test_service.unittest.TestCase):
    setUp=test_service.ServiceTests.setUp
    tearDown=test_service.ServiceTests.tearDown

    def payload(self):
        return {'name':'grey','target':'https://test.company/','authorized':True,
                'accounts':[{'label':'A','method':'bearer','token':'synthetic-secret','verify_path':'/me'}]}

    def test_encryption_validation_ownership_and_redaction(self):
        with patch('socket.getaddrinfo',return_value=[(socket.AF_INET,socket.SOCK_STREAM,6,'',('10.20.30.40',443))]):
            response=self.client.post('/v1/scans/greybox',headers=self.auth,json=self.payload())
        self.assertEqual(response.status_code,202,response.text)
        job_id=response.json()['id'];root=service.job_dir(job_id)
        self.assertNotIn(b'synthetic-secret',(root/'auth.enc').read_bytes())
        self.assertEqual(greybox.load(root)['accounts'][0]['token'],'synthetic-secret')
        service.update_job(job_id,'running',{'reason':'echo synthetic-secret'})
        result=self.client.get('/v1/scans/'+job_id,headers=self.auth)
        self.assertNotIn('synthetic-secret',result.text)
        self.assertEqual(self.client.get('/v1/scans/'+job_id,headers={'Authorization':'Bearer '+'b'*40}).status_code,404)
        payload=self.payload();payload['accounts'][0]['verify_path']='//other.example/'
        with patch('socket.getaddrinfo',return_value=[(socket.AF_INET,socket.SOCK_STREAM,6,'',('10.20.30.40',443))]):
            self.assertEqual(self.client.post('/v1/scans/greybox',headers=self.auth,json=payload).status_code,400)

    def test_http_200_and_header_injection_without_success_condition(self):
        observed=[]
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                observed.append((self.headers.get('Authorization'),self.headers.get('Cookie')))
                self.send_response(200 if self.path!='/reject' else 401);self.end_headers();self.wfile.write(b'OK')
            def log_message(self,*args): pass
        server=HTTPServer(('127.0.0.1',0),Handler)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            accounts=[{'label':'token','method':'bearer','token':'synthetic','cookie':'','verify_path':'/me','login_path':''},
                      {'label':'cookie','method':'cookie','token':'','cookie':'sid=demo','verify_path':'/reject','login_path':''}]
            result=subprocess.run([sys.executable,'-c',greybox.PROBE_SCRIPT],input=json.dumps({'target':f'http://127.0.0.1:{server.server_port}','accounts':accounts}),text=True,capture_output=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stderr)
            values=json.loads(result.stdout)
            self.assertEqual(values[0]['state'],'success')
            self.assertEqual(values[1]['http_status'],401)
            self.assertEqual(observed,[('Bearer synthetic',None),(None,'sid=demo')])
        finally:
            server.shutdown();server.server_close();thread.join()

    def test_scan_supplies_task_credentials_as_workspace_file_and_redacts_report(self):
        with patch('socket.getaddrinfo',return_value=[(socket.AF_INET,socket.SOCK_STREAM,6,'',('10.20.30.40',443))]):
            response=self.client.post('/v1/scans/greybox',headers=self.auth,json=self.payload())
            job=worker.claim_job()
            fake=self.root/'scanner.py'
            fake.write_text("import pathlib,json\np=pathlib.Path('strix_runs/fake');p.mkdir(parents=True)\n(p/'run.json').write_text(json.dumps({'status':'completed'}))\n(p/'penetration_test_report.md').write_text('redact synthetic-secret')\n")
            original=subprocess.Popen
            def spawn(command,**kwargs):
                from pathlib import Path
                source=command[command.index('--workspace-file')+1].removesuffix(':auth.json')
                self.assertEqual(json.loads(Path(source).read_text())['accounts'][0]['token'],'synthetic-secret')
                return original([sys.executable,str(fake)],**kwargs)
            with patch.dict(os.environ,{'EGRESS_POLICY_ACK':'true'}),patch('worker.child_environment',return_value={'PATH':os.environ['PATH']}),patch('worker.cleanup_sandboxes'),patch('worker.subprocess.Popen',side_effect=spawn):
                worker.run_job(job)
        root=service.job_dir(response.json()['id'])
        self.assertEqual(service.owned_job(job['id'],'alice')['status'],'completed')
        for name in ('report.json','report.md','scope.txt'):
            self.assertNotIn('synthetic-secret',(root/name).read_text())

    def test_dynamic_cookie_and_header_entries(self):
        auth={'accounts':[{'label':'账号 1','method':'headers','auth':[
            {'type':'cookie','name':'sid','value':'demo-session'},
            {'type':'cookie','name':'tenant','value':'test'},
            {'type':'header','name':'Authorization','value':'Custom demo-credential'}]}]}
        normalized=greybox.validate(auth,'http://example.test/')
        self.assertNotIn('demo-session',greybox.redact('demo-session demo-credential',normalized))
        observed=[]
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                observed.append((self.headers.get('Cookie'),self.headers.get('Authorization')))
                self.send_response(200);self.end_headers()
            def log_message(self,*args): pass
        server=HTTPServer(('127.0.0.1',0),Handler)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            result=subprocess.run([sys.executable,'-c',greybox.PROBE_SCRIPT],input=json.dumps({**normalized,'target':f'http://127.0.0.1:{server.server_port}'}),text=True,capture_output=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(observed,[('sid=demo-session; tenant=test','Custom demo-credential')])
        finally:
            server.shutdown();server.server_close();thread.join()
        auth['accounts'][0]['auth']=[]
        self.assertEqual(greybox.validate(auth,'http://example.test/')['accounts'][0]['auth'],[])
        auth['accounts'][0]['auth']=[{'type':'header','name':'Host','value':'other.example'}]
        with self.assertRaises(ValueError): greybox.validate(auth,'http://example.test/')
