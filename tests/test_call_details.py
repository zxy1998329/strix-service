import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch
import httpx
from call_details import CallDetails
import service
import test_service
import test_portal


class CallDetailTests(unittest.TestCase):
    setUp=test_service.ServiceTests.setUp
    tearDown=test_service.ServiceTests.tearDown
    zip_bytes=test_service.ServiceTests.zip_bytes

    def test_capture_actual_body_redact_and_admin_access(self):
        headers=test_portal.PortalTests.login(self)
        response=self.client.post('/v1/scans/whitebox',headers=headers,data={'authorized':'true'},files={'project':('test.zip',self.zip_bytes())})
        self.assertEqual(response.status_code,202,response.text)
        job_id=response.json()['id'];root=service.job_dir(job_id)
        request=httpx.Request('POST','https://model.example/v1/chat/completions?api_key=hidden',headers={'Authorization':'Bearer synthetic-private-key'},json={'model':'test','messages':[{'role':'user','content':'审计这个函数 synthetic-private-key <script>alert(1)</script>'}],'temperature':0.3})
        details=CallDetails(root)
        identifier='a'*32
        handle=details.start(identifier,request)
        details.finish(handle,{'choices':[{'message':{'content':'模型回答 synthetic-private-key'}}],'usage':{'prompt_tokens':17,'completion_tokens':8}},200)
        text=handle[0].read_text()
        self.assertNotIn('synthetic-private-key',text)
        self.assertNotIn('api_key=hidden',text)
        self.assertIn('审计这个函数',text)
        self.assertEqual(handle[0].stat().st_mode & 0o777,0o600)
        endpoint='/v1/scans/'+job_id+'/model-calls'
        listing=self.client.get(endpoint)
        self.assertEqual(listing.status_code,200)
        self.assertEqual(listing.json()['total'],1)
        self.assertNotIn('messages',listing.text)
        record=self.client.get(endpoint+'/'+identifier)
        self.assertEqual(record.status_code,200)
        self.assertEqual(record.json()['request']['temperature'],0.3)
        self.assertEqual(record.json()['response']['usage']['prompt_tokens'],17)
        self.assertEqual(record.headers['cache-control'],'no-store')
        self.assertEqual(self.client.get(endpoint+'/invalid').status_code,400)
        test_portal.PortalTests.login(self,role='user',employee='001234')
        self.assertIn(self.client.get(endpoint).status_code,(403,404))

    def test_request_recording_failure_does_not_block_model(self):
        import tempfile
        import model_calls
        with tempfile.TemporaryDirectory() as directory:
            original_sync=httpx.Client.send;original_async=httpx.AsyncClient.send
            with patch.object(httpx.Client,'send',original_sync),patch.object(httpx.AsyncClient,'send',original_async):
                model_calls.install_httpx(directory)
                with patch('call_details.CallDetails.start',side_effect=OSError('full')):
                    with httpx.Client(transport=httpx.MockTransport(lambda request:httpx.Response(200,json={'usage':{'prompt_tokens':2,'completion_tokens':1}}))) as client:
                        self.assertEqual(client.post('https://model.example/v1/chat/completions',json={'model':'test','messages':[]}).status_code,200)
