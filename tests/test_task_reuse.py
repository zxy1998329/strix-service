import json
import os
import socket
import unittest
from unittest.mock import patch
import service
import greybox
import runtime_config
import test_service


class ReuseTests(unittest.TestCase):
    setUp=test_service.ServiceTests.setUp
    tearDown=test_service.ServiceTests.tearDown
    zip_bytes=test_service.ServiceTests.zip_bytes
    submit=test_service.ServiceTests.submit

    def test_whitebox_copy_uses_latest_model_and_replacement_upload(self):
        with patch.dict(os.environ,{'EGRESS_POLICY_ACK':'true'}):
            runtime_config.save_settings({'enabled':True,'model':'openai/old-model','api_key':'old-key'})
            original=self.client.post('/v1/scans/whitebox',headers=self.auth,data={'name':'原任务','instructions':'原测试要求','authorized':'true'},files={'project':('app.zip',self.zip_bytes())}).json()['id']
            before=service.owned_job(original,'alice')
            draft=self.client.get('/v1/scans/'+original+'/reuse',headers=self.auth).json()
            self.assertTrue(draft['project_available']);self.assertEqual(draft['name'],'原任务')
            self.assertEqual(draft['instructions'],'原测试要求')
            self.assertNotIn('old-key',json.dumps(draft));self.assertNotIn('old-model',json.dumps(draft))
            runtime_config.save_settings({'model':'openai/new-model','api_key':'new-key'})
            response=self.client.post('/v1/scans/whitebox',headers=self.auth,data={'source_job_id':original,'name':'修改后的新任务','instructions':'新测试要求','authorized':'true'})
            self.assertEqual(response.status_code,202,response.text)
            new_id=response.json()['id'];new_root=service.job_dir(new_id)
            self.assertEqual((new_root/'source/src/app.py').read_text(),'print(1)')
            self.assertEqual(runtime_config.for_job(new_root)['model'],'openai/new-model')
            self.assertEqual(runtime_config.for_job(new_root)['api_key'],'new-key')
            self.assertEqual(runtime_config.for_job(service.job_dir(original))['model'],'openai/old-model')
            self.assertEqual(service.owned_job(original,'alice'),before)
            response=self.client.post('/v1/scans/whitebox',headers=self.auth,data={'source_job_id':original,'authorized':'true'},files={'project':('new.zip',self.zip_bytes(content='print(2)'))})
            self.assertEqual(response.status_code,202,response.text)
            self.assertEqual((service.job_dir(response.json()['id'])/'source/src/app.py').read_text(),'print(2)')

    def test_other_owner_cannot_reuse_or_copy_project(self):
        original=self.submit().json()['id'];other={'Authorization':'Bearer '+'b'*40}
        self.assertEqual(self.client.get('/v1/scans/'+original+'/reuse',headers=other).status_code,404)
        self.assertEqual(self.client.post('/v1/scans/whitebox',headers=other,data={'source_job_id':original,'authorized':'true'}).status_code,404)

    def test_missing_and_unsafe_original_project_requires_new_upload(self):
        original=self.submit().json()['id'];source=service.job_dir(original)/'source'
        (source/'outside').symlink_to('/etc/passwd')
        response=self.client.post('/v1/scans/whitebox',headers=self.auth,data={'source_job_id':original,'authorized':'true'})
        self.assertEqual(response.status_code,400,response.text)
        (source/'outside').unlink()
        import shutil
        shutil.rmtree(source)
        self.assertFalse(self.client.get('/v1/scans/'+original+'/reuse',headers=self.auth).json()['project_available'])
        self.assertEqual(self.client.post('/v1/scans/whitebox',headers=self.auth,data={'source_job_id':original,'authorized':'true'}).status_code,409)

    def test_greybox_masked_references_editing_and_isolation(self):
        payload={'name':'灰盒原任务','target':'https://test.company/','authorized':True,'instructions':'检查越权',
                 'accounts':[{'label':'普通用户','role':'只读本人','method':'headers','auth':[{'type':'header','name':'Authorization','value':'Bearer original-test-token'}]}]}
        with patch('socket.getaddrinfo',return_value=[(socket.AF_INET,socket.SOCK_STREAM,6,'',('10.20.30.40',443))]):
            response=self.client.post('/v1/scans/greybox',headers=self.auth,json=payload)
            self.assertEqual(response.status_code,202,response.text);original=response.json()['id']
            draft=self.client.get('/v1/scans/'+original+'/reuse',headers=self.auth).json()
            self.assertNotIn('original-test-token',json.dumps(draft))
            self.assertEqual(draft['instructions'],'检查越权')
            other={'Authorization':'Bearer '+'b'*40}
            self.assertEqual(self.client.get('/v1/scans/'+original+'/reuse',headers=other).status_code,404)
            reused={**payload,'name':'复用灰盒','source_job_id':original,'accounts':draft['accounts']}
            self.assertEqual(self.client.post('/v1/scans/greybox',headers=other,json=reused).status_code,404)
            response=self.client.post('/v1/scans/greybox',headers=self.auth,json=reused)
            self.assertEqual(response.status_code,202,response.text)
            self.assertEqual(greybox.load(service.job_dir(response.json()['id']))['accounts'][0]['auth'][0]['value'],'Bearer original-test-token')
            entry=reused['accounts'][0]['auth'][0];entry['value']='Bearer new-test-token'
            self.assertEqual(self.client.post('/v1/scans/greybox',headers=self.auth,json=reused).status_code,400)
            entry.pop('value_reference')
            response=self.client.post('/v1/scans/greybox',headers=self.auth,json=reused)
            self.assertEqual(response.status_code,202,response.text)
            self.assertEqual(greybox.load(service.job_dir(response.json()['id']))['accounts'][0]['auth'][0]['value'],'Bearer new-test-token')
            self.assertEqual(greybox.load(service.job_dir(original))['accounts'][0]['auth'][0]['value'],'Bearer original-test-token')

    def test_blackbox_reuse_is_read_only_and_legacy_credentials_remain_editable(self):
        with patch('socket.getaddrinfo',return_value=[(socket.AF_INET,socket.SOCK_STREAM,6,'',('10.20.30.40',443))]):
            original=self.client.post('/v1/scans/blackbox',headers=self.auth,json={'name':'黑盒','target':'https://test.company/','instructions':'排除退出接口','authorized':True}).json()['id']
        before=service.owned_job(original,'alice')
        draft=self.client.get('/v1/scans/'+original+'/reuse',headers=self.auth).json()
        self.assertEqual(draft['target'],'https://test.company/');self.assertEqual(draft['instructions'],'排除退出接口')
        self.assertEqual(service.owned_job(original,'alice'),before)
        auth={'accounts':[{'label':'测试','method':'password','username':'tester','password':'long-password-test','login_path':'/login','steps':'点击登录'}]}
        import task_reuse
        public=task_reuse.public_accounts(auth)
        self.assertEqual(public[0]['username'],'tester');self.assertNotIn('long-password-test',json.dumps(public))
