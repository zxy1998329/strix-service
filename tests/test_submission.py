import json
from unittest import TestCase
import test_service as base
import service
import greybox


class SubmissionTests(TestCase):
    setUp=base.ServiceTests.setUp
    tearDown=base.ServiceTests.tearDown
    zip_bytes=base.ServiceTests.zip_bytes
    submit=base.ServiceTests.submit

    def test_saved_inputs_are_read_only_and_owner_scoped(self):
        job_id=self.submit().json()['id']
        root=service.job_dir(job_id)
        (root/'requirements.json').write_text(json.dumps({'instructions':'重点验证权限'}))
        before=service.owned_job(job_id,'alice')
        value=self.client.get('/v1/scans/'+job_id+'/submission',headers=self.auth)
        self.assertEqual(value.status_code,200,value.text)
        self.assertEqual(value.json()['instructions'],'重点验证权限')
        self.assertEqual(value.json()['target'],'')
        self.assertTrue(value.json()['project_available'])
        self.assertEqual(service.owned_job(job_id,'alice'),before)
        self.assertEqual(self.client.get('/v1/scans/'+job_id+'/submission',headers={'Authorization':'Bearer '+'b'*40}).status_code,404)
        self.assertEqual(self.client.get('/v1/scans/'+job_id+'/submission').status_code,401)

    def test_greybox_preserves_input_fields_but_masks_credentials(self):
        job_id=self.submit().json()['id'];root=service.job_dir(job_id)
        with service.database() as conn:
            conn.execute("UPDATE jobs SET kind='greybox',target='https://test.company/' WHERE id=?",(job_id,))
        greybox.store(root,{'instructions':'检查横向越权','accounts':[{'label':'用户A','role':'普通用户','method':'headers','password':'test-password-1234','auth':[{'type':'header','name':'Authorization','value':'Bearer synthetic-secret-1234'}]}]})
        response=self.client.get('/v1/scans/'+job_id+'/submission',headers=self.auth)
        self.assertEqual(response.status_code,200,response.text)
        self.assertNotIn('synthetic-secret',response.text)
        self.assertNotIn('test-password',response.text)
        account=response.json()['accounts'][0]
        self.assertEqual(account['role'],'普通用户')
        self.assertEqual(account['auth'][0]['name'],'Authorization')
        self.assertEqual(account['password'],'test••••••••1234')
