import json
import time
import unittest
from fastapi.testclient import TestClient
from unittest.mock import patch
import service
import portal
import test_portal as base_tests


class APITokenTests(unittest.TestCase):
    setUp = base_tests.PortalTests.setUp
    tearDown = base_tests.PortalTests.tearDown
    zip_bytes = base_tests.PortalTests.zip_bytes
    login = base_tests.PortalTests.login

    def token(self, employee='001234'):
        csrf = self.login(role='user', employee=employee)
        response = self.client.post('/web/api-tokens', headers=csrf, json={'name': 'Postman', 'days': 7})
        self.assertEqual(response.status_code, 201, response.text)
        return response.json(), csrf

    def test_machine_token_without_cookies_and_task_isolation(self):
        token, _ = self.token()
        with TestClient(service.app) as machine:
            auth = {'Authorization': 'Bearer '+token['token']}
            created = machine.post('/v1/scans/whitebox', headers=auth, data={'authorized': 'true'},
                files={'project': ('code.zip', self.zip_bytes())})
            self.assertEqual(created.status_code, 202, created.text)
            job_id = created.json()['id']
            self.assertEqual(service.owned_job(job_id, '001234')['owner'], '001234')
            self.assertEqual(machine.get('/v1/scans/'+job_id, headers=auth).status_code, 200)
        other, _ = self.token(employee='006789')
        self.assertEqual(self.client.get('/v1/scans/'+job_id, headers={'Authorization': 'Bearer '+other['token']}).status_code, 404)
        # An explicit invalid Bearer must never inherit a valid browser cookie.
        self.assertEqual(self.client.get('/v1/scans/'+job_id, headers={'Authorization': 'Bearer invalid'}).status_code, 401)

    def test_hash_only_listing_and_revocation(self):
        token, csrf = self.token()
        listed = self.client.get('/web/api-tokens')
        self.assertNotIn(token['token'], listed.text)
        with service.database() as conn:
            stored = dict(conn.execute('SELECT * FROM portal_api_tokens WHERE id=?', (token['id'],)).fetchone())
        self.assertNotIn(token['token'], json.dumps(stored))
        self.assertEqual(self.client.delete('/web/api-tokens/'+token['id'], headers=csrf).status_code, 200)
        self.assertIsNone(portal.api_token_identity(token['token']))

    def test_expiry_disabled_user_and_validation(self):
        token, csrf = self.token()
        self.assertEqual(self.client.post('/web/api-tokens', headers=csrf, json={'days': 1000}).status_code, 400)
        with service.database() as conn:
            conn.execute('UPDATE portal_users SET disabled=1 WHERE employee=?', ('001234',))
        self.assertIsNone(portal.api_token_identity(token['token']))
        with service.database() as conn:
            conn.execute('UPDATE portal_users SET disabled=0 WHERE employee=?', ('001234',))
            conn.execute('UPDATE portal_api_tokens SET expires=?', (time.time()-1,))
        self.assertIsNone(portal.api_token_identity(token['token']))

    def test_api_guide_route_requires_login_for_token_management(self):
        self.assertEqual(self.client.get('/api-guide').status_code, 200)
        self.assertEqual(self.client.get('/web/api-tokens').status_code, 401)
        token, _ = self.token()
        self.login(employee='006789', role='user')
        self.assertEqual(self.client.get('/web/api-tokens').json()['items'], [])
        self.assertEqual(self.client.delete('/web/api-tokens/'+token['id'], headers={'x-csrf-token':self.client.get('/web/me').json()['csrf']}).status_code, 404)

    def test_personal_token_is_reusable_encrypted_and_expires_in_seven_days(self):
        csrf=self.login(role='user',employee='001234')
        response=self.client.post('/web/api-tokens/personal',headers=csrf)
        self.assertEqual(response.status_code,200,response.text)
        first=response.json()
        self.assertEqual(response.headers['cache-control'],'no-store')
        self.assertAlmostEqual(first['expires']-time.time(),7*86400,delta=5)
        second=self.client.post('/web/api-tokens/personal',headers=csrf).json()
        self.assertEqual(first,second)
        self.assertEqual(portal.api_token_identity(first['token']),'001234')
        with service.database() as conn:
            saved=dict(conn.execute('SELECT * FROM portal_personal_tokens WHERE owner=?',('001234',)).fetchone())
            self.assertNotIn(first['token'],json.dumps(saved))
            conn.execute('UPDATE portal_api_tokens SET expires=? WHERE id=?',(time.time()-1,saved['token_id']))
        self.assertIsNone(portal.api_token_identity(first['token']))
        third=self.client.post('/web/api-tokens/personal',headers=csrf).json()
        self.assertNotEqual(first['token'],third['token'])
        self.assertAlmostEqual(third['expires']-time.time(),7*86400,delta=5)

    def test_personal_token_requires_session_csrf_and_isolates_accounts(self):
        self.assertEqual(self.client.post('/web/api-tokens/personal').status_code,401)
        csrf=self.login(role='user',employee='001234')
        self.assertEqual(self.client.post('/web/api-tokens/personal').status_code,403)
        alice=self.client.post('/web/api-tokens/personal',headers=csrf).json()
        other=self.login(role='user',employee='006789')
        bob=self.client.post('/web/api-tokens/personal',headers=other).json()
        self.assertNotEqual(alice['token'],bob['token'])
        self.assertEqual(portal.api_token_identity(bob['token']),'006789')
        with service.database() as conn:
            conn.execute('UPDATE portal_api_tokens SET revoked=1 WHERE owner=?',('006789',))
        replacement=self.client.post('/web/api-tokens/personal',headers=other).json()
        self.assertNotEqual(replacement['token'],bob['token'])
        self.assertIsNone(portal.api_token_identity(bob['token']))
