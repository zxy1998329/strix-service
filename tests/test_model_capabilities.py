import io
import json
import urllib.error
import unittest
from unittest.mock import MagicMock, patch
import portal
import runtime_config
import test_service


class CapabilityTests(unittest.TestCase):
    def simulate(self, protocol='openai', broken=None):
        config=runtime_config.defaults()
        config.update(api_type=protocol,model='test-model',api_base='https://model.example/v1',api_key='secret-test-key')
        requests=[]
        def open_request(request,**kwargs):
            body=json.loads(request.data);requests.append(body)
            number=len(requests)
            if broken=='http' and number==2:
                raise urllib.error.HTTPError(request.full_url,400,'Bad Request',{},io.BytesIO(b'{"error":"tools unsupported", "echo":"secret-test-key"}'))
            if number==1:
                value={'content':[{'type':'text','text':'模型回答'}]} if protocol=='anthropic' else {'choices':[{'message':{'content':'模型回答'}}]}
            elif number==2:
                if broken=='no-tools':
                    value={'choices':[{'message':{'content':'pretend tool_call'}}]}
                elif protocol=='anthropic':
                    value={'content':[{'type':'tool_use','id':'call-1','name':'connectivity_probe','input':{'ok':True}}]}
                else:
                    value={'choices':[{'message':{'role':'assistant','content':None,'tool_calls':[{'id':'call-1','type':'function','function':{'name':'connectivity_probe','arguments':'{"ok":true}'}}]}}]}
                    if broken=='unknown-tool':value['choices'][0]['message']['tool_calls'][0]['function']['name']='exec_command'
            else:
                if protocol=='anthropic':
                    output=body['messages'][-1]['content'][0]
                    self.assertEqual(output['tool_use_id'],'call-1')
                    code=json.loads(output['content'])['verification_code']
                    value={'content':[{'type':'text','text':code}]}
                else:
                    output=body['messages'][-1]
                    self.assertEqual(output['role'],'tool');self.assertEqual(output['tool_call_id'],'call-1')
                    code=json.loads(output['content'])['verification_code']
                    value={'choices':[{'message':{'content':code if broken!='roundtrip' else 'ignored result'}}]}
            response=MagicMock()
            response.__enter__.return_value.read.return_value=json.dumps(value).encode()
            return response
        with patch('portal.urllib.request.build_opener') as opener:
            opener.return_value.open.side_effect=open_request
            result=portal.probe_model(config,'自定义问题')
        self.assertEqual(requests[0]['messages'][0]['content'],'自定义问题')
        self.assertNotIn('tools',requests[0])
        return result,requests

    def test_answer_and_real_tool_result_roundtrip_for_both_protocols(self):
        for protocol in ('openai','anthropic'):
            with self.subTest(protocol=protocol):
                result,requests=self.simulate(protocol)
                self.assertTrue(result['ok']);self.assertTrue(result['question_ok'])
                self.assertTrue(result['tool_calls']);self.assertTrue(result['tool_roundtrip'])
                self.assertEqual(result['answer'],'模型回答');self.assertEqual(len(requests),3)

    def test_http_200_without_tool_call_is_not_overall_success(self):
        result,requests=self.simulate(broken='no-tools')
        self.assertFalse(result['ok']);self.assertTrue(result['question_ok']);self.assertFalse(result['tool_calls'])
        self.assertEqual(len(requests),2)

    def test_unknown_tool_not_executed_and_bad_result_not_accepted(self):
        result,requests=self.simulate(broken='unknown-tool')
        self.assertFalse(result['ok']);self.assertEqual(len(requests),2)
        result,requests=self.simulate(broken='roundtrip')
        self.assertTrue(result['tool_calls']);self.assertFalse(result['tool_roundtrip']);self.assertFalse(result['ok'])

    def test_tool_failure_keeps_answer_and_redacts_error(self):
        result,_=self.simulate(broken='http')
        self.assertFalse(result['ok']);self.assertEqual(result['answer'],'模型回答')
        self.assertEqual(result['status_code'],400);self.assertNotIn('secret-test-key',json.dumps(result))


class RequiredQuestionTests(unittest.TestCase):
    setUp=test_service.ServiceTests.setUp
    tearDown=test_service.ServiceTests.tearDown
    def test_empty_question_rejected_without_model_call(self):
        response=self.client.post('/web/login',json={'role':'admin','password':'296419'})
        headers={'x-csrf-token':response.json()['csrf']}
        with patch('portal.probe_model') as probe:
            for question in ('','   ',None):
                payload={'api_type':'openai','model':'test','api_base':'https://model.example/v1','api_key':'','question':question}
                self.assertEqual(self.client.post('/web/admin/test-model',headers=headers,json=payload).status_code,400)
            probe.assert_not_called()
