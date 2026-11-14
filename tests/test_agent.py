import hashlib
import hmac
import json
import os
import subprocess
import sys
import threading
import time
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import server


class AssessmentTests(unittest.TestCase):
    def test_missing_fields_never_claim_safe(self):
        result=server.assess({})
        self.assertEqual(result['decision'],'CAUTION')
        self.assertEqual(result['checks']['onchain_queries'],0)
        self.assertFalse(result['checks']['wallet_connected'])
        self.assertTrue(any(x['severity']=='unknown' for x in result['findings']))

    def test_flags_unlimited_approval(self):
        r=server.assess({'unlimited_approval':True})
        self.assertIn('UNLIMITED_APPROVAL',[x['code'] for x in r['findings']])
        self.assertEqual(r['decision'],'CAUTION')

    def test_cannot_say_safe_just_from_false_flags(self):
        r=server.assess({'simulation_failed':False,'unlimited_approval':False,'unverified_contract':False,'owner_can_mint':False,'owner_can_pause':False,'owner_can_blacklist':False,'proxy_admin_present':False,'recipient_is_new':False,'chain':'BSC'})
        self.assertEqual(r['decision'],'NO_FLAGS_IN_PROVIDED_INPUT')
        self.assertIn('not an audit',r['disclaimer'].lower())
        self.assertEqual(r['checks']['onchain_queries'],0)

    def test_bad_contract_address_format(self):
        r=server.assess({'contract_address':'not-an-address'})
        self.assertTrue(any(x['code']=='INVALID_ADDRESS_FORMAT' for x in r['findings']))

    def test_non_object_rejected(self):
        with self.assertRaises(ValueError):server.assess([])


class HttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd=server.ThreadingHTTPServer(('127.0.0.1',0),server.Handler)
        cls.thread=threading.Thread(target=cls.httpd.serve_forever,daemon=True);cls.thread.start()
        cls.base=f'http://127.0.0.1:{cls.httpd.server_port}'
    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown();cls.httpd.server_close();cls.thread.join(timeout=2)
    def request(self,path,body=None,headers=None):
        req=urllib.request.Request(self.base+path,data=body,headers=headers or {},method='POST' if body is not None else 'GET')
        try:
            with urllib.request.urlopen(req,timeout=3) as resp:return resp.status,resp.headers,resp.read()
        except urllib.error.HTTPError as e:return e.code,e.headers,e.read()
    def test_health_endpoint(self):
        status,_,body=self.request('/health');self.assertEqual(status,200);self.assertEqual(json.loads(body)['status'],'ok')
    def test_agent_response(self):
        status,_,body=self.request('/agent',b'{"unlimited_approval":true}',{'Content-Type':'application/json'})
        self.assertEqual(status,200);self.assertEqual(json.loads(body)['decision'],'CAUTION')
    def test_bad_signature_is_rejected(self):
        os.environ['AGENT_GAMES_HMAC_SECRET']='unit-test-secret'
        try:
            status,_,_=self.request('/agent',b'{}',{'x-agent-games-signature':'00'})
            self.assertEqual(status,401)
        finally:os.environ.pop('AGENT_GAMES_HMAC_SECRET',None)
    def test_valid_signature_and_response_signature(self):
        secret='unit-test-secret';body=b'{"chain":"BSC"}';os.environ['AGENT_GAMES_HMAC_SECRET']=secret
        try:
            sig=hmac.new(secret.encode(),body,hashlib.sha256).hexdigest()
            status,headers,raw=self.request('/agent',body,{'x-agent-games-signature':sig})
            self.assertEqual(status,200)
            self.assertEqual(headers['x-agent-games-signature'],hmac.new(secret.encode(),raw,hashlib.sha256).hexdigest())
        finally:os.environ.pop('AGENT_GAMES_HMAC_SECRET',None)


if __name__=='__main__':unittest.main(verbosity=2)
