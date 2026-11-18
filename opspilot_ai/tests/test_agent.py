"""Offline tests: no LLM service required."""
import json
import os
import tempfile
import unittest
from pathlib import Path

class FakeModel:
    def __init__(self, responses): self.responses=iter(responses)
    def complete(self,messages): return next(self.responses)

def tool_response(name,args,id='tc1'):
    return {'role':'assistant','content':'','tool_calls':[{'id':id,'type':'function','function':{'name':name,'arguments':json.dumps(args)}}]}

class AgentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory()
        os.environ['OPSPILOT_DB']=str(Path(cls.tmp.name)/'test.db')
        from opspilot import store
        store.DB_PATH=Path(os.environ['OPSPILOT_DB'])
        store.init_db()

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_seed_and_retrieval(self):
        from opspilot.tools import execute_tool
        self.assertEqual(execute_tool('get_device',{'device_id':'DEV-104'})['device_id'],'DEV-104')
        self.assertTrue(execute_tool('get_alerts',{'device_id':'DEV-104'}))
        self.assertTrue(execute_tool('search_knowledge',{'query':'malware quarantine approval'}))
        self.assertEqual(execute_tool('get_owner',{'device_id':'DEV-104'})['name'],'Jordan Lee')

    def test_agent_dynamic_tool_and_completion(self):
        from opspilot.agent import Agent
        from opspilot import store
        model=FakeModel([tool_response('get_device',{'device_id':'DEV-207'}),
                         {'role':'assistant','content':'DEV-207 is active per SQLite device records.'}])
        result=Agent(model=model).start('Check DEV-207')
        self.assertEqual(result['status'],'completed')
        self.assertTrue(store.query('SELECT * FROM audit WHERE run_id=?',(result['run_id'],)))

    def test_approval_denial_does_not_quarantine(self):
        from opspilot.agent import Agent
        from opspilot import store
        model=FakeModel([tool_response('quarantine_device',{'device_id':'DEV-104','reason':'critical malware alert'}),
                         {'role':'assistant','content':'Reviewer denied quarantine; device remains active.'}])
        agent=Agent(model=model)
        first=agent.start('Assess DEV-104 and isolate if needed')
        self.assertEqual(first['status'],'awaiting_approval')
        self.assertEqual(store.query("SELECT status FROM devices WHERE device_id='DEV-104'")[0]['status'],'active')
        approval=store.query("SELECT * FROM approvals WHERE run_id=?",(first['run_id'],))[0]
        final=agent.review(approval['id'],False,'More evidence needed')
        self.assertEqual(final['status'],'completed')
        self.assertEqual(store.query("SELECT status FROM devices WHERE device_id='DEV-104'")[0]['status'],'active')

    def test_approval_executes_and_verifies(self):
        from opspilot.agent import Agent
        from opspilot import store
        model=FakeModel([tool_response('quarantine_device',{'device_id':'DEV-104','reason':'high risk after review'}),
                         tool_response('verify_device_status',{'device_id':'DEV-104'},'tc2'),
                         {'role':'assistant','content':'Human-approved quarantine verified in SQLite.'}])
        agent=Agent(model=model)
        first=agent.start('Simulate approved quarantine')
        approval=store.query("SELECT * FROM approvals WHERE run_id=?",(first['run_id'],))[0]
        result=agent.review(approval['id'],True,'Approved demo')
        self.assertEqual(result['status'],'completed')
        self.assertEqual(store.query("SELECT status FROM devices WHERE device_id='DEV-104'")[0]['status'],'quarantined')
        self.assertTrue(store.query("SELECT * FROM audit WHERE run_id=? AND tool='verify_device_status'",(first['run_id'],)))

if __name__=='__main__': unittest.main()
