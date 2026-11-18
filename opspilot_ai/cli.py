"""Headless CLI demo: python cli.py --objective 'Investigate DEV-104...'"""
import argparse
from opspilot import store
from opspilot.agent import Agent
from opspilot.report import save_report

def main():
    parser=argparse.ArgumentParser(description='OpsPilot AI autonomous operations demo')
    parser.add_argument('--objective',help='Natural-language investigation request')
    parser.add_argument('--approve',help='Pending approval ID to approve')
    parser.add_argument('--deny',help='Pending approval ID to deny')
    parser.add_argument('--list-approvals',action='store_true')
    parser.add_argument('--export',help='Run ID to export as Markdown')
    args=parser.parse_args()
    store.init_db()
    if args.objective: result=Agent().start(args.objective)
    elif args.approve: result=Agent().review(args.approve,True)
    elif args.deny: result=Agent().review(args.deny,False)
    elif args.list_approvals:
        for x in store.query("SELECT id,run_id,tool,arguments FROM approvals WHERE status='pending'"): print(x)
        return
    elif args.export:
        print(save_report(args.export,'reports/'+args.export+'.md'))
        return
    else:
        parser.print_help();return
    print('RUN:',result['run_id'],'STATUS:',result['status'],'\n',result['result'])
    if result['status']=='awaiting_approval': print('Run python cli.py --list-approvals and then --approve APPROVAL_ID or --deny APPROVAL_ID')

if __name__=='__main__': main()
