"""Save Markdown reports with traceable evidence and audit logs."""
import json
from pathlib import Path
from . import store

def markdown_report(run_id):
    run=store.get_run(run_id)
    if not run: raise ValueError('Unknown run')
    audits=store.query('SELECT * FROM audit WHERE run_id=? ORDER BY id',(run_id,))
    approvals=store.query('SELECT * FROM approvals WHERE run_id=? ORDER BY created_at',(run_id,))
    text=[f'# OpsPilot AI — Run {run_id}', '',f'**Objective:** {run["objective"]}',
          f'**Status:** {run["status"]}', f'**Created:** {run["created_at"]}', '',
          '## Agent assessment', '',run['result'] or '_No final result yet._', '',
          '## Human approvals', '']
    if approvals:
        for a in approvals:
            text.append(f'- **{a["id"]}** — {a["tool"]} — {a["status"]} — note: {a["reviewer_note"] or "(none)"}')
    else: text.append('_None._')
    text.extend(['','## Tool audit',''])
    for a in audits:
        text.extend([f'### {a["id"]}: {a["tool"]}',
                     '```json',json.dumps({'arguments':json.loads(a['arguments']),'outcome':json.loads(a['outcome'])},indent=2), '```',''])
    return '\n'.join(text)

def save_report(run_id,output):
    path=Path(output)
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(markdown_report(run_id),encoding='utf-8')
    return path
