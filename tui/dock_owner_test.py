"""Read-only dock agrees with assembled bytes; a fold compares against the actual checkpoint."""
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import tempfile

binary = Path(sys.argv[1]).resolve(strict=True)


def frames(home, *inputs):
    wire = ''.join(json.dumps({'id':i, 'jsonrpc':'2.0', 'method':method, 'params':{'schema_version':1, **args}}) + '\n'
                   for i,(method,args) in enumerate(inputs))
    proc = subprocess.run([binary, '--ui-wire-v1'], cwd=home, env={'HOME':str(home),'PATH':'/usr/bin:/bin'},
                          input=wire, capture_output=True, text=True, check=True, timeout=10)
    return [json.loads(row) for row in proc.stdout.splitlines()]


with tempfile.TemporaryDirectory() as path:
    home = Path(path)
    session = frames(home, ('session.project',{}))[0]['result']['session_id']
    attach = ('session.attach',{'session_id':session,'bootstrap_id':'dock-read'})
    create = lambda n: ('task.submit',{'session_id':session,'kind':'create','command_id':f'item-{n}','goal':f'report {n}',
                                        'contract':{'criteria':[],'constraints':[]}})
    first, _, chosen = (frame['result']['task_id'] for frame in frames(home,attach,create(1),create(2),create(3))[1:])
    payload = 'private evidence observation ' * 600
    db_path = home / '.rivect/runtime/rivect.db'
    with sqlite3.connect(db_path) as db:
        db.executemany('INSERT INTO evidence VALUES (?,?,?,?,?,?,?)',
                       [(f'e{i}',chosen,'task:'+chosen,payload,hashlib.sha256((payload+str(i)).encode()).hexdigest(),'current','o1') for i in range(64)])
    def dock(task, owner=session):
        return ('operator.action',{'session_id':owner,'action':{'kind':'dock','task_id':task}})
    def command(kind,task):
        return ('composer.command',{'session_id':session,'kind':kind,'task_id':task})
    def durable():
        with sqlite3.connect(db_path.as_uri()+'?mode=ro',uri=True) as db:
            digest = hashlib.sha256()
            for row in db.execute('SELECT * FROM evidence ORDER BY evidence_id'):
                digest.update(json.dumps(row).encode())
            events, settlements = db.execute('SELECT (SELECT count(*) FROM events),(SELECT count(*) FROM usage_settlements)').fetchone()
            return events, settlements, digest.hexdigest()
    baseline = durable()
    _, preview, projected, small, refused, same_preview, repeat = frames(home, attach, command('rewind',chosen), dock(chosen),
        dock(first), command('compact',first), command('rewind',chosen), dock(chosen))
    measured = re.search(r'(\d+) assembled bytes',preview['result']['lines'][0])
    assert measured is not None, preview
    count = int(measured[1])
    assert count >= (1 << 20)*.8
    assert 'result' in projected, f'dock did not project active task: {projected}'
    page = projected['result']
    assert page['task_id'] == chosen and page['percent'] == count*100//(1 << 20)
    assert small['result']['percent'] is None and repeat['result'] == page
    assert refused['error']['cause'] == 'compaction_not_shorter' and preview['result'] == same_preview['result']
    assert all(any(task in row for row in page['rows']) for task in (first,chosen))
    assert 'private evidence observation' not in json.dumps(page)
    assert durable() == baseline
    other = frames(home, ('session.open',{'bootstrap_id':'foreign'}))[0]['result']['session_id']
    foreign = frames(home, ('session.attach',{'session_id':other,'bootstrap_id':'other'}), dock(chosen,other))[-1]
    assert foreign['error']['code'] == 'not_found'
    _, accepted, after, refused = frames(home, attach, command('compact',chosen), dock(chosen), command('compact',first))
    assert 'Context compacted:' in accepted['result']['lines'][0] and after['result']['percent'] is None
    assert refused['error']['code'] == 'conflict' and refused['error']['cause'] == 'compaction_not_shorter'
    assert durable()[1:] == baseline[1:]
