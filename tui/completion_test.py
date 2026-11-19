"""Completions disclose workspace names, never contents or another directory."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

BINARY = Path(sys.argv.pop(1)).resolve()
LOCAL = ('config_version = 1\n[connections.loopback]\nkind = "local"\nendpoint = ""\n'
         '[models.defaults]\nmodel = { mode = "fixed", connection = "loopback", model_id = "offline" }\n'
         'effort = { mode = "fixed", value = "medium" }\nfallback = { mode = "off" }\n')


class Completion(unittest.TestCase):
    def test_collocated_data_root_never_exposes_private_config_or_reports(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            (root / 'config.toml').write_text(LOCAL)
            (root / 'reports').mkdir()
            (root / 'reports' / 'receipt.txt').write_text('private receipt')
            (root / 'public.txt').write_text('operator file')
            frame = dict(jsonrpc='2.0', id=1, method='composer.complete', params=dict(schema_version=1, token='@'))
            reply = subprocess.run([BINARY, '--ui-wire-v1'], env={'HOME':str(root), 'RIVECT_DATA_ROOT':str(root)}, cwd=root,
                input=json.dumps(frame) + '\n', capture_output=True, text=True, timeout=5)
            self.assertEqual(reply.returncode, 0, reply.stdout + reply.stderr)
            visible = json.loads(reply.stdout)['result']['candidates']
            self.assertIn('@public.txt', visible)
            self.assertNotIn('@config.toml', visible)
            self.assertNotIn('@reports/', visible)
            self.assertNotIn('@runtime/', visible)

    def test_catalog_names_and_scoped_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            project = home / 'project'
            (project / 'notes').mkdir(parents=True)
            (project / 'notes' / 'paper.txt').write_text('secret contents')
            (project / 'outside').symlink_to(home, target_is_directory=True)
            tokens = ['/ne', '@no', '@notes/pa', '/decis', '/usage', '/unknown', '@outside/', '@../']
            requests = [dict(jsonrpc='2.0', id=i, method='composer.complete',
                             params=dict(schema_version=1, token=t)) for i, t in enumerate(tokens)]
            run = subprocess.run([BINARY, '--ui-wire-v1'], cwd=project, env={'HOME': tmp},
                                 input=''.join(json.dumps(r) + '\n' for r in requests),
                                 capture_output=True, text=True, timeout=10, check=True)
            replies = [json.loads(line) for line in run.stdout.splitlines()]
            self.assertEqual(len(replies), len(tokens))
            for reply, expected in zip(replies, [['/new'], ['@notes/'], ['@notes/paper.txt'], ['/decision', '/decisions'], ['/usage'], []]):
                self.assertEqual(reply.get('result'), {'candidates': expected})
            for reply in replies[6:]:
                self.assertEqual(reply['error']['code'], 'denied')

    def test_hook_protected_names_are_not_listed_or_read_by_machine(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            private = home / '.rivect'
            private.mkdir(mode=0o700)
            project = home / 'workspace'
            (project / 'notes').mkdir(parents=True)
            (project / 'notes' / 'figure.png').write_bytes(bytes.fromhex('89504e470d0a1a0a'))
            marker = private / 'hook-called'
            hook = private / 'review-hook'
            hook.write_text('#!/bin/sh\ntouch "$1"\nprintf \'{"decision":"deny"}\'\n')
            hook.chmod(0o700)
            (private / 'config.toml').write_text(LOCAL + '[hooks."effect.request@project"]\n'
                f'command = {json.dumps(str(hook))}\nargs = [{json.dumps(str(marker))}]\n')
            with subprocess.Popen([BINARY, '--ui-wire-v1'], cwd=project, env={'HOME':tmp},
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True) as child:
                sender, reader = child.stdin, child.stdout
                assert sender is not None and reader is not None
                def request(method, **params):
                    sender.write(json.dumps({'jsonrpc':'2.0','id':1,'method':method,
                        'params':{'schema_version':1, **params}}) + '\n')
                    sender.flush()
                    return json.loads(reader.readline())
                try:
                    self.assertEqual(request('composer.complete', token='/ne')['result']['candidates'], ['/new'])
                    for token in ('@no', '@notes/'):
                        self.assertEqual(request('composer.complete', token=token)['error']['code'], 'denied')
                    sid = request('session.open', bootstrap_id='hook-preview')['result']['session_id']
                    self.assertEqual(request('composer.command', session_id=sid, kind='image', path='notes/figure.png')['error']['code'], 'denied')
                    self.assertFalse(marker.exists())
                finally:
                    sender.close()
                    child.wait(timeout=5)

if __name__ == '__main__':
    unittest.main()
