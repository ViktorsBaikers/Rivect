import { strict as assert } from 'node:assert';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Database } from 'bun:sqlite';
import { test } from 'bun:test';
import { connectCore, type CoreClient } from './core';
import { applyDelivery, record, snapshot, u64 } from './wire';

test('only canonical decimal u64 reaches the projection', () => {
  assert.equal(u64('18446744073709551615'), 18446744073709551615n);
  for (const bad of [1, '18446744073709551616', '-1', '01', '+1', '1.0', '1\n', '', null])
    assert.throws(() => u64(bad));
});

test('a session snapshot restores submitted text and provider reply without replay', () => {
  const raw = {kind:'snapshot', session_id:'s', task_id:'t', lifecycle:'waiting', revision:'3',
    event_cursor:'3', outbox_cursor:'7', goal:'first line\nsecond line', reply:'saved answer', events:[], activity:[]};
  const restored = snapshot(raw, 's', 't');
  assert.equal(restored.goal, raw.goal);
  assert.equal(restored.reply, raw.reply);
  assert.throws(() => snapshot({...raw, reply: {text:'invalid'}}, 's', 't'));
  const blocked = {...raw, lifecycle:'blocked', reply:undefined, error_code:'outcome_unknown'};
  assert.equal(snapshot(blocked, 's', 't').errorCode, 'outcome_unknown');
  assert.throws(() => snapshot({...blocked, reply:'looks successful'}, 's', 't'));
});

test('Rust task frames preserve adjacent large revisions, deduplicate a delivery and recover without another command', async () => {
  const home = mkdtempSync(join(tmpdir(), 'rivect-wire-'));
  const root = join(home, '.rivect');
  const previousRoot = process.env.RIVECT_DATA_ROOT;
  process.env.RIVECT_DATA_ROOT = root;
  const oldHome = process.env.HOME;
  process.env.HOME = home;
  const binary = join(import.meta.dir, 'build/core/rivect');
  const database = join(root, 'runtime/rivect.db');
  const base = 9007199254740992n;
  async function useCore<T>(fn: (core: CoreClient) => Promise<T>) {
    const core = await connectCore();
    try { return await fn(core); } finally { assert.equal(await core.close(), 0); }
  }
  // Run a real Rust owner with pipes closed at EOF. Fixture writes happen only
  // between owners; no parallel SQLite writer or synthetic JSON frame producer.
  function request(method: string, params: Record<string, unknown>, flag = '--ui-wire-v1') {
    const line = JSON.stringify({jsonrpc: '2.0', id: 1, method, params: {schema_version: 1, ...params}});
    const attach = JSON.stringify({jsonrpc:'2.0', id:0, method:'session.attach', params:{schema_version:1, session_id:params.session_id, bootstrap_id:crypto.randomUUID()}});
    const input = flag === '--headless' ? line : attach + '\n' + line;
    const p = Bun.spawnSync([binary, flag], {stdin: Buffer.from(input + '\n'), stdout: 'pipe', stderr: 'pipe',
      cwd: home, env: {HOME: home, TMPDIR: home, RIVECT_DATA_ROOT: root, PATH: '/usr/bin:/bin'}, timeout: 5000});
    assert.equal(p.exitCode, 0, p.stderr.toString());
    // Do not parse the public result with a JS number parser.
    if (flag === '--headless') return p.stdout.toString();
    const lines = p.stdout.toString().trimEnd().split('\n');
    assert.equal(lines.length, 2);
    assert.equal(JSON.parse(lines[0]!).result.session_id, params.session_id);
    const reply: unknown = JSON.parse(lines[1]!);
    assert(record(reply) && record(reply.result));
    return reply.result.frame;
  }
  try {
    const created = await useCore(core => core.submit('projection replay'));
    assert.equal(created.state, 'waiting');
    assert.equal(typeof created.revision, 'bigint');
    const {session, id} = created;
    const params = {session_id: session, task_id: id};
    function publish(revision: bigint, type: string, answered = false, detail = '{}') {
      const db = new Database(database, {readwrite: true, safeIntegers: true});
      try {
        if (revision === base) db.run('INSERT INTO attempts(attempt_id,task_id,action_id,effect_class,describe,state) VALUES(?,?,?,?,?,?)',
          ['proc-id', id, 'exec', 'exec', 'private command', 'confirmed']);
        db.transaction(() => {
          db.run('UPDATE tasks SET revision=?,event_cursor=?,lifecycle=? WHERE task_id=?',
            [revision, revision, revision > base ? 'completed' : 'waiting', id]);
          db.run(`INSERT INTO events(event_id,aggregate_id,aggregate_revision,cursor,session_id,task_id,event_type,delta_json,origin)
                  VALUES(?,?,?,?,?,?,?,?,'runtime')`, [crypto.randomUUID(), id, revision, revision, session, id, type, detail]);
          if (answered) {
            db.run(`INSERT INTO answer_attempts(question_id,task_id,question_revision,selection_json,author,outcome)
                    SELECT question_id,task_id,revision,'{}','human','applied' FROM questions WHERE task_id=?`, [id]);
            db.run("UPDATE questions SET state='answered' WHERE task_id=?", [id]);
          }
        })();
      } finally { db.close(); }
    }
    publish(base - 1n, 'diff.observed', false, '{"added":3,"removed":1,"patch":"private source line"}');
    publish(base, 'task.waiting');
    const attached = await useCore(core => core.resume(session));
    assert.equal(attached.more, false);
    assert.equal(attached.tasks.length, 1);
    const [first] = attached.tasks;
    assert.deepEqual([first.revision, first.eventCursor, first.outboxCursor], [base, base, base]);
    assert.equal(first.events.at(-1)?.category, 'waiting');
    assert.equal(first.events.at(-2)?.text, '+3 −1');
    assert(!JSON.stringify(first.events).includes('private source line'));
    assert(first.activity?.some(event => event.category === 'process' && event.text === 'confirmed'));
    assert(!JSON.stringify(first.activity).includes('private command'));
    publish(base + 1n, 'question.answered', true);
    const delta = request('task.changes', {...params, after: base.toString()});
    assert(record(delta) && delta.kind === 'delta', JSON.stringify(delta));
    const noRead = async (): Promise<never> => { throw new Error('duplicate or contiguous delivery caused resync'); };
    const second = await applyDelivery(first, delta, noRead);
    assert.equal(second.state, 'completed');
    assert.deepEqual([second.revision, second.eventCursor, second.outboxCursor], [base + 1n, base + 1n, base + 1n]);
    assert.equal(await applyDelivery(second, delta, noRead), second);
    assert.deepEqual(second.events.map(event => event.type), [...first.events.map(event => event.type), 'question.answered']);
    await assert.rejects(applyDelivery({...first, session: crypto.randomUUID()}, delta, noRead), /owner/);
    publish(base + 2n, 'task.changed');
    publish(base + 3n, 'task.changed');
    const marker = request('task.changes', {...params, after: second.outboxCursor.toString()});
    assert(record(marker) && marker.kind === 'resync_marker');
    assert.equal(marker.revision, '9007199254740995');
    let reads = 0;
    const restored = await applyDelivery(second, marker, async () => { reads++; return request('task.snapshot', params); });
    assert.equal(reads, 1);
    assert.deepEqual([restored.revision, restored.eventCursor, restored.outboxCursor], [base + 3n, base + 3n, base + 3n]);
    assert.deepEqual(restored.events.map(event => event.type), [...second.events.map(event => event.type), 'task.changed', 'task.changed']);
    assert.equal(await applyDelivery(restored, delta, noRead), restored);
    const refreshed = await useCore(async core => { await core.resume(session); return core.refresh(second); });
    assert.deepEqual(refreshed, restored);
    const headless = request('task.snapshot', params, '--headless');
    assert.equal(typeof headless, 'string');
    assert.match(String(headless), /"revision":9007199254740995[,}]/u);
    // A stopped WAL owner removes its sidecars. Allow SQLite to recreate them,
    // but forbid changes to the database being inspected.
    const db = new Database(database, {readwrite: true, safeIntegers: true});
    try {
      db.run('PRAGMA query_only = ON');
      assert.deepEqual(db.query('SELECT outcome,author FROM answer_attempts').all(), [{outcome:'applied',author:'human'}]);
      assert.deepEqual(db.query('SELECT count(*) AS n FROM command_receipts').get(), {n:1n});
      assert.deepEqual(db.query('SELECT count(*) AS n FROM attempts').get(), {n:1n});
    } finally { db.close(); }
  } finally {
    if (previousRoot === undefined) delete process.env.RIVECT_DATA_ROOT; else process.env.RIVECT_DATA_ROOT = previousRoot;
    if (oldHome === undefined) delete process.env.HOME; else process.env.HOME = oldHome;
    rmSync(home, {recursive: true, force: true});
  }
});
