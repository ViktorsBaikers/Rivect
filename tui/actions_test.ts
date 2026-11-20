import { test } from 'bun:test';
import { strict as assert } from 'node:assert';
import { mkdtempSync, rmSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { connectCore } from './core';
import { operatorAction } from './actions';
import type { SettingsRequest } from './settings-data';
import { looksLikeOAuthCallback } from './auth-input';
import { applyDelivery, snapshot } from './wire';

test('callback-bearing drafts never qualify as ordinary input', () => {
  for (const draft of ['http://localhost:1455/auth/callback', '/task https://app.test/return?%63ode=',
    'https://app.test/old#access_token=', '/login http://wrong']) assert(looksLikeOAuthCallback(draft));
  for (const draft of ['/login', '/login callback', '/login device', '/login cancel', '/login complete',
    'visit https://example.test/docs?page=2']) assert.equal(looksLikeOAuthCallback(draft),false);
});

test('a provider echo of old private input stays out of previews and restored replies', async () => {
  const raw = {kind:'snapshot', session_id:'s', task_id:'t', lifecycle:'running', revision:'1', event_cursor:'1', outbox_cursor:'1',
    goal:'http://localhost:1455/auth/callback?code=private-old-code', activity:[], events:[]};
  const task = snapshot(raw, 's');
  const text = 'private-old-code';
  const next = await applyDelivery(task, {...raw, kind:'preview', offset:0, text}, async () => raw);
  assert.equal(next.preview?.bytes, Buffer.byteLength(text));
  assert.equal(next.preview?.text, '');
  assert.equal(snapshot({...raw, lifecycle:'completed', reply:text}, 's').reply, undefined);
});

const states = ['start-no-connection', 'no-project-index', 'ready-for-input', 'streaming-long-output',
  'parallel-work', 'awaiting-decision', 'awaiting-permission', 'fullscreen-inline', 'pause-cancel',
  'quota-fallback', 'error-offline-partial', 'success', 'settings-default-modified-locked-pending',
  'settings-invalid-conflict', 'resume-compaction-upgrade', 'rewind-preview-conflict-partial',
  'big-list-narrow-window', 'workflow-off', 'non-tty'];

test('all nineteen passive states project without opening the store', () => {
  const home = mkdtempSync(join(tmpdir(), 'rivect-review-'));
  try {
    for (const state of [...states, 'unknown-state']) {
      const run = Bun.spawnSync([join(import.meta.dir, 'build/core/rivect'), '--ui-review-data', state],
        {cwd: home, env: {HOME: home, RIVECT_DATA_ROOT: home, PATH: '/usr/bin:/bin'}, timeout: 5000});
      if (state === 'unknown-state') { assert.notEqual(run.exitCode, 0); continue; }
      assert.equal(run.exitCode, 0, state);
      const frame = JSON.parse(run.stdout.toString());
      assert.equal(frame.state, state);
      if (state === 'awaiting-permission') assert.match(frame.panel.join(' '), /deny/i);
      if (state === 'awaiting-decision') assert.match(frame.panel.join(' '), /custom/i);
      if (state === 'ready-for-input') assert.equal(frame.composer, 'draft a change');
    }
    assert.deepEqual(readdirSync(home), []);
  } finally { rmSync(home, {recursive: true, force: true}); }
});

test('operator projections use the bound core; pasted or extended commands do not parse', async () => {
  const home = mkdtempSync(join(tmpdir(), 'rivect-operator-'));
  const prev = process.env.RIVECT_DATA_ROOT, oldHome = process.env.HOME;
  process.env.RIVECT_DATA_ROOT = home; process.env.HOME = home;
  try {
    writeFileSync(join(home, 'config.toml'), [
      'config_version = 1', '[connections.openai-codex]', 'kind = "api_key"',
      'endpoint = "https://chatgpt.com/backend-api/codex"', 'credential_ref = "keychain:rivect-test/openai-codex"',
      'profile = "openai-codex"', '[profiles.openai-codex]', 'credential_ref = "keychain:rivect-test/openai-codex"',
      '[models.defaults]', 'model = { mode = "auto" }', 'effort = { mode = "auto" }', 'fallback = { mode = "off" }',
    ].join('\n'));
    const core = await connectCore();
    try {
      const center = (request: SettingsRequest) => core.settings({kind:'settings_center', request});
      const file = join(home,'config.toml'), before = readFileSync(file);
      const initial = await center({op:'inspect'});
      assert.equal(initial.userConfig,true);
      assert(initial.entries.some(row => row.key === 'connections.openai-codex.profile'));
      assert.match(initial.harness,/running 0/);
      assert.deepEqual(readFileSync(file), before);
      const change = {scope:'user' as const,key:'workflow.enabled',expected_source_digest:initial.digest};
      const disabled = await center({op:'set',...change,value:false});
      assert.equal(disabled.entries.find(row=>row.key === change.key)?.value,false);
      const saved = readFileSync(file);
      await assert.rejects(center({op:'reset',...change}),/conflict/);
      assert.deepEqual(readFileSync(file),saved);
      const reset = await center({op:'reset',...change,expected_source_digest:disabled.digest});
      assert.equal(reset.entries.find(row=>row.key === change.key)?.source,'shipped');
      const policy = await center({op:'set',key:'decisions.mode',scope:'user',expected_source_digest:reset.digest,value:'auto'});
      assert.equal(policy.entries.find(row=>row.key === 'decisions.mode')?.value,'auto');
      await center({op:'set',key:'decisions.mode',scope:'user',expected_source_digest:policy.digest,value:'ask'});
      for (const [input, expected] of [['/config', /Settings:/], ['/permissions', /Permissions:/],
        ['/accounting', /economy|quota|tokens/i], ['/login cancel', /No login is pending/]] as const) {
        const action = operatorAction(input);
        assert(action);
        assert.match((await core.action(action)).join('\n'), expected);
      }
      const login = await core.action({kind: 'login_browser'});
      assert.equal(core.loginStatus,'Login pending · /login cancel');
      assert.match(login[0]!, /^Login pending: https:\/\//u);
      assert(!login.join(' ').includes('code_verifier'));
      await assert.rejects(core.action({kind: 'login_complete'})); // Browser leg requires a callback; no exchange.
      assert.deepEqual(await core.action({kind: 'login_cancel'}), ['Login cancelled.']);
      assert.equal(core.loginStatus,'Session not connected · Run /login');
      // The picker reads the core catalogue, not a client-side provider list.
      const providers = await core.loginProviders();
      assert.deepEqual(providers.map(provider => provider.id),
        ['anthropic', 'github-copilot', 'kimi-code', 'openai-codex', 'zai']);
      const codex = providers.find(provider => provider.id === 'openai-codex');
      assert.deepEqual(codex?.methods.map(method => method.id), ['browser', 'device']);
      assert.equal(codex?.methods[0]?.capture, true);
      assert.equal(providers.find(provider => provider.id === 'zai')?.methods[0]?.capture, false);
      // Selecting a row declares its connection through the journaled edit.
      await core.login({kind:'login_connect', provider:'anthropic'});
      const declared = await core.loginProviders();
      assert.equal(declared.find(provider => provider.id === 'anthropic')?.declared, true);
      // A method the row does not record is refused by the core.
      await assert.rejects(core.login({kind:'login_start', provider:'zai', method:'device'}));
      for (const input of ['/settings now', '/login cancel\n/permissions', '/grant everything', '/config\n'])
        assert.equal(operatorAction(input), undefined);
      // An older client could persist a callback as a goal. Reopening must not echo it.
      const waiting = await core.submit('http://localhost:1455/auth/callback?code=old-private-input', 'project');
      assert.equal(waiting.goal, '[private login input omitted]');
      assert.equal((await core.resume(waiting.session)).tasks.find(task=>task.id === waiting.id)?.goal, waiting.goal);
      const card = await core.question(waiting);
      assert(card);
      assert.equal(card.prompt, 'Begin the first step');
      assert.equal(card.pin.task_id, waiting.id);
      const selected = card.options.find(row => row.id === card.recommended);
      assert(selected);
      await assert.rejects(core.answer(card, {kind: 'option', option_id: selected.id}));
      assert.deepEqual(await core.question(waiting), card);
      await core.newSession();
      await assert.rejects(core.question(waiting));
      await assert.rejects(core.answer(card, {kind: 'custom', text: 'not this session'}));
    } finally { await core.close(); }
  } finally {
    if (prev === undefined) delete process.env.RIVECT_DATA_ROOT; else process.env.RIVECT_DATA_ROOT = prev;
    if (oldHome === undefined) delete process.env.HOME; else process.env.HOME = oldHome;
    rmSync(home, {recursive: true, force: true});
  }
});
