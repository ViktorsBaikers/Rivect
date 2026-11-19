import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {once} from 'node:events';
import {readFile} from 'node:fs/promises';
import {createServer} from 'node:http';
import {setTimeout as delay} from 'node:timers/promises';
import {send} from '../tests/fixtures/messages-sdk/sdk.mjs';

const fixtures = new URL('../tests/fixtures/messages-sdk/', import.meta.url);
const descriptor = JSON.parse(await readFile(new URL('read-file.json', fixtures)));
const stream = await readFile(new URL('tool.sse', fixtures), 'utf8');
const corpus = {
  split: stream,
  incomplete: stream.slice(0, stream.indexOf('event: message_stop')),
  partial: stream.replace('café.ts\\"}', 'café.ts'),
  extension: stream.replace('event: content_block_start', 'event: future_event\ndata: {"type":"future_event"}\n\nevent: content_block_start'),
  pause_turn: stream.replace('"type":"tool_use","id":"toolu_fixture","name":"read_file"', '"type":"server_tool_use","id":"srvtoolu_fixture","name":"web_search"')
    .replace('{\\"pa', '{\\"que').replace('th\\":', 'ry\\":').replace('"stop_reason":"tool_use"', '"stop_reason":"pause_turn"'),
  unknown_stop: stream.replace('"stop_reason":"tool_use"', '"stop_reason":"fixture_future"'),
  unknown_usage: stream.replace(',"usage":{"input_tokens":4,"output_tokens":1}', '').replace(',"usage":{"output_tokens":3}', ''),
  cancel: stream,
  disconnect: null,
  redirect: null,
};
for (const name of ['incomplete','partial','extension','unknown_stop','unknown_usage']) assert.notEqual(corpus[name], stream, name);
const baseline = {model: 'claude-opus-4-8', messages: [{role: 'user', content: 'fixture'}], max_tokens: 8192, tools: [descriptor], stream: true};
const binary = process.argv[2];
assert(binary, 'pass the compiled Rust integration test or --sdk-only');
const cases = process.argv[3] ? [process.argv[3]] : Object.keys(corpus);

async function listen(handler) {
  const server = createServer(handler);
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  return server;
}

function runRust(port, name) {
  const child = spawn(binary, ['--ignored', '--exact', 'direct_against_shared_peer', '--nocapture'], {
    env: {RIVECT_MESSAGES_TRIAL_PORT: String(port), RIVECT_MESSAGES_TRIAL_CASE: name},
    stdio: ['pipe','pipe','pipe'], timeout: 8000, killSignal: 'SIGKILL',
  });
  let out = '', err = '';
  child.stdout.on('data', bytes => { out += bytes; });
  child.stderr.on('data', bytes => { err += bytes; });
  const result = (async () => {
    const [status, signal] = await once(child, 'close');
    assert.equal(status, 0, `${signal ?? ''} ${out} ${err}`);
    const row = /^OBS (.+)$/m.exec(out);
    assert(row, out);
    return JSON.parse(row[1]);
  })();
  return {result, cancel: () => child.stdin.end('cancel\n')};
}

async function trial(client, name, body) {
  const wire = [], redirects = [];
  let cancel, releaseTimer, socketCloseMs;
  let released = false;
  const sink = await listen((req, res) => {
    redirects.push({credential: Boolean(req.headers['x-api-key'] || req.headers.authorization)});
    res.writeHead(403).end();
  });
  const peer = await listen(async (req, res) => {
    const bytes = [];
    for await (const chunk of req) bytes.push(chunk);
    wire.push({method: req.method, path: req.url, origin: req.headers.host,
      version: req.headers['anthropic-version'], key: req.headers['x-api-key'] === 'fixture-not-a-key',
      bearer: Boolean(req.headers.authorization), body: JSON.parse(Buffer.concat(bytes))});
    if (name === 'disconnect') return req.socket.destroy();
    if (name === 'redirect') return res.writeHead(307, {location: `http://127.0.0.1:${sink.address().port}/sink`}).end();
    if (name === 'cancel') {
      const cancelAt = performance.now();
      res.on('close', () => { if (!res.writableEnded) socketCloseMs = performance.now() - cancelAt; });
      releaseTimer = setTimeout(() => {
        released = true;
        res.writeHead(200, {'content-type':'text/event-stream'}).end(corpus.cancel);
      }, 1000);
      cancel();
      return;
    }
    res.writeHead(200, {'content-type':'text/event-stream'}).end(corpus[name]);
  });
  try {
    let outcome;
    if (client === 'rust') {
      const rust = runRust(peer.address().port, name);
      cancel = rust.cancel;
      outcome = await rust.result;
    } else {
      const controller = new AbortController();
      cancel = () => controller.abort();
      outcome = await send(peer.address().port, body, controller.signal);
    }
    if (client === 'sdk' && name === 'cancel') {
      for (let i = 0; i < 100 && socketCloseMs === undefined; ++i) await delay(10);
      assert.notEqual(socketCloseMs, undefined, 'aborted POST must close the peer socket');
    }
    if (name === 'cancel') assert.equal(released, client === 'rust');
    const row = {client, name, posts: wire.length, redirects, outcome, socketCloseMs,
      ...(name === 'cancel' && {responseReleased: released})};
    console.log(JSON.stringify(row));
    assert.equal(wire.length, 1, 'one physical request');
    const post = wire[0];
    assert.equal(post.method, 'POST');
    assert.equal(post.path, '/v1/messages');
    assert.equal(post.origin, `127.0.0.1:${peer.address().port}`);
    assert.equal(post.version, '2023-06-01', 'do not migrate API version in the SDK trial');
    assert.equal(post.key, true);
    assert.equal(post.bearer, false);
    assert.deepEqual(redirects, [], 'no request, even without credentials, to a second origin');
    assert.deepEqual(post.body.tools, [descriptor]);
    assert.equal(post.body.stream, true);
    if (client === 'sdk') assert.deepEqual(post.body, body);
    if (name === 'split' || name === 'extension' || (name === 'cancel' && client === 'rust')) {
      assert.deepEqual(outcome.args, {path: 'café.ts'});
      assert.equal(outcome.tool, 'read_file');
      assert.equal(outcome.input, 4);
      assert.equal(outcome.output, 3);
    }
    if (['incomplete','disconnect','redirect'].includes(name) || (name === 'cancel' && client === 'sdk')) assert.equal(outcome.status, 'error');
    if (client === 'rust') {
      const expected = {partial: 'StreamViolation', incomplete: 'UnknownTerminal',
        unknown_stop: 'UnknownTerminal', pause_turn: 'IncompatibleOutput'};
      if (Object.hasOwn(expected, name)) assert.deepEqual(outcome, {status: 'error', kind: expected[name]});
      if (name === 'unknown_usage') assert.equal(outcome.status, 'ok');
    }
    if (name === 'unknown_usage' && outcome.status === 'ok') {
      assert.equal(outcome.input, null);
      assert.equal(outcome.output, null);
    }
    return post.body;
  } finally {
    clearTimeout(releaseTimer);
    for (const server of [peer, sink]) { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
  }
}
for (const name of cases) {
  assert(Object.hasOwn(corpus, name), 'unknown trial');
  const body = binary === '--sdk-only' ? baseline : await trial('rust', name);
  await trial('sdk', name, body);
}
