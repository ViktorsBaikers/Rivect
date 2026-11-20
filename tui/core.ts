import { constants, lstatSync, readFileSync } from 'node:fs';
import { open } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { applyDelivery, decodeImage, record, snapshot, type Image, type Task } from './wire';
import { decodeQuestion, loginPending, loginProviders, type LoginAction, type LoginProvider, type LoginReceipt, type OperatorAction, type Question, type Selection } from './actions';
import { decodeSettings, missingUserConfig, type SettingsAction, type SettingsPage } from './settings-data';
import { loginStatus } from './auth-input';
import { terminalText } from './modes-output';
import { decodePermission, type Permission, type PermissionChoice } from './permission-data';
import { compactNotShorter, decodeDock, type Dock } from './dock-data';

const frameLimit = 1 << 20;
const packaged = import.meta.dir.startsWith('/$bunfs/');
const root = packaged ? dirname(dirname(process.execPath)) : join(import.meta.dir, 'build', 'core');
const executable = join(root, 'rivect');

function installedCoreDigest(): string {
  const receipt = root + '.manifest.sha256', manifest = join(root, 'rivect.manifest.json');
  const stamp = lstatSync(receipt), inventory = lstatSync(manifest);
  if (!stamp.isFile() || stamp.size !== 65 || !inventory.isFile() || inventory.size > 64 * 1024)
    throw new Error('invalid release metadata');
  const bytes = readFileSync(manifest);
  if (new Bun.CryptoHasher('sha256').update(bytes).digest('hex') + '\n' !== readFileSync(receipt, 'ascii'))
    throw new Error('invalid release manifest digest');
  const data: unknown = JSON.parse(bytes.toString('utf8'));
  if (!record(data) || data.schema_version !== 2 || !record(data.executable) || data.executable.name !== 'rivect' ||
      typeof data.executable.sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(data.executable.sha256))
    throw new Error('invalid release executable');
  return data.executable.sha256;
}
// Pin at startup: a reconnect must not adopt a later manifest or active release.
const pinnedCore = packaged ? installedCoreDigest() : undefined;

class CoreRefusal extends Error {}
export type { Image } from './wire';

const bootCauses = ['another owner already holds this data root', 'owner configuration failed',
  'owner storage failed', 'owner i/o failed', 'supervisor construction failed'];

export class BootFailure extends Error {
  constructor(cause: string, readonly diagnostics: string[]) {
    super('tui runtime open failed: ' + cause);
  }
}

function recovery(value: unknown): string[] {
  if (!record(value) || !Array.isArray(value.lines) || value.lines.length > 256 ||
      !value.lines.every(line => typeof line === 'string') ||
      typeof value.omitted !== 'number' || !Number.isSafeInteger(value.omitted) || value.omitted < 0)
    throw new Error('invalid recovery diagnostics');
  const lines: string[] = value.lines.map(line => terminalText(line).replaceAll('\n', '\\n'));
  if (value.omitted) lines.push(`${value.omitted} more recovery diagnostics; see core stderr for the full list`);
  return lines;
}

export interface CoreClient {
  readonly disconnected: boolean;
  readonly boot: {diagnostics: string[]; previous: string | null; loginAvailable:boolean};
  readonly loginStatus:string;
  close(): Promise<number>;
  complete(token: string): Promise<string[]>;
  action(action: OperatorAction): Promise<string[]>;
  loginProviders(): Promise<LoginProvider[]>;
  login(action: LoginAction): Promise<LoginReceipt>;
  settings(action: SettingsAction): Promise<SettingsPage>;
  dock(task: Task): Promise<Dock>;
  permission(): Promise<Permission | undefined>;
  resolvePermission(permission: Permission, choice: PermissionChoice): Promise<{closed:boolean; note:string}>;
  question(task: Task): Promise<Question | undefined>;
  reveal(question: Question): Promise<string>;
  answer(question: Question, selection: Selection, image?: Image): Promise<string[]>;
  command(kind: 'compact' | 'rewind' | 'image' | 'read', detail: {task_id?: string; path?: string}): Promise<{lines: string[]; image?: Image}>;
  newSession(): Promise<{session: string; previous: string} | {running: string}>;
  recentSessions(): Promise<string[]>;
  resume(target: string): Promise<{tasks: Task[]; more: boolean}>;
  older(before: Task): Promise<{tasks: Task[]; more: boolean}>;
  refresh(task: Task): Promise<Task>;
  cancel(task: Task): Promise<Task>;
  submit(goal: string, kind?: 'project'): Promise<Task>;
}

export async function verifiedCore(): Promise<string> {
  if (pinnedCore !== undefined) {
    const file = await open(executable, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    try {
      if (!(await file.stat()).isFile()) throw new Error('invalid installed core');
      const hash = new Bun.CryptoHasher('sha256');
      for await (const chunk of file.createReadStream({autoClose: false})) hash.update(chunk);
      if (hash.digest('hex') !== pinnedCore) throw new Error('installed core checksum mismatch');
    } finally { await file.close(); }
  }
  return executable;
}

function strings(value: unknown): string[] {
  if (!Array.isArray(value) || !value.every(item => typeof item === 'string')) throw new Error('invalid core list');
  return value;
}

function taskPage(reply: Record<string, unknown>, target: string, before?: string) {
  if (reply.session_id !== target || !Array.isArray(reply.tasks) || reply.tasks.length > 20 ||
      typeof reply.more !== 'boolean' || (!reply.tasks.length && reply.more)) throw new Error('invalid task page');
  const tasks = reply.tasks.map((raw: unknown) => snapshot(raw, target));
  const ids = new Set(tasks.map(task => task.id));
  if (ids.size !== tasks.length || (before !== undefined && ids.has(before))) throw new Error('non-advancing task page');
  return {tasks, more: reply.more};
}

// Fatal renderer teardown can happen while a newly spawned owner is still
// handshaking, before Thread has a CoreClient to close.
const ownerClosers = new Set<() => Promise<number>>();
let stopping = false;
export async function closeTerminalOwners() {
  stopping = true;
  await Promise.all(Array.from(ownerClosers, close => close()));
}

/** One outstanding request; neither UIs nor subprocess stdout grant human authority. */
export async function connectCore(): Promise<CoreClient> {
  const mode = packaged && process.argv.includes('--terminal-client') ? '--ui-terminal-wire-v1' : '--ui-wire-v1';
  let program: string;
  try { program = await verifiedCore(); }
  catch { throw new BootFailure('installed core unavailable or invalid', []); }
  if (stopping) throw new Error('terminal client stopped');
  const child = Bun.spawn([program, mode], {
    stdin: 'pipe', stdout: 'pipe', stderr: 'inherit',
    env: Object.fromEntries(['HOME', 'TMPDIR', 'LANG', 'PATH', 'RIVECT_DATA_ROOT'].flatMap(key =>
      process.env[key] === undefined ? [] : [[key, process.env[key]!]])),
  });
  const reader = child.stdout.getReader();
  let busy = false;
  let session: string | undefined;
  let closed = false;
  function close() {
    if (closed) return child.exited;
    closed = true;
    child.stdin.end();
    const timer = setTimeout(() => child.kill('SIGKILL'), 2000);
    void child.exited.finally(() => clearTimeout(timer));
    return child.exited;
  }
  ownerClosers.add(close);
  void child.exited.then(() => ownerClosers.delete(close));
  async function request(method: string, params: Record<string, unknown>) {
    if (busy) throw new Error('core request already pending');
    const id = crypto.randomUUID();
    const frame = JSON.stringify({ jsonrpc: '2.0', id, method, params: { schema_version: 1, ...params } }) + '\n';
    if (Buffer.byteLength(frame) > frameLimit) throw new Error('message exceeds core limit');
    if (closed) throw new Error('core connection closed');
    busy = true;
    try {
      child.stdin.write(frame);
      await child.stdin.flush();
      const chunks: Uint8Array[] = [];
      let bytes = 0;
      for (;;) {
        const {done, value} = await reader.read();
        if (done) throw new Error('core closed before replying');
        bytes += value.length;
        if (bytes > frameLimit) throw new Error('core reply exceeds limit');
        chunks.push(value);
        const newline = value.indexOf(10);
        if (newline < 0) continue;
        if (newline !== value.length - 1) throw new Error('unexpected trailing core frame');
        const reply: unknown = JSON.parse(Buffer.concat(chunks, bytes).toString('utf8'));
        if (!record(reply) || reply.jsonrpc !== '2.0' || reply.id !== id) throw new Error('invalid core reply');
        if (record(reply.error)) {
          if (method === 'runtime.boot' && typeof reply.error.cause === 'string' && bootCauses.includes(reply.error.cause))
            throw new BootFailure(reply.error.cause, recovery(reply.error.recovery));
          if (method === 'composer.command' && params.kind === 'compact' && reply.error.code === 'conflict' && reply.error.cause === 'compaction_not_shorter')
            throw new CoreRefusal(compactNotShorter);
          if (reply.error.code === 'conflict') throw new CoreRefusal('conflict: refresh before retrying');
          if (reply.error.code === 'not_found' && method === 'operator.action' && record(params.action) && params.action.kind === 'settings_center')
            throw new CoreRefusal(missingUserConfig);
          if (reply.error.code === 'outcome_unknown') throw new CoreRefusal('command outcome unknown; inspect session before retrying');
          throw new CoreRefusal('core refused request');
        }
        if (!record(reply.result)) throw new Error('invalid core result');
        return reply.result;
      }
    } catch (error) { if (!(error instanceof CoreRefusal)) close(); throw error; }
    finally { busy = false; }
  }
  async function currentSession() {
    if (!session) {
      const opened = await request('session.project', {});
      if (typeof opened.session_id !== 'string') throw new Error('invalid core session');
      session = opened.session_id;
    }
    return session;
  }
  let boot: CoreClient['boot'];
  let pendingLogin = false, authenticated:string | undefined;
  try {
    const reply = await request('runtime.boot', {});
    if (reply.session_id !== null && typeof reply.session_id !== 'string') throw new Error('invalid project session');
    if (typeof reply.login_available !== 'boolean') throw new Error('invalid login availability');
    boot = {diagnostics: recovery(reply.recovery), previous: reply.session_id, loginAvailable:reply.login_available};
  } catch (error) { await close(); throw error; }
  return { boot, close, get disconnected() { return closed || child.exitCode != null || child.signalCode != null; },
    get loginStatus() { return pendingLogin ? 'Login pending · /login cancel' : authenticated ?? loginStatus(boot.loginAvailable); },
    async complete(token) { return strings((await request('composer.complete', {token})).candidates); },
    async action(action) {
      const reply = await request('operator.action', {session_id: await currentSession(), action});
      const lines = strings(reply.lines);
      if (action.kind.startsWith('login_')) {
        if (reply.login === 'connected' && typeof reply.status === 'string') authenticated = reply.status;
        else if (reply.login !== 'pending' && reply.login !== 'idle') throw new Error('invalid login receipt');
        pendingLogin = reply.login === 'pending';
      }
      return lines;
    },
    async loginProviders() {
      const reply = await request('operator.action', {session_id: await currentSession(), action:{kind:'login_providers'}});
      if (reply.login !== 'idle') throw new Error('invalid sign-in catalogue');
      return loginProviders(reply.providers);
    },
    async login(action) {
      const reply = await request('operator.action', {session_id: await currentSession(), action});
      const lines = strings(reply.lines);
      if (reply.login === 'connected' && typeof reply.status === 'string') authenticated = reply.status;
      else if (reply.login !== 'pending' && reply.login !== 'idle') throw new Error('invalid login receipt');
      pendingLogin = reply.login === 'pending';
      return {lines, pending: loginPending(reply.pending)};
    },
    async dock(task) {
      if (!session || task.session !== session) throw new CoreRefusal('inactive dock subject');
      return decodeDock(await request('operator.action', {session_id:session, action:{kind:'dock',task_id:task.id}}),task);
    },
    async settings(action) { return decodeSettings(await request('operator.action', {session_id: await currentSession(), action})); },
    async permission() {
      if (mode !== '--ui-terminal-wire-v1' || !session) return;
      return decodePermission((await request('operator.permission', {session_id:session})).permission, session);
    },
    async resolvePermission(permission, choice) {
      if (mode !== '--ui-terminal-wire-v1' || permission.session_id !== session) throw new Error('inactive permission');
      const r = await request('operator.permission.resolve', {session_id:session, request_id:permission.request_id, choice});
      if (typeof r.closed !== 'boolean' || typeof r.note !== 'string') throw new Error('invalid permission receipt');
      return {closed:r.closed,note:r.note};
    },
    async question(task) {
      if (task.session !== session) throw new Error('inactive task session');
      return decodeQuestion(await request('operator.question', {session_id: task.session, task_id: task.id}), task);
    },
    async reveal(question) {
      if (question.session !== session || !question.canRevealDiff) throw new Error('inactive proposal');
      const {diff} = await request('operator.diff', {...question.pin, session_id: session});
      if (typeof diff !== 'string' || !diff || Buffer.byteLength(diff) > 65536) throw new Error('invalid proposal');
      return diff;
    },
    async answer(question, selection, image) {
      if (question.session !== session) throw new Error('inactive question session');
      return strings((await request('operator.answer', {...question.pin, session_id: session, selection, ...(image && {image})})).lines);
    },
    async command(kind, detail) {
      const reply = await request('composer.command', {...detail, kind, session_id: await currentSession()});
      const lines = strings(reply.lines);
      if (reply.image === undefined) return {lines};
      return {lines, image: decodeImage(reply.image)};
    },
    async newSession() {
    const previous = await currentSession();
    const next = await request('command.execute', {session_id: previous, command: {kind: 'session.new'}});
    if (next.previous_session_id === previous && typeof next.running === 'string' && next.running && next.session_id === undefined) return {running: next.running};
    if (next.previous_session_id !== previous || typeof next.session_id !== 'string' || next.session_id === previous)
      throw new Error('invalid session switch');
    session = next.session_id;
    return {session, previous};
  }, async recentSessions() {
    const {sessions} = await request('session.recent', {});
    if (!Array.isArray(sessions) || !sessions.every(id => typeof id === 'string'))
      throw new Error('invalid session list');
    return sessions;
  }, async resume(target: string) {
    const attached = await request('session.attach', {session_id: target, bootstrap_id: crypto.randomUUID()});
    const page = taskPage(attached, target);
    session = target;
    return page;
  }, async older(before: Task) {
    if (before.session !== session) throw new Error('inactive task session');
    return taskPage(await request('session.older', {session_id: before.session, before: before.id}), before.session, before.id);
  }, async refresh(task: Task) {
    if (task.session !== session) throw new Error('inactive task session');
    const params = {session_id: task.session, task_id: task.id};
    const {frame} = await request('task.changes', {...params, after: task.outboxCursor.toString(), preview_bytes: task.preview?.bytes ?? 0});
    return applyDelivery(task, frame, async () => (await request('task.snapshot', params)).frame);
  }, async cancel(task: Task) {
    if (task.session !== session) throw new Error('inactive task session');
    const {frame} = await request('task.cancel', {session_id: task.session, task_id: task.id});
    return snapshot(frame, task.session, task.id);
  }, async submit(goal: string, kind?: 'project') {
    const target = await currentSession();
    const params = {command_id: crypto.randomUUID(), session_id: target, goal};
    const receipt = kind === 'project'
      ? await request('task.submit', {...params, kind:'create', first_question:true, contract:{criteria:[], constraints:[]}})
      : await request('task.message', params);
    if (receipt.status !== 'accepted' || typeof receipt.task_id !== 'string') throw new Error('invalid task receipt');
    return snapshot(receipt.snapshot, target, receipt.task_id);
  }};
}
