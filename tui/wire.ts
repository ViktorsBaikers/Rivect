import { looksLikeOAuthCallback } from './auth-input';

export const record = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

export function u64(value: unknown): bigint {
  if (typeof value !== 'string' || !value.length || value.length > 20 || /[^0-9]/u.test(value) ||
      (value.length > 1 && value[0] === '0')) throw new Error('invalid decimal counter');
  const n = BigInt(value);
  if (n > 0xffffffffffffffffn) throw new Error('counter exceeds u64');
  return n;
}

export type Image = Readonly<{path: string; media_type: string; bytes: number; sha256: string; identity: string}>;

export function decodeImage(raw: unknown): Image {
  if (!record(raw) || typeof raw.path !== 'string' || !raw.path || typeof raw.media_type !== 'string' ||
      !['png', 'jpeg', 'webp'].includes(raw.media_type) || typeof raw.bytes !== 'number' || !Number.isInteger(raw.bytes) ||
      raw.bytes <= 0 || raw.bytes > 512 * 1024 || typeof raw.sha256 !== 'string' || raw.sha256.length !== 64 ||
      /[^0-9a-f]/u.test(raw.sha256) || typeof raw.identity !== 'string' || raw.identity.length > 83) throw new Error('invalid image receipt');
  const ids = raw.identity.split(':');
  if (ids.length !== 4) throw new Error('invalid image identity');
  ids.forEach(u64);
  return {path:raw.path, media_type:raw.media_type, bytes:raw.bytes, sha256:raw.sha256, identity:raw.identity};
}

type Lifecycle = 'running' | 'waiting' | 'paused' | 'blocked' | 'completed' | 'cancelled';
type Position = Readonly<{session: string; id: string; state: Lifecycle; origin?: string; goal?: string; reply?: string; errorCode?: string;
  privateInput?: boolean; output?: Readonly<{status: string; text?: string}>; proposedDiff?: string; activity?: readonly TaskEvent[]; revision: bigint; eventCursor: bigint; outboxCursor: bigint}>;
const categories = ['task', 'agent', 'process', 'stage', 'tool', 'diff', 'evidence', 'waiting'] as const;
export type TaskEvent = Readonly<{id: string; type: string; category?: typeof categories[number]; text?: string}>;

function decodeEvent(raw: unknown): TaskEvent {
  if (!record(raw) || typeof raw.event_id !== 'string' || !raw.event_id ||
      typeof raw.event_type !== 'string' || !raw.event_type) throw new Error('invalid task event');
  const category = categories.find(item => item === raw.category);
  if (!category || (raw.text !== undefined && typeof raw.text !== 'string')) throw new Error('invalid event detail');
  return {id: raw.event_id, type: raw.event_type, category, text: raw.text};
}
function eventList(raw: unknown): TaskEvent[] {
  if (!Array.isArray(raw) || raw.length > 32) throw new Error('invalid event history');
  return raw.map(decodeEvent);
}
function sameEvents(a: readonly TaskEvent[], b: readonly TaskEvent[]): boolean {
  return a.length === b.length && a.every((item, i) => {
    const other = b[i]!;
    return item.id === other.id && item.type === other.type && item.category === other.category && item.text === other.text;
  });
}
export type Task = Position & {readonly events: readonly TaskEvent[]; readonly preview?: Readonly<{text: string; bytes: number; status?: string}>};
export function goalAuthor(task: Task): 'You' | 'Machine' | 'Task' {
  if (task.goal === undefined) return 'Task';
  if (task.origin === 'machine') return 'Machine';
  return task.origin === 'ui-message' || task.origin === 'local_user' ? 'You' : 'Task';
}
type Frame = {kind: 'snapshot'; position: Position; events: TaskEvent[]} | {kind: 'resync_marker'; position: Position} |
  {kind: 'delta'; position: Position; after: bigint; event: TaskEvent};

function decode(raw: unknown, session: string, task?: string): Frame {
  if (!record(raw) || raw.session_id !== session || typeof raw.task_id !== 'string' || !raw.task_id ||
      (task !== undefined && raw.task_id !== task)) throw new Error('unexpected projection owner');
  const state = raw.lifecycle;
  if (state !== 'running' && state !== 'waiting' && state !== 'paused' && state !== 'blocked' &&
      state !== 'completed' && state !== 'cancelled') throw new Error('invalid lifecycle');
  const {goal: savedGoal, reply, error_code: errorCode, proposed_diff: proposedDiff} = raw;
  if (proposedDiff !== undefined && (state !== 'waiting' || typeof proposedDiff !== 'string' || proposedDiff.length > 16384))
    throw new Error('invalid pending diff');
  if ((savedGoal !== undefined && typeof savedGoal !== 'string') || (reply !== undefined && typeof reply !== 'string'))
    throw new Error('invalid task text');
  const privateInput = savedGoal !== undefined && looksLikeOAuthCallback(savedGoal);
  const goal = privateInput ? '[private login input omitted]' : savedGoal;
  if (errorCode !== undefined && (reply !== undefined || typeof errorCode !== 'string' || !/^[a-z][a-z0-9_]{0,63}$/u.test(errorCode)))
    throw new Error('invalid task failure');
  let output: Position['output'];
  if (raw.output !== undefined) {
    const value = raw.output;
    if (!record(value) || typeof value.status !== 'string' || value.status.length > 512 ||
        (value.text !== undefined && (typeof value.text !== 'string' || Buffer.byteLength(value.text) > 65536))) throw new Error('invalid output');
    output = {status: value.status, text: privateInput ? undefined : value.text};
  }
  const position = {session, id: raw.task_id, state, origin: typeof raw.origin === 'string' ? raw.origin : undefined, privateInput, output, goal,
    reply: privateInput ? undefined : reply, errorCode, proposedDiff, activity: eventList(raw.activity), revision: u64(raw.revision),
    eventCursor: u64(raw.event_cursor), outboxCursor: u64(raw.outbox_cursor)} satisfies Position;
  if (raw.kind === 'resync_marker') return {kind: raw.kind, position};
  if (raw.kind === 'snapshot') return {kind: raw.kind, position, events: eventList(raw.events)};
  if (raw.kind !== 'delta' || typeof raw.event_id !== 'string' || !raw.event_id ||
      typeof raw.event_type !== 'string' || !raw.event_type) throw new Error('invalid task delivery');
  const after = u64(raw.after);
  if (after >= position.outboxCursor) throw new Error('invalid delta cursor');
  return {kind: 'delta', position, after, event: decodeEvent(raw)};
}

export function snapshot(raw: unknown, session: string, task?: string): Task {
  const frame = decode(raw, session, task);
  if (frame.kind !== 'snapshot') throw new Error('expected task snapshot');
  return {...frame.position, events: frame.events};
}

function covers(position: Position, base: Position) {
  return position.revision >= base.revision && position.eventCursor >= base.eventCursor &&
    position.outboxCursor >= base.outboxCursor;
}

/** Recovery can only read the bound task; a notification is never a command. */
export async function applyDelivery(previous: Task, raw: unknown, readSnapshot: () => Promise<unknown>): Promise<Task> {
  if (record(raw) && raw.kind === 'preview') {
    if (raw.session_id !== previous.session || raw.task_id !== previous.id) throw new Error('unexpected preview owner');
    const revision = u64(raw.revision), event = u64(raw.event_cursor), outbox = u64(raw.outbox_cursor);
    if (revision > previous.revision || event > previous.eventCursor || outbox > previous.outboxCursor)
      throw new Error('preview ahead of task');
    if (previous.state !== 'running' || revision !== previous.revision || event !== previous.eventCursor ||
        outbox !== previous.outboxCursor) return previous;
    const {offset, text, status} = raw;
    if ((status !== undefined && (typeof status !== 'string' || status.length > 512)) ||
        typeof offset !== 'number' || !Number.isSafeInteger(offset) || offset < 0 || typeof text !== 'string')
      throw new Error('invalid preview');
    const end = offset + Buffer.byteLength(text), before = previous.preview?.bytes ?? 0;
    if (end > 65536 || offset > before || (offset < before && end > before)) throw new Error('invalid preview range');
    if (end < before || (end === before && (!status || status === previous.preview?.status))) return previous;
    return {...previous, preview: {text: previous.privateInput ? '' : (previous.preview?.text ?? '') + (end > before ? text : ''), bytes: end, status}};
  }
  const frame = decode(raw, previous.session, previous.id);
  const pos = frame.position;
  if (covers(previous, pos) && (!covers(pos, previous) || frame.kind !== 'snapshot' ||
      (pos.state === previous.state && pos.output?.text === previous.output?.text && pos.output?.status === previous.output?.status &&
       pos.proposedDiff === previous.proposedDiff && sameEvents(pos.activity ?? [], previous.activity ?? []) &&
       sameEvents(frame.events, previous.events)))) return previous;
  if (!covers(pos, previous)) throw new Error('inconsistent task coordinates');
  if (frame.kind === 'snapshot') return {...pos, events: frame.events};
  if (frame.kind === 'delta' && frame.after === previous.outboxCursor &&
      pos.revision <= previous.revision + 1n && pos.eventCursor <= previous.eventCursor + 1n)
    return {...pos, events: [...previous.events.slice(-31), frame.event]};
  const restored = snapshot(await readSnapshot(), previous.session, previous.id);
  if (!covers(restored, pos)) throw new Error('stale recovery snapshot');
  return restored;
}
