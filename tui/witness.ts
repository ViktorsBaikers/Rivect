import { randomBytes } from 'node:crypto';
import { fstatSync, read, readSync, writeSync } from 'node:fs';
import { terminalText } from './modes-output';
import { decodeImage, record } from './wire';

function field(value: unknown) {
  if (typeof value !== 'string') throw new Error('invalid decision text');
  // One quoted data field cannot manufacture a cue, a new label, or terminal control.
  return terminalText(JSON.stringify(value));
}

function description(raw: unknown): {lines: string[]; delay: number} {
  if (record(raw) && record(raw.question) && record(raw.question.permission) && record(raw.params)) {
    const p = raw.question.permission, choice = raw.params.choice;
    if (raw.consent_delay_ms !== 200 || (choice !== 'deny' && choice !== 'allow_once' && choice !== 'limited_grant'))
      throw new Error('invalid permission confirmation');
    // Invisible filename bytes must stay distinguishable on the independent confirmation.
    const exact = (s: unknown) => field(s).replace(/\p{Cf}/gu, c => '\\u{' + c.codePointAt(0)!.toString(16) + '}');
    return {delay:200, lines:['Confirm permission', 'Session: '+exact(p.session_id), 'Request: '+exact(p.request_id),
      'Initiator: '+exact(p.initiator), 'Effect: '+exact(p.effect), 'Grant: '+exact(p.grant), 'Expiry: '+exact(p.expiry),
      'Scope: '+(p.scope === null ? '[not valid unicode]' : exact(p.scope)),
      'Selected: '+(choice === 'limited_grant' ? 'allow with limited grant (10 min)' : choice === 'allow_once' ? 'allow once; no grant' : 'deny')]};
  }
  if (!record(raw) || !record(raw.question) || !record(raw.question.question) || !record(raw.params))
    throw new Error('invalid decision');
  const owner = raw.question, q = raw.question.question, p = raw.params, s = p.selection;
  if (!record(s) || owner.session_id !== p.session_id || owner.task_id !== p.task_id ||
      q.question_id !== p.question_id || q.question_revision !== p.question_revision ||
      q.intent_revision !== p.expected_intent_revision || !Array.isArray(q.options) ||
      raw.consent_delay_ms !== 200) throw new Error('stale decision');
  const lines = ['Confirm decision', 'Session: ' + field(owner.session_id), 'Task: ' + field(owner.task_id),
    'Question: ' + field(q.question_id) + ' · revision ' + field(q.question_revision) + ' · intent ' + field(q.intent_revision),
    field(q.title), field(q.prompt), 'Recommendation: ' + field(q.recommended_option_id) + ' · ' + field(q.recommendation_basis)];
  for (const option of q.options) {
    if (!record(option) || !record(option.availability)) throw new Error('invalid option');
    lines.push(field(option.option_id) + ': ' + field(option.label) + ' — ' + field(option.consequences) +
      (option.availability.kind === 'disabled' ? ' (unavailable: ' + field(option.availability.reason) + ')' : ''));
  }
  if (s.kind === 'option') {
    const option = q.options.find(o => record(o) && o.option_id === s.option_id);
    if (!record(option) || !record(option.availability) || option.availability.kind !== 'enabled') throw new Error('unavailable choice');
    lines.push('Selected: ' + field(option.label) + ' (' + field(option.option_id) + ')', 'Effect: ' + field(option.consequences));
  } else if (s.kind === 'custom' && q.custom === true) lines.push('Custom answer: ' + field(s.text));
  else throw new Error('invalid selection');
  if (p.image !== undefined) {
    const image = decodeImage(p.image);
    lines.push('Image: ' + field(image.path) + ' · ' + field(image.media_type) + ' · ' + image.bytes + ' bytes',
      'SHA-256: ' + image.sha256, 'Scope and file identity: ' + image.identity);
  } else lines.push('Image: none');
  return {lines, delay: raw.consent_delay_ms};
}

function paint(text: string) {
  const bytes = Buffer.from(text);
  let offset = 0;
  while (offset < bytes.length) {
    const n = writeSync(1, bytes, offset, bytes.length - offset);
    if (!n) throw new Error('decision terminal closed');
    offset += n;
  }
}

export async function runWitness() {
  if (!fstatSync(2).isSocket()) throw new Error('decision channel unavailable');
  // Bun's net.Socket({fd}) does not consume inherited Unix socketpair bytes.
  const buffer = Buffer.allocUnsafe(2 << 20);
  let length = 0;
  for (;;) {
    if (length === buffer.length) throw new Error('decision too large');
    const n = readSync(2, buffer, length, buffer.length - length, null);
    if (!n) return;
    length += n;
    if (buffer[length - 1] === 10) break;
  }
  const frame = description(JSON.parse(buffer.toString('utf8', 0, length)));
  // macOS kqueue rejects /dev/tty: use file reads, never a libuv TTY stream.
  // The core closes its anonymous endpoint after receiving our single verdict.
  let answered = false;
  read(2, Buffer.alloc(1), 0, 1, null, () => process.exit(answered ? 0 : 1));
  paint('\n' + frame.lines.join('\n') + '\n');
  await Bun.sleep(frame.delay);
  const challenge = randomBytes(3).toString('hex').toUpperCase();
  paint('Type ' + challenge + ' to confirm, or press Enter to cancel:\n');
  const input = Buffer.alloc(16);
  const answer = Promise.withResolvers<boolean>();
  read(0, input, 0, input.length, null, (err, n) => {
    if (err) answer.reject(err);
    else answer.resolve(input.toString('utf8', 0, n) === challenge + '\n');
  });
  const accepted = await answer.promise;
  answered = true;
  writeSync(2, accepted ? 'Y' : 'N');
}
