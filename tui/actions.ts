import { record, u64, type Task } from './wire';

export type OperatorAction = {kind: 'settings' | 'permissions' | 'accounting' | 'login_browser' | 'login_device' | 'login_cancel' | 'login_complete'} |
  {kind: 'login_callback'; redirect: string};

/** One sign-in method the core advertises for a provider. */
export type LoginMethod = {id: string; label: string; capture: boolean};
/** One provider row the `/login` picker renders. */
export type LoginProvider = {id: string; name: string; declared: boolean; methods: LoginMethod[]};
/** The receipt a started leg carries: what to open and whether the core
 * captures the redirect itself. */
export type LoginPending = {provider: string; method: string; url: string; user_code?: string; capture: boolean};
export type LoginReceipt = {lines: string[]; pending?: LoginPending};

/** The three picker actions plus the leg's own lifecycle. */
export type LoginAction =
  {kind: 'login_providers'} |
  {kind: 'login_connect'; provider: string} |
  {kind: 'login_start'; provider: string; method: string} |
  {kind: 'login_complete'} |
  {kind: 'login_cancel'} |
  {kind: 'login_callback'; redirect: string};

/** A provider row is only rendered from the exact recorded shape: an extra or
 * missing member is a protocol error, never a guess. */
export function loginProviders(value: unknown): LoginProvider[] {
  if (!Array.isArray(value) || !value.length) throw new Error('invalid sign-in catalogue');
  return value.map(raw => {
    if (!record(raw) || typeof raw.id !== 'string' || !raw.id || typeof raw.name !== 'string' || !raw.name ||
        typeof raw.declared !== 'boolean' || !Array.isArray(raw.methods) || !raw.methods.length)
      throw new Error('invalid sign-in provider');
    const methods = raw.methods.map(method => {
      if (!record(method) || typeof method.id !== 'string' || !method.id || typeof method.label !== 'string' ||
          typeof method.capture !== 'boolean') throw new Error('invalid sign-in method');
      return {id: method.id, label: method.label, capture: method.capture};
    });
    return {id: raw.id, name: raw.name, declared: raw.declared, methods};
  });
}

/** The pending receipt a started leg answers; absent for every other receipt. */
export function loginPending(value: unknown): LoginPending | undefined {
  if (value === undefined) return;
  if (!record(value) || typeof value.provider !== 'string' || typeof value.method !== 'string' ||
      typeof value.url !== 'string' || typeof value.capture !== 'boolean')
    throw new Error('invalid login receipt');
  const code = value.user_code;
  if (code != null && typeof code !== 'string') throw new Error('invalid login receipt');
  return {provider: value.provider, method: value.method, url: value.url,
    user_code: code ?? undefined, capture: value.capture};
}


export function operatorAction(input: string): OperatorAction | undefined {
  switch (input) {
    case '/settings': case '/config': return {kind: 'settings'};
    case '/permissions': return {kind: 'permissions'};
    case '/accounting': case '/usage': return {kind: 'accounting'};
    case '/login': return {kind: 'login_browser'};
    case '/login device': return {kind: 'login_device'};
    case '/login cancel': return {kind: 'login_cancel'};
    case '/login complete': return {kind: 'login_complete'};
  }
  const prefix = '/login ';
  if (input.startsWith(prefix)) {
    const redirect = input.slice(prefix.length);
    if (redirect && !/[\s\p{Cc}]/u.test(redirect)) return {kind: 'login_callback', redirect};
  }
}

export type Selection = {kind: 'option'; option_id: string} | {kind: 'custom'; text: string};
export type Question = Readonly<{
  session: string;
  pin: {task_id: string; question_id: string; question_revision: string; expected_intent_revision: string};
  title: string; prompt: string; recommendation: string; recommended: string; custom: boolean;
  canRevealDiff: boolean;
  options: readonly {id: string; label: string; consequences: string; disabled?: string}[];
}>;

export function decodeQuestion(raw: unknown, task: Task): Question | undefined {
  if (!record(raw) || raw.session_id !== task.session || raw.task_id !== task.id) throw new Error('unexpected question owner');
  if (raw.question === null) return undefined;
  const q = raw.question;
  if (!record(q) || typeof q.question_id !== 'string' || !q.question_id || typeof q.prompt !== 'string' ||
      typeof q.title !== 'string' || typeof q.custom !== 'boolean' || typeof q.recommendation_basis !== 'string' ||
      typeof q.recommended_option_id !== 'string' || !Array.isArray(q.options) || !q.options.length)
    throw new Error('invalid question');
  const options = q.options.map((op: unknown) => {
    if (!record(op) || typeof op.option_id !== 'string' || !op.option_id || typeof op.label !== 'string' ||
        typeof op.consequences !== 'string' || !record(op.availability)) throw new Error('invalid question option');
    const a = op.availability;
    if (a.kind !== 'enabled' && !(a.kind === 'disabled' && typeof a.reason === 'string'))
      throw new Error('invalid option availability');
    return {id: op.option_id, label: op.label, consequences: op.consequences,
      disabled: a.kind === 'disabled' ? String(a.reason) : undefined};
  });
  return {session: task.session, pin: {task_id: task.id, question_id: q.question_id,
    question_revision: u64(q.question_revision).toString(), expected_intent_revision: u64(q.intent_revision).toString()},
    title: q.title, prompt: q.prompt, recommendation: q.recommendation_basis, recommended: q.recommended_option_id,
    custom: q.custom, canRevealDiff: q.can_reveal_diff === true, options};
}
