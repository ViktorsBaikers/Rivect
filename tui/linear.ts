import { emitKeypressEvents, type Key } from 'node:readline';
import { PassThrough } from 'node:stream';
import { framedInput } from './linear-paste';
import { BootFailure, connectCore, type CoreClient } from './core';
import { restoredFailure, startup } from './startup';
import { operatorAction, type Question, type Selection } from './actions';
import { loginStatus, looksLikeOAuthCallback } from './auth-input';
import { linearSettings } from './linear-settings';
import { compactNotShorter } from './dock-data';
import { goalByteLimit, pasteText } from './input';
import { sourceLines, terminalText, turnLines } from './modes-output';
import type { Task } from './wire';

// No cursor commands, alternate screen, colors, or terminal queries. Raw input
// keeps Ctrl+C local to the client and never echoes pasted login callbacks.
export async function linear() {
  const input = process.stdin;
  const previousRaw = input.isRaw;
  let echoing = false;
  const line = (text: string) => {
    const prefix = echoing && text ? '\n' : '';
    echoing = false;
    process.stdout.write(prefix + terminalText(text) + '\n');
  };
  const coreLine = (text: string) => line(sourceLines('Core', text));
  const settings = linearSettings(text => line(sourceLines('Settings', text)));
  const opened = await startup();
  let owner = opened.owner, last = opened.page?.tasks.at(-1);
  let live: Task | undefined;
  let bootFailure: BootFailure | undefined;
  let question = opened.question, image: Awaited<ReturnType<CoreClient['command']>>['image'];
  let permission = opened.permission, permissionPainted = Infinity;
  function showPermission() {
    if (!permission) return;
    line('Awaiting permission · '+permission.effect+' · details shown on the confirmation terminal.');
    line('/deny · /allow-once · /allow-limited (10 min). Type one choice, then Enter.');
    permissionPainted = performance.now();
  }
  let draft = '', size = 0, busy = false, closing = false;
  let pasted = false, discarded = false, privateInput = false;
  const reset = () => { draft = ''; size = 0; pasted = false; };
  let poll: ReturnType<typeof setTimeout> | undefined, refresh: Promise<void> | undefined;
  async function connect() {
    const next = await connectCore();
    if (!closing) for (const note of next.boot.diagnostics) coreLine(note);
    return next;
  }
  const done = Promise.withResolvers<void>();
  const stop = () => { closing = true; done.resolve(); };
  function prompt() { if (!permission) line('Message · Enter submits · Ctrl+D exits'); }
  function showQuestion(q: Question) {
    line(sourceLines('Question', q.title + '\n' + q.prompt));
    for (const opt of q.options) line(sourceLines('Option', opt.id + ': ' + opt.label + ' — ' + (opt.disabled ?? opt.consequences)));
    line('/answer <option id>' + (q.custom ? ' · /custom <answer>' : ''));
  }
  async function update(task: Task, before?: Task) {
    if (closing) return;
    for (const row of turnLines(task, before)) line(row);
    last = task;
    live = task.state === 'running' ? task : undefined;
    if (owner && task.state !== 'running') { permission = await owner.permission(); if (!closing) showPermission(); }
    if (task.state === 'waiting' && owner) {
      question = await owner.question(task);
      if (question && !closing) showQuestion(question);
    }
  }
  function watch() {
    clearTimeout(poll);
    const target = live, core = owner;
    if (!target || !core || busy || closing || permission) return;
    poll = setTimeout(() => {
      refresh = core.refresh(target).then(next => update(next, target)).then(watch).catch(() => {
        if (!closing) line('Updates stopped. Use /resume to read the saved state.');
      }).finally(() => { refresh = undefined; });
    }, 150);
  }
  async function send(text: string, fromPaste = false) {
    if (busy) return;
    if (permission && owner) {
      const choice = text === '/deny' ? 'deny' : text === '/allow-once' ? 'allow_once' : text === '/allow-limited' ? 'limited_grant' : undefined;
      if (fromPaste || !choice || performance.now() - permissionPainted < 200) { line('Permission not confirmed. Type one displayed choice.'); return; }
      busy = true;
      try {
        input.pause(); input.setRawMode(false);
        let result;
        try { result = await owner.resolvePermission(permission, choice); }
        finally { if (!closing) { input.setRawMode(true); input.resume(); } }
        if (closing) return;
        coreLine(result.note);
        if (result.closed) permission = await owner.permission();
        showPermission();
      } catch { if (!closing) line('Permission outcome unknown. Check session before retrying.'); }
      finally { busy = false; if (!closing) { prompt(); watch(); } }
      return;
    }
    const callback = privateInput;
    if (callback) { privateInput = false; reset(); }
    else if (text === '/login callback') { reset(); privateInput = true; line('Input hidden · paste callback and press Enter · Esc discards'); return; }
    else if (looksLikeOAuthCallback(text)) { reset(); line('Use /login callback for private input.'); return; }
    if (!text.trim()) { prompt(); return; }
    if (callback && (!looksLikeOAuthCallback(text) || /[\s\p{Cc}]/u.test(text))) { line('Invalid callback. Use /login callback to retry.'); prompt(); return; }
    if (text.trimStart().startsWith('/') && (text !== text.trim() || /[\r\n]/u.test(text))) {
      line('Enter a slash command on one line.'); return;
    }
    busy = true;
    clearTimeout(poll);
    try {
      await refresh;
      if (closing) return;
      if (callback) {
        owner ??= await connect();
        for (const row of await owner.action({kind:'login_callback', redirect:text})) coreLine(row);
        line(owner.loginStatus);
      } else if (text === '/compact' && !last) {
        line('No conversation to compact yet; submit a task first.');
      } else if (text === '/help') {
        line('/exit · /new · /clear · /resume [session]\n/decision · /answer <id> · /custom <text>\n'
          + '/image <path> · /read <path>\n/settings · /permissions · /accounting\n'
          + '/login · /login callback\n/compact · /rewind\n/task <goal> · /cancel');
      } else {
        if (owner?.disconnected && /^\/resume(?: |$)/u.test(text)) {
          live = undefined; await owner.close(); owner = undefined;
        }
        owner ??= await connect();
        if (closing) return;
        if (await settings(owner, text, fromPaste)) return;
        if (text === '/new' || text === '/clear') {
          const result = await owner.newSession();
          if ('running' in result) line(sourceLines('Status', 'task ' + result.running + ' is running; session unchanged.'));
          else {
            last = live = question = image = undefined;
            line(sourceLines('New conversation', result.session));
            line(sourceLines('Previous session', result.previous));
          }
        } else if (text === '/resume') {
          const ids = await owner.recentSessions(); line(ids.length ? sourceLines('Session', ids.join('\n')) : 'No saved sessions.');
        } else if (/^\/resume \S+$/u.test(text)) {
          const page = await owner.resume(text.slice(8)); live = question = image = undefined;
          last = page.tasks.at(-1); for (const task of page.tasks) for (const row of turnLines(task)) line(row);
          line(sourceLines('Resumed session', text.slice(8)));
          permission = await owner.permission(); if (!closing) showPermission();
        } else if (text === '/decision') {
          question = last && await owner.question(last);
          if (question) showQuestion(question); else line('No pending question.');
        } else if (text === '/cancel') {
          if (live) await update(await owner.cancel(live), live); else line('No local task to cancel.');
        } else if (question && (/^\/answer .+/u.test(text) || /^\/custom .+/u.test(text))) {
          const selection: Selection = text.startsWith('/custom ') ? {kind:'custom', text:text.slice(8)} : {kind:'option', option_id:text.slice(8)};
          if (selection.kind === 'option' ? !question.options.some(o => o.id === selection.option_id && !o.disabled) : !question.custom)
            throw new Error('invalid selection');
          input.setRawMode(false); input.pause();
          try { for (const row of await owner.answer(question, selection, image)) coreLine(row); }
          finally { if (!closing) { input.setRawMode(true); input.resume(); } }
          question = image = undefined;
          if (last) await update(await owner.refresh(last), last);
        } else if (text === '/image') { image = undefined; line('Image detached.'); }
        else if (text.startsWith('/read ') && last) {
          for (const row of (await owner.command('read', {task_id:last.id, path:text.slice(6)})).lines) coreLine(row);
        } else if (text.startsWith('/image ') || text === '/compact' || text === '/rewind') {
          const result = text.startsWith('/image ') ? await owner.command('image', {path:text.slice(7)})
            : await owner.command(text === '/compact' ? 'compact' : 'rewind', {task_id:last?.id});
          if (result.image) image = result.image;
          for (const row of result.lines) coreLine(row);
        } else {
          const action = operatorAction(text);
          if (action) {
            for (const row of await owner.action(action)) coreLine(row);
            if (action.kind.startsWith('login_')) line(owner.loginStatus);
          }
          else if (text.startsWith('/task ') && text.slice(6).trim() && !question) await update(await owner.submit(text.slice(6), 'project'));
          else if (text.startsWith('/')) line('Unknown command or pending decision. Use /help.');
          else if (question) line('Answer the pending question or use /new.');
          else await update(await owner.submit(text));
        }
      }
    } catch (error) {
      if (error instanceof BootFailure) { bootFailure = error; process.exitCode = 1; stop(); }
      else if (!closing && text === '/compact' && error instanceof Error && error.message === compactNotShorter) coreLine(compactNotShorter);
      else if (!closing) line('Request not confirmed. Check session history before retrying.');
    }
    finally { busy = false; if (!closing) { prompt(); watch(); } }
  }
  let work: Promise<void> | undefined;
  function keypress(char: string | undefined, key: Key) {
    if (key.ctrl && key.name === 'd') { stop(); return; }
    if (key.ctrl && key.name === 'c') {
      if (!busy && live && !permission) work = send('/cancel'); else { process.exitCode = 130; stop(); }
      return;
    }
    if (key.name === 'return' || key.name === 'enter') {
      if (discarded) { discarded = false; prompt(); }
      else if (draft === '/exit' && !privateInput) stop();
      else if (!busy) {
        const text = draft, fromPaste = pasted;
        reset(); line(''); work = send(text, fromPaste);
      } else line('Request in progress. Press Enter again when ready.');
      return;
    }
    if (discarded || closing) return;
    if (key.name === 'backspace' || key.name === 'delete') {
      const clusters = new Intl.Segmenter(undefined, {granularity:'grapheme'}).segment(draft);
      const last = clusters.containing(draft.length - 1);
      if (last) { size -= Buffer.byteLength(last.segment); draft = draft.slice(0, last.index); line('Character removed.'); }
      return;
    }
    if (key.ctrl || key.meta || !char || /[\p{Cc}]/u.test(char)) return;
    append(char);
  }
  function append(char: string, fromPaste = false) {
    if (discarded) return;
    const bytes = Buffer.byteLength(char);
    if (size + bytes > goalByteLimit) { line('Composer input exceeds the goal size limit.'); return; }
    const next = draft + char;
    if (!privateInput && looksLikeOAuthCallback(next)) {
      reset(); discarded = true; line('Use /login callback for private input.'); return;
    }
    size += bytes; draft = next; pasted ||= fromPaste;
    if (!permission && !privateInput && !/^\s*\/login(?:\s|$)/u.test(draft) && !/^\s*\/settings set /u.test(draft)) {
      process.stdout.write((echoing ? '' : 'Draft: ') + terminalText(char).replaceAll('\n', '\nDraft: '));
      echoing = true;
    }
  }
  const keys = new PassThrough();
  emitKeypressEvents(keys); keys.on('keypress', keypress);
  const consume = framedInput(bytes => { keys.write(bytes); }, bytes => {
    if (busy || closing) return;
    if (permission) { reset(); line('Paste refused while permission is pending.'); return; }
    const text = pasteText(bytes);
    if (typeof text === 'string') append(text, true); else line(text.error);
  }, () => line('Composer input exceeds the goal size limit.'), () => {
    if (closing || (!privateInput && !discarded)) return false;
    privateInput = discarded = false; reset(); line('Private input discarded.'); prompt(); return true;
  });
  const fatal = () => { process.exitCode = 1; stop(); };
  process.once('uncaughtException', fatal); process.once('unhandledRejection', fatal);
  input.once('end', stop); process.once('SIGTERM', stop); process.once('SIGHUP', stop); process.once('SIGINT', stop);
  try {
    input.setRawMode(true); process.stdout.write('\x1b[?2004h'); input.on('data', consume); input.resume();
    line(sourceLines('Project', opened.project)); line(loginStatus(opened.loginAvailable));
    for (const note of opened.diagnostics) coreLine(note);
    for (const task of opened.page?.tasks ?? []) for (const row of turnLines(task)) line(row);
    if (question) showQuestion(question);
    showPermission();
    prompt(); watch(); await done.promise;
  }
  finally {
    clearTimeout(poll); input.off('data', consume); keys.destroy(); input.off('end', stop); input.setRawMode(previousRaw); input.pause();
    process.stdout.write('\x1b[?2004l');
    process.off('uncaughtException', fatal); process.off('unhandledRejection', fatal);
    if (bootFailure) process.stderr.write(restoredFailure(bootFailure));
    else if (process.exitCode === 1) process.stderr.write('terminal client stopped unexpectedly\n');
    process.off('SIGTERM', stop); process.off('SIGHUP', stop); process.off('SIGINT', stop);
    await owner?.close(); await work; await refresh; await owner?.close();
  }
}
