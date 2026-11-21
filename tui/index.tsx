import { useKeyboard, usePaste, useRenderer, useTerminalDimensions } from '@opentui/solid';
import { SyntaxStyle, TextAttributes, type ScrollBoxRenderable, type TextareaRenderable } from '@opentui/core';
import { createEffect, createSignal, For, Index, onCleanup, onMount, Show } from 'solid-js';
import { BootFailure, connectCore, type CoreClient, type Image } from './core';
import { restoredFailure, type Startup } from './startup';
import { operatorAction, type LoginPending, type OperatorAction, type Question, type Selection } from './actions';
import { DecisionView } from './decision';
import { currentFork, sameFork } from './question-watch';
import { PermissionView } from './permission';
import type { Permission } from './permission-data';
import { SettingsCenter } from './settings';
import { settingsCommand, type SettingsStart } from './settings-data';
import { goalAuthor, type Task } from './wire';
import { waitingVerifier } from './activity';
import { goalByteLimit, mouseCommand, pasteDraft } from './input';
import { loginStatus, looksLikeOAuthCallback } from './auth-input';
import { ProviderPicker } from './provider-picker';
import { PrivateLogin } from './private-login';
import { modeOutput, surfaceCommand } from './modes-output';
import { palette } from './theme';
import { compactNotShorter, dockObservation, dockSubject, emptyDock } from './dock-data';
import { DockBand } from './dock';
import { checkResult, ThreadBranch, ThreadNode, ThreadRail } from './thread-layout';
import { basename } from 'node:path';

const {canvas, surface, secondary, ink, accent, line} = palette;

function confirmedWrites(task: Task) {
  return task.activity?.reduce((count, event) => count + Number(event.type === 'attempt.write' && event.text === 'confirmed'), 0) ?? 0;
}

export function Thread(opened: Startup) {
  const size = useTerminalDimensions();
  const narrow = () => size().width < 57;
  const compact = () => size().height < 30;
  const inset = () => size().width < 82 ? 1 : 2;
  const railWidth = () => Math.min(26, Math.max(19, Math.round(size().width * .225)));
  const project = basename(opened.project) || opened.project;
  const renderer = useRenderer();
  const [turns, setTurns] = createSignal<Task[]>(opened.page?.tasks ?? []);
  const style = SyntaxStyle.fromStyles({ 'markup.heading': { fg: secondary, bold: true },
    'markup.bold': { bold: true }, 'markup.italic': { italic: true }, 'markup.raw': { fg: accent } }, renderer.nativeScene);
  const [selected, setSelected] = createSignal<number>();
  const [selectedWait, setSelectedWait] = createSignal<ReturnType<typeof waitingVerifier>>();
  function openDetail(index: number) {
    setSelectedWait(waitingVerifier(turns()[index]));
    setSelected(index);
  }
  const [choices, setChoices] = createSignal<string[]>([]);
  const [choice, setChoice] = createSignal(0);
  let details: ScrollBoxRenderable | undefined;
  const [notice, setNotice] = createSignal('');
  const [recent, setRecent] = createSignal<string[]>([]);
  const [moreHistory, setMoreHistory] = createSignal(opened.page?.more ?? false);
  const [bootNotes, setBootNotes] = createSignal(opened.diagnostics);
  const [connection, setConnection] = createSignal(loginStatus(opened.loginAvailable));
  const [actionLines, setActionLines] = createSignal<string[]>([]);
  const [privatePanel, setPrivatePanel] = createSignal(false);
  const publish = modeOutput(renderer);
  createEffect(() => publish(turns(), [notice(), ...(privatePanel() ? [] : actionLines())].filter(Boolean).join('\n')));
  const [question, setQuestion] = createSignal<Question | undefined>(opened.question);
  // A patch is shown only after explicit review and a new confirmed write. It never enters scrollback or storage.
  type ReviewedPatch = {question: Question; eventId: string; content: string; writes: number};
  let reviewedPatch: ReviewedPatch | undefined;
  const [appliedPatch, setAppliedPatch] = createSignal<ReviewedPatch>();
  const [fullscreen, setFullscreen] = createSignal(renderer.screenMode === 'alternate-screen');
  let dismissedFork: Question | undefined;
  const trackedReview = () => question() ?? dismissedFork;
  const [permission, setPermission] = createSignal<Permission | undefined>(opened.permission);
  const [settings,setSettings] = createSignal<SettingsStart>();
  const [picker,setPicker] = createSignal<string>();
  const [loginPending,setLoginPending] = createSignal<LoginPending>();
  const loginOpen = () => picker() !== undefined || loginPending() !== undefined;
  let lastLogin: LoginPending | undefined;
  let image: Image | undefined;
  let core = opened.owner;
  let replacement: CoreClient | undefined;
  let live: Task | undefined;
  let pendingSubject = opened.question && turns().find(t=>t.session === opened.question!.session && t.id === opened.question!.pin.task_id);
  const subject = () => dockSubject(pendingSubject,turns());
  const [dock,setDock] = createSignal(emptyDock);
  let nextDock = 0;
  function clearDock() { pendingSubject = undefined; nextDock = 0; setDock(emptyDock); }
  async function newOwner() {
    const owner = await connectCore();
    if (!disposed) { setBootNotes(owner.boot.diagnostics); setConnection(owner.loginStatus); }
    return owner;
  }
  async function failedRetry(error: BootFailure) {
    if (disposed) return;
    process.exitCode = 1;
    renderer.destroy();
    await renderer.closed;
    process.stderr.write(restoredFailure(error));
  }
  let editor!: TextareaRenderable;
  let history!: ScrollBoxRenderable;
  function discardCallback(text:string) {
    if (!looksLikeOAuthCallback(text)) return false;
    clearTimeout(timer); setChoices([]); setActionLines([]); setPrivatePanel(false);
    setNotice('Callback discarded. It was not sent to Main. Use /login to start sign-in.');
    editor.editBuffer.setText(''); // Also clears native undo history.
    return true;
  }
  usePaste(event => {
    if (permission() || question() || settings() || loginOpen()) return;
    if (event.bytes.length <= goalByteLimit && discardCallback(new TextDecoder().decode(event.bytes))) { event.preventDefault(); return; }
    if (selected() !== undefined) { event.preventDefault(); setNotice('Close task details before pasting.'); return; }
    const refused = pasteDraft(editor, event);
    if (refused) setNotice(refused);
  });
  useKeyboard(key => {
    if (key.ctrl && key.name === 'c') {
      key.preventDefault();
      void interrupt();
      return;
    }
    if (permission() || question() || settings() || loginOpen()) return;
    if (key.ctrl && key.name === 't' && key.eventType === 'press' && !key.repeated) {
      key.preventDefault();
      setNotice(surfaceCommand(renderer, renderer.screenMode === 'split-footer' ? '/tui fullscreen' : '/tui inline') ?? '');
      setFullscreen(renderer.screenMode === 'alternate-screen');
      return;
    }
    if (choices().length && ['up', 'down', 'escape', 'tab'].includes(key.name)) {
      key.preventDefault();
      if (key.name === 'escape') setChoices([]);
      else if (key.name === 'tab') {
        const prefix = completionToken();
        const candidate = choices()[choice()];
        if (prefix && candidate?.startsWith(prefix)) editor.insertText(candidate.slice(prefix.length));
        setChoices([]);
      } else setChoice(i => (i + (key.name === 'up' ? -1 : 1) + choices().length) % choices().length);
      return;
    }
    if (selected() !== undefined && ['up', 'down', 'escape', 'tab'].includes(key.name)) {
      key.preventDefault();
      if (key.name === 'escape' || key.name === 'tab') { setSelected(undefined); setSelectedWait(undefined); }
      else { openDetail(Math.max(0, Math.min(turns().length - 1, selected()! + (key.name === 'up' ? -1 : 1)))); details?.scrollTo(0); }
      return;
    }
    if (key.name === 'escape') { key.preventDefault(); renderer.destroy(); return; }
    if (key.name === 'tab') {
      key.preventDefault();
      const token = completionToken();
      if (token) void complete(token);
      else if (turns().length) openDetail(turns().length - 1);
      return;
    }
    if (key.name !== 'pageup' && key.name !== 'pagedown') return;
    key.preventDefault();
    if (key.name === 'pageup' && selected() === undefined && history.scrollTop === 0 && moreHistory()) {
      void loadOlder(); return;
    }
    (selected() === undefined ? history : details)?.scrollBy(key.name === 'pageup' ? -1 : 1, 'viewport');
  });
  let sending = false;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let reading: Promise<void> | undefined;
  let disposed = false;
  onCleanup(() => {
    disposed = true;
    clearTimeout(timer);
    style.destroy();
    void renderer.closed.then(() => Promise.all([core?.close(), replacement?.close()]));
  });
  async function loadOlder() {
    const owner = core, first = turns()[0];
    if (sending || !owner || !first) return;
    sending = true;
    clearTimeout(timer);
    try {
      await reading;
      const page = await owner.older(first);
      if (disposed || owner !== core || turns()[0]?.id !== first.id) return;
      setTurns(list => [...page.tasks, ...list]);
      setMoreHistory(page.more);
      history.scrollTo(0);
    } catch { if (!disposed) setNotice('Older history unavailable. Page Up retries.'); }
    finally { sending = false; watch(); }
  }
  function completionToken() {
    const before = editor.getTextRange(0, editor.cursorOffset);
    return /(?:^|\s)(@[^\s]*)$/u.exec(before)?.[1] ?? /^\/[^\s]*$/u.exec(before)?.[0];
  }
  async function complete(token: string) {
    if (sending) return;
    const draft = editor.plainText, offset = editor.cursorOffset;
    sending = true;
    clearTimeout(timer);
    try {
      await reading;
      if (disposed) return;
      core ??= await newOwner();
      if (disposed) { await core.close(); return; }
      const result = await core.complete(token);
      if (disposed || editor.plainText !== draft || editor.cursorOffset !== offset) return;
      if (result.length === 1 && result[0]!.startsWith(token)) editor.insertText(result[0]!.slice(token.length));
      else { setChoice(0); setChoices(result); }
      setNotice(result.length ? '' : 'No matches.');
    } catch (error) {
      if (error instanceof BootFailure) await failedRetry(error);
      else if (!disposed) setNotice('Completion unavailable. Draft kept.');
    }
    finally { sending = false; watch(); }
  }
  function replace(previous: Task, next: Task) {
    if (disposed || previous === next) return;
    live = next.state === 'running' ? next : undefined;
    if (pendingSubject?.id === next.id) pendingSubject = next.state === 'running' || next.state === 'waiting' ? next : undefined;
    setTurns(list => list.map(task => task === previous ? next : task));
  }
  const reviewingHistory = () => !!editor?.plainText || selected() !== undefined || choices().length > 0 ||
    history.scrollTop + history.height < history.scrollHeight;
  async function loadQuestion(owner: CoreClient, task: Task, mode: 'open' | 'inspect' | 'update' = 'open', answered?: Question) {
    try {
      const value = await owner.question(task);
      if (disposed || core !== owner) return;
      if (value && value.session === task.session && value.pin.task_id === task.id) {
        if (answered && sameFork(value, answered)) return;
        if (mode === 'update' && reviewingHistory()) return;
        pendingSubject = task;
        dismissedFork = undefined;
        setChoices([]);
        setQuestion(value);
      } else if (mode === 'inspect') setNotice('No pending question.');
    } catch { if (!disposed) setNotice('Question unavailable. Use /decision to retry.'); }
  }
  async function pollReview(owner: CoreClient, task: Task, observed: Question) {
    const next = await currentFork(owner, task, observed);
    if (disposed || core !== owner || trackedReview() !== observed || next === observed) return;
    if (next && !question() && reviewingHistory()) return;
    image = undefined;
    if (!next) {
      const wasOpen = !!question();
      dismissedFork = observed;
      setQuestion(undefined);
      if (wasOpen) setNotice('Question changed.');
      const fresh = await owner.refresh(task);
      if (disposed || core !== owner || trackedReview() !== observed) return;
      replace(task, fresh);
      if (fresh.state !== 'waiting') dismissedFork = undefined;
      return;
    }
    dismissedFork = undefined;
    setChoices([]);
    setQuestion(next);
    setNotice('Question changed.');
  }
  async function answer(selection: Selection) {
    const pending = question(), owner = core;
    const task = turns().find(t => t.session === pending?.session && t.id === pending?.pin.task_id);
    if (sending || !pending || !owner || !task) return;
    sending = true;
    clearTimeout(timer);
    try {
      await reading;
      if (disposed || pending !== question()) return;
      await renderer.suspend();
      let lines: string[];
      try { lines = await owner.answer(pending, selection, image); }
      finally { if (!disposed) await renderer.resume(); }
      image = undefined;
      if (disposed) return;
      if (reviewedPatch?.question === pending && selection.kind === 'option' && selection.option_id === 'allow-write-once') {
        setAppliedPatch(reviewedPatch);
      }
      reviewedPatch = undefined;
      setActionLines(lines);
      setQuestion(undefined);
      const next = await owner.refresh(task);
      replace(task, next);
      if (!disposed && next.state === 'waiting') await loadQuestion(owner, next, 'update', pending);
    } catch {
      if (!disposed) {
        dismissedFork = pending;
        setQuestion(undefined);
        const previousNotice = notice();
        await loadQuestion(owner, task, 'open', pending);
        if (!disposed && notice() === previousNotice) setNotice('Check /decision before attempting another answer.');
      }
    } finally { sending = false; watch(); }
  }
  async function loadPermission(owner: CoreClient) {
    try {
      const request = await owner.permission();
      if (!disposed && owner === core) setPermission(request);
    } catch { if (!disposed) setNotice('Permission unavailable. Use /resume to check.'); }
  }
  async function sampleDock(owner: CoreClient) {
    const task = subject();
    if (!task || disposed || sending || question() || permission() || loginOpen() || settings() || performance.now() < nextDock) return;
    nextDock = performance.now() + 1000;
    let result;
    try { result = await owner.dock(task); }
    catch { result = owner.disconnected ? 'owner disconnected' : 'projection unavailable'; }
    if (!disposed && core === owner && subject()?.id === task.id) setDock(old => dockObservation(old,result));
  }
  function watch() {
    clearTimeout(timer);
    const owner = core, task = live, observed = trackedReview();
    if (disposed || sending || permission() || settings() || loginOpen() || !owner || (!subject() && !observed)) return;
    const review = observed && turns().find(t => t.session === observed.session && t.id === observed.pin.task_id);
    timer = setTimeout(() => {
      reading = (async () => {
        if (disposed || sending || permission() || settings() || loginOpen() || owner !== core) return;
        if (!owner.disconnected) {
          try {
            if (observed && review) await pollReview(owner,review,observed);
            else if (task) {
              const next = await owner.refresh(task);
              replace(task,next);
              if (next.state !== 'running') await loadPermission(owner);
              if (!disposed && next.state === 'waiting') await loadQuestion(owner,next,'update');
            }
          } catch {
            if (!disposed && owner === core) {
              if (task?.preview) replace(task,{...task, preview:undefined});
              live = undefined;
              setNotice('Updates stopped. Use /resume to read the saved state.');
            }
          }
        }
        await sampleDock(owner);
      })().finally(() => { reading = undefined; watch(); });
    }, !owner.disconnected && (task || review) ? 150 : Math.max(50,nextDock-performance.now()));
  }
  onMount(watch);
  async function reveal(request:Question) {
    const owner=core;
    if (!owner || sending) throw new Error('proposal unavailable');
    sending=true; clearTimeout(timer);
    try {
      await reading;
      if (disposed || owner!==core || request!==question()) throw new Error('proposal changed');
      const content = await owner.reveal(request);
      const task = turns().find(item => item.session === request.session && item.id === request.pin.task_id);
      const event = task?.events.findLast(item => item.category === 'diff' && item.type === 'question.published');
      if (task && event && request === question()) {
        reviewedPatch = {question: request, eventId: event.id, content, writes: confirmedWrites(task)};
      }
      return content;
    } finally { sending=false; watch(); }
  }
  async function interrupt() {
    const owner = core;
    if (!live || !owner || owner.disconnected || sending) { process.exitCode = 130; renderer.destroy(); return; }
    sending = true;
    clearTimeout(timer);
    try {
      await reading;
      const current = live;
      if (!disposed && current) replace(current, await owner.cancel(current));
    } catch { if (!disposed) setNotice('Cancellation not confirmed. Check session history.'); }
    finally { sending = false; watch(); }
  }
  async function ensureOwner(): Promise<CoreClient | undefined> {
    if (core) return core;
    setNotice('Starting the runtime…');
    try { core = await newOwner(); }
    catch { setNotice('The runtime could not start. Check the data root and retry.'); return; }
    if (disposed) return;
    setNotice('');
    return core;
  }
  async function openLoginPicker(query: string) {
    if (!(await ensureOwner())) return;
    setPicker(query); setNotice('');
  }
  async function loginStart(provider: string, method: string) {
    const owner = await ensureOwner();
    if (!owner) return;
    setPicker(undefined); setNotice('Starting sign-in…');
    try {
      await owner.login({kind: 'login_connect', provider});
      const receipt = await owner.login({kind: 'login_start', provider, method});
      setActionLines(receipt.lines);
      if (receipt.pending) {
        lastLogin = receipt.pending;
        setLoginPending(receipt.pending);
        setPrivatePanel(false);
        setConnection(owner.loginStatus);
        setNotice('');
      } else {
        setLoginPending(undefined);
        setConnection(owner.loginStatus);
        setNotice(receipt.lines.at(-1) ?? '');
      }
    } catch (error) {
      setNotice(error instanceof Error ? error.message : 'Sign-in could not start.');
    }
  }
  async function loginCheck() {
    const owner = core;
    if (!owner || !loginPending()) { setNotice('No sign-in is pending.'); return; }
    try {
      const receipt = await owner.login({kind: 'login_complete'});
      if (receipt.pending) { setNotice('Still waiting for the provider.'); return; }
      setActionLines(receipt.lines);
      lastLogin = undefined;
      setLoginPending(undefined);
      setConnection(owner.loginStatus);
      setNotice('');
    } catch {
      setNotice('Sign-in not confirmed. Check the pending page or cancel with /login cancel.');
    }
  }
  async function loginCancel() {
    const owner = core;
    if (!owner) return;
    try {
      const receipt = await owner.login({kind: 'login_cancel'});
      setActionLines(receipt.lines);
    } catch {
      setNotice('Cancellation not confirmed.');
    }
    lastLogin = undefined;
    setLoginPending(undefined);
    setConnection(owner.loginStatus);
  }
  async function submit() {
    const goal = editor.plainText;
    if (sending || permission() || question() || settings() || loginOpen() || !goal.trim() || discardCallback(goal)) return;
    const command = goal;
    if (/^\s*\/login(?:\s|$)/u.test(command)) editor.clear();
    if (command.trimStart().startsWith('/') && (command !== command.trim() || /[\r\n]/u.test(command))) {
      setNotice('Enter a slash command on one line.'); return;
    }
    if (command === '/exit') { renderer.destroy(); return; }
    if (command === '/cancel') {
      editor.clear();
      if (live) await interrupt(); else setNotice('No local task to cancel.');
      return;
    }
    const login = /^\s*\/login(?:\s+(.*))?$/u.exec(command);
    if (login) {
      editor.clear();
      const argument = (login[1] ?? '').trim();
      if (!argument) { void openLoginPicker(''); return; }
      if (argument === 'cancel') { await loginCancel(); return; }
      if (argument === 'complete') { await loginCheck(); return; }
      if (argument === 'device') { await loginStart('openai-codex', 'device'); return; }
      if (argument === 'callback') {
        if (lastLogin) setLoginPending(lastLogin); else setNotice('No sign-in is pending.');
        return;
      }
      if (!/[\s\p{Cc}]/u.test(argument)) { void openLoginPicker(argument); return; }
      setNotice('Enter /login on one line.');
      return;
    }
    const localNotice = mouseCommand(renderer, command) ?? surfaceCommand(renderer, command);
    if (localNotice !== undefined) {
      setFullscreen(renderer.screenMode === 'alternate-screen');
      setNotice(localNotice); editor.clear(); return;
    }
    if (Buffer.byteLength(goal) > goalByteLimit) { setNotice('Composer input exceeds the goal size limit.'); return; }
    if (command === '/help') {
      setActionLines(['Commands: Enter submits · Shift+Enter adds a line · Tab opens details · /cancel stops work · /exit quits.',
        '/task <goal> starts project work · /new · /clear · /resume [session] · /compact · /rewind · /decision',
        '/settings · /workflow · /decisions · /harness status · /permissions · /accounting · /login · /image <path> · /read <path> · /tui']);
      setPrivatePanel(false);
      setNotice(''); editor.clear(); return;
    }
    if (command === '/image') { image = undefined; setNotice('Image detached.'); editor.clear(); return; }
    const file = /^\/image\s+(\S+)$/u.exec(command)?.[1];
    const context = command === '/rewind' ? 'rewind' : command === '/compact' ? 'compact' : undefined;
    const readPath = /^\/read[ \t]+(\S.*)$/u.exec(command)?.[1];
    const project = /^\/task[ \t]+(\S.*)$/u.exec(command)?.[1];
    const target = context === 'compact' ? subject() : turns().at(-1);
    if ((context || readPath) && !target) { setNotice(context === 'compact' ? 'No conversation to compact yet; submit a task first.' : 'No task to ' + (context ?? 'read for') + '.'); editor.clear(); return; }
    const switchSession = command === '/new' || command === '/clear';
    const resume = /^\/resume\s+(\S+)$/u.exec(command)?.[1];
    const listSessions = command === '/resume';
    const decision = command === '/decision';
    const center = settingsCommand(command);
    let action: OperatorAction | undefined;
    try { if (!decision) action = operatorAction(command); }
    catch { setNotice('Invalid command arguments.'); return; }
    if (command.startsWith('/') && !center && !switchSession && !resume && !listSessions && !decision && !project && !file && !readPath && !context && !action) {
      setNotice('Unknown command. Use /help or Tab for commands.');
      editor.clear();
      return;
    }
    sending = true;
    clearTimeout(timer);
    setNotice('Submitting…');
    let sessions: string[] | undefined;
    try {
      await reading;
      if (disposed || permission() || question()) return;
      core ??= await newOwner();
      if (disposed) { await core.close(); return; }
      let owner = core;
      if ((resume || listSessions) && core.disconnected) {
        live = undefined;
        await core.close();
        if (disposed) return;
        owner = replacement = await newOwner();
        if (disposed) return;
      }
      setActionLines([]);
      setPrivatePanel(action?.kind.startsWith('login_') ?? false);
      if (center) {
        setSettings(center); setChoices([]); setNotice('');
      } else if (readPath && target) {
        setPrivatePanel(true);
        const result = await owner.command('read', {task_id: target.id, path: readPath});
        if (disposed) return;
        setActionLines(result.lines); setNotice('');
      } else if (file || (context && target)) {
        const result = file ? await owner.command('image', {path: file}) : await owner.command(context!, {task_id: target!.id});
        if (disposed) return;
        if (context === 'compact') nextDock = 0;
        if (file) image = result.image;
        setActionLines(result.lines);
        setNotice('');
      } else if (decision) {
        const target = turns().filter(task => task.state === 'waiting').at(-1);
        if (target) await loadQuestion(owner, target, 'inspect');
        else setNotice('No pending question.');
      } else if (listSessions) {
        sessions = await owner.recentSessions();
        if (disposed) return;
      } else if (switchSession) {
        const result = await owner.newSession();
        if (disposed) return;
        if ('running' in result) {
          setNotice(command + ' refused: task ' + result.running + ' is running');
          editor.clear(); return;
        }
        dismissedFork = undefined;
        live = undefined;
        clearDock();
        reviewedPatch = undefined; setAppliedPatch(undefined);
        image = undefined;
        setTurns([]);
        setMoreHistory(false);
        setNotice('New conversation: ' + result.session + '\nPrevious session: ' + result.previous);
      } else if (resume) {
        const result = await owner.resume(resume);
        if (disposed) return;
        core = owner;
        replacement = undefined;
        dismissedFork = undefined;
        live = undefined;
        clearDock();
        reviewedPatch = undefined; setAppliedPatch(undefined);
        image = undefined;
        setTurns(result.tasks);
        setMoreHistory(result.more);
        setNotice('Resumed session: ' + resume);
        await loadPermission(owner);
        const waiting = result.tasks.findLast(task => task.state === 'waiting');
        if (waiting) await loadQuestion(owner, waiting);
      } else if (action) {
        const lines = await owner.action(action);
        if (disposed) return;
        setConnection(owner.loginStatus);
        const usage = action.kind === 'accounting' && dock().page;
        setActionLines(usage ? [...lines, ...usage.rows, ...(usage.profile ? [usage.profile] : []), usage.economy] : lines);
        setNotice('');
      } else {
        const task = await owner.submit(project ?? goal, project ? 'project' : undefined);
        if (disposed) return;
        dismissedFork = undefined;
        live = task.state === 'running' ? task : undefined;
        clearDock();
        pendingSubject = task.state === 'running' || task.state === 'waiting' ? task : undefined;
        setTurns(previous => [...previous, task]);
        setNotice('');
        if (task.state !== 'running') await loadPermission(owner);
        if (task.state === 'waiting') await loadQuestion(owner, task);
      }
      if (!listSessions) setRecent([]);
      if (editor.plainText === goal) editor.clear();
    } catch (error) {
      if (error instanceof BootFailure) { await failedRetry(error); return; }
      if (!disposed && context === 'compact' && error instanceof Error && error.message === compactNotShorter) {
        setNotice(compactNotShorter); if (editor.plainText === goal) editor.clear(); return;
      }
      if (!disposed) setNotice(readPath ? 'Read not confirmed. Check project scope and permission.' : file ? 'Image refused. Check file type, size and project scope.' : context || action ? 'Action not confirmed. Check current state before retrying.' : listSessions ? 'Cannot list sessions. Draft kept.' : switchSession || resume ? 'Session switch failed. Draft kept.' : 'No task receipt. Check session history before retrying.');
    } finally {
      // Listing is passive: an unbound replacement must not receive the next message.
      if (replacement) { await replacement.close(); replacement = undefined; }
      if (!disposed && sessions) {
        setRecent(sessions);
        setNotice(sessions.length ? 'Open with /resume <session-id>.' : 'No saved sessions.');
      }
      sending = false;
      watch();
    }
  }
  const detail = () => turns()[selected() ?? -1];
  const sidebarTask = () => subject();
  const transient = (task: () => Task) => <>
    {task().preview && <><text fg={secondary}>{task().preview!.status}</text><text fg={ink}>{task().preview!.text}</text></>}
    {task().output && <><text fg={secondary}>{task().output!.status}</text>
      {task().reply === undefined && task().output!.text && <text fg={ink}>{task().output!.text}</text>}</>}
    {task().proposedDiff && <text fg={secondary}>Proposed change · {task().proposedDiff}</text>}
  </>;
  const eventList = (task: () => Task) => <Index each={task().events}>{event => <box flexDirection="column">
    <text fg={secondary}>├─ {event().category ?? 'event'} · {event().type}</text>
    {event().text && (event().category === 'diff' && /^(?:diff --git |--- |@@ )/u.test(event().text!)
      ? <diff diff={event().text} view="unified" wrapMode="char" fg={ink} />
      : <text fg={ink}>{event().text}</text>)}
  </box>}</Index>;
  return <box flexDirection={narrow() ? 'column' : 'row'} height="100%" minHeight={0} overflow="hidden" backgroundColor={canvas}>
    <Show when={!narrow()} fallback={<text fg={accent} bg={surface} flexShrink={0} wrapMode="none" truncate>
      ╞╪ RIVECT{sidebarTask() ? ' · ' + (waitingVerifier(sidebarTask())?.text ?? sidebarTask()!.state) : ''}
    </text>}>
      <ThreadRail width={railWidth()} height={size().height} project={project} task={sidebarTask()} turns={turns()} />
    </Show>
    <box flexDirection="column" flexGrow={1} flexBasis={0} minWidth={0} minHeight={0}>
      <box flexDirection="row" justifyContent="space-between" border={['bottom']} borderColor={line}
        paddingX={inset()} paddingTop={compact() ? 0 : 1} flexShrink={0}>
        <text fg={ink} attributes={TextAttributes.BOLD} wrapMode="none" truncate>
          {detail() ? selectedWait() ? 'Verifier detail' : 'Task detail' : project}
        </text>
        <Show when={size().width >= 82}><text fg={secondary} wrapMode="none" flexShrink={0}>
          {turns().length ? 'thread / ' + turns().at(-1)!.session.slice(0, 8) : 'thread'}
        </text></Show>
      </box>
      <box flexGrow={1} flexBasis={0} minHeight={0} overflow="hidden">
      <scrollbox ref={history} flexGrow={1} minHeight={0} stickyScroll stickyStart="bottom"
        contentOptions={{paddingLeft: narrow() ? 1 : inset() * 2, paddingRight: narrow() ? 0 : inset(), paddingTop: narrow() ? 0 : 1}}
        verticalScrollbarOptions={{trackOptions: {foregroundColor: line, backgroundColor: canvas}}}>
        {!turns().length && <>
          <text fg={secondary}>{connection()}</text>
          <text fg={secondary} wrapMode="char">Project: {opened.project}</text>
        </>}
        <For each={bootNotes()}>{diagnostic => <text fg={ink}>{diagnostic}</text>}</For>
        {moreHistory() && <text fg={secondary}>Page Up here for older messages</text>}
        <Index each={turns()}>{task => {
          const result = () => checkResult(task());
          const reply = () => result() ? task().reply?.slice(result()!.length + 1) : task().reply;
          const patch = () => {
            const applied = appliedPatch();
            if (fullscreen() && applied && applied.question.session === task().session &&
                applied.question.pin.task_id === task().id && confirmedWrites(task()) > applied.writes) return applied;
          };
          return <>
            <ThreadNode label={goalAuthor(task())} state={task().state} human={goalAuthor(task()) === 'You'} compact={compact()}>
              {task().goal !== undefined && <text fg={ink}>{task().goal}</text>}
            </ThreadNode>
            <Show when={task().events.some(event => event.category !== 'task' && event.category !== 'waiting') ||
              task().preview || task().output || task().reply !== undefined || task().proposedDiff || task().errorCode}>
              <ThreadNode label="Main" compact={compact()}
                footer={fullscreen() || task().reply === undefined ? task().output?.status : undefined}>
                <Index each={task().events.filter(event => event.category !== 'task' && event.category !== 'waiting')}>{event =>
                  <ThreadBranch label={event().category === 'agent' && event().type === 'question.published' ? event().type : event().category ?? event().type}>
                    <Show when={event().text}>{description => <text fg={ink}>{description()}</text>}</Show>
                    <Show when={patch()?.eventId === event().id ? patch()?.content : undefined}>{content =>
                      <diff diff={content()} view="unified" wrapMode="char" fg={ink}
                        gutter={{paddingLeft: 0, paddingRight: 1, minDigits: 1}}
                        addedBg={surface} removedBg={surface} contextBg={surface}
                        addedSignColor={palette.agent} removedSignColor={accent} />}
                    </Show>
                  </ThreadBranch>
                }</Index>
                {task().proposedDiff && <ThreadBranch label="Proposed change"><text fg={ink}>{task().proposedDiff}</text></ThreadBranch>}
                <Show when={result()}>{observed => <ThreadBranch label="Verifier · check result"><text fg={ink}>{observed()}</text></ThreadBranch>}</Show>
                <Show when={reply()}>{body => <markdown content={body()} syntaxStyle={style} fg={ink} />}</Show>
                {task().preview && <>
                  {!fullscreen() && <text fg={secondary}>{task().preview!.status}</text>}
                  <text fg={ink}>{task().preview!.text}</text>
                </>}
                {task().reply === undefined && task().output?.text && <text fg={ink}>{task().output!.text}</text>}
                <Show when={task().errorCode}>{code => <text fg={accent}>{task().state}: {code()}</text>}</Show>
              </ThreadNode>
            </Show>
          </>;
        }}</Index>
        {recent().length > 0 && <text fg={secondary}>Recent sessions</text>}
        <For each={recent()}>{id => <text fg={ink}>{id}</text>}</For>
        <For each={actionLines()}>{line => <text fg={ink}>{line}</text>}</For>
      </scrollbox>
      <Show when={detail()}>{current => <scrollbox ref={details} position="absolute" top={0} left={0} width="100%" height="100%" backgroundColor={canvas}>
        <text fg={accent}>{current().state} · {current().id}</text>
        <Show when={selectedWait()} fallback={<>
          <text fg={ink}>{current().goal}</text>
          <Index each={current().activity}>{e => <text fg={secondary}>{e().category ?? 'activity'} · {e().type}{e().text ? ': ' + e().text : ''}</text>}</Index>
          {eventList(current)}
          {transient(current)}
          {current().reply && <markdown content={current().reply!} syntaxStyle={style} fg={ink} />}
          <text fg={secondary}>{current().errorCode}</text>
        </>}>{event => <>
          <text fg={ink}>{event().text}</text>
          <text fg={secondary}>{event().type} · {event().id}</text>
          <text fg={secondary}>/decision opens the pending check</text>
        </>}</Show>
      </scrollbox>}</Show>
      </box>
      {picker() !== undefined && core && <ProviderPicker owner={core} initialQuery={picker()} close={result => {
        setPicker(undefined);
        if (!result) { setNotice(''); return; }
        setActionLines(result.lines);
        if (result.pending) {
          lastLogin = result.pending; setLoginPending(result.pending);
          if (core) setConnection(core.loginStatus);
        }
        else setNotice(result.lines.at(-1) ?? '');
        watch();
      }}/>}
      {loginPending() && core && <PrivateLogin pending={loginPending()!} owner={core} lines={actionLines()} close={result => {
        if (core) setConnection(core.loginStatus);
        lastLogin = undefined; setLoginPending(undefined);
        setActionLines(result ?? []); setNotice(''); watch();
      }}/>}
      {settings() && core && <SettingsCenter initial={settings()!} owner={core} close={()=>{setSettings(undefined);watch();}}/>}
      {!permission() && question() && core && <DecisionView question={question()!} confirm={answer} reveal={reveal} dismiss={() => {
        if (!sending) { dismissedFork = question(); setQuestion(undefined); setNotice('Unanswered; question stays pending'); watch(); }
      }} />}
      <box flexDirection="column" flexShrink={0} backgroundColor={surface} border={['top']} borderColor={line} paddingX={inset()}>
        {notice() && <text fg={ink} flexShrink={0}>{notice()}</text>}
        {choices().length > 0 && <text fg={secondary}>↑↓ · Tab: {choices()[choice()]} ({choice() + 1}/{choices().length})</text>}
        <box flexDirection="row" gap={2}>
          <text fg={accent} attributes={TextAttributes.BOLD} flexShrink={0}>{detail() ? '↑↓ Tasks · Esc back' : 'Message → Main'}</text>
          <textarea ref={editor} focused={selected() === undefined && !permission() && !question() && !settings() && !loginOpen()}
            height={size().height < 12 ? 1 : size().height < 26 ? 2 : 3} flexGrow={1} minWidth={0} textColor={ink} focusedTextColor={ink}
            backgroundColor={surface} focusedBackgroundColor={surface} placeholderColor={secondary}
            placeholder={detail() ? '' : 'Reply to Main…'}
            onContentChange={() => { if (!loginOpen() && editor?.plainText && discardCallback(editor.plainText)) return; if (choices().length) setChoices([]); }}
            keyBindings={[{ name: 'return', action: 'submit' }, { name: 'return', shift: true, action: 'newline' }]}
            onSubmit={submit} />
        </box>
        {!question() && !permission() && !settings() && !loginOpen() && <>
          <Show when={fullscreen() && turns().at(-1)?.preview?.status}>{status =>
            <text fg={secondary}>{status()}</text>
          }</Show>
          <DockBand state={dock()} width={size().width - (narrow() ? 0 : railWidth()) - inset() * 2}
            connection={connection()} phase={sidebarTask()?.state} />
        </>}
      </box>
    </box>
    {permission() && core && <PermissionView request={permission()!} owner={core} close={note => {
      setPermission(undefined); setNotice(note);
      const owner = core;
      if (owner) void loadPermission(owner).then(watch);
    }} />}
  </box>;
}
