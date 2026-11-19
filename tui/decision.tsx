import { CliRenderEvents, type ScrollBoxRenderable, type TextRenderable, type TextareaRenderable } from '@opentui/core';
import { useKeyboard, usePaste, useRenderer, useTerminalDimensions } from '@opentui/solid';
import { createSignal, For, onCleanup, onMount, Show } from 'solid-js';
import type { Question, Selection } from './actions';
import { goalByteLimit, pasteDraft } from './input';
import { palette } from './theme';
import { callbackGuard } from './auth-input';

type Props = {question: Question; confirm: (selection: Selection) => Promise<void>; dismiss: () => void; reveal: (question: Question) => Promise<string>};

export function DecisionView(props: Props) {
  return <Show when={props.question} keyed>{question => <Card {...props} question={question} />}</Show>;
}

function Card(props: Props) {
  const q = props.question, count = q.options.length + Number(q.custom);
  const [focus, setFocus] = createSignal(0), [editing, setEditing] = createSignal(false);
  const [draft, setDraft] = createSignal(''), [note, setNote] = createSignal('');
  const privacy = callbackGuard(setNote);
  const [source, setSource] = createSignal<string>();
  let active = true, diffBody: ScrollBoxRenderable | undefined;
  onCleanup(() => { active = false; setSource(undefined); });
  const renderer = useRenderer(), size = useTerminalDimensions();
  let body!: ScrollBoxRenderable, prompt!: TextRenderable, editor: TextareaRenderable | undefined;
  const rows: TextRenderable[] = [];
  let firstFrame = Infinity;
  let promptSince = Infinity, promptRead = false, rowSince = Infinity, pending = false;
  function resetPaint() { promptRead = false; promptSince = rowSince = Infinity; }
  let draftByteUpperBound = goalByteLimit;
  function visible(node: TextRenderable | undefined) {
    if (!node?.visible || !body || source() !== undefined || editing()) return false;
    const v = body.viewport, width = Math.min(size().width, process.stdout.columns), height = Math.min(size().height, process.stdout.rows);
    // The card has one padding cell on each side. A flushed frame can contain no inner cells.
    return Math.max(1, v.screenX, node.screenX) < Math.min(width - 1, v.screenX + v.width, node.screenX + node.width) &&
      Math.max(0, v.screenY, node.screenY) < Math.min(height, v.screenY + v.height, node.screenY + node.height);
  }
  function painted() {
    const now = performance.now();
    if (firstFrame === Infinity) firstFrame = now;
    if (now - promptSince >= 200) promptRead = true;
    promptSince = visible(prompt) ? Math.min(promptSince, now) : Infinity;
    rowSince = visible(rows[focus()]) ? Math.min(rowSince, now) : Infinity;
  }
  onMount(() => { renderer.on(CliRenderEvents.RESIZE, resetPaint); renderer.on(CliRenderEvents.FRAME, painted); });
  onCleanup(() => { renderer.off(CliRenderEvents.RESIZE, resetPaint); renderer.off(CliRenderEvents.FRAME, painted); });
  usePaste(event => {
    if (privacy.intercept()) { event.preventDefault(); return; }
    if (editing() && editor) {
      const refusal = pasteDraft(editor, event);
      if (privacy.capture(editor)) return;
      if (refusal) setNote(refusal);
      draftByteUpperBound = goalByteLimit;
    }
    else { event.preventDefault(); setNote('Paste refused while the decision card owns input.'); }
  });
  function move(by: number) {
    const next = (focus() + by + count) % count;
    setFocus(next); setNote(''); rowSince = Infinity;
    const row = rows[next];
    if (row) body.scrollChildIntoView(row);
  }
  async function submit(selection: Selection) {
    pending = true;
    try { await props.confirm(selection); }
    finally { pending = false; }
  }
  useKeyboard(key => {
    if (key.ctrl && key.name === 'c') return;
    if (privacy.intercept(key)) { key.preventDefault(); return; }
    if (key.eventType !== 'press' || key.repeated || pending) { key.preventDefault(); return; }
    if (source() !== undefined) {
      key.preventDefault();
      if (key.name === 'escape') { setSource(undefined); resetPaint(); }
      else if (key.name === 'pageup' || key.name === 'pagedown') diffBody?.scrollBy(key.name === 'pageup' ? -1 : 1, 'viewport');
      return;
    }
    if (!editing() && q.canRevealDiff && key.name === 'v' && !key.ctrl && !key.meta && !key.option && !key.super && renderer.screenMode === 'alternate-screen') {
      key.preventDefault(); pending = true;
      void props.reveal(q).then(text => { if (active) setSource(text); }, () => { if (active) setNote('Proposal no longer available.'); }).finally(() => { pending = false; });
      return;
    }
    if (editing()) {
      if (privacy.capture(editor)) { key.preventDefault(); return; }
      if (key.name === 'escape') {
        key.preventDefault(); setDraft(editor?.plainText ?? ''); setEditing(false); setNote('');
      } else if (editor) {
        const text = key.name === 'return' ? '\n' : key.sequence;
        const first = text.charCodeAt(0);
        if (text !== '\n' && (key.meta || key.ctrl || key.option || key.super || !text || first < 32 || first === 127)) {
          draftByteUpperBound = goalByteLimit; // Undo or redo may restore a longer draft.
        } else {
          const bytes = Buffer.byteLength(text);
          if (draftByteUpperBound + bytes > goalByteLimit) draftByteUpperBound = Buffer.byteLength(editor.plainText) -
            (editor.hasSelection() ? Buffer.byteLength(editor.getSelectedText()) : 0);
          if (draftByteUpperBound + bytes > goalByteLimit) {
            key.preventDefault(); setNote('Custom answer exceeds the size limit.');
          } else draftByteUpperBound += bytes;
        }
      }
      return;
    }
    key.preventDefault();
    if (key.ctrl || key.meta || key.option || key.super) return;
    if (['up','left','k','h'].includes(key.name) || key.name === 'tab' && key.shift) move(-1);
    else if (['down','right','j','l','tab'].includes(key.name)) move(1);
    else if (key.name === 'pageup' || key.name === 'pagedown') {
      rowSince = Infinity;
      body.scrollBy(key.name === 'pageup' ? -1 : 1, 'viewport');
    }
    // Ignore arrival type-ahead. Esc is never a grant and remains available
    // after this floor even when geometry cannot display a complete option.
    else if (key.name === 'escape' && performance.now() - firstFrame >= 200) props.dismiss();
    else if (key.name === 'return' && !key.shift) {
      const now = performance.now();
      if ((!promptRead && now - promptSince < 200) || now - rowSince < 200 || !visible(rows[focus()])) return;
      const option = q.options[focus()];
      if (option?.disabled !== undefined) setNote('Unavailable: ' + option.disabled);
      else if (option) void submit({kind:'option', option_id:option.id});
      else if (!draft().trim()) setEditing(true);
      else if (Buffer.byteLength(draft()) > goalByteLimit) { setNote('Custom answer exceeds the size limit.'); setEditing(true); }
      else void submit({kind:'custom', text:draft()});
    }
  });
  return <box position="absolute" zIndex={2} top={0} left={0} width="100%" height="100%" backgroundColor={palette.surface} paddingX={1}>
    <text flexShrink={0} fg={palette.modal}>{q.title}</text>
    <text flexShrink={0} fg={palette.secondary}>task: {q.pin.task_id} · question: {q.pin.question_id} rev {q.pin.question_revision}</text>
    <scrollbox ref={body} flexGrow={1} flexBasis={0} minHeight={0}>
      <text ref={prompt} fg={palette.ink}>{q.prompt}</text>
      <text fg={palette.secondary}>recommended: {q.recommended} — {q.recommendation}</text>
      <For each={q.options}>{(option, i) => <text ref={node => { rows[i()] = node; }} fg={focus() === i() ? palette.accent : palette.ink}>
        {focus() === i() ? '> ' : '  '}{i() + 1}. {option.label} — {option.consequences}{option.id === q.recommended ? ' (recommended)' : ''}
        {option.disabled !== undefined ? ' — unavailable: ' + option.disabled : ''}
      </text>}</For>
      <Show when={q.custom}><text ref={node => { rows[q.options.length] = node; }} fg={focus() === q.options.length ? palette.accent : palette.ink}>
        {focus() === q.options.length ? '> ' : '  '}{count}. custom answer — {draft() || 'type your own answer'}
      </text></Show>
    </scrollbox>
    <Show when={editing()}><textarea ref={node => { editor = node; }} focused height={3} initialValue={draft()}
      onContentChange={() => { privacy.capture(editor); }}
      keyBindings={[{name:'return', action:'newline'}]} focusedBackgroundColor={palette.canvas} textColor={palette.ink} /></Show>
    <Show when={note()}><text fg={palette.accent}>{note()}</text></Show>
    <Show when={q.canRevealDiff && renderer.screenMode === 'alternate-screen'}><text fg={palette.secondary}>V view proposed diff</text></Show>
    <text flexShrink={0} fg={palette.secondary}>{editing() ? 'Esc finish · Enter newline' : 'Esc returns · Enter selects'} · focus {focus() + 1}/{count}{size().width >= 99 ? ' · ↑↓ move · PgUp/PgDn scroll' : ''}</text>
    <Show when={source()}>{diff => <box position="absolute" zIndex={3} top={0} left={0} width="100%" height="100%" backgroundColor={palette.surface}>
      <text fg={palette.modal}>Proposed diff · Esc back</text>
      <scrollbox flexGrow={1} minHeight={0} ref={node => { diffBody = node; }}><diff diff={diff()} view="unified" wrapMode="char" fg={palette.ink} /></scrollbox>
    </box>}</Show>
  </box>;
}
