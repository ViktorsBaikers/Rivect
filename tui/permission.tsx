import { CliRenderEvents, type ScrollBoxRenderable, type TextRenderable } from '@opentui/core';
import { useKeyboard, usePaste, useRenderer, useTerminalDimensions } from '@opentui/solid';
import { createSignal, onMount, onCleanup, Show } from 'solid-js';
import { setSurface } from './modes-output';
import { palette } from './theme';
import type { CoreClient } from './core';
import type { Permission } from './permission-data';

const actions = ['deny', 'allow once', 'allow with limited grant (10 min)'] as const;
const choices = ['deny', 'allow_once', 'limited_grant'] as const;
export function PermissionView(props: {request: Permission; owner: CoreClient; close: (note: string) => void}) {
  const r = props.request, renderer = useRenderer(), size = useTerminalDimensions();
  const [focus,setFocus] = createSignal(0), [note,setNote] = createSignal('');
  let body!: ScrollBoxRenderable, title!: TextRenderable, actionsRow!: TextRenderable;
  let paintedAt = Infinity, paintedChoice = -1, busy = false, active = true;
  function onScreen(node: TextRenderable | undefined) {
    return !!node && node.visible && node.width > 0 && node.height > 0 && node.y >= 0 && node.y + node.height <= size().height;
  }
  function painted() {
    if (!onScreen(title) || !onScreen(actionsRow) || !body || body.height < 1) { paintedAt = Infinity; paintedChoice = -1; return; }
    if (paintedAt === Infinity) paintedAt = performance.now();
    paintedChoice = focus();
  }
  const inline = renderer.screenMode === 'split-footer';
  const [privateSurface, setPrivateSurface] = createSignal(!inline);
  function afterResize() {
    // The mode getter includes queued transitions. RESIZE follows the native screen change.
    if (renderer.screenMode === 'alternate-screen' && renderer.height === renderer.terminalHeight) setPrivateSurface(true);
  }
  onMount(() => {
    renderer.on(CliRenderEvents.FRAME, painted);
    if (inline) { renderer.on(CliRenderEvents.RESIZE, afterResize); setSurface(renderer, false); }
  });
  onCleanup(() => {
    active = false;
    renderer.off(CliRenderEvents.FRAME, painted);
    renderer.off(CliRenderEvents.RESIZE, afterResize);
    if (inline && !renderer.isDestroyed) setSurface(renderer, true);
  });
  usePaste(event => { event.preventDefault(); setNote('paste refused while the permission panel owns input'); });
  async function confirm(choice: typeof choices[number]) {
    busy = true;
    try {
      await renderer.suspend();
      let result;
      try { result = await props.owner.resolvePermission(r, choice); }
      finally { if (active) await renderer.resume(); }
      if (!active) return;
      if (result.closed) { props.close(result.note); return; }
      setNote(result.note);
    } catch { if (active) setNote('Permission outcome unknown. Check session before retrying.'); }
    finally { busy = false; paintedAt = Infinity; paintedChoice = -1; if (active) setFocus(0); }
  }
  useKeyboard(key => {
    if (key.ctrl && key.name === 'c') return;
    key.preventDefault();
    if (!privateSurface() || busy || key.eventType !== 'press' || key.repeated || key.ctrl || key.meta || key.option || key.super) return;
    const backwards = key.name === 'up' || key.name === 'left' || key.name === 'tab' && key.shift;
    if (backwards || key.name === 'down' || key.name === 'right' || key.name === 'tab') {
      paintedChoice = -1; setFocus(i => (i + (backwards ? 2 : 1)) % 3); setNote('');
    } else if (key.name === 'pageup' || key.name === 'pagedown') body.scrollBy(key.name === 'pageup' ? -1 : 1, 'viewport');
    else if (!key.shift && paintedChoice === focus() && performance.now()-paintedAt >= 200) {
      if (key.name === 'return') void confirm(choices[focus()]!);
      else if (key.name === 'escape') void confirm('deny');
    }
  });
  return <Show when={privateSurface()}><box position="absolute" zIndex={3} top={0} left={0} width="100%" height="100%" backgroundColor={palette.surface} paddingX={1}>
    <text ref={title} fg={palette.modal}>awaiting permission</text>
    <text fg={palette.ink}>{'decision: ask\neffect: '+r.effect+'\ninitiator: '+r.initiator+'\nexpiry: '+r.expiry+'\ngrant: '+r.grant}</text>
    <scrollbox ref={body} minHeight={0} flexGrow={1} flexBasis={0}><text wrapMode="char" fg={palette.ink}>{'scope: '+r.scope}</text></scrollbox>
    <Show when={note()}><text flexShrink={0} fg={palette.accent}>{note()}</text></Show>
    <text ref={actionsRow} flexShrink={0} fg={palette.accent}>{actions.map((a,i) => i===focus() ? '['+a+']' : a).join(' | ')}</text>
    <text flexShrink={0} fg={palette.secondary}>arrows move, PgUp/PgDn scroll, Enter confirms, Esc denies</text>
  </box></Show>;
}
