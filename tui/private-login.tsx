import { createEffect, createMemo, createSignal, For, onCleanup, Show } from 'solid-js';
import { useKeyboard, usePaste } from '@opentui/solid';
import type { ScrollBoxRenderable } from '@opentui/core';
import { palette } from './theme';
import { goalByteLimit } from './input';
import type { CoreClient } from './core';
import type { LoginPending } from './actions';

/** One started sign-in leg. The core captures a loopback browser redirect on
 * its own; this panel polls the completion, shows the device code, and keeps
 * the manual redirect entry hidden from the transcript when the browser
 * cannot reach this machine. */
export function PrivateLogin(props: {pending: LoginPending; owner: CoreClient; lines: readonly string[];
  close: (result?: string[]) => void}) {
  const [state, setState] = createSignal(''), [filled, setFilled] = createSignal(false);
  const [showUrl, setShowUrl] = createSignal(false), [done, setDone] = createSignal(false);
  const signIn = createMemo(() => {
    const url = props.pending.url;
    return /^https:\/\/[^\s\p{C}]+$/u.test(url) ? url : undefined;
  });
  const device = () => props.pending.user_code !== undefined;
  const browser = () => !device();
  let storage: Uint8Array | undefined, used = 0, pending = false, disposed = false, timer: ReturnType<typeof setInterval> | undefined;
  let details: ScrollBoxRenderable | undefined;

  function clear() { storage?.fill(0, 0, used); used = 0; setFilled(false); }
  onCleanup(() => { disposed = true; clear(); clearInterval(timer); });
  function reject() { clear(); setState('Input discarded. Paste the complete redirect on one line.'); }
  function append(bytes: Uint8Array) {
    if (!browser() || pending) return;
    if (bytes.length > goalByteLimit - used || bytes.some(byte => byte < 33 || byte > 126)) { reject(); return; }
    storage ??= new Uint8Array(goalByteLimit);
    storage.set(bytes, used); used += bytes.length; setFilled(used > 0); setState('');
  }

  async function check(redirect?: string) {
    if (pending || done()) return;
    pending = true;
    try {
      const receipt = await props.owner.login(redirect === undefined ? {kind: 'login_complete'} : {kind: 'login_callback', redirect});
      if (disposed) return;
      if (receipt.pending) {
        setState('');
      } else {
        setDone(true);
        props.close(receipt.lines);
      }
    } catch {
      if (!disposed) setState(redirect === undefined ? 'Waiting for the browser. Press Esc to cancel.' : 'Redirect refused and discarded. Paste a fresh redirect or press Esc.');
    } finally { pending = false; }
  }

  // Cancelling can race one completion poll; the cancel retries after the
  // pending request settles instead of leaving the panel without a timer.
  async function cancelLeg(attempt = 0) {
    if (disposed || done()) return;
    clearInterval(timer); timer = undefined;
    try {
      const receipt = await props.owner.login({kind: 'login_cancel'});
      if (!disposed) props.close(receipt.lines);
    } catch {
      if (disposed) return;
      if (attempt < 5) setTimeout(() => void cancelLeg(attempt + 1), 300);
      else setState('Cancellation not confirmed. Press Esc to retry.');
    }
  }

  function submit() {
    if (!storage || !used) return;
    const redirect = new TextDecoder().decode(storage.subarray(0, used)); clear();
    void check(redirect);
  }

  // A browser leg whose redirect the core captures, and every device leg,
  // complete without operator input: poll until the leg settles.
  createEffect(() => {
    const settle = props.pending.capture || device();
    if (!settle || timer) return;
    timer = setInterval(() => { if (!disposed) void check(); }, 1500);
  });

  usePaste(event => { event.preventDefault(); if (event.metadata?.kind !== 'binary') append(event.bytes); else reject(); });
  useKeyboard(key => {
    if (key.ctrl && key.name === 'c') return;
    key.preventDefault();
    if (key.eventType !== 'press' || key.repeated || done()) return;
    // Cancel is never dropped: a completion poll may hold the client, and the
    // cancel path retries once that request settles.
    if (key.name === 'escape') {
      clear();
      void cancelLeg();
      return;
    }
    if (pending) return;
    if (key.ctrl && !key.meta && !key.option && !key.super && key.name === 'y') {
      if (signIn()) setShowUrl(value => !value);
      return;
    }
    if (key.name === 'pageup' || key.name === 'pagedown') {
      details?.scrollBy(key.name === 'pageup' ? -1 : 1, 'viewport'); return;
    }
    if (!browser() || key.ctrl || key.meta || key.option || key.super) return;
    if (key.name === 'return') { submit(); return; }
    if (key.name === 'backspace' || key.name === 'delete') {
      if (used && storage) { storage[--used] = 0; setFilled(used > 0); }
    } else if (key.sequence.length === 1) {
      const byte = key.sequence.charCodeAt(0);
      if (byte < 33 || byte > 126 || used === goalByteLimit) { reject(); return; }
      storage ??= new Uint8Array(goalByteLimit);
      storage[used++] = byte; setFilled(true); setState('');
    }
  });
  return <box position="absolute" top={0} left={0} width="100%" height="100%" zIndex={4} minHeight={0} paddingX={1}
    backgroundColor={palette.surface}>
    <text fg={palette.modal}>{device() ? 'Sign in · device code' : 'Sign in · browser'}</text>
    <scrollbox ref={node => { details = node; }} flexGrow={1} minHeight={0}>
      <Show when={signIn()} keyed>{url => <>
        <text fg={palette.accent}><a href={url}><u>Open sign-in page</u></a></text>
        <text fg={palette.ink}>Ctrl+Y shows the full URL · use the terminal’s Copy Link action</text>
        <Show when={showUrl()}><text fg={palette.ink}>{url}</text></Show>
      </>}</Show>
      <Show when={device()}>
        <text fg={palette.ink}>Enter code: <span style={{fg: palette.accent}}>{props.pending.user_code}</span></text>
        <text fg={palette.ink}>Waiting for authorization…</text>
      </Show>
      <Show when={browser() && props.pending.capture}>
        <text fg={palette.ink}>Waiting for the browser redirect on this machine.</text>
      </Show>
      <Show when={browser() && !props.pending.capture}>
        <text fg={palette.ink}>The browser lands on a private address this terminal cannot receive.</text>
        <text fg={palette.ink}>Copy the full redirect URL from the browser address bar.</text>
      </Show>
      <For each={props.lines}>{line => <text fg={palette.secondary}>{line}</text>}</For>
    </scrollbox>
    <Show when={state()}><text fg={palette.ink}>{state()}</text></Show>
    <Show when={browser()}><text fg={palette.accent}>
      {filled() ? 'Redirect entered · hidden' : 'Paste the redirect URL · input hidden'}
    </text></Show>
    <text flexShrink={0} fg={palette.secondary}>
      {device() ? 'Esc cancels · automatic check' : 'Esc cancels · Enter checks a pasted redirect · PgUp/PgDn scroll'}
    </text>
  </box>;
}
