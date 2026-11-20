import { createMemo, createSignal, onCleanup, Show } from 'solid-js';
import { useKeyboard, usePaste, useRenderer } from '@opentui/solid';
import type { ScrollBoxRenderable } from '@opentui/core';
import { palette } from './theme';
import { goalByteLimit } from './input';
import type { CoreClient } from './core';

export type LoginInput = 'blocked' | 'callback';
export function PrivateLogin(props:{mode:LoginInput; owner?:CoreClient; lines:readonly string[]; close:(result?:string[])=>void}) {
  const [state,setState] = createSignal(''), [filled,setFilled] = createSignal(false);
  const renderer = useRenderer();
  const signIn = createMemo(() => {
    const prefix = 'Login pending: ';
    const line = props.lines[0];
    if (!line?.startsWith(prefix)) return;
    const url = line.slice(prefix.length);
    if (url.startsWith('https://auth.openai.com/oauth/authorize?') && !/[\s\p{C}]/u.test(url)) return url;
  });
  const [showUrl,setShowUrl] = createSignal(false);
  let storage:Uint8Array | undefined, used = 0, pending = false, disposed = false;
  let details:ScrollBoxRenderable | undefined;
  function clear() { storage?.fill(0,0,used); used = 0; setFilled(false); }
  onCleanup(() => { disposed = true; clear(); });
  function reject() { clear(); setState('Input discarded. Paste the complete callback on one line.'); }
  function append(bytes:Uint8Array) {
    if (props.mode !== 'callback' || pending) return;
    if (bytes.length > goalByteLimit - used || bytes.some(b=>b < 33 || b > 126)) { reject(); return; }
    storage ??= new Uint8Array(goalByteLimit);
    storage.set(bytes,used); used += bytes.length; setFilled(used > 0); setState('');
  }
  async function complete() {
    if (!storage || !used || !props.owner || pending) return;
    const redirect = new TextDecoder().decode(storage.subarray(0,used)); clear();
    if (!redirect.startsWith('http://localhost:1455/auth/callback?')) { reject(); return; }
    pending = true; setState('Checking authorization…');
    try {
      const lines = await props.owner.action({kind:'login_callback',redirect});
      if (!disposed) props.close(lines);
    } catch { if (!disposed) setState('Callback refused and discarded. Paste a fresh callback or press Esc.'); }
    finally { pending = false; }
  }
  usePaste(event => { event.preventDefault(); if (event.metadata?.kind !== 'binary') append(event.bytes); else reject(); });
  useKeyboard(key=>{
    if (key.ctrl && key.name === 'c') return;
    key.preventDefault();
    if (key.eventType !== 'press' || key.repeated || pending) return;
    if (key.name === 'escape') { clear(); props.close(); return; }
    if (props.mode === 'callback' && key.ctrl && !key.meta && !key.option && !key.super && key.name === 'y') {
      const url = signIn();
      if (url) {
        const sent = renderer.copyToClipboardOSC52(url);
        setShowUrl(true);
        setState(sent ? 'Copy requested. If blocked, select the URL below.' : 'Terminal clipboard unavailable. Select the URL below.');
      }
      return;
    }
    if (props.mode === 'blocked' || key.ctrl || key.meta || key.option || key.super) return;
    if (key.name === 'pageup' || key.name === 'pagedown') { details?.scrollBy(key.name === 'pageup' ? -1 : 1,'viewport'); return; }
    if (key.name === 'return') { void complete(); return; }
    if (key.name === 'backspace' || key.name === 'delete') {
      if (used && storage) { storage[--used] = 0; setFilled(used > 0); }
    } else if (key.sequence.length === 1) {
      const byte = key.sequence.charCodeAt(0);
      if (byte < 33 || byte > 126 || used === goalByteLimit) { reject(); return; }
      storage ??= new Uint8Array(goalByteLimit);
      storage[used++] = byte; setFilled(true); setState('');
    }
  });
  return <box position="absolute" top={0} left={0} width="100%" height="100%" zIndex={4} minHeight={0} paddingX={1} backgroundColor={palette.surface}>
    <text fg={palette.modal}>Private login</text>
    <Show when={props.mode === 'callback'} fallback={<text fg={palette.ink}>Callback discarded. It was not sent to Main. Use /login callback for private entry.</text>}>
      <scrollbox ref={node=>{details=node;}} flexGrow={1} minHeight={0}>
        <Show when={signIn()} keyed>{url => <>
          <text fg={palette.accent}><a href={url}><u>Open OpenAI sign-in</u></a></text>
          <text fg={palette.ink}>Ctrl+Y copies sign-in URL</text>
          <Show when={showUrl()}><text fg={palette.ink}>{url}</text></Show>
        </>}</Show>
        <text fg={palette.ink}>If the browser cannot reach localhost, leave that tab open.</text>
        <text fg={palette.ink}>Copy the full callback URL from the browser address bar.</text>
      </scrollbox>
      <text fg={palette.accent}>{filled() ? 'Callback entered · hidden' : 'Paste the callback URL · input hidden'}</text>
    </Show>
    <Show when={state()}><text fg={palette.ink}>{state()}</text></Show>
    <text flexShrink={0} fg={palette.secondary}>{props.mode === 'callback' ? 'Esc discards · Enter checks · PgUp/PgDn scroll' : 'Esc returns'}</text>
  </box>;
}
