import { For, Show, createMemo, createSignal, onCleanup, onMount } from 'solid-js';
import { useKeyboard, usePaste } from '@opentui/solid';
import type { ScrollBoxRenderable } from '@opentui/core';
import { palette } from './theme';
import type { CoreClient } from './core';
import type { LoginMethod, LoginPending, LoginProvider } from './actions';

const KEY_LIMIT = 8192;

/** The `/login` picker: every core-advertised provider, filtered as the
 * operator types, then the provider's own method list. Selecting a leg
 * declares the connection and starts it in one step; a stored-key row keeps
 * its key hidden in this overlay and never sends it to a provider. */
export function ProviderPicker(props: {owner: CoreClient; initialQuery?: string;
  close: (result?: {lines: string[]; pending?: LoginPending}) => void}) {
  const [providers, setProviders] = createSignal<LoginProvider[]>();
  const [mode, setMode] = createSignal<'providers' | 'methods' | 'key'>('providers');
  const [query, setQuery] = createSignal(props.initialQuery ?? '');
  const [focus, setFocus] = createSignal(0);
  const [chosen, setChosen] = createSignal<LoginProvider>();
  const [notice, setNotice] = createSignal('Reading providers…');
  const [busy, setBusy] = createSignal(false);
  const [key, setKey] = createSignal('');
  let body: ScrollBoxRenderable | undefined, disposed = false;
  onCleanup(() => { disposed = true; setKey(''); });

  const matches = createMemo(() => {
    const words = query().trim().toLocaleLowerCase().split(/\s+/u).filter(Boolean);
    return (providers() ?? []).filter(provider => {
      const searchable = (provider.id + ' ' + provider.name + ' ' + provider.methods.map(method => method.label).join(' '))
        .toLocaleLowerCase();
      return words.every(word => searchable.includes(word));
    });
  });
  const rows = () => mode() === 'providers' ? matches().length
    : mode() === 'key' ? 0 : (chosen()?.methods.length ?? 0);
  const clamp = () => setFocus(value => Math.max(0, Math.min(value, Math.max(0, rows() - 1))));

  onMount(async () => {
    try {
      const loaded = await props.owner.loginProviders();
      if (disposed) return;
      setProviders(loaded);
      setNotice('');
    } catch {
      if (!disposed) setNotice('Providers are unavailable. Check the runtime and try /login again.');
    }
  });

  function back() {
    if (mode() === 'key') {
      setKey(''); setMode('methods'); setFocus(0); setNotice('');
      return;
    }
    if (mode() === 'methods' && (providers()?.length ?? 0) > 1) {
      setMode('providers'); setFocus(0); setNotice('');
      return;
    }
    props.close();
  }

  function refusal(error: unknown): string {
    const text = error instanceof Error ? error.message : String(error);
    return text.replace(/[\p{Cc}]+/gu, ' ').slice(0, 240);
  }

  async function start(provider: LoginProvider, method: LoginMethod) {
    if (busy()) return;
    // A stored-key row collects the key here; the write action declares the
    // connection and stores the key in one step.
    if (method.id === 'api_key') {
      setKey(''); setNotice(''); setMode('key');
      return;
    }
    setBusy(true);
    try {
      // A declared row needs no journal write; only a new provider is
      // materialized before its leg is minted.
      if (provider.declared) {
        setNotice('Opening the sign-in page…');
      } else {
        setNotice('Declaring the provider…');
        await props.owner.login({kind: 'login_connect', provider: provider.id});
        if (disposed) return;
        setNotice('Opening the sign-in page…');
      }
      const receipt = await props.owner.login({kind: 'login_start', provider: provider.id, method: method.id});
      if (!disposed) props.close(receipt);
    } catch (error) {
      if (!disposed) { setBusy(false); setNotice(`Sign-in refused: ${refusal(error)}`); }
    }
  }

  async function submitKey() {
    const provider = chosen();
    if (!provider || !key() || busy()) return;
    setBusy(true);
    try {
      const receipt = await props.owner.login({kind: 'login_key', provider: provider.id, key: key()});
      setKey('');
      if (!disposed) props.close(receipt);
    } catch (error) {
      if (!disposed) {
        setBusy(false);
        setNotice(`Key refused: ${refusal(error)}. Check the key and retry.`);
      }
    }
  }

  function choose() {
    if (busy()) return;
    if (mode() === 'key') { void submitKey(); return; }
    if (mode() === 'methods') {
      const provider = chosen(), method = provider?.methods[focus()];
      if (provider && method) void start(provider, method);
      return;
    }
    const provider = matches()[focus()];
    if (!provider) return;
    setChosen(provider);
    const only = provider.methods.length === 1 ? provider.methods[0] : undefined;
    if (only) { void start(provider, only); return; }
    setMode('methods'); setFocus(0); setNotice('');
  }

  usePaste(event => {
    if (mode() !== 'key' || busy()) return;
    event.preventDefault();
    const text = event.metadata?.kind === 'binary' ? '' : new TextDecoder().decode(event.bytes);
    if (key().length + text.length > KEY_LIMIT) { setNotice('The key exceeds the size limit.'); return; }
    setKey(value => value + text.replace(/[\p{Cc}]/gu, ''));
    setNotice('');
  });

  useKeyboard(keyboard => {
    if (keyboard.ctrl && keyboard.name === 'c') return;
    keyboard.preventDefault();
    if (keyboard.eventType !== 'press' || keyboard.repeated || busy()) return;
    if (keyboard.name === 'escape') { back(); return; }
    if (mode() === 'key') {
      if (keyboard.name === 'return') { void submitKey(); return; }
      if (keyboard.name === 'backspace' || keyboard.name === 'delete') {
        setKey(value => value.slice(0, -1)); return;
      }
      if (keyboard.ctrl || keyboard.meta || keyboard.option || keyboard.super) return;
      if (keyboard.sequence.length === 1 && !/[\p{Cc}]/u.test(keyboard.sequence)) {
        if (key().length >= KEY_LIMIT) { setNotice('The key exceeds the size limit.'); return; }
        setKey(value => value + keyboard.sequence); setNotice('');
      }
      return;
    }
    if (keyboard.name === 'pageup' || keyboard.name === 'pagedown') {
      body?.scrollBy(keyboard.name === 'pageup' ? -1 : 1, 'viewport'); return;
    }
    if (keyboard.name === 'return') { choose(); return; }
    if (mode() === 'methods') {
      if (keyboard.name === 'up' || keyboard.name === 'k') { setFocus(value => Math.max(0, value - 1)); return; }
      if (keyboard.name === 'down' || keyboard.name === 'j') { setFocus(value => Math.min(rows() - 1, value + 1)); return; }
      return;
    }
    if (keyboard.name === 'up') { setFocus(value => Math.max(0, value - 1)); return; }
    if (keyboard.name === 'down') { setFocus(value => Math.min(rows() - 1, value + 1)); return; }
    if (keyboard.name === 'backspace' || keyboard.name === 'delete') {
      setQuery(value => value.slice(0, -1)); clamp(); return;
    }
    if (keyboard.ctrl || keyboard.meta || keyboard.option || keyboard.super) return;
    if (keyboard.sequence.length === 1 && !/[\p{Cc}]/u.test(keyboard.sequence)) {
      setQuery(value => value + keyboard.sequence); setFocus(0);
    }
  });

  const methods = () => chosen()?.methods ?? [];
  const title = () => mode() === 'providers' ? 'Sign in to a provider'
    : mode() === 'key' ? `API key · ${chosen()?.name ?? ''}`
    : `Sign in · ${chosen()?.name ?? ''}`;
  return <box position="absolute" top={0} left={0} width="100%" height="100%" zIndex={4} minHeight={0} paddingX={1}
    overflow="hidden" backgroundColor={palette.surface}>
    <text flexShrink={0} fg={palette.modal}>{title()}</text>
    <Show when={mode() === 'providers'}><text flexShrink={0} fg={palette.ink}>
      <span style={{fg: palette.secondary}}>Search: </span>{query() || 'type to filter'}
    </text></Show>
    <scrollbox ref={node => { body = node; }} flexGrow={1} flexBasis={0} minHeight={0}>
      <Show when={mode() === 'key'} fallback={
        <Show when={mode() === 'methods'} fallback={
          <For each={matches()}>{(provider, index) => <text fg={index() === focus() ? palette.accent : palette.ink}>
            {index() === focus() ? '▪ ' : '  '}{provider.name}
            <span style={{fg: palette.secondary}}> · {provider.methods.map(method => method.label).join(' / ')}{provider.declared ? '' : ' · new'}</span>
          </text>}</For>
        }>
          <For each={methods()}>{(method, index) => <text fg={index() === focus() ? palette.accent : palette.ink}>
            {index() === focus() ? '▪ ' : '  '}{method.label}
            <span style={{fg: palette.secondary}}>{method.capture ? ' · captured automatically' : method.id === 'api_key' ? ' · stored locally' : ' · paste the redirect'}</span>
          </text>}</For>
        </Show>
      }>
        <text fg={palette.ink}>Paste the key · input hidden</text>
        <text fg={palette.secondary}>{key() ? 'Key entered · hidden' : 'The key is stored in the owner-only credential file.'}</text>
      </Show>
      <Show when={mode() === 'providers' && providers() && !matches().length}>
        <text fg={palette.secondary}>No provider matches this search.</text>
      </Show>
    </scrollbox>
    <Show when={notice()}><text fg={palette.ink}>{notice()}</text></Show>
    <text flexShrink={0} fg={palette.secondary}>
      {mode() === 'key' ? 'Enter stores the key · Esc back'
        : mode() === 'methods' ? '↑↓ method · Enter start · Esc back'
        : 'type to search · ↑↓ provider · Enter · Esc close'}
    </text>
  </box>;
}
