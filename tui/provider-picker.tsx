import { For, Show, createMemo, createSignal, onCleanup, onMount } from 'solid-js';
import { useKeyboard } from '@opentui/solid';
import type { ScrollBoxRenderable } from '@opentui/core';
import { palette } from './theme';
import type { CoreClient } from './core';
import type { LoginMethod, LoginPending, LoginProvider } from './actions';

/** The `/login` picker: every core-advertised provider, filtered as the
 * operator types, then the provider's own method list. Selecting a leg
 * declares the connection and starts it in one step; the panel that follows
 * owns the URL, the code and the redirect. */
export function ProviderPicker(props: {owner: CoreClient; initialQuery?: string;
  close: (result?: {lines: string[]; pending?: LoginPending}) => void}) {
  const [providers, setProviders] = createSignal<LoginProvider[]>();
  const [mode, setMode] = createSignal<'providers' | 'methods'>('providers');
  const [query, setQuery] = createSignal(props.initialQuery ?? '');
  const [focus, setFocus] = createSignal(0);
  const [chosen, setChosen] = createSignal<LoginProvider>();
  const [notice, setNotice] = createSignal('Reading providers…');
  const [busy, setBusy] = createSignal(false);
  let body: ScrollBoxRenderable | undefined, disposed = false;
  onCleanup(() => { disposed = true; });

  const matches = createMemo(() => {
    const words = query().trim().toLocaleLowerCase().split(/\s+/u).filter(Boolean);
    return (providers() ?? []).filter(provider => {
      const searchable = (provider.id + ' ' + provider.name + ' ' + provider.methods.map(method => method.label).join(' '))
        .toLocaleLowerCase();
      return words.every(word => searchable.includes(word));
    });
  });
  const rows = () => mode() === 'providers' ? matches().length : (chosen()?.methods.length ?? 0);
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
    if (mode() === 'methods' && (providers()?.length ?? 0) > 1) {
      setMode('providers'); setFocus(0); setNotice('');
      return;
    }
    props.close();
  }

  async function start(provider: LoginProvider, method: LoginMethod) {
    if (busy()) return;
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
    } catch {
      if (!disposed) { setBusy(false); setNotice('Sign-in could not start. Check the provider configuration and retry.'); }
    }
  }

  function choose() {
    if (busy()) return;
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

  useKeyboard(key => {
    if (key.ctrl && key.name === 'c') return;
    key.preventDefault();
    if (key.eventType !== 'press' || key.repeated || busy()) return;
    if (key.name === 'escape') { back(); return; }
    if (key.name === 'pageup' || key.name === 'pagedown') {
      body?.scrollBy(key.name === 'pageup' ? -1 : 1, 'viewport'); return;
    }
    if (key.name === 'return') { choose(); return; }
    if (mode() === 'methods') {
      if (key.name === 'up' || key.name === 'k') { setFocus(value => Math.max(0, value - 1)); return; }
      if (key.name === 'down' || key.name === 'j') { setFocus(value => Math.min(rows() - 1, value + 1)); return; }
      return;
    }
    if (key.name === 'up') { setFocus(value => Math.max(0, value - 1)); return; }
    if (key.name === 'down') { setFocus(value => Math.min(rows() - 1, value + 1)); return; }
    if (key.name === 'backspace' || key.name === 'delete') {
      setQuery(value => value.slice(0, -1)); clamp(); return;
    }
    if (key.ctrl || key.meta || key.option || key.super) return;
    if (key.sequence.length === 1 && !/[\p{Cc}]/u.test(key.sequence)) {
      setQuery(value => value + key.sequence); setFocus(0);
    }
  });

  const methods = () => chosen()?.methods ?? [];
  return <box position="absolute" top={0} left={0} width="100%" height="100%" zIndex={4} minHeight={0} paddingX={1}
    backgroundColor={palette.surface}>
    <text fg={palette.modal}>{mode() === 'methods' ? `Sign in · ${chosen()?.name ?? ''}` : 'Sign in to a provider'}</text>
    <Show when={mode() === 'providers'}><text fg={palette.ink}>
      <span style={{fg: palette.secondary}}>Search: </span>{query() || 'type to filter'}
    </text></Show>
    <scrollbox ref={node => { body = node; }} flexGrow={1} minHeight={0}>
      <Show when={mode() === 'providers'} fallback={
        <For each={methods()}>{(method, index) => <text fg={index() === focus() ? palette.accent : palette.ink}>
          {index() === focus() ? '▪ ' : '  '}{method.label}
          <span style={{fg: palette.secondary}}>{method.capture ? ' · captured automatically' : ' · paste the redirect'}</span>
        </text>}</For>
      }>
        <For each={matches()}>{(provider, index) => <text fg={index() === focus() ? palette.accent : palette.ink}>
          {index() === focus() ? '▪ ' : '  '}{provider.name}
          <span style={{fg: palette.secondary}}> · {provider.methods.map(method => method.label).join(' / ')}{provider.declared ? '' : ' · new'}</span>
        </text>}</For>
      </Show>
      <Show when={mode() === 'providers' && providers() && !matches().length}>
        <text fg={palette.secondary}>No provider matches this search.</text>
      </Show>
    </scrollbox>
    <Show when={notice()}><text fg={palette.ink}>{notice()}</text></Show>
    <text flexShrink={0} fg={palette.secondary}>
      {mode() === 'methods' ? '↑↓ method · Enter start · Esc back' : 'type to search · ↑↓ provider · Enter · Esc close'}
    </text>
  </box>;
}
