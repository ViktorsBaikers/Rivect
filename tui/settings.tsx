import { For, Show, createMemo, createSignal, onCleanup, onMount } from 'solid-js';
import { useKeyboard, usePaste } from '@opentui/solid';
import type { ScrollBoxRenderable, TextareaRenderable, TextRenderable } from '@opentui/core';
import { pasteDraft } from './input';
import { palette } from './theme';
import type { CoreClient } from './core';
import { missingUserConfig, type Setting, type SettingsPage, type SettingsRequest, type SettingsStart, type SettingValue } from './settings-data';
import { callbackGuard } from './auth-input';

type Draft = {key:string; digest:string; value?:SettingValue};
type Mode = 'list' | 'search' | 'address' | 'edit';
const hints: Record<string,string> = {'context.auto_compact':'compaction auto compact автосжатие',
  'decisions.mode':'ask auto decisions решения', 'workflow.enabled':'workflow on off процесс'};

export function SettingsCenter(props:{owner:CoreClient; initial:SettingsStart; close:()=>void}) {
  const [page,setPage] = createSignal<SettingsPage>(), [mode,setMode] = createSignal<Mode>('list');
  const [query,setQuery] = createSignal(''), [focus,setFocus] = createSignal(0), [input,setInput] = createSignal('');
  const [draft,setDraft] = createSignal<Draft>(), [notice,setNotice] = createSignal('Reading settings…');
  const [busy,setBusy] = createSignal(false), [stale,setStale] = createSignal(false);
  const privacy = callbackGuard(setNotice);
  let editor:TextareaRenderable | undefined, body:ScrollBoxRenderable | undefined, disposed = false;
  const rows = new Map<string,TextRenderable>();
  const results = createMemo(() => {
    const words = query().trim().toLocaleLowerCase().split(/\s+/u);
    return (page()?.entries ?? []).filter(entry => {
      const searchable = (entry.key + ' ' + (hints[entry.key] ?? '') + ' ' + entry.source).toLocaleLowerCase();
      return words.every(word => searchable.includes(word)); // Never index credential references or values.
    });
  });
  const selected = () => results()[focus()];
  async function read(request:SettingsRequest):Promise<SettingsPage | undefined> {
    if (busy()) return;
    setBusy(true);
    try {
      const result = await props.owner.settings({kind:'settings_center',request});
      if (!disposed) { setPage(result); return result; }
    } catch (error) {
      if (!disposed) {
        setStale(!!draft());
        setNotice(error instanceof Error && error.message === missingUserConfig ? missingUserConfig : error instanceof Error && error.message.startsWith('conflict:') ? 'Conflict. Draft kept; U reloads before retry.' :
          'Owner did not confirm. U reloads the setting; your draft is kept.');
      }
    } finally { if (!disposed) setBusy(false); }
  }
  onCleanup(() => { disposed = true; });
  onMount(async () => {
    const initial = props.initial, snapshot = await read({op:'inspect'});
    if (!snapshot) return;
    setNotice('');
    if (initial.key) {
      setQuery(initial.key); setFocus(0);
      if (snapshot.userConfig && initial.value !== undefined) setDraft({key:initial.key, value:initial.value, digest:snapshot.digest});
    } else if (initial.harness) setNotice(snapshot.harness);
  });
  function edit(next:Mode) {
    setMode(next); setInput(next === 'search' ? query() : ''); setNotice('');
  }
  function choose(index:number) {
    if (!results().length) return;
    setFocus(Math.max(0,Math.min(index,results().length - 1)));
    const row = rows.get(selected()!.key); if (row) body?.scrollChildIntoView(row);
  }
  async function acceptInput() {
    if (busy() || privacy.capture(editor)) return;
    const text = editor?.plainText ?? '';
    if (mode() === 'search') { setQuery(text); setFocus(0); setMode('list'); return; }
    if (mode() === 'address') {
      const result = await read({op:'get',key:text});
      if (result) { setQuery(text); setFocus(0); setMode('list'); setNotice(''); }
      return;
    }
    const entry = selected(), snapshot = page(); if (!entry || !snapshot || mode() !== 'edit') return;
    let value:SettingValue = text;
    if (typeof entry.value === 'boolean') {
      if (text !== 'true' && text !== 'false') { setNotice('Enter true or false.'); return; }
      value = text === 'true';
    } else if (entry.key === 'decisions.mode' && !['ask','auto','inherit'].includes(text)) {
      setNotice('Choose ask, auto, or inherit.'); return;
    }
    setDraft({key:entry.key,value,digest:snapshot.digest}); setMode('list'); setNotice('');
  }
  async function save(proposal:Draft) {
    const fields = {key:proposal.key, scope:'user' as const, expected_source_digest:proposal.digest};
    const response = await read(proposal.value === undefined ? {op:'reset',...fields} : {op:'set',...fields,value:proposal.value});
    if (response) { setDraft(undefined); setStale(false); setNotice(proposal.value === undefined ? 'Reset user override.' : 'Saved to user config.'); }
  }
  async function refresh() {
    const proposal = draft(), key = proposal?.key ?? selected()?.key;
    const next = await read(key ? {op:'get',key} : {op:'inspect'});
    if (!next) return;
    if (proposal) setDraft({...proposal,digest:next.digest});
    setStale(false); setNotice(proposal ? 'Reloaded. Compare the current value before confirming.' : 'Reloaded settings.');
  }
  usePaste(event => {
    if (privacy.intercept() || mode() === 'list' || !editor) { event.preventDefault(); return; }
    const refusal = pasteDraft(editor,event);
    if (!privacy.capture(editor) && refusal) setNotice(refusal);
  });
  useKeyboard(key => {
    if (key.ctrl && key.name === 'c') return;
    if (privacy.intercept(key)) { key.preventDefault(); return; }
    if (key.eventType !== 'press' || key.repeated || busy()) { key.preventDefault(); return; }
    if (key.name === 'escape') {
      key.preventDefault();
      if (mode() !== 'list') { setMode('list'); setNotice(''); }
      else if (draft()) { setDraft(undefined); setStale(false); setNotice('Change discarded.'); }
      else props.close();
      return;
    }
    if (mode() !== 'list') return;
    key.preventDefault(); if (key.ctrl || key.meta || key.option || key.super) return;
    const d = draft();
    if (key.name === 'u') { void refresh(); return; }
    if (d) { if (key.name === 'y' && !stale()) void save(d); return; }
    if (!page()) return;
    if (key.sequence === '/') edit('search');
    else if (key.name === 'g') edit('address');
    else if (key.name === 'down' || key.name === 'j') choose(focus()+1);
    else if (key.name === 'up' || key.name === 'k') choose(focus()-1);
    else if (key.name === 'pageup' || key.name === 'pagedown') body?.scrollBy(key.name === 'pageup' ? -1 : 1,'viewport');
    else {
      const entry = selected(), snapshot = page();
      if (!entry || !snapshot?.userConfig || entry.redacted) return;
      if (key.name === 'e' || key.name === 'return') edit('edit');
      else if (key.name === 'space' && typeof entry.value === 'boolean') { setNotice(''); setDraft({key:entry.key,digest:snapshot.digest,value:!entry.value}); }
      else if (key.name === 'r') { setNotice(''); setDraft({key:entry.key,digest:snapshot.digest}); }
    }
  });
  const label = (entry:Setting) => entry.redacted ? 'redacted' : entry.value === null ? 'not set' : JSON.stringify(entry.value);
  return <box position="absolute" top={0} left={0} width="100%" height="100%" zIndex={3} minHeight={0} backgroundColor={palette.surface} paddingX={1}>
    <text flexShrink={0} fg={palette.modal}>{busy() && !page() ? 'Opening settings…' : 'Settings Center'}</text>
    <text flexShrink={0} fg={palette.secondary}>{page()?.userConfig === false ? missingUserConfig : 'Write scope: User · config.toml'}</text>
    <scrollbox ref={node=>{body=node;}} flexGrow={1} minHeight={0}>
      <text fg={palette.ink}>{query() ? `Search: ${query()} · ` : ''}{results().length} result{results().length === 1 ? '' : 's'}</text>
      <For each={results()}>{(entry,i)=><text ref={node=>{rows.set(entry.key,node);}} fg={focus() === i() ? palette.accent : palette.ink}>
        {focus() === i() ? '> ' : '  '}{entry.key} = {label(entry)} ({entry.source})
      </text>}</For>
      <Show when={page()?.userConfig && typeof selected()?.value === 'boolean'}><text fg={palette.secondary}>Space previews the opposite value.</text></Show>
      <Show when={selected()?.key === 'decisions.mode'}><text fg={palette.secondary}>Effective decision mode: {page()?.decisions}. This does not grant tool permissions.</text></Show>
      <Show when={!results().length && page()}><text fg={palette.secondary}>No matching settings. G opens an exact key.</text></Show>
      <Show when={page()}>{snapshot=><><text fg={palette.secondary}>{snapshot().harness}</text>
        <text fg={palette.secondary}>Registry: {snapshot().hint}</text></>}</Show>
    </scrollbox>
    <Show when={mode() !== 'list'}><text fg={palette.ink}>{mode() === 'search' ? 'Search settings' : mode() === 'address' ? 'Open exact setting key' : selected()?.key === 'decisions.mode' ? 'Decision mode: ask / auto / inherit' : typeof selected()?.value === 'boolean' ? 'Value (JSON) · true / false' : 'Text value · ' + selected()?.key}</text>
      <textarea ref={node=>{editor=node;}} focused height={2} initialValue={input()} textColor={palette.ink} focusedBackgroundColor={palette.canvas}
        onContentChange={()=>{ privacy.capture(editor); }}
        keyBindings={[{name:'return',action:'submit'}]} onSubmit={()=>void acceptInput()} /></Show>
    <Show when={draft()}>{proposal=><text flexShrink={0} fg={palette.accent}>{proposal().value === undefined ? 'Confirm reset' : 'Confirm change'} · User · {proposal().key}{'\n'}{label(page()!.entries.find(entry=>entry.key === proposal().key)!)} → {proposal().value === undefined ? 'inherit' : JSON.stringify(proposal().value)}</text>}</Show>
    <Show when={notice()}><text fg={palette.ink}>{notice()}</text></Show>
    <text flexShrink={0} fg={palette.secondary}>{mode() !== 'list' ? 'Enter: review · Esc: discard' : draft() ? 'Y confirm · U reload · Esc discard' : page()?.userConfig === false ? '/ search · G key · ↑↓ select · Esc close' : '/ search · G key · ↑↓ select · E edit · R reset · U reload · Esc close'}</text>
  </box>;
}
