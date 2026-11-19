import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import type { ScrollBoxRenderable } from '@opentui/core';
import { createSignal, For, onCleanup, onMount, Show } from 'solid-js';
import { useKeyboard, useRenderer, useTerminalDimensions } from '@opentui/solid';
import { verifiedCore } from './core';
import { record } from './wire';
import { palette } from './theme';

type Frame = {status: string; composer: string; dock: string[]; lines: string[]; panel: string[]};
const rows = (v: unknown): v is string[] => Array.isArray(v) && v.every(line => typeof line === 'string');
const exec = promisify(execFile);

// The native word breaker also splits after punctuation ("[" or "."). Review actions,
// identifiers and their labels wrap at spaces; native character wrap still handles overlong paths.
function wrapReview(text: string, width: number): string {
  return text.split('\n').map(line => {
    if (Bun.stringWidth(line) <= width) return line;
    let used = 0;
    return line.split(' ').map((word, index) => {
      const cells = Bun.stringWidth(word);
      const wrap = index > 0 && used + 1 + cells > width;
      const separator = index === 0 ? '' : wrap ? '\n' : ' ';
      used = index === 0 || wrap ? cells : used + 1 + cells;
      return separator + word;
    }).join('');
  }).join('\n');
}

export function ReviewView(props: {state: string}) {
  const renderer = useRenderer(), size = useTerminalDimensions();
  const abort = new AbortController();
  const [frame, setFrame] = createSignal<Frame>();
  const narrow = () => size().width < 64;
  // Outer and column padding take four cells; reserve one more for the scrollbar.
  const columnWidth = () => Math.max(1, size().width - 5);
  const dockWidth = () => narrow() ? columnWidth() : 24;
  const bodyWidth = () => narrow() ? columnWidth() : Math.max(1, columnWidth() - 26);
  let content: ScrollBoxRenderable | undefined;
  useKeyboard(key => {
    key.preventDefault();
    if (key.eventType !== 'press') return;
    if (key.ctrl && key.name === 'c') { process.exitCode = 130; renderer.destroy(); }
    else if (key.name === 'escape') renderer.destroy();
    else if (key.name === 'pageup' || key.name === 'pagedown') content?.scrollBy(key.name === 'pageup' ? -1 : 1, 'viewport');
    else if (key.name === 'up' || key.name === 'down') content?.scrollBy(key.name === 'up' ? -1 : 1);
  });
  onCleanup(() => abort.abort());
  onMount(async () => {
    try {
      const binary = await verifiedCore();
      if (abort.signal.aborted) return;
      const {stdout} = await exec(binary, ['--ui-review-data', props.state], {signal: abort.signal,
        timeout: 5000, maxBuffer: 1 << 20, encoding: 'utf8', env: {}});
      const result: unknown = JSON.parse(stdout);
      if (!record(result) || result.state !== props.state || typeof result.status !== 'string' ||
          typeof result.composer !== 'string' || !rows(result.lines) || !rows(result.dock) || !rows(result.panel))
        throw new Error('invalid review projection');
      if (!abort.signal.aborted) setFrame({status: result.status, composer: result.composer, lines: result.lines,
        dock: result.dock, panel: result.panel});
    } catch {
      if (!abort.signal.aborted) {
        process.exitCode = 2;
        renderer.destroy();
        process.stderr.write('unknown or unavailable review state\n');
      }
    }
  });
  return <box width="100%" height="100%" minHeight={0} flexDirection="column" overflow="hidden" backgroundColor={palette.canvas} paddingX={1}>
    <Show when={frame()} fallback={<text fg={palette.secondary}>Opening review…</text>}>{data => <>
      <text flexShrink={0} fg={palette.secondary}>{data().status}</text>
      <scrollbox ref={node => { content = node; }} flexGrow={1} flexShrink={1} flexBasis={0} minHeight={0} minWidth={0}>
        <box width="100%" flexDirection={narrow() ? 'column' : 'row'}>
          <box width={narrow() ? '100%' : 26} flexShrink={0} paddingX={1} backgroundColor={palette.surface}>
            <text fg={palette.secondary}>Activity</text><For each={data().dock}>{line => <text wrapMode="char" fg={palette.ink}>{wrapReview(line, dockWidth())}</text>}</For>
          </box>
          <box flexGrow={1} minWidth={0} paddingX={1}>
            <For each={data().panel}>{(line,i) => <text wrapMode="char" fg={i() === 0 ? palette.modal : palette.ink}>{wrapReview(line, bodyWidth())}</text>}</For>
            <For each={data().lines}>{line => <text wrapMode="char" fg={palette.ink}>{wrapReview(line, bodyWidth())}</text>}</For>
          </box>
        </box>
      </scrollbox>
      <text flexShrink={0} fg={palette.accent}>{data().composer ? '> ' + data().composer : '>'}</text>
      <text flexShrink={0} fg={palette.secondary}>Review · Esc closes · PgUp/PgDn scroll</text>
    </>}</Show>
  </box>;
}
