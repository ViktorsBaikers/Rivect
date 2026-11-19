import { Show } from 'solid-js';
import type { DockState } from './dock-data';
import { palette } from './theme';

export function DockBand(props:{state:DockState; width:number; connection:string; phase?:string}) {
  const page = () => props.state.page;
  const summary = () => {
    const report = page()?.summary;
    if (!report) return props.connection;
    return props.width >= 55 ? report : report.split(' · ', 1)[0]?.replace(/ unknown tok$/u, ' unknown');
  };
  const warning = () => {
    const dock = page();
    if (!dock || dock.percent === null) return;
    const short = `${dock.percent}% full (auto-compact off): /compact`;
    const head = `Context ${short}`;
    const named = `${head} folds task ${dock.task}`;
    if (Bun.stringWidth(named) <= props.width) return named;
    return Bun.stringWidth(head) <= props.width ? head : short;
  };
  return <box flexDirection="column" flexShrink={0}>
    <box flexDirection="row" gap={2}>
      <text fg={palette.secondary} flexShrink={0} wrapMode="none">/accounting</text>
      <text fg={palette.secondary} flexGrow={1} minWidth={0} wrapMode="none" truncate>
        {summary()}
      </text>
      <Show when={props.phase && props.width >= 38}><text fg={palette.accent} flexShrink={0} wrapMode="none">{props.phase}</text></Show>
    </box>
    <Show when={warning()}>{text => <text fg={palette.accent}>{text()}</text>}</Show>
    <Show when={props.state.stale}><text fg={palette.accent}>dock refresh failed: {props.state.stale}</text></Show>
  </box>;
}
