import { createMemo, For, Show, type JSX } from 'solid-js';
import { TextAttributes } from '@opentui/core';
import { waitingVerifier } from './activity';
import { palette } from './theme';
import type { Task } from './wire';

const { ink, surface, secondary, agent, accent, line } = palette;
const bold = TextAttributes.BOLD;

export function checkResult(task: Task): string | undefined {
  if (!task.activity?.some(event => event.type === 'attempt.exec' && event.text === 'confirmed')) return;
  const result = task.reply?.split('\n', 1)[0];
  if (result && /^Cargo test [\w:-]+: (?:exit -?\d+|signal \d+|exit unknown)\.$/u.test(result)) return result;
}

export function ThreadRail(props: {width: number; height: number; project: string; task?: Task; turns: readonly Task[]}) {
  const compact = () => props.height < 30;
  const wait = () => waitingVerifier(props.task)?.text?.split(' · ', 2)[1];
  const check = createMemo(() => {
    for (let i = props.turns.length - 1; i >= 0; i--) {
      const observed = checkResult(props.turns[i]!);
      if (observed) return observed;
    }
  });
  const processes = createMemo(() => props.task?.activity?.filter(event => event.category === 'process' && event.text !== 'confirmed') ?? []);
  const stages = createMemo(() => props.task?.activity?.filter(event => event.category === 'stage') ?? []);
  const indent = () => compact() ? 1 : 2;
  return <box width={props.width} flexShrink={0} flexDirection="column" border={['right']} borderColor={line} backgroundColor={surface}>
    <box border={['bottom']} borderColor={line} paddingTop={compact() ? 0 : 1} paddingX={indent()} flexShrink={0}>
      <text fg={ink} attributes={bold}><span style={{fg: accent}}>╞╪</span> RIVECT</text>
    </box>
    <scrollbox flexGrow={1} flexBasis={0} minHeight={0} contentOptions={{paddingLeft: indent(), paddingRight: 1, paddingTop: 1}}
      verticalScrollbarOptions={{visible: false}}>
      <text fg={secondary}>Agents</text>
      <text fg={agent} attributes={bold}>Main{props.task?.state === 'running' ? ' · running' : ''}</text>
      <Show when={wait()}>{reason => <>
        <text fg={ink}><span style={{fg: line}}>└─ </span>Verifier</text>
        <text fg={secondary} paddingLeft={2}>{reason().replace(/^waiting for /u, 'waiting for\n')}</text>
      </>}</Show>
      <text fg={secondary} marginTop={1}>Processes</text>
      <Show when={check()}>{observed => <>
        <text fg={ink}><span style={{fg: line}}>└─ </span>Cargo test</text>
        <text fg={secondary} paddingLeft={2}>{observed().split(': ').at(-1)?.replace(/\.$/u, '')}</text>
      </>}</Show>
      <For each={processes()}>{event => <text fg={ink}><span style={{fg: line}}>├─ </span>Exec · {event.text}</text>}</For>
      {!check() && !processes().length && <text fg={secondary}>No processes</text>}
      <text fg={secondary} marginTop={1}>Plan</text>
      <Show when={props.task} fallback={<text fg={secondary}>No active task</text>}>{task => <>
        <For each={stages()}>{event => <text fg={ink} wrapMode="none" truncate>
          <span style={{fg: line}}>├─ </span>{event.type.slice('stage.'.length)} <span style={{fg: secondary}}>{event.text}</span>
        </text>}</For>
        <Show when={wait()} fallback={<text fg={task().state === 'running' ? accent : secondary}>└─ Task · {task().state}</text>}>
          <Show when={!stages().length && task().activity?.some(event => event.type === 'attempt.read' && event.text === 'confirmed')}>
            <text fg={ink}><span style={{fg: line}}>├─ </span>Read <span style={{fg: secondary}}>done</span></text>
          </Show>
          <Show when={!stages().length && task().activity?.some(event => event.type === 'attempt.write' && event.text === 'confirmed')}>
            <text fg={ink}><span style={{fg: line}}>├─ </span>Patch <span style={{fg: secondary}}>done</span></text>
          </Show>
          <text fg={accent}>{props.width < 21 ? '└─ Verify active' : '└─ Verify · active'}</text>
        </Show>
      </>}</Show>
    </scrollbox>
    <box border={['top']} borderColor={line} paddingX={indent()} flexShrink={0}>
      <text fg={secondary} marginTop={compact() ? 0 : 1}>workspace</text>
      <text fg={ink} wrapMode="none" truncate>{props.project}</text>
    </box>
  </box>;
}

export function ThreadNode(props: {label: string; state?: string; human?: boolean; children: JSX.Element; compact: boolean; footer?: string}) {
  return <box flexDirection="column" width="100%" maxWidth={76}>
    <text fg={props.human ? accent : agent} attributes={bold}>
      {props.human ? '▪' : '▫'}<span style={{fg: line}}>── </span>{props.label}
      <span style={{fg: secondary}}>{props.state && `  ${props.state}`}</span>
    </text>
    <box flexDirection="column" border={['left']} borderColor={line} paddingLeft={3}
      paddingBottom={(props.compact ? 1 : 2) - (props.footer ? 1 : 0)}>
      {props.children}
      <Show when={props.footer}>{status => <text fg={secondary}>{status()}</text>}</Show>
    </box>
  </box>;
}

export function ThreadBranch(props: {label: string; children?: JSX.Element}) {
  return <box flexDirection="column" marginLeft={2}>
    <text fg={secondary}><span style={{fg: line}}>├─ </span>{props.label}</text>
    <box flexDirection="column" border={['left']} borderColor={line} paddingLeft={2}>{props.children}</box>
  </box>;
}
