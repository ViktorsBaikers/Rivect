import type { CliRenderer } from '@opentui/core';
import { goalAuthor, type Task } from './wire';
import { looksLikeOAuthCallback } from './auth-input';

// Direct stdout in linear/scrollback mode is terminal input, not an escaped widget.
export function terminalText(value: string): string {
  return value.replace(/[\x00-\x09\x0b-\x1f\x7f-\x9f\u061c\u200e\u200f\u2028-\u202e\u2066-\u2069]/gu,
    c => '\u005cu{' + c.codePointAt(0)!.toString(16) + '}');
}

export function sourceLines(source: string, text: string) {
  const prefix = source + ': ';
  return prefix + text.replaceAll('\n', '\n' + prefix);
}

let mouseAllowed = true;

export function setMouseAllowed(enabled: boolean) { mouseAllowed = enabled; }

export function setSurface(renderer: CliRenderer, inline: boolean) {
  // Inline hands the transcript to native scrollback, so capture must not
  // keep swallowing the wheel; returning to fullscreen restores the
  // operator's choice (default on, --no-mouse or /tui mouse off opt out).
  renderer.useMouse = !inline && mouseAllowed;
  if (!inline) renderer.externalOutputMode = 'passthrough';
  renderer.screenMode = inline ? 'split-footer' : 'alternate-screen';
  if (inline) renderer.externalOutputMode = 'capture-stdout';
}

export function surfaceCommand(renderer: CliRenderer, command: string): string | undefined {
  if (command !== '/tui inline' && command !== '/tui fullscreen' && command !== '/tui') return;
  if (command !== '/tui') setSurface(renderer, command.endsWith('inline'));
  return 'tui: ' + (command === '/tui' ? '' : 'switched to ') + (renderer.screenMode === 'split-footer' ? 'inline' : 'fullscreen');
}

export function turnLines(task: Task, before?: Task): string[] {
  const lines: string[] = [];
  if (task.goal !== undefined && task.goal !== before?.goal && !/^\s*\/login(?:\s|$)/u.test(task.goal) && !looksLikeOAuthCallback(task.goal))
    lines.push(sourceLines(goalAuthor(task), task.goal));
  if (task.reply !== undefined && task.reply !== before?.reply) lines.push(sourceLines('Main', task.reply));
  if (task.events !== before?.events) {
    const seen = new Set(before?.events.map(event => event.id));
    for (const event of task.events) if (!seen.has(event.id) && event.text) lines.push(sourceLines(event.category ?? 'Activity', event.text));
  }
  if (task.state !== before?.state || task.errorCode !== before?.errorCode)
    lines.push(sourceLines('Task', task.state + (task.errorCode ? ': ' + task.errorCode : '') + ' · ' + task.id));
  return lines;
}

export function modeOutput(renderer: CliRenderer) {
  let previous = new Map<string, Task>();
  let lastNotice = '';
  return (turns: readonly Task[], notice: string) => {
    if (renderer.screenMode !== 'split-footer') { previous.clear(); lastNotice = ''; return; }
    const current = new Map<string, Task>();
    const lines: string[] = [];
    for (const task of turns) {
      const before = previous.get(task.id);
      if (before !== task) lines.push(...turnLines(task, before));
      current.set(task.id, task);
    }
    previous = current;
    if (notice && notice !== lastNotice && notice !== 'Submitting…') lines.push(sourceLines('Status', notice));
    lastNotice = notice;
    if (lines.length) process.stdout.write(terminalText(lines.join('\n')) + '\n');
  };
}
