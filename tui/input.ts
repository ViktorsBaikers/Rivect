import type { CliRenderer, PasteEvent, TextareaRenderable } from '@opentui/core';
import { setMouseAllowed } from './modes-output';

// Rust contracts::TEXT_MAX_BYTES bounds a composed goal, not the larger transport frame.
export const goalByteLimit = 65_536;
const utf8 = new TextDecoder('utf-8', { fatal: true });

export function mouseCommand(renderer: CliRenderer, command: string): string | undefined {
  const match = /^\/tui\s+mouse\s+(on|off)$/u.exec(command);
  if (!match) return;
  const enabled = match[1] === 'on';
  renderer.useMouse = enabled;
  setMouseAllowed(enabled);
  return 'tui: mouse ' + match[1];
}

export function pasteText(bytes: Uint8Array): string | {error: string} {
  if (bytes.length > goalByteLimit) return {error: 'Composer input exceeds the goal size limit.'};
  let text: string;
  try { text = utf8.decode(bytes).replace(/\r\n?/gu, '\n'); }
  catch { return {error: 'Paste is not valid UTF-8 text.'}; }
  for (const char of text) {
    const n = char.codePointAt(0)!;
    if ((n < 32 && n !== 9 && n !== 10) || (n >= 127 && n <= 159)) return {error: 'Paste contains terminal control characters.'};
  }
  return text;
}

/** Never treat clipboard bytes as keystrokes or read the system clipboard. */
export function pasteDraft(editor: TextareaRenderable, event: PasteEvent): string | undefined {
  event.preventDefault();
  if (event.metadata?.kind === 'binary') return 'Only text can be pasted into a message.';
  const text = pasteText(event.bytes);
  if (typeof text !== 'string') return text.error;
  if (!text) return;
  const selectedBytes = editor.hasSelection() ? Buffer.byteLength(editor.getSelectedText()) : 0;
  if (Buffer.byteLength(editor.plainText) - selectedBytes + Buffer.byteLength(text) > goalByteLimit)
    return 'Composer input exceeds the goal size limit.';
  if (selectedBytes) editor.deleteSelection();
  editor.insertText(text);
}
