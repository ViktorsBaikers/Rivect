import { RGBA, TextAttributes, type OptimizedBuffer } from '@opentui/core';

const unknownTheme = 'rivect: unknown RIVECT_THEME; accepted values are light|dark|high-contrast; no theme applied';
const terminalInk = RGBA.defaultForeground(), terminalCanvas = RGBA.defaultBackground();
const raw = process.env.RIVECT_THEME, background = process.env.COLORFGBG?.split(';').at(-1);
const inferred = background && /^\d+$/u.test(background) && Number(background) < 16
  ? Number(background) < 8 ? 'dark' : 'light' : undefined;
const theme = raw === undefined ? inferred : raw === 'dark' || raw === 'light' || raw === 'high-contrast' ? raw : undefined;
const term = process.env.TERM?.toLowerCase() ?? '';
const color = !!process.stdout.isTTY && process.env.NO_COLOR === undefined && term !== 'dumb';
const mux = process.env.RIVECT_HOST_MUX === '1' || /^(?:tmux|screen)(?:-|$)/u.test(term);
const capable = /^(?:truecolor|24bit)$/iu.test(process.env.COLORTERM ?? '') || term.endsWith('-direct');
const thread = color && capable && !mux && (theme === 'dark' || (raw === undefined && theme === undefined));
// SSH may forward TERM without the local emulator's theme or truecolor hints.
const indexed = color && !thread && (theme !== undefined ||
  (raw === undefined && (capable || /-(?:256|88)color$/u.test(term))));
const token = (light: number, dark: number, high: number, plum: string) => thread ? RGBA.fromHex(plum)
  : indexed ? RGBA.fromIndex(theme === 'light' ? light : theme === 'high-contrast' ? high : dark) : terminalInk;
const ink = thread ? RGBA.fromHex('#f0e2ee') : terminalInk;
const canvas = thread ? RGBA.fromHex('#1c1521') : terminalCanvas;

export const palette = { ink, canvas, surface: thread ? RGBA.fromHex('#241b29') : canvas,
  secondary: token(4, 6, 11, '#b7a2bc'), accent: token(5, 13, 14, '#ffa58f'),
  agent: token(4, 6, 15, '#d7b2f6'), line: token(4, 6, 11, '#533e58'),
  modal: token(4, 6, 15, '#d7b2f6'),
  note: raw !== undefined && theme === undefined ? unknownTheme : undefined };

// Native empty cells, scrollbars and syntax spans may request RGB despite explicit widget colors.
// OpenTUI stores intent in the high byte of its green channel (RGBA.intent). Keep native indexed
// accents and reset only offending cells; never request another frame from a paint callback.
const indexedIntent = RGBA.fromIndex(0).buffer[1]! >>> 8;
const defaultIntent = ink.buffer[1]! >>> 8;
export function terminalPaletteFrame(buffer: OptimizedBuffer) {
  if (thread) return;
  buffer.withBuffers(({fg, bg, attributes}) => {
    for (let i = 0, cell = 0; i < fg.length; i += ink.buffer.length, cell++) {
      const intent = fg[i + 1]! >>> 8;
      if (intent !== defaultIntent && !(indexed && intent === indexedIntent && (fg[i]! >>> 8) < 16)) fg.set(ink.buffer, i);
      if ((bg[i + 1]! >>> 8) !== defaultIntent) bg.set(canvas.buffer, i);
      if (theme === 'high-contrast') attributes[cell] = attributes[cell]! | TextAttributes.BOLD;
    }
  });
}
