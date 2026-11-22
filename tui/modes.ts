import { writeSync } from 'node:fs';
import type { CliRendererExternalOutputEvent } from '@opentui/core';
import { guardSplitScrollback } from './native-guard';
import { setMouseAllowed } from './modes-output';

export async function runClient(args: string[]) {
  try { await start(args); }
  catch { process.exitCode = 1; writeSync(2, 'terminal client stopped unexpectedly\n'); }
}

async function start(args: string[]) {
  if (args[0] === '--terminal-client') args = args.slice(1);
  if (args.length === 1 && args[0] === '--decision-witness') return (await import('./witness')).runWitness();
  const noMouse = args.includes('--no-mouse');
  args = args.filter(arg => arg !== '--no-mouse');
  setMouseAllowed(!noMouse);
  const review = args[0] === '--ui-review' && args.length === 2 ? args[1] : undefined;
  const mode = review ? 'fullscreen' : args.length === 0 ? (process.env.RIVECT_LINEAR === '1' ? 'linear' : 'fullscreen')
    : args.length === 1 && args[0] === '--linear' ? 'linear'
    : args.length === 2 && (args[0] === '--surface' || args[0] === '--tui') ? args[1] : undefined;
  if (mode === 'linear') return (await import('./linear')).linear();
  if (mode !== 'inline' && mode !== 'fullscreen') throw new Error('unknown terminal mode');
  const { createCliRenderer, CliRenderEvents } = await import('@opentui/core');
  const { render } = await import('@opentui/solid');
  const { palette, terminalPaletteFrame } = await import('./theme');
  if (palette.note) process.stderr.write(palette.note + '\n');
  const events = ['uncaughtException', 'unhandledRejection'] as const;
  const prior = new Map(events.map(event => [event, new Set(process.listeners(event))]));
  const opened = review ? undefined : await (await import('./startup')).startup();
  const renderer = await createCliRenderer({exitOnCtrlC: false,
    // Fullscreen owns no native scrollback to protect, so the wheel scrolls the
    // transcript by default; inline and --no-mouse keep native selection.
    useMouse: !noMouse && mode === 'fullscreen', consoleMode: 'disabled',
    // Immediate edits cannot meet a 16 ms budget behind the default 60 Hz gate; live frames stay at 30 Hz.
    maxFps: 120,
    synchronizedOutput: process.env.RIVECT_HOST_MUX === '1' || process.env.TMUX || process.env.STY || process.env.ZELLIJ ||
      /^(?:tmux|screen)(?:-|$)/iu.test(process.env.TERM ?? '') ? 'never' : 'auto',
    screenMode: mode === 'inline' ? 'split-footer' : 'alternate-screen', footerHeight: 12,
    postProcessFns: [terminalPaletteFrame]}).catch(async error => { await opened?.owner?.close(); throw error; });
  guardSplitScrollback(renderer);
  // Inline scrollback commits its own buffers outside the footer paint callback.
  renderer.on(CliRenderEvents.EXTERNAL_OUTPUT, ({snapshot}: CliRendererExternalOutputEvent) => terminalPaletteFrame(snapshot));
  let failing = false;
  const fatal = () => {
    if (failing) return;
    failing = true;
    process.exitCode = 1;
    renderer.destroy();
    const exit = async () => {
      try {
        writeSync(2, 'terminal client stopped unexpectedly\n');
      } finally {
        try { if (!review) await (await import('./core')).closeTerminalOwners(); }
        finally { process.exit(1); }
      }
    };
    void renderer.closed.then(exit, exit);
  };
  for (const event of events) {
    // OpenTUI installs console-only handlers that leave the PTY raw and print arbitrary errors.
    for (const listener of process.listeners(event)) if (!prior.get(event)?.has(listener)) process.off(event, listener);
    process.on(event, fatal);
  }
  void renderer.closed.then(() => { for (const event of events) process.off(event, fatal); });
  try {
    if (review) {
      const { ReviewView } = await import('./review');
      await render(() => ReviewView({state: review}), renderer);
    } else if (opened) {
      const { Thread } = await import('./index');
      await render(() => Thread(opened), renderer);
    }
  } catch { fatal(); }
}
