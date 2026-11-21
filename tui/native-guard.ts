/** A terminal capability answer can arrive while a frame is in flight; the
 * native split-scrollback reset then rejects with OutputBusy. That reset is a
 * rendering hint — the next sync repaints — so the renderer's own reset is
 * wrapped to keep the previous offset instead of aborting the caller. Every
 * other failure keeps its fatal path. */
export function isSplitControlBusy(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return message.includes('ot_session_split_control') && message.includes('OutputBusy');
}

type SplitReset = {resetSplitScrollback?: (seedRows?: number) => void};

export function guardSplitScrollback(renderer: unknown): void {
  const target = renderer as SplitReset;
  const original = target.resetSplitScrollback;
  if (typeof original !== 'function') return;
  target.resetSplitScrollback = function (seedRows = 0) {
    try {
      original.call(this, seedRows);
    } catch (error) {
      if (!isSplitControlBusy(error)) throw error;
    }
  };
}
