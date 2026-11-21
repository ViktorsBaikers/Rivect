/** The native renderer answers a terminal capability query while a frame may
 * still be in flight; its split-scrollback reset then rejects with OutputBusy
 * from the stdin handler. That reset is a rendering hint — the next sync
 * repaints — so this one operation is ignored while every other uncaught error
 * stays fatal. */
export function isSplitControlBusy(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return message.includes('ot_session_split_control') && message.includes('OutputBusy');
}

export function installNativeGuard(): void {
  process.on('uncaughtException', error => {
    if (isSplitControlBusy(error)) return;
    throw error;
  });
}
