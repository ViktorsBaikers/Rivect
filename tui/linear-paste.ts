import { goalByteLimit } from './input';

const open = Buffer.from('\x1b[200~'), close = Buffer.from('\x1b[201~');

// Framing happens before key decoding: pasted Enter, Ctrl+C and slash commands never dispatch.
export function framedInput(keys: (bytes: Buffer) => void, paste: (bytes: Buffer) => void, overflow: () => void, escape: () => boolean) {
  let tail: Buffer = Buffer.alloc(0), storage: Buffer | undefined, size = 0, tooLarge = false;
  let timer: ReturnType<typeof setTimeout> | undefined, escaped = false;
  function append(bytes: Buffer) {
    if (!bytes.length) return;
    if (!storage) {
      if (escaped) { bytes = bytes.subarray(1); escaped = false; }
      if (bytes.length) keys(bytes);
      return;
    }
    if (bytes.length > goalByteLimit - size) tooLarge = true;
    if (!tooLarge) { bytes.copy(storage, size); size += bytes.length; }
  }
  return (chunk: Buffer) => {
    clearTimeout(timer);
    let data = tail.length ? Buffer.concat([tail, chunk]) : chunk;
    tail = Buffer.alloc(0);
    while (data.length) {
      const marker = storage ? close : open, index = data.indexOf(marker);
      if (index === -1) {
        let kept = Math.min(data.length, marker.length - 1);
        while (kept && !data.subarray(-kept).equals(marker.subarray(0, kept))) kept--;
        append(data.subarray(0, data.length - kept));
        if (kept) tail = Buffer.from(data.subarray(-kept));
        // Keep the prefix even after Escape: a delayed [200~ is still a single paste, never keys.
        if (!storage && kept === 1 && !escaped) timer = setTimeout(() => { escaped = escape(); }, 60).unref();
        break;
      }
      append(data.subarray(0, index));
      escaped = false;
      if (storage) {
        if (tooLarge) overflow(); else paste(storage.subarray(0, size));
        storage = undefined;
      } else { storage = Buffer.allocUnsafe(goalByteLimit); size = 0; tooLarge = false; }
      data = data.subarray(index + marker.length);
    }
  };
}
