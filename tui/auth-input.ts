import type { KeyEvent, TextareaRenderable } from '@opentui/core';

// Classify before echo or routing; only the auth owner may interpret a callback.
export function looksLikeOAuthCallback(text: string): boolean {
  if (!text) return false;
  const value = text.includes('%') ? text.replace(/%([0-9a-f]{2})/giu, (_, byte:string) => String.fromCharCode(parseInt(byte,16))) : text;
  if (/(?:localhost|127\.0\.0\.1|\[::1\]):1455(?:\/|\b)|\/(?:auth|oauth2?)\/callback\b|[?&#](?:code|state|access_token|id_token|refresh_token|error_description)=/iu.test(value)) return true;
  const argument = /^\s*\/login\s+(\S+)$/iu.exec(value)?.[1];
  // `/login <provider>` filters the picker; only a URL-shaped argument is the
  // old private callback entry.
  return argument !== undefined && /^(?:[a-z][a-z0-9+.-]*:\/\/|(?:localhost|127\.0\.0\.1|\[::1\]):)/iu.test(argument);
}

export function loginStatus(available:boolean | undefined):string {
  if (available === undefined) return 'Session not connected · Run /login to check';
  return available ? 'Session not connected · Run /login' : 'ChatGPT login not configured';
}

// Bytes still arriving after a discarded prefix must not become a second draft or a shortcut.
export function callbackGuard(notice:(text:string)=>void) {
  let blocked = false;
  return {
    capture(editor:TextareaRenderable | undefined) {
      if (!blocked && editor && looksLikeOAuthCallback(editor.plainText)) {
        blocked = true;
        editor.editBuffer.setText('');
        notice('Private login callback discarded. Esc resumes editing.');
      }
      return blocked;
    },
    intercept(key?:KeyEvent) {
      if (!blocked) return false;
      if (key?.name === 'escape' && key.eventType === 'press') { blocked = false; notice(''); }
      return true;
    },
  };
}
