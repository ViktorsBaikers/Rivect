import { record } from './wire';
export type Permission = Readonly<{session_id: string; request_id: string; effect: string; initiator: string; expiry: string; grant: string; scope: string}>;
export type PermissionChoice = 'deny' | 'allow_once' | 'limited_grant';
export function decodePermission(raw: unknown, session: string): Permission | undefined {
  if (raw === null) return;
  if (!record(raw) || raw.session_id !== session || typeof raw.request_id !== 'string' || !raw.request_id ||
      typeof raw.effect !== 'string' || !['read','write','exec','egress'].includes(raw.effect) ||
      typeof raw.initiator !== 'string' || typeof raw.expiry !== 'string' || typeof raw.grant !== 'string' || typeof raw.scope !== 'string')
    throw new Error('invalid permission request');
  return {session_id:session,request_id:raw.request_id,effect:raw.effect,initiator:raw.initiator,expiry:raw.expiry,grant:raw.grant,scope:raw.scope};
}
