import { record } from './wire';

export type SettingValue = boolean | string;
type Change = {key: string; scope: 'user'; expected_source_digest: string};
export type SettingsRequest = {op:'inspect'} | {op:'get'; key:string} | (Change & ({op:'set'; value: SettingValue} | {op:'reset'}));
export type SettingsAction = {kind:'settings_center'; request:SettingsRequest};
export type SettingsStart = {key?:string; value?:SettingValue; harness?:true};
export type Setting = {key:string; value:SettingValue | null; redacted:boolean; source:string; revision:string};
export type SettingsPage = {digest:string; userConfig:boolean; entries:Setting[]; hint:string; harness:string; decisions:'ask'|'auto'};
export const missingUserConfig = 'User config.toml missing. Create it with config_version = 1, then restart Rivect.';

export function settingsCommand(command:string): SettingsStart | undefined {
  if (command === '/settings' || command === '/config') return {};
  if (command === '/harness' || command === '/harness status') return {harness:true};
  if (command === '/workflow' || command === '/workflow status') return {key:'workflow.enabled'};
  if (command === '/workflow on' || command === '/workflow off') return {key:'workflow.enabled', value:command.endsWith(' on')};
  if (command === '/decisions' || command === '/decisions status') return {key:'decisions.mode'};
  if (command === '/decisions ask' || command === '/decisions auto') return {key:'decisions.mode', value:command.slice(11)};
}

export function decodeSettings(raw: unknown): SettingsPage {
  if (!record(raw) || typeof raw.source_digest !== 'string' || !/^[0-9a-f]{64}$/u.test(raw.source_digest) ||
      typeof raw.user_config !== 'boolean' || !Array.isArray(raw.entries) || !record(raw.harness) || !record(raw.harness.scheduler) || typeof raw.key_hint !== 'string' ||
      (raw.decision_mode !== 'ask' && raw.decision_mode !== 'auto'))
    throw new Error('invalid settings snapshot');
  const entries = raw.entries.map((item:unknown): Setting => {
    if (!record(item) || typeof item.key !== 'string' || !record(item.source) || typeof item.source.kind !== 'string' ||
        typeof item.source.revision !== 'string' || !record(item.effective)) throw new Error('invalid setting');
    const redacted = item.effective.kind === 'redacted';
    const value = redacted ? null : item.effective.value;
    if ((!redacted && item.effective.kind !== 'visible') || !(value === null || typeof value === 'boolean' || typeof value === 'string'))
      throw new Error('invalid setting value');
    return {key:item.key, source:item.source.kind, revision:item.source.revision, redacted, value};
  });
  const {scheduler, index} = raw.harness;
  if (typeof scheduler.running !== 'number' || typeof scheduler.held_units !== 'number' ||
      (index !== null && (!record(index) || typeof index.state !== 'string' || typeof index.generation !== 'number')))
    throw new Error('invalid harness snapshot');
  return {digest:raw.source_digest, userConfig:raw.user_config, entries, hint:raw.key_hint, decisions:raw.decision_mode,
    harness:`Harness · running ${scheduler.running} · held units ${scheduler.held_units} · index ${index === null ? 'none' : `${index.generation}: ${index.state}`}`};
}
