import type { CoreClient } from './core';
import { missingUserConfig, settingsCommand, type SettingValue, type SettingsRequest } from './settings-data';

export function linearSettings(line: (text:string) => void) {
  let proposal: Extract<SettingsRequest, {op:'set'|'reset'}> | undefined;
  return async (core:CoreClient, command:string, pasted:boolean) => {
    if (command === '/settings confirm') {
      if (!proposal) line('No pending settings change.');
      else if (pasted) line('Type the confirmation; paste cannot save a setting.');
      else {
        const request = proposal; proposal = undefined;
        try {
          await core.settings({kind:'settings_center', request});
          line(request.op === 'reset' ? 'Reset user override.' : 'Saved to user config.');
        } catch { line('Change not confirmed. Read the current value and preview again.'); }
      }
      return true;
    }
    proposal = undefined;
    const route = settingsCommand(command);
    const exact = /^\/settings (get|reset|set) (\S+)(?: (.+))?$/u.exec(command);
    if (!route && !exact) return false;
    const key = route?.key ?? exact?.[2];
    const page = await core.settings({kind:'settings_center',request:key ? {op:'get', key} : {op:'inspect'}});
    line('Settings Center · Write scope: User · config.toml');
    if (!page.userConfig) line(missingUserConfig);
    if (route?.harness) { line(page.harness); return true; }
    const selected = key ? page.entries.filter(entry => entry.key === key) : page.entries;
    for (const entry of selected) line(entry.key + ' = ' + (entry.redacted ? 'redacted' : JSON.stringify(entry.value)) + ' (' + entry.source + ')');
    if (!key) { line('/settings get <key> · /settings set <key> <value> · /settings reset <key>'); return true; }
    const entry = selected[0];
    if (!page.userConfig || !entry || entry.redacted) return true;
    const fields = {key, scope:'user' as const, expected_source_digest:page.digest};
    if (exact?.[1] === 'reset' && exact[3] === undefined) proposal = {op:'reset', ...fields};
    else {
      let value:SettingValue | undefined = route?.value;
      if (exact?.[1] === 'set') {
        const raw = exact[3];
        if (raw === undefined) { line('Enter a value.'); return true; }
        if (typeof entry.value === 'boolean' && raw !== 'true' && raw !== 'false') { line('Enter true or false.'); return true; }
        value = typeof entry.value === 'boolean' ? raw === 'true' : raw;
      }
      if (value === undefined) return true;
      proposal = {op:'set', ...fields, value};
    }
    line('Preview: ' + key + ' → ' + (proposal.op === 'reset' ? 'reset user override' : JSON.stringify(proposal.value)) +
      ' · source digest ' + page.digest + '\nType /settings confirm to save.');
    return true;
  };
}
