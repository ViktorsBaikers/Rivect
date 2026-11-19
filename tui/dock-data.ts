import { record, type Task } from './wire';
import { terminalText } from './modes-output';

export type Dock = {session:string; task:string; rows:string[]; profile:string | null; economy:string; summary:string; percent:number | null};
export type DockState = {page?:Dock; failures:number; stale?:string};
export const emptyDock:DockState = {failures:0};
export const compactNotShorter = 'compaction would not shorten the history';

export function dockSubject(pending:Task | undefined, turns:readonly Task[]) {
  const last = turns.at(-1);
  return pending && last?.session === pending.session ? pending : last;
}

export function decodeDock(raw:unknown, task:Task):Dock {
  if (!record(raw) || raw.session_id !== task.session || raw.task_id !== task.id || !Array.isArray(raw.rows) || raw.rows.length > 3 ||
      !raw.rows.every((line:unknown)=>typeof line === 'string') || typeof raw.economy !== 'string' || typeof raw.summary !== 'string' ||
      !(raw.profile === null || typeof raw.profile === 'string') || !(raw.percent === null || typeof raw.percent === 'number' &&
        Number.isSafeInteger(raw.percent) && raw.percent >= 80)) throw new Error('invalid dock projection');
  const clean = (value:string) => terminalText(value).replaceAll('\n','\\n');
  return {session:task.session, task:task.id, rows:raw.rows.map(clean), profile:raw.profile && clean(raw.profile),
    economy:clean(raw.economy), summary:clean(raw.summary), percent:raw.percent};
}

export function dockObservation(before:DockState, result:Dock | string):DockState {
  if (typeof result === 'string') {
    if (!before.failures) return {page:before.page, failures:1};
    return before.stale === result ? before : {page:before.page, failures:2, stale:result};
  }
  const old = before.page;
  if (!before.failures && old?.session === result.session && old.task === result.task && old.percent === result.percent && old.economy === result.economy &&
      old.summary === result.summary && old.profile === result.profile && old.rows.length === result.rows.length &&
      old.rows.every((row,i)=>row === result.rows[i])) return before;
  return {page:result, failures:0};
}
