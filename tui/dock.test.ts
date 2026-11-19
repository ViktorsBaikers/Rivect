import { expect, test } from 'bun:test';
import { decodeDock, dockObservation, dockSubject, emptyDock } from './dock-data';
import type { Task } from './wire';

const task = (id:string, session='s'):Task => ({id, session, state:'running', revision:1n, eventCursor:2n, outboxCursor:3n, events:[]});

test('local pending wins over a newer task; fallback never selects a previous session',()=>{
  const a=task('a'), b=task('b');
  expect(dockSubject(a,[a,b])).toBe(a);
  expect(dockSubject(undefined,[a,b])).toBe(b);
  expect(dockSubject(task('c','other'),[a,b])).toBe(b);
  expect(dockSubject(a,[])).toBeUndefined();
});

test('one missed refresh is quiet; two retain the exact prior facts with a separate stale mark; success clears it',()=>{
  const t=task('a');
  const raw={session_id:t.session, task_id:t.id, rows:['task a: running'], profile:null,
    economy:'settled 12 tok', summary:'context 12 tok · model offline', percent:85};
  const good=dockObservation(emptyDock,decodeDock(raw,t));
  const first=dockObservation(good,'projection unavailable');
  expect(first.page).toBe(good.page); expect(first.stale).toBeUndefined();
  const second=dockObservation(first,'projection unavailable');
  expect(second.page).toBe(good.page); expect(second.stale).toBe('projection unavailable');
  expect(dockObservation(second,'projection unavailable')).toBe(second);
  const fresh=dockObservation(second,decodeDock({...raw,percent:null},t));
  expect(fresh.page?.percent).toBeNull(); expect(fresh.stale).toBeUndefined();
  expect(dockObservation(fresh,decodeDock({...raw,percent:null},t))).toBe(fresh);
  expect(()=>decodeDock(raw, task('b'))).toThrow('invalid dock projection');
});
