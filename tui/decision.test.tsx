import { expect, test } from 'bun:test';
import { ManualClock } from '@opentui/core/testing';
import { testRender } from '@opentui/solid';
import type { Question } from './actions';
import { DecisionView } from './decision';

const question: Question = {
  session: 'fixture', pin: {task_id:'task', question_id:'question', question_revision:'1', expected_intent_revision:'1'},
  title: 'Review plan', prompt: 'Begin the first step?', recommended: 'begin', recommendation: 'No external effects',
  custom: true, canRevealDiff: false, options: [{id:'begin', label:'Begin', consequences:'Prepare a plan'}],
};

test('inline decision ignores Esc at 199 ms and handles it at 200 ms after paint', async () => {
  const clock = new ManualClock();
  let dismissals = 0;
  await using terminal = await testRender(() => <DecisionView question={question}
    confirm={async () => { throw new Error('Esc must not confirm'); }}
    reveal={async () => { throw new Error('Esc must not reveal'); }}
    dismiss={() => { dismissals++; }} />,
    {width:80, height:24, screenMode:'split-footer', kittyKeyboard:true, clock});
  await terminal.renderOnce();
  expect(terminal.captureCharFrame()).toContain('Begin the first step?');
  clock.advance(199);
  terminal.mockInput.pressEscape();
  expect(dismissals).toBe(0);
  clock.advance(1);
  terminal.mockInput.pressEscape();
  expect(dismissals).toBe(1);
});
