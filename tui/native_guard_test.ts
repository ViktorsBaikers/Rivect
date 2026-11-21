import { test } from 'bun:test';
import { strict as assert } from 'node:assert';
import { guardSplitScrollback, isSplitControlBusy } from './native-guard';

test('only the native split-scrollback busy rejection is tolerated', () => {
  assert(isSplitControlBusy(new Error('NativeError: ot_session_split_control failed: OutputBusy')));
  assert(!isSplitControlBusy(new Error('NativeError: ot_session_split_control failed: InvalidPhase')));
  assert(!isSplitControlBusy(new Error('NativeError: ot_session_render failed: OutputBusy')));
  assert(!isSplitControlBusy('plain failure'));
  assert(!isSplitControlBusy(undefined));
});

test('a busy split reset keeps the previous offset and other failures stay fatal', () => {
  let calls = 0;
  const renderer = {
    renderOffset: 41,
    resetSplitScrollback(_seedRows = 0) {
      calls += 1;
      throw new Error('NativeError: ot_session_split_control failed: OutputBusy');
    },
  };
  guardSplitScrollback(renderer);
  renderer.resetSplitScrollback(7);
  assert.equal(calls, 1);
  assert.equal(renderer.renderOffset, 41);

  const fatal = {
    resetSplitScrollback() {
      throw new Error('NativeError: ot_session_split_control failed: InvalidPhase');
    },
  };
  guardSplitScrollback(fatal);
  assert.throws(() => fatal.resetSplitScrollback(), /InvalidPhase/u);

  const absent = {};
  guardSplitScrollback(absent);
  assert.deepEqual(absent, {});
});
