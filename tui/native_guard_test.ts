import { test } from 'bun:test';
import { strict as assert } from 'node:assert';
import { isSplitControlBusy } from './native-guard';

test('only the native split-scrollback busy rejection is tolerated', () => {
  assert(isSplitControlBusy(new Error('NativeError: ot_session_split_control failed: OutputBusy')));
  assert(!isSplitControlBusy(new Error('NativeError: ot_session_split_control failed: InvalidPhase')));
  assert(!isSplitControlBusy(new Error('NativeError: ot_session_render failed: OutputBusy')));
  assert(!isSplitControlBusy('plain failure'));
  assert(!isSplitControlBusy(undefined));
});
