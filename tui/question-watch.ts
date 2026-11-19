import type {CoreClient} from './core';
import type {Question} from './actions';
import type {Task} from './wire';

export function sameFork(left: Question, right: Question) {
  return left.session === right.session && left.pin.task_id === right.pin.task_id &&
    left.pin.question_id === right.pin.question_id && left.pin.question_revision === right.pin.question_revision &&
    left.pin.expected_intent_revision === right.pin.expected_intent_revision;
}

// The owner is authoritative. Preserve object identity on a stable pin so polling cannot reset
// keyboard focus, discard an edit, or restart the paint clock. Never dispatch from this read.
export async function currentFork(owner: Pick<CoreClient, 'question'>, task: Task, previous: Question) {
  const current = await owner.question(task);
  return current && sameFork(previous, current) ? previous : current;
}
