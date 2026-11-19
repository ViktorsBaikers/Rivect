import type { Task } from './wire';

/** A later answer or supersession clears the wait; a retained task state alone cannot name its executor. */
export function waitingVerifier(task: Task | undefined) {
  if (task?.state !== 'waiting') return;
  const question = task.events.findLast(event => event.type.startsWith('question.'));
  return question?.type === 'question.published' && question.category === 'agent' ? question : undefined;
}
