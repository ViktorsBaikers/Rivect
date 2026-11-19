import { lstat, realpath } from 'node:fs/promises';
import { join } from 'node:path';
import { BootFailure, connectCore, type CoreClient } from './core';
import type { Question } from './actions';
import type { Task } from './wire';
import type { Permission } from './permission-data';
import { terminalText } from './modes-output';

export interface Startup {
  project: string;
  loginAvailable?: boolean;
  owner?: CoreClient;
  page?: {tasks: Task[]; more: boolean};
  question?: Question;
  permission?: Permission;
  diagnostics: string[];
}

// A config alone is not a session. Only the owner's existing database can
// carry previous conversations or unfinished recovery.
export async function startup(): Promise<Startup> {
  const project = terminalText(await realpath('.')).replaceAll('\n','\\n');
  const root = process.env.RIVECT_DATA_ROOT ?? join(process.env.HOME ?? '.', '.rivect');
  try { await lstat(join(root, 'runtime', 'rivect.db')); }
  catch (error) {
    if (error instanceof Error && 'code' in error && error.code === 'ENOENT') return {project, diagnostics: []};
    // Let the core classify an inaccessible root; absence is the only lazy path.
  }
  let owner: CoreClient | undefined;
  try {
    owner = await connectCore();
    const {previous, diagnostics} = owner.boot;
    const page = previous === null ? undefined : await owner.resume(previous);
    const waiting = page?.tasks.findLast(task => task.state === 'waiting');
    const question = waiting && await owner.question(waiting);
    const permission = page && await owner.permission();
    return {project, loginAvailable:owner.boot.loginAvailable, owner, diagnostics, page, question, permission};
  } catch (error) {
    if (owner) await owner.close();
    if (error instanceof BootFailure) return {project, diagnostics: [...error.diagnostics, 'session open failed: ' + error.message]};
    throw error;
  }
}

// The first failed open leaves a usable degraded screen. A requested retry that
// also fails is reported once, after renderer teardown restores the primary screen.
export function restoredFailure(error: BootFailure): string {
  return ['tui failed: ' + error.message, ...error.diagnostics].join('\n') + '\n';
}
