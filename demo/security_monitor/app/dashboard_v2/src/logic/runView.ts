// Turns the stored run steps into what the Watch screen shows: blocked attempts,
// whether the agent has started, the output written. Pure; see runView.test.ts.
import { TaskStep } from '../types';

export type RunState =
  | 'idle'
  | 'preparing'
  | 'running'
  | 'waiting_approval'
  | 'stopping'
  | 'completed'
  | 'stopped'
  | 'failed'
  | 'timed_out';

export const TERMINAL_STATES: RunState[] = ['completed', 'stopped', 'failed', 'timed_out'];

export const isTerminal = (s: RunState) => TERMINAL_STATES.includes(s);

export type AttemptAction = 'open' | 'write' | 'run' | 'reach';

export interface BlockedAttempt {
  action: AttemptAction;
  target: string;
  name: string;
  stepNumber: number;
}

export function fileName(path: string): string {
  const p = (path || '').trim().replace(/[\\/]+$/, '');
  if (/^https?:\/\//i.test(p)) {
    try {
      return new URL(p).host;
    } catch {
      return p;
    }
  }
  const parts = p.split(/[\\/]/);
  return parts[parts.length - 1] || p;
}

// The launcher records this once the agent is released; before it the run is still preparing.
export const isAgentLaunchStep = (s: TaskStep) =>
  s.layer === 'launcher' && s.summary.startsWith('Agent process launched');

const BLOCK_VERDICTS = new Set(['BLOCK_ACTION', 'DENY', 'BLOCKED']);

// Step summaries written by the broker and the launcher:
//   "read_file blocked: <path>", "write_file blocked: <path>",
//   "run_command check blocked: <cmd>", "Landlock blocked file_read on <target>".
export function blockedAttemptFromStep(step: TaskStep): BlockedAttempt | null {
  if (!BLOCK_VERDICTS.has(step.verdict)) return null;
  if (step.kind !== 'tool' && step.kind !== 'sensor') return null;
  // A non-zero exit reported by the shim is not proof of a block; the sensor step covers real ones.
  if (step.source_label === 'reported by the in-sandbox shim') return null;
  const s = step.summary || '';
  let m = s.match(/^read_file blocked:\s*(.+)$/);
  if (m) return mk('open', m[1], step);
  m = s.match(/^write_file blocked:\s*(.+)$/);
  if (m) return mk('write', m[1], step);
  m = s.match(/^run_command check blocked:\s*(.+)$/);
  if (m) return mk('run', m[1], step);
  m = s.match(/^\w+ blocked (\S+) on (.+)$/);
  if (m) {
    const kind = m[1].toLowerCase();
    const action: AttemptAction = kind.includes('write')
      ? 'write'
      : kind.includes('net') || kind.includes('connect') || kind.includes('http')
      ? 'reach'
      : kind.includes('exec') || kind.includes('command')
      ? 'run'
      : 'open';
    return mk(action, m[2], step);
  }
  m = s.match(/blocked:\s*(.+)$/);
  if (m) return mk('open', m[1], step);
  return null;
}

function mk(action: AttemptAction, target: string, step: TaskStep): BlockedAttempt {
  const t = target.trim();
  return { action, target: t, name: action === 'run' ? t : fileName(t), stepNumber: step.step_number };
}

// One attempt can be recorded twice (broker refusal + sensor record): count it once.
export function blockedAttempts(steps: TaskStep[]): BlockedAttempt[] {
  const seen = new Set<string>();
  const out: BlockedAttempt[] = [];
  for (const st of [...steps].sort((a, b) => a.step_number - b.step_number)) {
    const a = blockedAttemptFromStep(st);
    if (!a) continue;
    const key = `${a.action === 'write' ? 'write' : 'access'}|${a.name}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(a);
  }
  return out;
}

// The block that is "news": the last agent action recorded was refused.
export function justBlocked(steps: TaskStep[]): BlockedAttempt | null {
  const actions = [...steps]
    .sort((a, b) => a.step_number - b.step_number)
    .filter(s => s.kind === 'tool' || s.kind === 'sensor' || s.kind === 'expansion');
  const last = actions[actions.length - 1];
  return last ? blockedAttemptFromStep(last) : null;
}

export function agentStarted(steps: TaskStep[]): boolean {
  return steps.some(isAgentLaunchStep) || steps.some(s => s.kind === 'model' || s.kind === 'tool');
}

export interface OutputPreview {
  path: string;
  name: string;
  content: string;
}

export function outputsFromSteps(steps: TaskStep[]): OutputPreview[] {
  const byPath = new Map<string, OutputPreview>();
  for (const s of steps) {
    if (s.kind !== 'output') continue;
    const m = (s.summary || '').match(/^Output file written:\s*(.+)$/);
    if (!m) continue;
    byPath.set(m[1], { path: m[1], name: fileName(m[1]), content: s.detail || '' });
  }
  return [...byPath.values()];
}
