// "What the records show" (Records page): three numbers, each counted from real records. No I/O.

import type { ExpansionItem, TaskRecord } from '../types';

export interface RecordStats {
  runs: number;
  stopped: number; // actions stopped (broker and kernel), summed over runs
  runsWithStops: number;
  decidedByPerson: number;
  approvedByPerson: number;
  deniedByPerson: number;
  timeLimited: number;
  revoked: number;
  decidedOtherwise: number; // automatic policy, standing rules, timeouts, simulated approver
  verified: number;
  checked: number;
  failed: number;
}

const MACHINE = new Set(['auto_policy', 'policy_deny_high_risk', 'timeout_fail_closed']);

/** Was this request decided by a person (not the risk policy, a rule, a timeout or the evaluation's simulated approver)? */
export function decidedByPerson(e: Pick<ExpansionItem, 'status' | 'resolved_by'>): boolean {
  if (!['APPROVED', 'DENIED', 'REVOKED', 'EXPIRED'].includes(String(e.status))) return false;
  const by = (e.resolved_by || '').trim();
  if (!by || MACHINE.has(by)) return false;
  return !by.startsWith('standing_rule:') && !by.startsWith('simulated_user');
}

const isComparison = (t: TaskRecord) => !!t.comparison_mode || t.condition === 'B';

export function recordStats(
  tasks: TaskRecord[],
  expansions: ExpansionItem[],
  summary: { total: number; verified: number; failed: number } | null,
): RecordStats {
  const real = tasks.filter(t => !isComparison(t));
  const ids = new Set(real.map(t => t.task_id));
  const stops = real.map(t => t.prevented_count || t.os_denials_count || 0);
  const decided = expansions.filter(e => ids.has(e.task_id) && String(e.status) !== 'PENDING');
  const byPerson = decided.filter(decidedByPerson);
  return {
    runs: real.length,
    stopped: stops.reduce((a, b) => a + b, 0),
    runsWithStops: stops.filter(n => n > 0).length,
    decidedByPerson: byPerson.length,
    approvedByPerson: byPerson.filter(e => ['APPROVED', 'REVOKED', 'EXPIRED'].includes(String(e.status))).length,
    deniedByPerson: byPerson.filter(e => String(e.status) === 'DENIED').length,
    timeLimited: byPerson.filter(e => !!e.expires_at).length,
    revoked: byPerson.filter(e => String(e.status) === 'REVOKED').length,
    decidedOtherwise: decided.length - byPerson.length,
    verified: summary?.verified ?? 0,
    checked: summary?.total ?? 0,
    failed: summary?.failed ?? 0,
  };
}

const plural = (n: number, one: string, many: string) => `${n.toLocaleString()} ${n === 1 ? one : many}`;

export function stoppedLine(s: RecordStats): string {
  if (s.runs === 0) return 'No runs yet.';
  return `In ${plural(s.runsWithStops, 'run', 'runs')} of ${s.runs.toLocaleString()}.`;
}

export function decisionsLine(s: RecordStats): string {
  if (s.decidedByPerson === 0) return s.decidedOtherwise ? `${plural(s.decidedOtherwise, 'other request was', 'other requests were')} decided by policy, a rule or a timeout.` : 'No requests decided yet.';
  const parts = [`${s.approvedByPerson.toLocaleString()} allowed`, `${s.deniedByPerson.toLocaleString()} refused`];
  if (s.timeLimited) parts.push(`${s.timeLimited.toLocaleString()} for a limited time`);
  if (s.revoked) parts.push(`${s.revoked.toLocaleString()} taken back`);
  return parts.join(', ') + '.';
}

export function recordsLine(s: RecordStats): string {
  if (s.checked === 0) return 'No records yet.';
  if (s.failed) return `${plural(s.failed, 'record does', 'records do')} not check out.`;
  return `${s.verified.toLocaleString()} of ${s.checked.toLocaleString()} checked; none changed.`;
}


/** What the Records table may say about one run's record, from the server's check only.
 *  'unknown': this user cannot read the records summary (or it failed to load), so no badge
 *  is claimed; 'none': the server checked the stored records and this run has none. An older
 *  server without verified_ids also gives 'unknown' rather than a green badge. */
export type RecordBadge = 'checked' | 'events_only' | 'failed' | 'none' | 'unknown';

export function recordBadge(
  taskId: string,
  summary: { failed_ids?: string[]; verified_ids?: string[]; events_only_ids?: string[] } | null,
): RecordBadge {
  if (!summary) return 'unknown';
  if (summary.failed_ids?.includes(taskId)) return 'failed';
  if (!summary.verified_ids) return 'unknown';
  if (summary.events_only_ids?.includes(taskId)) return 'events_only';
  if (summary.verified_ids.includes(taskId)) return 'checked';
  return 'none';
}
