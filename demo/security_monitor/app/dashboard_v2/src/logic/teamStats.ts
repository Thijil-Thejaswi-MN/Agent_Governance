// Numbers for the Inbox and Team lead pages, computed only from what the server returned.
// When there is nothing to compute from, the result is null (shown as "—"), never a made-up value.

export interface ExpansionLike {
  task_id: string;
  agent_id?: string;
  status?: string;
  created_at?: string;
  resolved_at?: string | null;
  resolved_by?: string | null;
}

export interface EventLike {
  task_id?: string;
  agent_id?: string;
  timestamp?: string;
  prevented?: boolean;
  action_taken?: string;
}

export interface TaskLike {
  task_id: string;
  agent_id?: string;
  owner?: string | null;
  status?: string;
  created_at?: string;
  total_actions?: number;
  prevented_count?: number;
  os_denials_count?: number;
}

const HOUR = 3600_000;
const PERSON_DECIDER = /^(operator|admin|team_lead|security_reviewer|developer|auditor):/;

const ms = (iso?: string | null): number | null => {
  if (!iso) return null;
  const t = Date.parse(iso);
  return Number.isFinite(t) ? t : null;
};

export function median(values: number[]): number | null {
  if (!values.length) return null;
  const s = [...values].sort((a, b) => a - b);
  const mid = Math.floor(s.length / 2);
  return s.length % 2 ? s[mid] : (s[mid - 1] + s[mid]) / 2;
}

/** Median seconds from request to a person's decision, over decisions made in the window. */
export function medianDecisionSeconds(exps: ExpansionLike[], now: number, windowHours = 24): number | null {
  const from = now - windowHours * HOUR;
  const secs: number[] = [];
  for (const e of exps) {
    if (!e.resolved_by || !PERSON_DECIDER.test(e.resolved_by)) continue;
    const c = ms(e.created_at);
    const r = ms(e.resolved_at);
    if (c == null || r == null || r < from || r > now || r < c) continue;
    secs.push((r - c) / 1000);
  }
  return median(secs);
}

/** How many requests were decided in the window by a decider matching `test`. */
export function countDecided(exps: ExpansionLike[], test: (resolvedBy: string) => boolean, now: number, windowHours = 24): number {
  const from = now - windowHours * HOUR;
  return exps.filter(e => {
    const r = ms(e.resolved_at);
    return !!e.resolved_by && r != null && r >= from && r <= now && test(e.resolved_by);
  }).length;
}

export const isTimeout = (by: string) => by === 'timeout_fail_closed';
export const isRule = (by: string) => by.startsWith('standing_rule:');

/** "42s", "1m 48s", "2h 5m"; "—" for null. */
export function formatDuration(sec: number | null): string {
  if (sec == null || !Number.isFinite(sec)) return '—';
  const s = Math.round(sec);
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60}s`;
  return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
}

export type HourCell = 'none' | 'quiet' | 'asked' | 'stopped';

const isBlockedEvent = (e: EventLike) => !!e.prevented || e.action_taken === 'BLOCK_ACTION';

/** Start of the local day containing `now`. */
export function startOfLocalDay(now: number): number {
  const d = new Date(now);
  d.setHours(0, 0, 0, 0);
  return d.getTime();
}

/**
 * One row per agent, 24 local hours of today. A cell is 'stopped' if an action of that agent
 * was blocked in that hour, else 'asked' if it asked for something, else 'quiet' if a task of
 * that agent was created then, else 'none'. Agents come from the task list (events from the OS
 * monitor are matched to their task's agent).
 */
export function hourlyHeat(
  tasks: TaskLike[],
  events: EventLike[],
  exps: ExpansionLike[],
  now: number,
): { agentId: string; cells: HourCell[] }[] {
  const dayStart = startOfLocalDay(now);
  const agentOfTask = new Map(tasks.map(t => [t.task_id, t.agent_id || null]));
  const rows = new Map<string, HourCell[]>();
  const rank: Record<HourCell, number> = { none: 0, quiet: 1, asked: 2, stopped: 3 };
  const mark = (agent: string | null | undefined, iso: string | undefined | null, cell: HourCell) => {
    if (!agent) return;
    const t = ms(iso);
    if (t == null || t < dayStart || t > now) return;
    const h = new Date(t).getHours();
    const row = rows.get(agent);
    if (!row) return;
    if (rank[cell] > rank[row[h]]) row[h] = cell;
  };
  for (const t of tasks) if (t.agent_id && !rows.has(t.agent_id)) rows.set(t.agent_id, Array<HourCell>(24).fill('none'));
  for (const t of tasks) mark(t.agent_id, t.created_at, 'quiet');
  for (const e of exps) mark(agentOfTask.get(e.task_id) ?? e.agent_id, e.created_at, 'asked');
  for (const e of events) if (isBlockedEvent(e)) mark(agentOfTask.get(e.task_id || '') ?? null, e.timestamp, 'stopped');
  return [...rows.entries()].map(([agentId, cells]) => ({ agentId, cells }));
}

export interface AgentRow {
  agentId: string;
  owner: string | null;
  actions: number;
  stops: number;
  running: boolean;
}

/** Per-agent totals from tasks; no defaults for missing agents or owners. */
export function agentRows(tasks: TaskLike[]): AgentRow[] {
  const map = new Map<string, AgentRow>();
  for (const t of tasks) {
    if (!t.agent_id) continue;
    const row = map.get(t.agent_id) ?? { agentId: t.agent_id, owner: null, actions: 0, stops: 0, running: false };
    row.owner = row.owner ?? (t.owner || null);
    row.actions += t.total_actions || 0;
    row.stops += Math.max(t.prevented_count || 0, t.os_denials_count || 0);
    if (t.status === 'ACTIVE' || t.status === 'RUNNING') row.running = true;
    map.set(t.agent_id, row);
  }
  return [...map.values()].sort((a, b) => b.stops - a.stops || a.agentId.localeCompare(b.agentId));
}
