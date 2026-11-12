// Overview numbers, computed only from server data. Empty input gives zeros, nulls and empty lists.
import { EventLike, ExpansionLike, TaskLike, median, startOfLocalDay } from './teamStats';

const HOUR = 3600_000;
const ms = (iso?: string | null) => {
  if (!iso) return null;
  const t = Date.parse(iso);
  return Number.isFinite(t) ? t : null;
};
const blocked = (e: EventLike) => !!e.prevented || e.action_taken === 'BLOCK_ACTION';
const running = (t: TaskLike) => t.status === 'ACTIVE' || t.status === 'RUNNING';

export interface OverviewTask extends TaskLike {
  team?: string | null;
  started_at?: string | null;
  completed_at?: string | null;
}

export function inLast(iso: string | null | undefined, now: number, hours: number): boolean {
  const t = ms(iso);
  return t != null && t <= now && t >= now - hours * HOUR;
}

export function runsInLast24h(tasks: OverviewTask[], now: number): OverviewTask[] {
  return tasks.filter(t => inLast(t.created_at, now, 24));
}

/** Median seconds from start to end of runs that finished in the last 24 hours. */
export function medianRunSeconds(tasks: OverviewTask[], now: number): number | null {
  const secs: number[] = [];
  for (const t of tasks) {
    const s = ms(t.started_at || t.created_at);
    const e = ms(t.completed_at);
    if (s == null || e == null || e < s || !inLast(t.completed_at, now, 24)) continue;
    secs.push((e - s) / 1000);
  }
  return median(secs);
}

export function stoppedInLast24h(events: EventLike[], now: number): number {
  return events.filter(e => blocked(e) && inLast(e.timestamp, now, 24)).length;
}

export interface HourBucket {
  hour: number;
  allowed: number;
  stopped: number;
  asked: number;
}

/** Today's local hours: actions let through, actions stopped, and requests made. */
export function actionsPerHour(events: EventLike[], exps: ExpansionLike[], now: number): HourBucket[] {
  const day = startOfLocalDay(now);
  const out: HourBucket[] = Array.from({ length: 24 }, (_, hour) => ({ hour, allowed: 0, stopped: 0, asked: 0 }));
  const put = (iso: string | null | undefined, key: 'allowed' | 'stopped' | 'asked') => {
    const t = ms(iso);
    if (t == null || t < day || t > now) return;
    out[new Date(t).getHours()][key] += 1;
  };
  for (const e of events) put(e.timestamp, blocked(e) ? 'stopped' : 'allowed');
  for (const x of exps) put(x.created_at, 'asked');
  return out;
}

export type AgentState = 'asking' | 'stopped' | 'running' | 'idle';

export interface AgentDot {
  agentId: string;
  team: string | null;
  state: AgentState;
}

/** One entry per agent: asking (a request waits), stopped (blocked in the last hour), running, idle. */
export function agentDots(tasks: OverviewTask[], pending: ExpansionLike[], events: EventLike[], now: number): AgentDot[] {
  const agentOfTask = new Map(tasks.map(t => [t.task_id, t.agent_id]));
  const asking = new Set(pending.map(p => agentOfTask.get(p.task_id) || p.agent_id).filter(Boolean) as string[]);
  const stopped = new Set(
    events.filter(e => blocked(e) && inLast(e.timestamp, now, 1)).map(e => agentOfTask.get(e.task_id || '')).filter(Boolean) as string[],
  );
  const map = new Map<string, AgentDot>();
  for (const t of tasks) {
    if (!t.agent_id) continue;
    const d = map.get(t.agent_id) ?? { agentId: t.agent_id, team: t.team ?? null, state: 'idle' as AgentState };
    if (!d.team && t.team) d.team = t.team;
    if (running(t) && d.state === 'idle') d.state = 'running';
    map.set(t.agent_id, d);
  }
  for (const d of map.values()) {
    if (stopped.has(d.agentId)) d.state = 'stopped';
    if (asking.has(d.agentId)) d.state = 'asking';
  }
  const rank: Record<AgentState, number> = { asking: 0, stopped: 1, running: 2, idle: 3 };
  return [...map.values()].sort((a, b) => rank[a.state] - rank[b.state] || a.agentId.localeCompare(b.agentId));
}

export interface TeamGroup {
  team: string;
  agents: number;
  running: number;
  waiting: number;
}

export function teamGroups(dots: AgentDot[]): TeamGroup[] {
  const map = new Map<string, TeamGroup>();
  for (const d of dots) {
    const key = d.team || 'No team';
    const g = map.get(key) ?? { team: key, agents: 0, running: 0, waiting: 0 };
    g.agents += 1;
    if (d.state === 'running' || d.state === 'asking' || d.state === 'stopped') g.running += 1;
    if (d.state === 'asking') g.waiting += 1;
    map.set(key, g);
  }
  return [...map.values()].sort((a, b) => b.waiting - a.waiting || b.agents - a.agents || a.team.localeCompare(b.team));
}

/** Map layout by number of running tasks (same edges as the server's layout_mode). */
export function mapMode(runningTasks: number): 'individual' | 'teams' | 'canvas' {
  return runningTasks <= 20 ? 'individual' : runningTasks <= 500 ? 'teams' : 'canvas';
}
