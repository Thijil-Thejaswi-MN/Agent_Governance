// Agent inventory cards: one per agent, from tasks and approval requests only. No I/O.

export interface InvTask {
  task_id: string;
  agent_id?: string;
  owner?: string | null;
  team?: string | null;
  created_at?: string | null;
  started_at?: string | null;
  completed_at?: string | null;
  prevented_count?: number;
  os_denials_count?: number;
}

export interface InvRequest {
  task_id: string;
  agent_id?: string;
  escalated_by_provenance?: boolean;
}

export type Risk = 'low' | 'medium' | 'high';

export interface AgentCard {
  agentId: string;
  owner: string | null;
  team: string | null;
  tasks: number;
  blocked: number;
  asks: number;
  promptedAsks: number;
  lastActive: string | null;
  risk: Risk;
}

/** The rule, in words, shown on hover. */
export const RISK_RULE =
  'High: 5 or more blocked actions, or 2 or more requests prompted by a file it read. ' +
  'Medium: at least 1 blocked action, 3 or more requests, or 1 request prompted by a file it read. ' +
  'Low: none of these. Counted over all of its runs.';

export function riskOf(blocked: number, asks: number, promptedAsks: number): Risk {
  if (blocked >= 5 || promptedAsks >= 2) return 'high';
  if (blocked >= 1 || asks >= 3 || promptedAsks >= 1) return 'medium';
  return 'low';
}

export function riskWhy(c: Pick<AgentCard, 'blocked' | 'asks' | 'promptedAsks'>): string {
  const b = `${c.blocked} blocked ${c.blocked === 1 ? 'action' : 'actions'}`;
  const a = `${c.asks} ${c.asks === 1 ? 'request' : 'requests'}`;
  const p = c.promptedAsks ? ` (${c.promptedAsks} prompted by a file it read)` : '';
  return `This agent: ${b}, ${a}${p}.`;
}

const latest = (...isos: (string | null | undefined)[]) =>
  isos.filter((x): x is string => !!x && Number.isFinite(Date.parse(x))).sort((a, b) => Date.parse(b) - Date.parse(a))[0] ?? null;

const RANK: Record<Risk, number> = { high: 0, medium: 1, low: 2 };

/** Owner and team come from the agent's most recent run that names them; missing stays null. */
export function inventoryCards(tasks: InvTask[], requests: InvRequest[]): AgentCard[] {
  const agentOfTask = new Map(tasks.map(t => [t.task_id, t.agent_id]));
  const byAgent = new Map<string, InvTask[]>();
  for (const t of tasks) {
    if (!t.agent_id) continue;
    byAgent.set(t.agent_id, [...(byAgent.get(t.agent_id) ?? []), t]);
  }
  const cards: AgentCard[] = [];
  for (const [agentId, ts] of byAgent) {
    const ordered = [...ts].sort((a, b) => (Date.parse(b.created_at || '') || 0) - (Date.parse(a.created_at || '') || 0));
    const reqs = requests.filter(r => (agentOfTask.get(r.task_id) ?? r.agent_id) === agentId);
    const blocked = ts.reduce((n, t) => n + Math.max(t.prevented_count || 0, t.os_denials_count || 0), 0);
    const asks = reqs.length;
    const promptedAsks = reqs.filter(r => r.escalated_by_provenance).length;
    cards.push({
      agentId,
      owner: ordered.find(t => t.owner)?.owner ?? null,
      team: ordered.find(t => t.team)?.team ?? null,
      tasks: ts.length,
      blocked,
      asks,
      promptedAsks,
      lastActive: latest(...ts.flatMap(t => [t.completed_at, t.started_at, t.created_at])),
      risk: riskOf(blocked, asks, promptedAsks),
    });
  }
  return cards.sort(
    (a, b) => RANK[a.risk] - RANK[b.risk] || (Date.parse(b.lastActive || '') || 0) - (Date.parse(a.lastActive || '') || 0) || a.agentId.localeCompare(b.agentId),
  );
}
