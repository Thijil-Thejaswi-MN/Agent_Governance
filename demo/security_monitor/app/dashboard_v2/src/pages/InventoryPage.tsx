import React, { useCallback, useEffect, useState } from 'react';
import { api } from '../api/client';
import { AgentInventoryItem, ExpansionItem, TaskRecord } from '../types';
import { EmptyState, ErrorState, LoadingState } from '../components/common/States';
import { AgentCard, RISK_RULE, Risk, inventoryCards, riskWhy } from '../logic/inventory';
import { relativeTime } from '../logic/plain';

const RISK: Record<Risk, { label: string; style: React.CSSProperties }> = {
  high: { label: 'High risk', style: { color: '#FCA5A5', background: 'rgba(239,68,68,0.12)', borderColor: 'rgba(239,68,68,0.4)' } },
  medium: { label: 'Medium risk', style: { color: '#FCD34D', background: 'rgba(245,158,11,0.12)', borderColor: 'rgba(245,158,11,0.4)' } },
  low: { label: 'Low risk', style: { color: '#86EFAC', background: 'rgba(34,197,94,0.12)', borderColor: 'rgba(34,197,94,0.35)' } },
};

/** One agent. No effects, so tests can render it. */
export const InventoryCard: React.FC<{ c: AgentCard; now: number }> = ({ c, now }) => {
  const tipId = `risk-rule-${c.agentId}`;
  return (
    <li className="card p-4 sm:p-5 flex flex-col gap-3 min-w-0" data-agent={c.agentId} data-risk={c.risk}>
      <div className="flex items-start justify-between gap-3">
        <span className="font-mono text-[15px] font-semibold text-[#E6E9EF] [overflow-wrap:anywhere] min-w-0">{c.agentId}</span>
        <span className="group relative shrink-0">
          <button
            type="button"
            className="inline-flex items-center px-2.5 py-0.5 min-h-[28px] rounded-full border text-[12px] font-semibold whitespace-nowrap cursor-help bg-transparent"
            style={RISK[c.risk].style}
            aria-describedby={tipId}
          >
            {RISK[c.risk].label}
          </button>
          <span
            id={tipId}
            role="tooltip"
            className="pointer-events-none absolute right-0 top-full mt-2 z-30 w-[min(300px,80vw)] rounded-lg border border-[#2A3344] bg-[#1A2232] px-3 py-2 text-[12px] leading-snug text-[#E6E9EF] shadow-lg opacity-0 transition-opacity group-hover:opacity-100 group-focus-within:opacity-100"
          >
            {riskWhy(c)} {RISK_RULE}
          </span>
        </span>
      </div>
      <dl className="m-0 grid grid-cols-2 gap-x-4 gap-y-2 text-[14px]">
        <Fact k="Owner" v={c.owner ?? '—'} />
        <Fact k="Team" v={c.team ?? '—'} />
        <Fact k="Tasks run" v={String(c.tasks)} />
        <Fact k="Blocked" v={String(c.blocked)} color={c.blocked ? '#F87171' : undefined} />
        <Fact k="Requests" v={c.promptedAsks ? `${c.asks} (${c.promptedAsks} prompted by a file)` : String(c.asks)} />
        <Fact k="Last active" v={relativeTime(c.lastActive, now) || '—'} title={c.lastActive ?? undefined} />
      </dl>
    </li>
  );
};

export const DiscoveredAgentCard: React.FC<{ item: AgentInventoryItem }> = ({ item }) => {
  const isGoverned = item.governance_state === 'Governed';
  const stateStyle = isGoverned
    ? { color: '#86EFAC', background: 'rgba(34,197,94,0.12)', borderColor: 'rgba(34,197,94,0.35)' }
    : { color: '#FCD34D', background: 'rgba(245,158,11,0.12)', borderColor: 'rgba(245,158,11,0.4)' };

  return (
    <li
      className="card p-4 sm:p-5 flex flex-col gap-3 min-w-0"
      data-discovered-agent={item.name || item.agent_id}
      data-governance-state={item.governance_state || 'Not governed yet'}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="flex flex-col gap-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-mono text-[15px] font-semibold text-[#E6E9EF] [overflow-wrap:anywhere] min-w-0">
              {item.name || item.agent_id}
            </span>
            <span
              className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-semibold text-[#93C5FD] border border-[#3B82F6]/30 bg-[#1E293B]"
              data-badge="discovered-card"
            >
              Discovered (A2A card)
            </span>
          </div>
          {item.owner && (
            <span className="text-[12px]" style={{ color: 'var(--text-3)' }}>
              Provider: {item.owner}
            </span>
          )}
        </div>
        <span
          className="inline-flex items-center px-2.5 py-0.5 min-h-[28px] rounded-full border text-[12px] font-semibold whitespace-nowrap shrink-0"
          style={stateStyle}
          data-testid="governance-state-badge"
        >
          {item.governance_state || 'Not governed yet'}
        </span>
      </div>

      {item.description && (
        <p className="m-0 text-[13px] leading-relaxed" style={{ color: 'var(--text-2)' }}>
          {item.description}
        </p>
      )}

      {item.skills && item.skills.length > 0 && (
        <div className="flex flex-col gap-1.5">
          <span className="text-[11px] font-medium" style={{ color: 'var(--text-3)' }}>
            Declared skills
          </span>
          <div className="flex flex-wrap gap-1.5">
            {item.skills.map(skill => (
              <span
                key={skill}
                className="px-2 py-0.5 rounded text-[11px] font-mono bg-[#0F172A] text-[#CBD5E1] border border-[#334155]"
                data-skill={skill}
              >
                {skill}
              </span>
            ))}
          </div>
        </div>
      )}

      {item.metadata?.card_url && (
        <div className="pt-2 border-t border-[#2A3344] flex items-center justify-between text-[11px]" style={{ color: 'var(--text-3)' }}>
          <span className="truncate font-mono">{item.metadata.card_url}</span>
          {item.metadata.version && <span>v{item.metadata.version}</span>}
        </div>
      )}
    </li>
  );
};

export const InventoryPage: React.FC = () => {
  const [tasks, setTasks] = useState<TaskRecord[] | null>(null);
  const [requests, setRequests] = useState<ExpansionItem[]>([]);
  const [inventory, setInventory] = useState<AgentInventoryItem[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [now, setNow] = useState(Date.now());

  const load = useCallback(() => {
    Promise.all([
      api.getTasks(),
      api.getExpansions().catch(() => [] as ExpansionItem[]),
      api.getInventory().catch(() => [] as AgentInventoryItem[]),
    ])
      .then(([ts, rs, inv]) => {
        setTasks(ts);
        setRequests(rs);
        setInventory(inv);
        setNow(Date.now());
        setError(null);
      })
      .catch(err => setError(err?.message || 'Could not load the agents.'));
  }, []);

  useEffect(() => {
    load();
    const t = setInterval(load, 10000);
    return () => clearInterval(t);
  }, [load]);

  const cards = tasks ? inventoryCards(tasks, requests) : [];
  const discoveredAgents = inventory.filter(
    item => item.classification === 'DISCOVERED_A2A' || item.metadata?.a2a_card
  );
  const counts = { high: 0, medium: 0, low: 0 } as Record<Risk, number>;
  cards.forEach(c => (counts[c.risk] += 1));

  const totalAgents = cards.length + discoveredAgents.filter(d => !cards.some(c => c.agentId === d.agent_id)).length;

  return (
    <div className="max-w-[1200px] pb-12 flex flex-col gap-6">
      <header className="flex flex-col gap-2">
        <h1 id="inventory-headline" className="m-0 font-display font-bold text-[28px] sm:text-[32px] leading-[1.15] text-[#E6E9EF]">
          {tasks == null && inventory.length === 0
            ? 'Agent inventory'
            : totalAgents === 0
            ? 'No agents yet.'
            : `${totalAgents} ${totalAgents === 1 ? 'agent' : 'agents'}.`}
        </h1>
        <p className="m-0 text-[16px] leading-relaxed" style={{ color: 'var(--text-2)' }}>
          Every agent that has run here, from its runs and requests, plus local A2A agents discovered via Agent Cards.
          {cards.length > 0 && ` ${counts.high} high, ${counts.medium} medium and ${counts.low} low risk.`}
        </p>
      </header>
      {error && !tasks ? (
        <ErrorState message={error} onRetry={load} id="inventory-error" />
      ) : !tasks ? (
        <LoadingState label="Loading agents…" id="inventory-loading" />
      ) : (
        <>
          {discoveredAgents.length > 0 && (
            <section className="flex flex-col gap-3" id="discovered-agents-section">
              <div className="flex items-center justify-between">
                <h2 className="m-0 font-display font-semibold text-[18px] sm:text-[20px] text-[#E6E9EF]">
                  Discovered A2A Agents
                </h2>
                <span className="text-[13px]" style={{ color: 'var(--text-3)' }}>
                  Discovered via local Agent Cards
                </span>
              </div>
              <ul id="discovered-agents-list" className="list-none m-0 p-0 grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
                {discoveredAgents.map(a => (
                  <DiscoveredAgentCard key={a.agent_id} item={a} />
                ))}
              </ul>
            </section>
          )}

          <section className="flex flex-col gap-3" id="governed-agents-section">
            {discoveredAgents.length > 0 && (
              <h2 className="m-0 font-display font-semibold text-[18px] sm:text-[20px] text-[#E6E9EF]">
                Governed Runs & Activity
              </h2>
            )}
            {cards.length === 0 ? (
              <EmptyState id="inventory-empty" title="No agents yet." body="An agent appears here after its first run." />
            ) : (
              <ul id="inventory-list" className="list-none m-0 p-0 grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
                {cards.map(c => (
                  <InventoryCard key={c.agentId} c={c} now={now} />
                ))}
              </ul>
            )}
          </section>
        </>
      )}
    </div>
  );
};

const Fact: React.FC<{ k: string; v: string; color?: string; title?: string }> = ({ k, v, color, title }) => (
  <div className="flex flex-col min-w-0">
    <dt className="text-[12px]" style={{ color: 'var(--text-3)' }}>
      {k}
    </dt>
    <dd className="m-0 [overflow-wrap:anywhere]" style={{ color: color ?? '#E6E9EF' }} title={title}>
      {v}
    </dd>
  </div>
);