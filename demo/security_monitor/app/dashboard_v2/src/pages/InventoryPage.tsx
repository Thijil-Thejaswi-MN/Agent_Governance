import React, { useCallback, useEffect, useState } from 'react';
import { AgentScan } from '../components/effects/AgentScan';
import { api } from '../api/client';
import {
  AgentInventoryItem,
  ConfiguredAgent,
  DiscoveredAgent,
  ExpansionItem,
  TaskRecord,
} from '../types';
import { EmptyState, ErrorState, LoadingState } from '../components/common/States';
import { AgentCard, RISK_RULE, Risk, inventoryCards, riskWhy } from '../logic/inventory';
import { outcomeLabel, relativeTime } from '../logic/plain';
import { getTone } from '../logic/tones';
import { PageHeader } from '../components/ui/PageHeader';
import { StatusPill } from '../components/ui/StatusPill';
import { Button } from '../components/ui/Button';

const RISK: Record<Risk, { label: string }> = {
  high: { label: 'High risk' },
  medium: { label: 'Medium risk' },
  low: { label: 'Low risk' },
};

/** One agent. No effects, so tests can render it. */
export const InventoryCard: React.FC<{ c: AgentCard; now: number }> = ({ c, now }) => {
  const tipId = `risk-rule-${c.agentId}`;
  const modelsUsed = c.modelsUsed ?? [];
  const recent = c.recent ?? [];
  return (
    <li className="card p-5 rounded-xl border border-line bg-surface-1 flex flex-col gap-4 min-w-0" data-agent={c.agentId} data-risk={c.risk}>
      <div className="flex items-start justify-between gap-3">
        <div className="flex flex-col gap-1 min-w-0">
          {c.name && <span className="text-[17px] font-semibold text-fg">{c.name}</span>}
          <span className={`font-mono [overflow-wrap:anywhere] ${c.name ? 'text-[12px] text-fg-3' : 'text-[15px] font-semibold text-fg'}`}>
            {c.agentId}
          </span>
          {!c.configured && (
            <span className="text-[12px] text-fg-3" data-badge="earlier-runs">
              Seen in earlier runs; not in the agent list
            </span>
          )}
        </div>
        <span className="group relative shrink-0">
          <button
            type="button"
            className="cursor-help bg-transparent border-none p-0 inline-flex"
            aria-describedby={tipId}
          >
            <StatusPill
              tone={c.risk === 'high' ? 'bad' : c.risk === 'medium' ? 'wait' : 'ok'}
              label={RISK[c.risk].label}
            />
          </button>
          <span
            id={tipId}
            role="tooltip"
            className="pointer-events-none absolute right-0 top-full mt-2 z-30 w-[min(300px,80vw)] rounded-lg border border-line-strong bg-surface-hover px-3 py-2 text-[12px] leading-snug text-fg shadow-lg opacity-0 transition-opacity group-hover:opacity-100 group-focus-within:opacity-100"
          >
            {riskWhy(c)} {RISK_RULE}
          </span>
        </span>
      </div>

      {c.description && (
        <p className="m-0 text-[14px] leading-relaxed text-fg-2">
          {c.description}
        </p>
      )}

      {(c.model || (c.tools && c.tools.length > 0)) && (
        <div className="flex flex-col gap-2 rounded-lg border border-line bg-surface-2 p-3" data-agent-setup>
          {c.model && (
            <div className="flex items-baseline gap-2 flex-wrap text-[13px]">
              <span className="text-fg-3">Runs on</span>
              <span className="font-mono text-[13px] text-fg" data-agent-model={c.model}>
                {c.model}
              </span>
              <span className="text-fg-3">(its model; a run can override it)</span>
            </div>
          )}
          {c.tools && c.tools.length > 0 && (
            <div className="flex flex-col gap-1.5">
              <span className="text-[13px] text-fg-3">
                Its tool limit (any other tool is refused)
              </span>
              <div className="flex flex-wrap gap-1.5">
                {c.tools.map(tool => (
                  <span key={tool} className="px-2 py-0.5 rounded text-[12px] font-mono bg-surface-3 text-fg-2 border border-line" data-tool={tool}>
                    {tool}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      <dl className="m-0 grid grid-cols-2 gap-x-4 gap-y-2 text-[14px]">
        <Fact k="Owner" v={c.owner ?? '—'} />
        <Fact k="Team" v={c.team ?? '—'} />
        <Fact k="Tasks run" v={String(c.tasks)} />
        <Fact k="Blocked actions" v={String(c.blocked)} color={c.blocked ? 'var(--bad-light)' : undefined} />
        <Fact k="Requests" v={c.promptedAsks ? `${c.asks} (${c.promptedAsks} prompted by a file)` : String(c.asks)} />
        <Fact k="Last active" v={relativeTime(c.lastActive, now) || '—'} title={c.lastActive ?? undefined} />
      </dl>

      {modelsUsed.length > 0 && (
        <p className="m-0 text-[13px] text-fg-3" data-models-used>
          Models used in its runs:{' '}
          {modelsUsed.map((m, i) => (
            <React.Fragment key={m.model}>
              {i > 0 && ', '}
              <span className="font-mono text-fg-2">{m.model}</span>
              <span className="text-fg-3"> ({m.runs})</span>
            </React.Fragment>
          ))}
        </p>
      )}

      {recent.length > 0 && (
        <div className="flex flex-col gap-1.5 pt-2 border-t border-line text-[13px]" data-recent-runs>
          <span className="text-fg-3">Recent runs</span>
          <ul className="list-none m-0 p-0 flex flex-col gap-1">
            {recent.map(r => {
              const o = outcomeLabel(r.status);
              return (
                <li key={r.taskId} className="flex items-center justify-between gap-2">
                  <a
                    href={`/dashboard/report/${r.taskId}`}
                    className="font-mono text-[12px] text-accent hover:underline truncate"
                    title={r.request}
                  >
                    {r.request}
                  </a>
                  <span className="shrink-0 flex items-center gap-1.5 text-[12px]">
                    {r.blocked > 0 && (
                      <span className="text-bad" data-recent-blocked>
                        {r.blocked} blocked
                      </span>
                    )}
                    <span className="text-fg-2 font-medium">{o.text}</span>
                  </span>
                </li>
              );
            })}
          </ul>
        </div>
      )}

      {c.comparisonRuns != null && c.comparisonRuns > 0 && (
        <p className="m-0 text-[12px] text-fg-3 pt-2 border-t border-line" data-comparison-note>
          {c.comparisonRuns} comparison {c.comparisonRuns === 1 ? 'run' : 'runs'} (kernel lock off) not counted.
        </p>
      )}
    </li>
  );
};

export const DiscoveredAgentCard: React.FC<{ item: AgentInventoryItem }> = ({ item }) => {
  const isGoverned = item.governance_state === 'Governed';

  return (
    <li
      className="card p-5 rounded-xl border border-line bg-surface-1 flex flex-col gap-3 min-w-0"
      data-discovered-agent={item.name || item.agent_id}
      data-governance-state={item.governance_state || 'Not governed yet'}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="flex flex-col gap-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-mono text-[15px] font-semibold text-fg [overflow-wrap:anywhere] min-w-0">
              {item.name || item.agent_id}
            </span>
            <span
              className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-semibold text-info border border-line bg-surface-2"
              data-badge="discovered-card"
            >
              Discovered (A2A card)
            </span>
          </div>
          {item.owner && (
            <span className="text-[12px] text-fg-3">
              Provider: {item.owner}
            </span>
          )}
        </div>
        <StatusPill
          id="governance-state-badge"
          data-testid="governance-state-badge"
          tone={isGoverned ? 'ok' : 'wait'}
          label={item.governance_state || 'Not governed yet'}
        />
      </div>

      {item.description && (
        <p className="m-0 text-[13px] leading-relaxed text-fg-2">
          {item.description}
        </p>
      )}

      {item.skills && item.skills.length > 0 && (
        <div className="flex flex-col gap-1.5">
          <span className="text-[11px] font-medium text-fg-3">
            Declared skills
          </span>
          <div className="flex flex-wrap gap-1.5">
            {item.skills.map(skill => (
              <span
                key={skill}
                className="px-2 py-0.5 rounded text-[11px] font-mono bg-surface-2 text-fg-2 border border-line"
                data-skill={skill}
              >
                {skill}
              </span>
            ))}
          </div>
        </div>
      )}

      {item.metadata?.card_url && (
        <div className="pt-2 border-t border-line flex items-center justify-between text-[11px] text-fg-3">
          <span className="truncate font-mono">{item.metadata.card_url}</span>
          {item.metadata.version && <span>v{item.metadata.version}</span>}
        </div>
      )}
    </li>
  );
};

export const InventoryPage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'inventory' | 'discovered'>('inventory');

  // Inventory tab state
  const [tasks, setTasks] = useState<TaskRecord[] | null>(null);
  const [requests, setRequests] = useState<ExpansionItem[]>([]);
  const [inventory, setInventory] = useState<AgentInventoryItem[]>([]);
  const [configured, setConfigured] = useState<ConfiguredAgent[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [now, setNow] = useState(Date.now());

  // Discovered tab state
  const [discoveredAgents, setDiscoveredAgents] = useState<DiscoveredAgent[]>([]);
  const [loadingDiscovered, setLoadingDiscovered] = useState<boolean>(false);
  const [discoveredError, setDiscoveredError] = useState<string | null>(null);
  const [scanning, setScanning] = useState<boolean>(false);
  const [scanWarning, setScanWarning] = useState<string | null>(null);
  const [selectedAgent, setSelectedAgent] = useState<DiscoveredAgent | null>(null);
  const [ownerInput, setOwnerInput] = useState<string>('');
  const [purposeInput, setPurposeInput] = useState<string>('');
  const [linkInput, setLinkInput] = useState<string>('');
  const [drawerMsg, setDrawerMsg] = useState<string | null>(null);

  const loadInventory = useCallback(() => {
    Promise.all([
      api.getTasks(),
      api.getExpansions().catch(() => [] as ExpansionItem[]),
      api.getInventory().catch(() => [] as AgentInventoryItem[]),
      api.getRunAgents().catch(() => [] as ConfiguredAgent[]),
    ])
      .then(([ts, rs, inv, cfg]) => {
        setConfigured(cfg);
        setTasks(ts);
        setRequests(rs);
        setInventory(inv);
        setNow(Date.now());
        setError(null);
      })
      .catch(err => setError(err?.message || 'Could not load the agents.'));
  }, []);

  const loadDiscovered = useCallback(() => {
    setLoadingDiscovered(true);
    api.getDiscoveredAgents({ include_retired: true })
      .then(agents => {
        setDiscoveredAgents(agents);
        setLoadingDiscovered(false);
        setDiscoveredError(null);
      })
      .catch(err => {
        setDiscoveredError(err?.message || 'Could not load discovered agents.');
        setLoadingDiscovered(false);
      });
  }, []);

  useEffect(() => {
    loadInventory();
    loadDiscovered();
    const t = setInterval(() => {
      loadInventory();
      if (activeTab === 'discovered') {
        loadDiscovered();
      }
    }, 10000);
    return () => clearInterval(t);
  }, [loadInventory, loadDiscovered, activeTab]);

  const handleScanNow = async () => {
    setScanning(true);
    setScanWarning(null);
    setDiscoveredError(null);
    try {
      const res = await api.triggerDiscoveryScan();
      const scanId = res.scan_id;
      const pollTimer = setInterval(async () => {
        try {
          const rec = await api.getDiscoveryScan(scanId);
          if (rec.status !== 'RUNNING') {
            clearInterval(pollTimer);
            setScanning(false);
            if (rec.unreadable_count > 0 || rec.details?.warning) {
              setScanWarning(rec.details?.warning || `partial scan: ${rec.unreadable_count} processes not readable`);
            }
            loadDiscovered();
          }
        } catch {
          clearInterval(pollTimer);
          setScanning(false);
          loadDiscovered();
        }
      }, 800);
    } catch (err: any) {
      setScanning(false);
      setDiscoveredError(err?.message || 'Scan trigger failed.');
    }
  };

  const handleSelectAgent = (agent: DiscoveredAgent) => {
    setSelectedAgent(agent);
    setOwnerInput(agent.owner || '');
    setPurposeInput(agent.purpose || '');
    setLinkInput(agent.linked_agent_id || '');
    setDrawerMsg(null);
  };

  const handlePatch = async (updates: { owner?: string; purpose?: string; status?: string; linked_agent_id?: string }) => {
    if (!selectedAgent) return;
    try {
      const updated = await api.patchDiscoveredAgent(selectedAgent.discovery_id, updates);
      setSelectedAgent(updated);
      setDrawerMsg('Updated.');
      loadDiscovered();
    } catch (err: any) {
      setDrawerMsg(err?.message || 'Update failed.');
    }
  };

  const handleRetire = async () => {
    if (!selectedAgent) return;
    try {
      const retired = await api.retireDiscoveredAgent(selectedAgent.discovery_id);
      setSelectedAgent(retired);
      setDrawerMsg('Retired.');
      loadDiscovered();
    } catch (err: any) {
      setDrawerMsg(err?.message || 'Retire failed.');
    }
  };

  const cards = tasks ? inventoryCards(tasks, requests, configured) : [];
  const a2aAgents = inventory.filter(
    item => item.classification === 'DISCOVERED_A2A' || item.metadata?.a2a_card
  );
  const counts = { high: 0, medium: 0, low: 0 } as Record<Risk, number>;
  cards.forEach(c => (counts[c.risk] += 1));
  const totalAgents = cards.length + a2aAgents.filter(d => !cards.some(c => c.agentId === d.agent_id)).length;

  return (
    <div className="max-w-[1200px] pb-12 flex flex-col gap-6 font-sans">
      <PageHeader
        titleId="inventory-headline"
        title={
          activeTab === 'inventory'
            ? tasks == null && inventory.length === 0
              ? 'Agent inventory'
              : totalAgents === 0
              ? 'No agents yet.'
              : `${totalAgents} ${totalAgents === 1 ? 'agent' : 'agents'}.`
            : `Discovered agents (${discoveredAgents.length})`
        }
        subtitle={
          activeTab === 'inventory' ? (
            <span>
              An agent is an identity we hold accountable: a name, an owner and a team, the model it runs on, and its tool
              limit, the only tools it may ever call. Which files and sites it may touch is not part of the agent: each
              request sets that, inside the agent's limit, and every tool call is checked against both. Counts come from real runs here; comparison runs (kernel lock off) are not counted.
              {cards.length > 0 && ` ${counts.high} high, ${counts.medium} medium and ${counts.low} low risk.`}
            </span>
          ) : (
            <span>
              System-wide discovery across host processes, repositories, MCP servers, and local model endpoints.
              Governed agents are bound to active tasks, known agents have an assigned owner and purpose, and shadow agents operate outside the governance fence.
            </span>
          )
        }
        actions={
          activeTab === 'inventory' ? (
            tasks && totalAgents > 0 ? (
              <Button
                variant="secondary"
                id="inventory-scan"
                onClick={loadInventory}
                className="h-auto p-2.5 flex flex-col items-center gap-1.5 cursor-pointer border border-line"
              >
                <AgentScan count={totalAgents} size={110} />
              </Button>
            ) : undefined
          ) : (
            <Button
              variant="primary"
              id="discovery-scan-btn"
              onClick={handleScanNow}
              disabled={scanning}
            >
              {scanning ? 'Scanning…' : 'Scan now'}
            </Button>
          )
        }
      />

      {/* Tabs */}
      <div className="flex items-center gap-2 border-b border-line pb-2" role="tablist">
        <button
          type="button"
          role="tab"
          id="tab-inventory"
          aria-selected={activeTab === 'inventory'}
          onClick={() => setActiveTab('inventory')}
          className={`px-4 py-2 text-[14px] font-medium rounded-lg border-none cursor-pointer transition-colors ${
            activeTab === 'inventory'
              ? 'bg-surface-2 text-fg shadow-sm'
              : 'bg-transparent text-fg-3 hover:text-fg hover:bg-surface-1'
          }`}
        >
          Inventory
        </button>
        <button
          type="button"
          role="tab"
          id="tab-discovered"
          aria-selected={activeTab === 'discovered'}
          onClick={() => setActiveTab('discovered')}
          className={`px-4 py-2 text-[14px] font-medium rounded-lg border-none cursor-pointer transition-colors ${
            activeTab === 'discovered'
              ? 'bg-surface-2 text-fg shadow-sm'
              : 'bg-transparent text-fg-3 hover:text-fg hover:bg-surface-1'
          }`}
        >
          Discovered
        </button>
      </div>

      {activeTab === 'inventory' ? (
        error && !tasks ? (
          <ErrorState message={error} onRetry={loadInventory} id="inventory-error" />
        ) : !tasks ? (
          <div className="card p-8 rounded-xl border border-line bg-surface-1 flex justify-center">
            <AgentScan count={null} id="inventory-loading" />
          </div>
        ) : (
          <>
            <section className="flex flex-col gap-3" id="governed-agents-section">
              {a2aAgents.length > 0 && (
                <h2 className="m-0 text-[18px] sm:text-[20px] font-semibold text-fg">
                  Our agents
                </h2>
              )}
              {cards.length === 0 ? (
                <EmptyState id="inventory-empty" title="No agents yet." body="An agent appears here after its trial run." />
              ) : (
                <ul id="inventory-list" className="list-none m-0 p-0 grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
                  {cards.map(c => (
                    <InventoryCard key={c.agentId} c={c} now={now} />
                  ))}
                </ul>
              )}
            </section>

            {a2aAgents.length > 0 && (
              <section className="flex flex-col gap-3" id="discovered-agents-section">
                <div className="flex items-center justify-between">
                  <h2 className="m-0 text-[18px] sm:text-[20px] font-semibold text-fg">
                    Other agents found on this machine
                  </h2>
                  <span className="text-[13px] text-fg-3">
                    From their A2A Agent Cards. Not governed until they run inside our boundary.
                  </span>
                </div>
                <ul id="discovered-agents-list" className="list-none m-0 p-0 grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
                  {a2aAgents.map(a => (
                    <DiscoveredAgentCard key={a.agent_id} item={a} />
                  ))}
                </ul>
              </section>
            )}
          </>
        )
      ) : (
        /* Discovered Tab */
        <div className="flex flex-col gap-4">
          {scanWarning && (
            <div
              className="p-3.5 rounded-lg border border-line bg-surface-2 text-[13px] text-fg-2 flex items-center justify-between"
              id="discovered-scan-warning"
            >
              <span>{scanWarning}</span>
              <button
                type="button"
                className="text-fg-3 hover:text-fg border-none bg-transparent cursor-pointer text-[15px]"
                onClick={() => setScanWarning(null)}
              >
                ✕
              </button>
            </div>
          )}

          {discoveredError && (
            <ErrorState message={discoveredError} onRetry={loadDiscovered} id="discovered-error" />
          )}

          {loadingDiscovered && discoveredAgents.length === 0 ? (
            <LoadingState label="Checking discovered agents…" id="discovered-loading" />
          ) : discoveredAgents.length === 0 ? (
            <EmptyState
              id="discovered-empty"
              title="No scan yet"
              body="No agents or frameworks detected yet. Run a host and repository discovery scan."
              action={
                <Button
                  variant="primary"
                  id="discovered-scan-btn-empty"
                  onClick={handleScanNow}
                  disabled={scanning}
                >
                  {scanning ? 'Scanning…' : 'Scan now'}
                </Button>
              }
            />
          ) : (
            <div className="overflow-x-auto rounded-xl border border-line bg-surface-1">
              <table className="w-full border-collapse text-left text-[13px]" id="discovered-agents-table">
                <thead>
                  <tr className="border-b border-line bg-surface-2 text-fg-3 font-medium">
                    <th className="py-3 px-4">Name</th>
                    <th className="py-3 px-3">Kind</th>
                    <th className="py-3 px-3">Host</th>
                    <th className="py-3 px-3">Frameworks</th>
                    <th className="py-3 px-3">LLM Endpoints</th>
                    <th className="py-3 px-3">Key Names</th>
                    <th className="py-3 px-3">Status</th>
                    <th className="py-3 px-3">Owner</th>
                    <th className="py-3 px-4">Last Seen</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-line">
                  {discoveredAgents.map(agent => {
                    const statusTone =
                      agent.retired_at
                        ? 'neutral'
                        : agent.status === 'governed'
                        ? 'ok'
                        : agent.status === 'known'
                        ? 'wait'
                        : 'bad';
                    const statusLabel = agent.retired_at
                      ? 'Retired'
                      : agent.status === 'governed'
                      ? 'Governed'
                      : agent.status === 'known'
                      ? 'Known'
                      : 'Shadow';

                    return (
                      <tr
                        key={agent.discovery_id}
                        onClick={() => handleSelectAgent(agent)}
                        className="cursor-pointer hover:bg-surface-2 transition-colors"
                        data-discovery-row={agent.discovery_id}
                      >
                        <td className="py-3 px-4 font-semibold text-fg">
                          <div>{agent.name}</div>
                          <div className="text-[11px] font-mono text-fg-3 truncate max-w-[200px]" title={agent.discovery_id}>
                            {agent.discovery_id}
                          </div>
                        </td>
                        <td className="py-3 px-3">
                          <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-surface-3 text-fg-2 border border-line">
                            {agent.kind}
                          </span>
                        </td>
                        <td className="py-3 px-3 font-mono text-[12px] text-fg-2">{agent.host}</td>
                        <td className="py-3 px-3">
                          {agent.frameworks.length > 0 ? (
                            <div className="flex flex-wrap gap-1 max-w-[180px]">
                              {agent.frameworks.map(f => (
                                <span key={f} className="px-1.5 py-0.5 rounded text-[11px] bg-surface-2 text-fg-2 border border-line">
                                  {f}
                                </span>
                              ))}
                            </div>
                          ) : (
                            <span className="text-fg-3">—</span>
                          )}
                        </td>
                        <td className="py-3 px-3">
                          {agent.llm_endpoints.length > 0 ? (
                            <div className="flex flex-wrap gap-1 max-w-[160px]">
                              {agent.llm_endpoints.map(e => (
                                <span key={e} className="font-mono text-[11px] text-fg-2">
                                  {e}
                                </span>
                              ))}
                            </div>
                          ) : (
                            <span className="text-fg-3">—</span>
                          )}
                        </td>
                        <td className="py-3 px-3">
                          {agent.key_names.length > 0 ? (
                            <div className="flex flex-wrap gap-1 max-w-[160px]">
                              {agent.key_names.map(k => (
                                <span key={k} className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-surface-2 text-fg-3 border border-line">
                                  {k}
                                </span>
                              ))}
                            </div>
                          ) : (
                            <span className="text-fg-3">—</span>
                          )}
                        </td>
                        <td className="py-3 px-3">
                          <StatusPill tone={statusTone} label={statusLabel} />
                        </td>
                        <td className="py-3 px-3 text-fg-2">{agent.owner || '—'}</td>
                        <td className="py-3 px-4 text-fg-3 text-[12px]">
                          {agent.updated_at ? relativeTime(agent.updated_at, now) : '—'}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Detail Drawer */}
      {selectedAgent && (
        <div
          className="fixed inset-0 z-50 flex justify-end bg-black/40 backdrop-blur-xs"
          id="discovered-detail-drawer"
          onClick={() => setSelectedAgent(null)}
        >
          <div
            className="w-full max-w-[480px] h-full bg-surface-1 border-l border-line p-6 flex flex-col gap-5 overflow-y-auto shadow-2xl"
            onClick={e => e.stopPropagation()}
          >
            <div className="flex items-start justify-between gap-3 border-b border-line pb-4">
              <div className="flex flex-col gap-1 min-w-0">
                <span className="text-[18px] font-semibold text-fg">{selectedAgent.name}</span>
                <span className="text-[12px] font-mono text-fg-3 truncate" title={selectedAgent.discovery_id}>
                  {selectedAgent.discovery_id}
                </span>
                <div className="flex items-center gap-2 mt-1">
                  <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-surface-3 text-fg-2 border border-line">
                    {selectedAgent.kind}
                  </span>
                  <StatusPill
                    tone={
                      selectedAgent.retired_at
                        ? 'neutral'
                        : selectedAgent.status === 'governed'
                        ? 'ok'
                        : selectedAgent.status === 'known'
                        ? 'wait'
                        : 'bad'
                    }
                    label={
                      selectedAgent.retired_at
                        ? 'Retired'
                        : selectedAgent.status === 'governed'
                        ? 'Governed'
                        : selectedAgent.status === 'known'
                        ? 'Known'
                        : 'Shadow'
                    }
                  />
                </div>
              </div>
              <button
                type="button"
                className="text-fg-3 hover:text-fg border-none bg-transparent cursor-pointer text-[20px] p-1"
                onClick={() => setSelectedAgent(null)}
                aria-label="Close"
              >
                ✕
              </button>
            </div>

            {drawerMsg && (
              <div className="p-3 rounded-lg border border-line bg-surface-2 text-[13px] text-fg">
                {drawerMsg}
              </div>
            )}

            {/* Evidence List */}
            <div className="flex flex-col gap-2">
              <span className="text-[14px] font-medium text-fg">Evidence items</span>
              {selectedAgent.evidence.length === 0 ? (
                <span className="text-[13px] text-fg-3">No direct evidence items stored.</span>
              ) : (
                <ul className="list-none m-0 p-0 flex flex-col gap-2" id="drawer-evidence-list">
                  {selectedAgent.evidence.map((ev, i) => (
                    <li key={i} className="p-3 rounded-lg border border-line bg-surface-2 flex flex-col gap-1 text-[12px]">
                      <div className="flex items-center justify-between">
                        <span className="font-semibold text-fg uppercase tracking-wide text-[10px]">
                          {ev.signal}
                        </span>
                        {ev.last_seen && (
                          <span className="text-fg-3 text-[11px]">
                            {relativeTime(ev.last_seen, now)}
                          </span>
                        )}
                      </div>
                      <div className="text-fg-2 [overflow-wrap:anywhere]">{ev.detail}</div>
                    </li>
                  ))}
                </ul>
              )}
            </div>

            {/* Actions */}
            <div className="flex flex-col gap-4 border-t border-line pt-4" id="drawer-actions">
              <span className="text-[14px] font-medium text-fg">Governance actions</span>

              {/* Assign owner */}
              <div className="flex flex-col gap-1.5">
                <label className="text-[12px] text-fg-3" htmlFor="drawer-owner-input">Owner</label>
                <div className="flex gap-2">
                  <input
                    id="drawer-owner-input"
                    type="text"
                    value={ownerInput}
                    onChange={e => setOwnerInput(e.target.value)}
                    placeholder="Engineering / Security / DevOps"
                    className="flex-1 px-3 py-1.5 rounded-lg border border-line bg-surface-2 text-[13px] text-fg focus:outline-hidden"
                  />
                  <Button
                    variant="secondary"
                    size="sm"
                    onClick={() => handlePatch({ owner: ownerInput })}
                  >
                    Save
                  </Button>
                </div>
              </div>

              {/* Purpose */}
              <div className="flex flex-col gap-1.5">
                <label className="text-[12px] text-fg-3" htmlFor="drawer-purpose-input">Purpose</label>
                <div className="flex gap-2">
                  <input
                    id="drawer-purpose-input"
                    type="text"
                    value={purposeInput}
                    onChange={e => setPurposeInput(e.target.value)}
                    placeholder="e.g. CI workflow assistant"
                    className="flex-1 px-3 py-1.5 rounded-lg border border-line bg-surface-2 text-[13px] text-fg focus:outline-hidden"
                  />
                  <Button
                    variant="secondary"
                    size="sm"
                    onClick={() => handlePatch({ purpose: purposeInput })}
                  >
                    Save
                  </Button>
                </div>
              </div>

              {/* Mark known */}
              {selectedAgent.status === 'shadow' && (
                <div className="flex items-center justify-between pt-2">
                  <span className="text-[13px] text-fg-2">Acknowledge this agent</span>
                  <Button
                    variant="secondary"
                    size="sm"
                    onClick={() => handlePatch({ status: 'known' })}
                  >
                    Mark known
                  </Button>
                </div>
              )}

              {/* Link to agent */}
              <div className="flex flex-col gap-1.5 pt-2">
                <label className="text-[12px] text-fg-3" htmlFor="drawer-link-input">Link to registered agent ID</label>
                <div className="flex gap-2">
                  <input
                    id="drawer-link-input"
                    type="text"
                    value={linkInput}
                    onChange={e => setLinkInput(e.target.value)}
                    placeholder="e.g. brief_bot"
                    className="flex-1 px-3 py-1.5 rounded-lg border border-line bg-surface-2 text-[13px] text-fg focus:outline-hidden"
                  />
                  <Button
                    variant="secondary"
                    size="sm"
                    onClick={() => handlePatch({ linked_agent_id: linkInput })}
                  >
                    Link
                  </Button>
                </div>
              </div>

              {/* Retire */}
              {!selectedAgent.retired_at && (
                <div className="flex items-center justify-between border-t border-line pt-3 mt-1">
                  <div className="flex flex-col">
                    <span className="text-[13px] font-medium text-bad">Retire agent</span>
                    <span className="text-[11px] text-fg-3">Deactivates tokens and cancels active grants</span>
                  </div>
                  <Button
                    variant="danger"
                    size="sm"
                    id="drawer-retire-btn"
                    onClick={handleRetire}
                  >
                    Retire
                  </Button>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

const Fact: React.FC<{ k: string; v: string; color?: string; title?: string }> = ({ k, v, color, title }) => (
  <div className="flex flex-col min-w-0">
    <dt className="text-[12px] text-fg-3">
      {k}
    </dt>
    <dd className="m-0 [overflow-wrap:anywhere]" style={{ color: color ?? 'var(--text)' }} title={title}>
      {v}
    </dd>
  </div>
);
