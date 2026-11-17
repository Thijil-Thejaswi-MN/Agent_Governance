import React, { useCallback, useEffect, useState } from 'react';
import { AgentScan } from '../components/effects/AgentScan';
import { Link, useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import { DotState, FleetDot, FleetSummary } from '../types';
import { DotField, DOT_COLORS, DOT_LEGEND } from '../components/v3/DotField';
import { DetailsDrawer, DetailsSection, KV } from '../components/v3/DetailsDrawer';
import { fleetHeadline, needsYouReason, needsYouTitle } from '../logic/plain';
import { PageHeader } from '../components/ui/PageHeader';
import { StatusPill } from '../components/ui/StatusPill';
import { Button } from '../components/ui/Button';

const REFRESH_MS = 5000;
const LEGEND_ORDER: DotState[] = ['working', 'waiting', 'blocked', 'idle', 'no_task'];

const agentLabel = (id: string) => (id ? id.replace(/_/g, ' ').replace(/^\w/, c => c.toUpperCase()) : 'An agent');

export const FleetPage: React.FC = () => {
  const navigate = useNavigate();
  const [data, setData] = useState<FleetSummary | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [detailsOpen, setDetailsOpen] = useState(false);

  const load = useCallback(() => {
    api
      .getFleetSummary()
      .then(d => {
        setData(d);
        setError(null);
      })
      .catch(err => setError(err.message || 'Could not load the fleet.'));
  }, []);

  useEffect(() => {
    load();
    const t = setInterval(load, REFRESH_MS);
    return () => clearInterval(t);
  }, [load]);

  const openDot = (d: FleetDot) => {
    if (!d.task_id) return;
    navigate(d.view === 'watch' ? `/run/${d.task_id}` : `/history/${d.task_id}`);
  };

  if (!data) {
    return (
      <div className="max-w-[1360px] py-12 text-fg-2">
        {error ? <p role="alert">{error}</p> : <AgentScan count={null} id="fleet-loading" />}
      </div>
    );
  }

  const [line1, line2] = fleetHeadline(data.agents_at_work, data.need_you);
  const quiet = data.agents_at_work === 0 && data.need_you === 0;
  const dots = data.dots.items;
  const fieldLabel =
    data.dots.basis === 'inventory'
      ? 'Each dot is one agent we know about. Calm dots need nothing from you.'
      : 'Each dot is one running task. Calm dots need nothing from you.';

  return (
    <div>
      <div className="max-w-[1360px] pb-12 flex flex-wrap gap-6 lg:gap-8 items-start">
        <section aria-label="All agents" className="flex-[999_1_620px] min-w-0 flex flex-col gap-5">
          <PageHeader
            titleId="fleet-headline"
            titleProps={{ 'data-quiet': quiet } as React.HTMLAttributes<HTMLHeadingElement>}
            title={
              <>
                {line1}
                <br />
                <span className={data.need_you > 0 ? 'text-wait-kpi' : 'text-fg-2'}>{line2}</span>
              </>
            }
          />

          {dots.length > 0 ? (
            <>
              <p className="m-0 text-[15px] text-fg-2" id="dot-basis">
                {fieldLabel}
              </p>
              <DotField dots={dots} onOpen={openDot} label={fieldLabel} />
              <div className="flex flex-wrap gap-5 text-[14px] text-fg-2">
                {LEGEND_ORDER.filter(s => (data.dots.counts[s] || 0) > 0).map(s => (
                  <span key={s} data-legend={s}>
                    <span
                      className="inline-block w-2.5 h-2.5 rounded-full mr-1.5"
                      style={s === 'no_task' ? { border: `2px solid ${DOT_COLORS[s]}` } : { background: DOT_COLORS[s] }}
                    />
                    {data.dots.counts[s]} {DOT_LEGEND[s]}
                  </span>
                ))}
              </div>
            </>
          ) : (
            <p className="m-0 text-[15px] rounded-xl border border-line bg-surface-1 px-5 py-6 text-fg-2" id="fleet-empty">
              When an agent starts a task, it shows up here. <Link to="/run" className="text-accent underline">Start one</Link>
            </p>
          )}
          {error && (
            <p className="m-0 text-[14px] text-bad" role="alert">
              Could not refresh: {error}
            </p>
          )}
        </section>

        <section aria-label="Needs attention" className="flex-[1_1_340px] max-w-[460px] min-w-0 flex flex-col gap-4">
          {/* Needs you table */}
          <div className="rounded-xl border border-line bg-surface-1 overflow-hidden">
            <div className="px-4 py-3 border-b border-line flex items-center justify-between">
              <h2 className="m-0 text-[14px] font-semibold text-fg">Needs you</h2>
              {data.needs_you.length > 0 && (
                <span className="font-mono text-[12px] text-wait-kpi font-semibold">{data.needs_you.length}</span>
              )}
            </div>

            {data.needs_you.length === 0 ? (
              <p className="m-0 p-4 text-[14px] text-fg-2" id="needs-you-empty">
                Nothing is waiting for a decision.
              </p>
            ) : (
              <>
                <div className="bg-surface-2 px-4 py-2 text-[12px] uppercase tracking-wider text-fg-3 font-semibold flex items-center justify-between border-b border-line">
                  <span>Request / Reason</span>
                  <span>Verdict / Action</span>
                </div>
                {data.needs_you.map(item => (
                  <div
                    key={item.request_id}
                    id={`needs-you-${item.request_id}`}
                    className="min-h-[44px] px-4 py-2.5 flex items-center justify-between gap-3 border-b border-line last:border-b-0 hover:bg-surface-2/50 transition-colors text-[14px]"
                  >
                    <div className="flex-1 min-w-0">
                      <div className="font-medium text-fg break-words">
                        {needsYouTitle(agentLabel(item.agent_id), item)}
                      </div>
                      <div className="text-[13px] text-fg-2">
                        {needsYouReason(item)}
                      </div>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      <StatusPill tone="wait" label="Waiting" />
                      <Link
                        id={`review-${item.request_id}`}
                        to={`/run/${item.task_id}`}
                        className="inline-flex items-center justify-center min-h-[36px] h-9 px-3 rounded-lg text-[13px] font-medium text-fg-2 hover:text-fg hover:bg-surface-2 transition-colors border border-line hover:border-line-strong no-underline"
                      >
                        Review
                      </Link>
                    </div>
                  </div>
                ))}
              </>
            )}
          </div>

          {/* Blocked in the last 24 hours table */}
          <div className="rounded-xl border border-line bg-surface-1 overflow-hidden">
            <div className="px-4 py-3 border-b border-line flex items-center justify-between">
              <h2 className="m-0 text-[14px] font-semibold text-fg">Blocked in the last 24 hours</h2>
              {data.blocked.groups.length > 0 && (
                <span className="font-mono text-[12px] text-bad font-semibold">{data.blocked.total}</span>
              )}
            </div>

            {data.blocked.groups.length === 0 ? (
              <p className="m-0 p-4 text-[14px] text-fg-2" id="blocked-empty">
                Nothing was blocked.
              </p>
            ) : (
              <>
                <div className="bg-surface-2 px-4 py-2 text-[12px] uppercase tracking-wider text-fg-3 font-semibold flex items-center justify-between border-b border-line">
                  <span>Target Class / Reason</span>
                  <span>Count</span>
                </div>
                {data.blocked.groups.map(g => (
                  <div
                    key={g.target_class}
                    data-group={g.target_class}
                    className="min-h-[44px] h-11 px-4 flex items-center justify-between gap-3 border-b border-line last:border-b-0 hover:bg-surface-2/50 transition-colors text-[14px]"
                  >
                    <div className="flex items-center gap-2 min-w-0">
                      <StatusPill tone="bad" label="Blocked" />
                      <span className="text-[13px] text-fg-2 truncate">{g.label}</span>
                    </div>
                    <span className="font-mono text-[14px] font-semibold text-bad tabular-nums shrink-0">
                      {g.count.toLocaleString('en-US')}
                    </span>
                  </div>
                ))}
                <div className="p-2 border-t border-line bg-surface-1">
                  <Link
                    id="see-blocked"
                    to="/history?filter=blocked"
                    className="inline-flex items-center justify-center w-full min-h-[36px] h-9 px-3 rounded-lg text-[13px] font-medium text-fg-2 hover:text-fg hover:bg-surface-2 transition-colors no-underline"
                  >
                    See every blocked action
                  </Link>
                </div>
              </>
            )}
          </div>

          <Button
            variant="ghost"
            size="sm"
            onClick={() => setDetailsOpen(true)}
            id="fleet-details-btn"
            className="self-start text-[13px]"
          >
            Details
          </Button>
        </section>
      </div>

      <DetailsDrawer open={detailsOpen} title="Fleet details" onClose={() => setDetailsOpen(false)}>
        <DetailsSection title="Counts">
          <KV k="Running tasks (ACTIVE)" v={data.agents_at_work} />
          <KV k="Pending expansions" v={data.need_you} />
          <KV k="Dots drawn from" v={data.dots.basis === 'inventory' ? `inventory (${data.inventory_size} agents)` : 'active tasks (inventory empty)'} />
          {LEGEND_ORDER.map(s => (
            <KV key={s} k={`state: ${s}`} v={data.dots.counts[s] || 0} />
          ))}
          <KV k="Known tasks" v={data.known_tasks} />
          <KV k="Generated" v={data.generated_at} />
        </DetailsSection>
        <DetailsSection title={`Blocked events, last ${data.blocked.window_hours} h (${data.blocked.total})`}>
          {data.blocked.groups.map(g => (
            <div key={g.target_class} className="p-3 rounded-xl bg-surface-2 border border-line">
              <KV k="Target class" v={g.target_class} />
              <KV k="Count" v={`${g.count} (${g.task_count} tasks, ${g.agent_count} agents)`} />
              <KV k="By layer" v={Object.entries(g.by_layer).map(([k, v]) => `${k}: ${v}`).join(', ')} />
              <KV k="By event kind" v={Object.entries(g.by_kind).map(([k, v]) => `${k}: ${v}`).join(', ')} />
              <KV k="Examples" v={g.examples.join(', ')} />
            </div>
          ))}
          <p className="m-0 text-[13px] text-fg-2">
            Grouped by target class: a file only mentioned inside content the agent read (and not in the request), an outside
            website, a private or home folder, or other. Broker, proxy and OS-sensor records of one attempt are counted once.
          </p>
        </DetailsSection>
        {data.needs_you.length > 0 && (
          <DetailsSection title="Pending expansions">
            {data.needs_you.map(n => (
              <div key={n.request_id} className="p-3 rounded-xl bg-surface-2 border border-line">
                <KV k="Request" v={n.request_id} />
                <KV k="Task" v={n.task_id} />
                <KV k="Resource" v={`${n.resource_type}: ${n.resource_target}`} />
                <KV k="Risk tier" v={`${n.baseline_risk_tier} → ${n.effective_risk_tier}`} />
                <KV k="Escalated by provenance" v={n.escalated_by_provenance ? 'yes' : 'no'} />
                <KV k="Fail-closed deadline" v={n.deadline || 'n/a'} />
              </div>
            ))}
          </DetailsSection>
        )}
      </DetailsDrawer>
    </div>
  );
};
