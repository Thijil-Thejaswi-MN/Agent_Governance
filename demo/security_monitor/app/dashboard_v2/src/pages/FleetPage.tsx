import React, { useCallback, useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import { DotState, FleetDot, FleetSummary } from '../types';
import { DotField, DOT_COLORS, DOT_LEGEND } from '../components/v3/DotField';
import { DetailsDrawer, DetailsSection, KV } from '../components/v3/DetailsDrawer';
import { fleetHeadline, needsYouReason, needsYouTitle } from '../logic/plain';

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
      <div className="max-w-[1360px] py-12" style={{ color: 'var(--text-2)' }}>
        {error ? <p role="alert">{error}</p> : <p>Loading…</p>}
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
          <h1 id="fleet-headline" data-quiet={quiet} className="m-0 font-display font-bold text-[28px] sm:text-[32px] leading-[1.15] text-[#E6E9EF]">
            {line1}
            <br />
            <span style={{ color: data.need_you > 0 ? '#FBBF24' : 'var(--text-2)' }}>{line2}</span>
          </h1>

          {dots.length > 0 ? (
            <>
              <p className="m-0 text-[15px]" style={{ color: 'var(--text-2)' }} id="dot-basis">
                {fieldLabel}
              </p>
              <DotField dots={dots} onOpen={openDot} label={fieldLabel} />
              <div className="flex flex-wrap gap-5 text-[14px]" style={{ color: 'var(--text-2)' }}>
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
            <p className="m-0 text-[15px] card px-5 py-6" style={{ color: 'var(--text-2)' }} id="fleet-empty">
              When an agent starts a task, it shows up here. <Link to="/run">Start one</Link>
            </p>
          )}
          {error && (
            <p className="m-0 text-[14px]" role="alert" style={{ color: '#FCA5A5' }}>
              Could not refresh: {error}
            </p>
          )}
        </section>

        <section aria-label="Needs attention" className="flex-[1_1_340px] max-w-[460px] min-w-0 flex flex-col gap-4">
          <div className="card p-5 flex flex-col gap-3">
            <h2 className="m-0 text-[15px] font-semibold text-[#E6E9EF]">Needs you</h2>
            {data.needs_you.length === 0 ? (
              <p className="m-0 text-[15px]" style={{ color: 'var(--text-2)' }} id="needs-you-empty">
                Nothing is waiting for a decision.
              </p>
            ) : (
              data.needs_you.map(item => (
                <div
                  key={item.request_id}
                  id={`needs-you-${item.request_id}`}
                  className="flex items-center gap-3 px-4 py-3 rounded-xl"
                  style={{ background: 'rgba(245,158,11,0.08)', border: '1px solid rgba(245,158,11,0.5)' }}
                >
                  <div className="flex-1 min-w-0">
                    <div className="font-semibold break-words">{needsYouTitle(agentLabel(item.agent_id), item)}</div>
                    <div className="text-[14px]" style={{ color: 'var(--text-2)' }}>
                      {needsYouReason(item)}
                    </div>
                  </div>
                  <Link
                    id={`review-${item.request_id}`}
                    to={`/run/${item.task_id}`}
                    className="inline-flex items-center min-h-[44px] px-4 rounded-lg font-semibold text-[14px] no-underline pulse-waiting"
                    style={{ background: '#F59E0B', color: '#1A1203' }}
                  >
                    Review
                  </Link>
                </div>
              ))
            )}
          </div>

          <div className="card p-5 flex flex-col gap-1">
            <h2 className="m-0 mb-1 text-[15px] font-semibold text-[#E6E9EF]">Blocked in the last 24 hours</h2>
            {data.blocked.groups.length === 0 ? (
              <p className="m-0 text-[15px]" style={{ color: 'var(--text-2)' }} id="blocked-empty">
                Nothing was blocked.
              </p>
            ) : (
              data.blocked.groups.map((g, i) => (
                <div
                  key={g.target_class}
                  data-group={g.target_class}
                  className="flex items-baseline gap-3.5 py-3"
                  style={i < data.blocked.groups.length - 1 ? { borderBottom: '1px solid var(--border)' } : undefined}
                >
                  <span className="text-[24px] font-bold tracking-tight min-w-[48px]" style={{ color: '#F87171' }}>
                    {g.count.toLocaleString('en-US')}
                  </span>
                  <span className="text-[14px] text-[#A7B0C0]">{g.label}</span>
                </div>
              ))
            )}
            <Link id="see-blocked" to="/history?filter=blocked" className="text-[15px] inline-flex items-center min-h-[44px]">
              See every blocked action
            </Link>
          </div>

          <button className="link-btn self-start text-[14px]" onClick={() => setDetailsOpen(true)} id="fleet-details-btn">
            Details
          </button>
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
            <div key={g.target_class} className="p-3 rounded-[14px]" style={{ background: 'var(--card-2)', border: '1px solid var(--line)' }}>
              <KV k="Target class" v={g.target_class} />
              <KV k="Count" v={`${g.count} (${g.task_count} tasks, ${g.agent_count} agents)`} />
              <KV k="By layer" v={Object.entries(g.by_layer).map(([k, v]) => `${k}: ${v}`).join(', ')} />
              <KV k="By event kind" v={Object.entries(g.by_kind).map(([k, v]) => `${k}: ${v}`).join(', ')} />
              <KV k="Examples" v={g.examples.join(', ')} />
            </div>
          ))}
          <p className="m-0 text-[13px]" style={{ color: 'var(--text-2)' }}>
            Grouped by target class: a file only mentioned inside content the agent read (and not in the request), an outside
            website, a private or home folder, or other. Broker, proxy and OS-sensor records of one attempt are counted once.
          </p>
        </DetailsSection>
        {data.needs_you.length > 0 && (
          <DetailsSection title="Pending expansions">
            {data.needs_you.map(n => (
              <div key={n.request_id} className="p-3 rounded-[14px]" style={{ background: 'var(--card-2)', border: '1px solid var(--line)' }}>
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
