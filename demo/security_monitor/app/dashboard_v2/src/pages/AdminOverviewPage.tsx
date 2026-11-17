import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import { loadRecentEvents } from '../api/events';
import { startOfLocalDay } from '../logic/teamStats';
import { ExpansionItem, FleetSummary, RecordsSummary, TaskEvent, TaskRecord } from '../types';
import { EmptyState, ErrorState, LoadingState } from '../components/common/States';
import { formatDuration, agentRows } from '../logic/teamStats';
import {
  AgentDot,
  AgentState,
  actionsPerHour,
  agentDots,
  mapMode,
  medianRunSeconds,
  runsInLast24h,
  stoppedInLast24h,
  teamGroups,
} from '../logic/overview';
import { layerLabel } from '../logic/report';
import { needsYouSentence } from '../logic/plain';
import { PALETTE } from '../logic/palette';

const STATE: Record<AgentState, { color: string; label: string }> = {
  asking: { color: PALETTE.wait, label: 'asking you' },
  stopped: { color: PALETTE.bad, label: 'stopped in the last hour' },
  running: { color: PALETTE.accent, label: 'running' },
  idle: { color: PALETTE.slate500, label: 'idle' },
};

export const AdminOverviewPage: React.FC = () => {
  const navigate = useNavigate();
  const [tasks, setTasks] = useState<TaskRecord[] | null>(null);
  const [pending, setPending] = useState<ExpansionItem[]>([]);
  const [allExps, setAllExps] = useState<ExpansionItem[]>([]);
  const [events, setEvents] = useState<TaskEvent[]>([]);
  const [fleet, setFleet] = useState<FleetSummary | null>(null);
  const [recordsSummary, setRecordsSummary] = useState<RecordsSummary | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [now, setNow] = useState(Date.now());

  useEffect(() => {
    let mounted = true;
    let slowBusy = false;
    const load = async () => {
      const t = Date.now();
      try {
        const since = new Date(Math.min(startOfLocalDay(t), t - 24 * 3600_000)).toISOString();
        const [taskList, exps, firstEvents] = await Promise.all([
          api.getTasks(),
          api.getExpansions().catch(() => [] as ExpansionItem[]),
          api.getEvents(since, 500).catch(() => ({ events: [] as TaskEvent[], cursor: null })),
        ]);
        if (!mounted) return;
        setTasks(taskList);
        setAllExps(exps);
        setPending(exps.filter(e => e.status === 'PENDING'));
        if (firstEvents?.events?.length) setEvents(firstEvents.events);
        setNow(t);
        setError(null);
      } catch (err: any) {
        if (mounted) setError(err?.message || 'Could not load the overview.');
        return;
      }
      if (slowBusy) return;
      slowBusy = true;
      loadRecentEvents(t).then(evts => {
        if (mounted && evts) setEvents(evts);
      }).catch(() => null);
      api.getFleetSummary().then(fl => {
        if (mounted) setFleet(fl);
      }).catch(() => null);
      api.getRecordsSummary().then(rec => {
        if (mounted) setRecordsSummary(rec);
      }).catch(() => null).finally(() => {
        slowBusy = false;
      });
    };
    load();
    const interval = setInterval(load, 5000);
    return () => {
      mounted = false;
      clearInterval(interval);
    };
  }, []);

  if (error && !tasks) return <ErrorState message={error} id="overview-error" />;
  if (!tasks) return <LoadingState label="Loading the overview…" id="overview-loading" />;

  const overviewTasks = (tasks ?? []).filter(t => !t.comparison_mode && t.condition !== 'B');
  const comparisonTaskIds = new Set((tasks ?? []).filter(t => t.comparison_mode || t.condition === 'B').map(t => t.task_id));
  const overviewEvents = events.filter(e => !comparisonTaskIds.has(e.task_id));

  const runs24 = runsInLast24h(overviewTasks, now);
  const agents24 = new Set(runs24.map(t => t.agent_id)).size;
  const runningTasks = overviewTasks.filter(t => t.status === 'ACTIVE' || t.status === 'RUNNING').length;
  const stopped24 = stoppedInLast24h(overviewEvents, now);
  const medianRun = medianRunSeconds(overviewTasks, now);
  const dots = agentDots(overviewTasks, pending, overviewEvents, now);
  const teams = teamGroups(dots);
  const hours = actionsPerHour(overviewEvents, allExps, now);
  const peak = Math.max(1, ...hours.map(h => h.allowed + h.stopped + h.asked));
  const anyToday = hours.some(h => h.allowed + h.stopped + h.asked > 0);
  const mode = mapMode(runningTasks);
  const watch = agentRows(overviewTasks).filter(r => r.stops > 0).slice(0, 5);
  const teamOf = new Map(overviewTasks.map(t => [t.agent_id, t.team || null]));

  return (
    <div className="flex flex-col gap-6 font-sans">
      <section className="flex flex-wrap items-end justify-between gap-4 anim-rise">
        <div>
          <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-fg">Overview</h1>
          <p id="overview-sentence" className="text-[15px] text-fg-2 mt-1.5">
            {runs24.length === 0
              ? 'No runs in the last 24 hours.'
              : `${agents24} ${agents24 === 1 ? 'agent' : 'agents'} ran ${runs24.length} ${runs24.length === 1 ? 'task' : 'tasks'} in the last 24 hours. ${stopped24} ${stopped24 === 1 ? 'action was' : 'actions were'} stopped at the fence.`}{' '}
            {pending.length > 0 && (
              <strong className="text-wait-kpi">
                {pending.length} {pending.length === 1 ? 'request needs' : 'requests need'} a decision.
              </strong>
            )}
          </p>
        </div>
        <button onClick={() => navigate('/records')} className="btn-primary min-h-[40px] px-4 text-[13px]">
          Open records
        </button>
      </section>

      <section className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-3.5">
        <Kpi id="kpi-active" label="Active agents" value={String(dots.filter(d => d.state !== 'idle').length)} sub={dots.length ? `${dots.length} ${dots.length === 1 ? 'agent' : 'agents'} in all` : 'No agents yet'} />
        <Kpi id="kpi-runs" label="Runs, last 24 hours" value={String(runs24.length)} sub={medianRun == null ? 'No finished runs' : `median ${formatDuration(medianRun)}`} />
        <Kpi id="kpi-stopped" label="Actions stopped" value={String(stopped24)} sub="last 24 hours" color={stopped24 ? PALETTE.bad : PALETTE.text} />
        <Kpi id="kpi-waiting" label="Waiting for a decision" value={String(pending.length)} sub={pending.length ? 'see the list below' : 'nothing waiting'} color={pending.length ? PALETTE.waitKpi : PALETTE.text} />
        <Kpi
          id="kpi-records"
          label="Records checked"
          value={!recordsSummary || recordsSummary.total === 0 ? '—' : recordsSummary.failed === 0 ? `${Math.round((recordsSummary.verified / recordsSummary.total) * 100)}%` : `${recordsSummary.failed} failed`}
          sub={!recordsSummary || recordsSummary.total === 0 ? 'No records yet' : `${recordsSummary.verified} of ${recordsSummary.total} records checked`}
          color={recordsSummary && recordsSummary.failed > 0 ? PALETTE.bad : recordsSummary && recordsSummary.total ? PALETTE.ok : PALETTE.text}
        />
      </section>

      <section data-mode={mode} className="p-5 rounded-2xl bg-surface-1 border border-line flex flex-col gap-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex flex-wrap items-center gap-3">
            <h2 className="text-[15px] font-bold text-fg">Live agent map</h2>
            <span className="text-[12px] text-fg-3">
              {mode === 'individual' ? 'One dot per agent.' : 'Grouped by team.'} Refreshes every 5 seconds.
            </span>
          </div>
          <div className="flex flex-wrap items-center gap-4 text-[12px] text-fg-3">
            {(Object.keys(STATE) as AgentState[]).map(s => (
              <span key={s} className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full" style={{ background: STATE[s].color }} /> {STATE[s].label}
              </span>
            ))}
          </div>
        </div>
        {dots.length === 0 ? (
          <EmptyState id="map-empty" title="No agents yet." body="Agents appear here after their first run." />
        ) : mode === 'individual' ? (
          <div data-view="individual" className="rounded-[28px] border-2 border-dashed border-accent/50 bg-accent/[0.04] p-4 flex flex-wrap gap-2">
            {dots.map(d => (
              <AgentChip key={d.agentId} d={d} />
            ))}
          </div>
        ) : (
          <div data-view={mode} className="overflow-x-auto">
            <table className="w-full text-left text-[13px] border-collapse">
              <thead>
                <tr className="border-b border-line text-fg-3 text-[12px]">
                  <th className="pb-2 pr-3 font-normal">Team</th>
                  <th className="pb-2 pr-3 font-normal">Agents</th>
                  <th className="pb-2 pr-3 font-normal">Active</th>
                  <th className="pb-2 pr-3 font-normal">Waiting</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {teams.slice(0, 20).map(g => (
                  <tr key={g.team}>
                    <td className="py-2 text-fg">{g.team}</td>
                    <td className="py-2">{g.agents.toLocaleString()}</td>
                    <td className="py-2">{g.running.toLocaleString()}</td>
                    <td className="py-2" style={{ color: g.waiting ? 'var(--wait-kpi)' : 'var(--text-3)' }}>
                      {g.waiting}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {teams.length > 20 && <p className="m-0 mt-2 text-[12px] text-fg-3">and {teams.length - 20} more teams</p>}
          </div>
        )}
      </section>

      <section className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        <div className="lg:col-span-2 p-5 rounded-xl bg-surface-2 border border-line flex flex-col gap-3">
          <div className="flex items-center justify-between gap-2 flex-wrap">
            <h2 className="text-[15px] font-bold text-fg">Agent actions per hour</h2>
            <div className="flex items-center gap-3 text-[12px] text-fg-3">
              <Legend color={PALETTE.accent} label="allowed" />
              <Legend color={PALETTE.bad} label="stopped" />
              <Legend color={PALETTE.wait} label="asked" />
            </div>
          </div>
          {!anyToday ? (
            <p id="actions-empty" className="m-0 py-8 text-[14px] text-fg-3">
              No agent actions today.
            </p>
          ) : (
            <div id="actions-chart" role="img" aria-label="Agent actions per hour today, local time" className="flex flex-col gap-1">
              <div className="h-44 flex items-end gap-[3px]">
                {hours.map(h => (
                  <div
                    key={h.hour}
                    className="flex-1 h-full flex flex-col justify-end min-w-0"
                    title={`${String(h.hour).padStart(2, '0')}:00 · ${h.allowed} allowed, ${h.stopped} stopped, ${h.asked} asked`}
                    data-hour={h.hour}
                  >
                    <div data-bar="asked" style={{ height: `${(h.asked / peak) * 100}%`, background: 'var(--wait)' }} />
                    <div data-bar="stopped" style={{ height: `${(h.stopped / peak) * 100}%`, background: 'var(--bad)' }} />
                    <div data-bar="allowed" style={{ height: `${(h.allowed / peak) * 100}%`, background: 'var(--accent)' }} />
                  </div>
                ))}
              </div>
              <div className="flex text-[11px] text-fg-3">
                {[0, 6, 12, 18].map(h => (
                  <span key={h} className="flex-1">{`${String(h).padStart(2, '0')}:00`}</span>
                ))}
              </div>
            </div>
          )}
        </div>

        <div className="p-5 rounded-xl bg-surface-2 border border-line flex flex-col gap-3">
          <div className="flex items-center justify-between">
            <h2 className="text-[15px] font-bold text-fg">Waiting for a decision</h2>
            <button onClick={() => navigate('/inbox')} className="text-[13px] text-info bg-transparent border-none cursor-pointer hover:underline min-h-[36px]">
              All →
            </button>
          </div>
          {pending.length === 0 ? (
            <p id="waiting-empty" className="m-0 py-6 text-[14px] text-fg-3">
              Nothing is waiting.
            </p>
          ) : (
            <div className="flex flex-col gap-2.5">
              {pending.slice(0, 5).map(exp => (
                <button
                  type="button"
                  key={exp.request_id}
                  onClick={() => navigate(`/run/${exp.task_id}`)}
                  className="text-left p-3 rounded-lg bg-surface-3 border border-line cursor-pointer hover:border-line-strong flex flex-col gap-1"
                >
                  <span className="text-[13px] font-semibold text-fg [overflow-wrap:anywhere]">
                    {exp.agent_id} → {exp.resource_target}
                  </span>
                  <span className="text-[12px] text-fg-2">{needsYouSentence(exp)}</span>
                </button>
              ))}
            </div>
          )}
        </div>
      </section>

      <section className="grid grid-cols-1 md:grid-cols-2 gap-5">
        <div className="p-5 rounded-xl bg-surface-2 border border-line flex flex-col gap-3">
          <h2 className="text-[15px] font-bold text-fg">Top stop patterns</h2>
          <span className="text-[12px] text-fg-3 -mt-2">last 24 hours</span>
          {!fleet || fleet.blocked.groups.length === 0 ? (
            <p id="patterns-empty" className="m-0 py-4 text-[14px] text-fg-3">
              Nothing was stopped in the last 24 hours.
            </p>
          ) : (
            <table className="w-full text-left text-[13px] border-collapse">
              <thead>
                <tr className="border-b border-line text-fg-3 text-[12px]">
                  <th className="pb-2 pr-3 font-normal">Pattern</th>
                  <th className="pb-2 pr-3 font-normal">Agents</th>
                  <th className="pb-2 pr-3 font-normal">Stops</th>
                  <th className="pb-2 pr-3 font-normal">Stopped by</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {fleet.blocked.groups.map(g => (
                  <tr key={g.target_class}>
                    <td className="py-2.5 pr-3 text-fg">{g.label}</td>
                    <td className="py-2.5">{g.agent_count}</td>
                    <td className="py-2.5 pr-3 text-bad-light font-semibold">{g.count}</td>
                    <td className="py-2.5 pr-3 text-fg-2">{Object.keys(g.by_layer).map(layerLabel).join(', ') || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        <div className="p-5 rounded-xl bg-surface-2 border border-line flex flex-col gap-3">
          <h2 className="text-[15px] font-bold text-fg">Agents to watch</h2>
          <span className="text-[12px] text-fg-3 -mt-2">most stops, all runs</span>
          {watch.length === 0 ? (
            <p id="watch-empty" className="m-0 py-4 text-[14px] text-fg-3">
              No agent has been stopped.
            </p>
          ) : (
            <table className="w-full text-left text-[13px] border-collapse">
              <thead>
                <tr className="border-b border-line text-fg-3 text-[12px]">
                  <th className="pb-2 pr-3 font-normal">Agent</th>
                  <th className="pb-2 pr-3 font-normal">Team</th>
                  <th className="pb-2 pr-3 font-normal">Status</th>
                  <th className="pb-2 pr-3 font-normal">Stops</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {watch.map(r => (
                  <tr key={r.agentId}>
                    <td className="py-2.5 pr-3 font-mono text-fg">{r.agentId}</td>
                    <td className="py-2.5 pr-3 text-fg-2">{teamOf.get(r.agentId) || '—'}</td>
                    <td className="py-2.5">{r.running ? 'running' : 'idle'}</td>
                    <td className="py-2.5 pr-3 text-bad-light font-semibold">{r.stops}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </section>
    </div>
  );
};

const AgentChip: React.FC<{ d: AgentDot }> = ({ d }) => (
  <span
    data-agent={d.agentId}
    data-state={d.state}
    title={`${d.agentId} · ${STATE[d.state].label}${d.team ? ` · team ${d.team}` : ''}`}
    className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-surface-2 border border-line-strong text-[13px] font-mono text-fg"
  >
    <span className="w-2.5 h-2.5 rounded-full shrink-0" style={{ background: STATE[d.state].color }} />
    {d.agentId}
  </span>
);

const Legend: React.FC<{ color: string; label: string }> = ({ color, label }) => (
  <span className="flex items-center gap-1.5">
    <span className="w-2.5 h-2.5 rounded-sm" style={{ background: color }} /> {label}
  </span>
);

const Kpi: React.FC<{ id: string; label: string; value: string; sub: string; color?: string }> = ({ id, label, value, sub, color = 'var(--text)' }) => (
  <div id={id} className="p-4 rounded-xl bg-surface-2 border border-line flex flex-col justify-between anim-rise">
    <div className="text-[12px] font-medium text-fg-3">{label}</div>
    <div className="mt-2 text-2xl sm:text-3xl font-bold" style={{ color }} data-value>
      {value}
    </div>
    <div className="text-[12px] text-fg-3">{sub}</div>
  </div>
);
