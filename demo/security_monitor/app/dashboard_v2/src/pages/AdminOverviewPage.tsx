import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import { loadRecentEvents } from '../api/events';
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

const STATE: Record<AgentState, { color: string; label: string }> = {
  asking: { color: '#F59E0B', label: 'asking you' },
  stopped: { color: '#EF4444', label: 'stopped in the last hour' },
  running: { color: '#3B82F6', label: 'running' },
  idle: { color: '#64748B', label: 'idle' },
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
        // Tasks and decisions first, so the page draws at once; events and patterns follow.
        const [taskList, exps] = await Promise.all([api.getTasks(), api.getExpansions().catch(() => [] as ExpansionItem[])]);
        if (!mounted) return;
        setTasks(taskList);
        setAllExps(exps);
        setPending(exps.filter(e => e.status === 'PENDING'));
        setNow(t);
        setError(null);
      } catch (err: any) {
        if (mounted) setError(err?.message || 'Could not load the overview.');
        return;
      }
      if (slowBusy) return;
      slowBusy = true;
      Promise.all([
        loadRecentEvents(t).catch(() => null),
        api.getFleetSummary().catch(() => null),
        api.getRecordsSummary().catch(() => null),
      ]).then(([evts, fl, rec]) => {
        slowBusy = false;
        if (!mounted) return;
        if (evts) setEvents(evts);
        setFleet(fl);
        setRecordsSummary(rec);
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

  const runs24 = runsInLast24h(tasks, now);
  const agents24 = new Set(runs24.map(t => t.agent_id)).size;
  const runningTasks = tasks.filter(t => t.status === 'ACTIVE' || t.status === 'RUNNING').length;
  const stopped24 = stoppedInLast24h(events, now);
  const medianRun = medianRunSeconds(tasks, now);
  const dots = agentDots(tasks, pending, events, now);
  const teams = teamGroups(dots);
  const hours = actionsPerHour(events, allExps, now);
  const peak = Math.max(1, ...hours.map(h => h.allowed + h.stopped + h.asked));
  const anyToday = hours.some(h => h.allowed + h.stopped + h.asked > 0);
  const mode = mapMode(runningTasks);
  const watch = agentRows(tasks).filter(r => r.stops > 0).slice(0, 5);
  const teamOf = new Map(tasks.map(t => [t.agent_id, t.team || null]));

  return (
    <div className="flex flex-col gap-6 font-sans">
      <section className="flex flex-wrap items-end justify-between gap-4 anim-rise">
        <div>
          <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-[#E6E9EF]">Overview</h1>
          <p id="overview-sentence" className="text-[15px] text-[#A7B0C0] mt-1.5">
            {runs24.length === 0
              ? 'No runs in the last 24 hours.'
              : `${agents24} ${agents24 === 1 ? 'agent' : 'agents'} ran ${runs24.length} ${runs24.length === 1 ? 'task' : 'tasks'} in the last 24 hours. ${stopped24} ${stopped24 === 1 ? 'action was' : 'actions were'} stopped at the fence.`}{' '}
            {pending.length > 0 && (
              <strong className="text-[#FBBF24]">
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
        <Kpi id="kpi-active" label="Active agents" value={String(dots.filter(d => d.state !== 'idle').length)} sub={dots.length ? `${dots.length} agents in all` : 'No agents yet'} />
        <Kpi id="kpi-runs" label="Runs, last 24 hours" value={String(runs24.length)} sub={medianRun == null ? 'No finished runs' : `median ${formatDuration(medianRun)}`} />
        <Kpi id="kpi-stopped" label="Actions stopped" value={String(stopped24)} sub="last 24 hours" color={stopped24 ? '#EF4444' : '#E6E9EF'} />
        <Kpi id="kpi-waiting" label="Waiting for a decision" value={String(pending.length)} sub={pending.length ? 'see the list below' : 'nothing waiting'} color={pending.length ? '#FBBF24' : '#E6E9EF'} />
        <Kpi
          id="kpi-records"
          label="Records checked"
          value={!recordsSummary || recordsSummary.total === 0 ? '—' : recordsSummary.failed === 0 ? `${Math.round((recordsSummary.verified / recordsSummary.total) * 100)}%` : `${recordsSummary.failed} failed`}
          sub={!recordsSummary || recordsSummary.total === 0 ? 'No records yet' : `${recordsSummary.verified} of ${recordsSummary.total} records checked`}
          color={recordsSummary && recordsSummary.failed > 0 ? '#EF4444' : recordsSummary && recordsSummary.total ? '#22C55E' : '#E6E9EF'}
        />
      </section>

      <section data-mode={mode} className="p-5 rounded-2xl bg-[#0E121A] border border-[#1F2633] flex flex-col gap-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex flex-wrap items-center gap-3">
            <h2 className="text-[15px] font-bold text-[#E6E9EF]">Live agent map</h2>
            <span className="text-[12px] text-[#8B95A7]">
              {mode === 'individual' ? 'One dot per agent.' : 'Grouped by team.'} Refreshes every 5 seconds.
            </span>
          </div>
          <div className="flex flex-wrap items-center gap-4 text-[12px] text-[#8B95A7]">
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
          <div data-view="individual" className="rounded-[28px] border-2 border-dashed border-[#3B82F6]/50 bg-[rgba(59,130,246,0.04)] p-4 flex flex-wrap gap-2">
            {dots.map(d => (
              <AgentChip key={d.agentId} d={d} />
            ))}
          </div>
        ) : (
          <div data-view={mode} className="overflow-x-auto">
            <table className="w-full text-left text-[13px] border-collapse">
              <thead>
                <tr className="border-b border-[#1F2633] text-[#8B95A7] text-[12px]">
                  <th className="pb-2 pr-3 font-normal">Team</th>
                  <th className="pb-2 pr-3 font-normal">Agents</th>
                  <th className="pb-2 pr-3 font-normal">Active</th>
                  <th className="pb-2 pr-3 font-normal">Waiting</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1F2633]">
                {teams.slice(0, 20).map(g => (
                  <tr key={g.team}>
                    <td className="py-2 text-[#E6E9EF]">{g.team}</td>
                    <td className="py-2">{g.agents.toLocaleString()}</td>
                    <td className="py-2">{g.running.toLocaleString()}</td>
                    <td className="py-2" style={{ color: g.waiting ? '#FBBF24' : '#8B95A7' }}>
                      {g.waiting}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {teams.length > 20 && <p className="m-0 mt-2 text-[12px] text-[#8B95A7]">and {teams.length - 20} more teams</p>}
          </div>
        )}
      </section>

      <section className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        <div className="lg:col-span-2 p-5 rounded-xl bg-[#11151D] border border-[#1F2633] flex flex-col gap-3">
          <div className="flex items-center justify-between gap-2 flex-wrap">
            <h2 className="text-[15px] font-bold text-[#E6E9EF]">Agent actions per hour</h2>
            <div className="flex items-center gap-3 text-[12px] text-[#8B95A7]">
              <Legend color="#3B82F6" label="allowed" />
              <Legend color="#EF4444" label="stopped" />
              <Legend color="#F59E0B" label="asked" />
            </div>
          </div>
          {!anyToday ? (
            <p id="actions-empty" className="m-0 py-8 text-[14px] text-[#8B95A7]">
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
                    <div data-bar="asked" style={{ height: `${(h.asked / peak) * 100}%`, background: '#F59E0B' }} />
                    <div data-bar="stopped" style={{ height: `${(h.stopped / peak) * 100}%`, background: '#EF4444' }} />
                    <div data-bar="allowed" style={{ height: `${(h.allowed / peak) * 100}%`, background: '#3B82F6' }} />
                  </div>
                ))}
              </div>
              <div className="flex text-[11px] text-[#8B95A7]">
                {[0, 6, 12, 18].map(h => (
                  <span key={h} className="flex-1">{`${String(h).padStart(2, '0')}:00`}</span>
                ))}
              </div>
            </div>
          )}
        </div>

        <div className="p-5 rounded-xl bg-[#11151D] border border-[#1F2633] flex flex-col gap-3">
          <div className="flex items-center justify-between">
            <h2 className="text-[15px] font-bold text-[#E6E9EF]">Waiting for a decision</h2>
            <button onClick={() => navigate('/inbox')} className="text-[13px] text-[#60A5FA] bg-transparent border-none cursor-pointer hover:underline min-h-[36px]">
              All →
            </button>
          </div>
          {pending.length === 0 ? (
            <p id="waiting-empty" className="m-0 py-6 text-[14px] text-[#8B95A7]">
              Nothing is waiting.
            </p>
          ) : (
            <div className="flex flex-col gap-2.5">
              {pending.slice(0, 5).map(exp => (
                <button
                  type="button"
                  key={exp.request_id}
                  onClick={() => navigate(`/run/${exp.task_id}`)}
                  className="text-left p-3 rounded-lg bg-[#161B26] border border-[#1F2633] cursor-pointer hover:border-[#2A3344] flex flex-col gap-1"
                >
                  <span className="text-[13px] font-semibold text-[#E6E9EF] [overflow-wrap:anywhere]">
                    {exp.agent_id} → {exp.resource_target}
                  </span>
                  <span className="text-[12px] text-[#A7B0C0]">{needsYouSentence(exp)}</span>
                </button>
              ))}
            </div>
          )}
        </div>
      </section>

      <section className="grid grid-cols-1 md:grid-cols-2 gap-5">
        <div className="p-5 rounded-xl bg-[#11151D] border border-[#1F2633] flex flex-col gap-3">
          <h2 className="text-[15px] font-bold text-[#E6E9EF]">Top stop patterns</h2>
          <span className="text-[12px] text-[#8B95A7] -mt-2">last 24 hours</span>
          {!fleet || fleet.blocked.groups.length === 0 ? (
            <p id="patterns-empty" className="m-0 py-4 text-[14px] text-[#8B95A7]">
              Nothing was stopped in the last 24 hours.
            </p>
          ) : (
            <table className="w-full text-left text-[13px] border-collapse">
              <thead>
                <tr className="border-b border-[#1F2633] text-[#8B95A7] text-[12px]">
                  <th className="pb-2 pr-3 font-normal">Pattern</th>
                  <th className="pb-2 pr-3 font-normal">Agents</th>
                  <th className="pb-2 pr-3 font-normal">Stops</th>
                  <th className="pb-2 pr-3 font-normal">Stopped by</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1F2633]">
                {fleet.blocked.groups.map(g => (
                  <tr key={g.target_class}>
                    <td className="py-2.5 pr-3 text-[#E6E9EF]">{g.label}</td>
                    <td className="py-2.5">{g.agent_count}</td>
                    <td className="py-2.5 pr-3 text-[#F87171] font-semibold">{g.count}</td>
                    <td className="py-2.5 pr-3 text-[#A7B0C0]">{Object.keys(g.by_layer).map(layerLabel).join(', ') || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        <div className="p-5 rounded-xl bg-[#11151D] border border-[#1F2633] flex flex-col gap-3">
          <h2 className="text-[15px] font-bold text-[#E6E9EF]">Agents to watch</h2>
          <span className="text-[12px] text-[#8B95A7] -mt-2">most stops, all runs</span>
          {watch.length === 0 ? (
            <p id="watch-empty" className="m-0 py-4 text-[14px] text-[#8B95A7]">
              No agent has been stopped.
            </p>
          ) : (
            <table className="w-full text-left text-[13px] border-collapse">
              <thead>
                <tr className="border-b border-[#1F2633] text-[#8B95A7] text-[12px]">
                  <th className="pb-2 pr-3 font-normal">Agent</th>
                  <th className="pb-2 pr-3 font-normal">Team</th>
                  <th className="pb-2 pr-3 font-normal">Status</th>
                  <th className="pb-2 pr-3 font-normal">Stops</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1F2633]">
                {watch.map(r => (
                  <tr key={r.agentId}>
                    <td className="py-2.5 pr-3 font-mono text-[#E6E9EF]">{r.agentId}</td>
                    <td className="py-2.5 pr-3 text-[#A7B0C0]">{teamOf.get(r.agentId) || '—'}</td>
                    <td className="py-2.5">{r.running ? 'running' : 'idle'}</td>
                    <td className="py-2.5 pr-3 text-[#F87171] font-semibold">{r.stops}</td>
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
    className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-[#11151D] border border-[#2A3344] text-[13px] font-mono text-[#E6E9EF]"
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

const Kpi: React.FC<{ id: string; label: string; value: string; sub: string; color?: string }> = ({ id, label, value, sub, color = '#E6E9EF' }) => (
  <div id={id} className="p-4 rounded-xl bg-[#11151D] border border-[#1F2633] flex flex-col justify-between anim-rise">
    <div className="text-[12px] font-medium text-[#8B95A7]">{label}</div>
    <div className="mt-2 text-2xl sm:text-3xl font-bold" style={{ color }} data-value>
      {value}
    </div>
    <div className="text-[12px] text-[#8B95A7]">{sub}</div>
  </div>
);
