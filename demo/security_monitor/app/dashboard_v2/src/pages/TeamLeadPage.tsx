import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import { ExpansionItem, RecordsSummary, TaskEvent, TaskRecord } from '../types';
import { useAuth } from '../context/AuthContext';
import { EmptyState, ErrorState, LoadingState } from '../components/common/States';
import { needsYouReason } from '../logic/plain';
import { HourCell, agentRows, hourlyHeat, startOfLocalDay } from '../logic/teamStats';
import { loadTodayEvents } from '../api/events';

const HOURS = Array.from({ length: 24 }, (_, i) => `${String(i).padStart(2, '0')}:00`);

const CELL: Record<HourCell, { bg: string; label: string }> = {
  none: { bg: 'rgba(139,149,167,0.10)', label: 'nothing' },
  quiet: { bg: 'rgba(34,197,94,0.45)', label: 'a run started' },
  asked: { bg: '#F59E0B', label: 'asked for something' },
  stopped: { bg: '#EF4444', label: 'stopped at the fence' },
};

export const TeamLeadPage: React.FC = () => {
  const navigate = useNavigate();
  const { user, team } = useAuth();
  const currentTeam = team || user?.team || null;

  const [tasks, setTasks] = useState<TaskRecord[] | null>(null);
  const [expansions, setExpansions] = useState<ExpansionItem[]>([]);
  const [askedToday, setAskedToday] = useState<ExpansionItem[]>([]);
  const [events, setEvents] = useState<TaskEvent[]>([]);
  const [recordsSummary, setRecordsSummary] = useState<RecordsSummary | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [now, setNow] = useState(Date.now());

  useEffect(() => {
    let mounted = true;
    const load = async () => {
      const t = Date.now();
      try {
        const [taskList, allExp, evts] = await Promise.all([
          api.getTasks(),
          api.getExpansions().catch(() => [] as ExpansionItem[]),
          loadTodayEvents(t).catch(() => [] as TaskEvent[]),
        ]);
        if (!mounted) return;
        // Team leads see their team's tasks; without a team (admin) every task is shown.
        const mine = taskList.filter(x => !currentTeam || !x.team || x.team === currentTeam);
        const ids = new Set(mine.map(x => x.task_id));
        setTasks(mine);
        setExpansions(allExp.filter(e => ids.has(e.task_id) && e.status === 'PENDING'));
        setAskedToday(allExp.filter(e => ids.has(e.task_id)));
        setEvents(evts.filter(e => ids.has(e.task_id)));
        setNow(t);
        setError(null);
      } catch (err: any) {
        if (mounted) setError(err?.message || 'Could not load the team.');
      }
    };
    load();
    api
      .getRecordsSummary()
      .then(r => mounted && setRecordsSummary(r))
      .catch(() => undefined);
    const interval = setInterval(load, 5000);
    return () => {
      mounted = false;
      clearInterval(interval);
    };
  }, [currentTeam]);

  if (error && !tasks) return <ErrorState message={error} id="team-error" />;
  if (!tasks) return <LoadingState label="Loading the team…" id="team-loading" />;

  const rows = agentRows(tasks);
  const heat = hourlyHeat(tasks, events, askedToday, now);
  const running = rows.filter(r => r.running).length;
  const waiting = expansions.length;
  const dayStart = startOfLocalDay(now);
  const stoppedToday = events.filter(e => {
    const t = Date.parse(e.timestamp);
    return (e.prevented || e.action_taken === 'BLOCK_ACTION') && t >= dayStart && t <= now;
  }).length;
  const top = rows.find(r => r.stops > 0);
  const teamLabel = currentTeam ? `${currentTeam} ` : '';

  return (
    <div className="flex flex-col gap-6 font-sans">
      <section className="anim-rise">
        <h1 id="team-headline" className="text-2xl sm:text-3xl font-bold tracking-tight text-[#E6E9EF]">
          {running} of {rows.length} {teamLabel}agents at work. {waiting === 0 ? 'Nothing needs you.' : `${waiting} need${waiting === 1 ? 's' : ''} you.`}
        </h1>
        <p className="text-[15px] text-[#A7B0C0] mt-1.5">
          {rows.length === 0
            ? 'No runs yet for this team.'
            : top
            ? `Most stops: ${top.agentId}, ${top.stops} ${top.stops === 1 ? 'time' : 'times'} in all.`
            : 'No agent has been stopped at the fence.'}
        </p>
      </section>

      <section className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
        <Kpi id="kpi-running" label="Agents running" value={rows.length ? `${running} / ${rows.length}` : '—'} sub={rows.length ? `${rows.length - running} idle` : 'No agents yet'} />
        <Kpi id="kpi-waiting" label="Waiting for you" value={String(waiting)} sub={waiting ? 'review requests below' : 'nothing waiting'} color="#FBBF24" />
        <Kpi
          id="kpi-stopped"
          label="Stopped at the fence"
          value={String(stoppedToday)}
          sub="today, from the record"
          color={stoppedToday ? '#EF4444' : '#E6E9EF'}
        />
        <Kpi
          id="kpi-records"
          label="Records checked"
          value={
            !recordsSummary || recordsSummary.total === 0
              ? '—'
              : recordsSummary.failed === 0
              ? `${Math.round((recordsSummary.verified / recordsSummary.total) * 100)}%`
              : `${recordsSummary.failed} failed`
          }
          sub={
            !recordsSummary
              ? 'Not available for this role'
              : recordsSummary.total === 0
              ? 'No records yet'
              : `${recordsSummary.verified} of ${recordsSummary.total} records checked`
          }
          color={recordsSummary && recordsSummary.failed > 0 ? '#EF4444' : recordsSummary && recordsSummary.total ? '#22C55E' : '#E6E9EF'}
        />
      </section>

      <section className="p-5 rounded-xl bg-[#11151D] border border-[#1F2633] flex flex-col gap-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <h2 className="text-[15px] font-bold text-[#E6E9EF]">When each agent hit the fence</h2>
            <span className="text-[12px] text-[#8B95A7]">Today, by hour (your local time) · one row per agent</span>
          </div>
          <div className="flex flex-wrap items-center gap-3 text-[12px] text-[#8B95A7]">
            {(['quiet', 'asked', 'stopped'] as HourCell[]).map(c => (
              <span key={c} className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-sm" style={{ background: CELL[c].bg }} /> {CELL[c].label}
              </span>
            ))}
          </div>
        </div>
        {heat.length === 0 ? (
          <p id="heat-empty" className="m-0 py-6 text-[14px] text-[#8B95A7]">
            Nothing to show yet. Rows appear once an agent has run.
          </p>
        ) : (
          <div className="overflow-x-auto mt-2">
            <div id="heatmap" className="min-w-[700px] flex flex-col gap-1.5">
              <div className="grid grid-cols-[160px_repeat(24,1fr)] gap-1 text-[10px] text-[#8B95A7]">
                <span />
                {HOURS.map((h, i) => (
                  <span key={h} className="text-center">{i % 6 === 0 ? h : ''}</span>
                ))}
              </div>
              {heat.map(row => (
                <div key={row.agentId} className="grid grid-cols-[160px_repeat(24,1fr)] gap-1 items-center" data-agent={row.agentId}>
                  <div className="font-mono text-[12px] text-[#C7D2FE] truncate pr-2" title={row.agentId}>
                    {row.agentId}
                  </div>
                  {row.cells.map((cell, h) => (
                    <div
                      key={h}
                      data-hour={h}
                      data-cell={cell}
                      title={`${row.agentId} · ${HOURS[h]} · ${CELL[cell].label}`}
                      className="h-4 rounded-sm"
                      style={{ background: CELL[cell].bg }}
                    />
                  ))}
                </div>
              ))}
            </div>
          </div>
        )}
      </section>

      <section className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        <div className="lg:col-span-2 p-5 rounded-xl bg-[#11151D] border border-[#1F2633] flex flex-col gap-3">
          <h2 className="text-[15px] font-bold text-[#E6E9EF]">Team agents</h2>
          {rows.length === 0 ? (
            <EmptyState id="team-agents-empty" title="No agents yet." body="Agents appear here after their first run." />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-[13px] border-collapse">
                <thead>
                  <tr className="border-b border-[#1F2633] text-[#8B95A7] font-medium text-[12px]">
                    <th className="pb-2.5 font-normal">Agent</th>
                    <th className="pb-2.5 font-normal">Owner</th>
                    <th className="pb-2.5 font-normal">Actions</th>
                    <th className="pb-2.5 font-normal">Stops</th>
                    <th className="pb-2.5 font-normal">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1F2633]">
                  {rows.map(agent => (
                    <tr key={agent.agentId}>
                      <td className="py-2.5 font-mono text-[#E6E9EF] font-medium">{agent.agentId}</td>
                      <td className="py-2.5 text-[#A7B0C0]">{agent.owner ?? '—'}</td>
                      <td className="py-2.5 text-[#E6E9EF]">{agent.actions.toLocaleString()}</td>
                      <td className="py-2.5 font-semibold" style={{ color: agent.stops > 0 ? '#F87171' : '#8B95A7' }}>
                        {agent.stops}
                      </td>
                      <td className="py-2.5">
                        <span
                          className="inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-semibold"
                          style={
                            agent.running
                              ? { backgroundColor: 'rgba(34,197,94,0.15)', color: '#4ADE80' }
                              : { backgroundColor: 'rgba(139,149,167,0.15)', color: '#A7B0C0' }
                          }
                        >
                          {agent.running ? 'running' : 'idle'}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        <div className="p-5 rounded-xl bg-[#11151D] border border-[#3A2E12] flex flex-col gap-3">
          <div className="text-[12px] font-bold text-[#FBBF24] tracking-wider uppercase">Needs you · {waiting}</div>
          {waiting === 0 ? (
            <p id="needs-you-empty" className="m-0 text-[14px] text-[#A7B0C0]">
              Nothing is waiting for you.
            </p>
          ) : (
            <div className="flex flex-col gap-3">
              {expansions.map(req => (
                <div key={req.request_id} className="p-3.5 rounded-xl bg-[#0B0E14] border border-[#1F2633] flex flex-col gap-2">
                  <div className="text-[13px] text-[#E6E9EF] [overflow-wrap:anywhere]">
                    <span className="font-mono text-[#C7D2FE]">{req.agent_id}</span> wants <b>{req.resource_target}</b>
                  </div>
                  <div className="text-[12px]" style={{ color: req.escalated_by_provenance ? '#FCA5A5' : '#A7B0C0' }}>
                    It {needsYouReason(req)}.
                  </div>
                  <div className="mt-1">
                    <button
                      onClick={() => navigate(`/run/${req.task_id}`)}
                      className="btn-primary min-h-[36px] px-3 text-[12px]"
                    >
                      Review
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
          <p className="text-[12px] text-[#8B95A7] mt-auto">Requests from other teams go to their own leads, or to Security.</p>
        </div>
      </section>
    </div>
  );
};

const Kpi: React.FC<{ id: string; label: string; value: string; sub: string; color?: string }> = ({ id, label, value, sub, color = '#E6E9EF' }) => (
  <div id={id} className="p-4 rounded-xl bg-[#11151D] border border-[#1F2633] flex flex-col justify-between anim-rise">
    <div className="text-[12px] font-medium text-[#8B95A7]">{label}</div>
    <div className="mt-2 text-3xl font-bold tracking-tight" style={{ color }} data-value>
      {value}
    </div>
    <div className="mt-1 text-[12px] text-[#8B95A7]">{sub}</div>
  </div>
);
