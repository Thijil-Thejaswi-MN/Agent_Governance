import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import { ExpansionItem, RecordsSummary, TaskEvent, TaskRecord } from '../types';
import { useAuth } from '../context/AuthContext';
import { EmptyState, ErrorState, LoadingState } from '../components/common/States';
import { needsYouSentence } from '../logic/plain';
import { HourCell, agentRows, hourlyHeat, startOfLocalDay } from '../logic/teamStats';
import { loadTodayEvents } from '../api/events';
import { PageHeader } from '../components/ui/PageHeader';
import { MetricCard } from '../components/ui/MetricCard';
import { StatusPill } from '../components/ui/StatusPill';
import { Button } from '../components/ui/Button';

const HOURS = Array.from({ length: 24 }, (_, i) => `${String(i).padStart(2, '0')}:00`);

const CELL: Record<HourCell, { bgClass: string; label: string }> = {
  none: { bgClass: 'bg-surface-2', label: 'nothing' },
  quiet: { bgClass: 'bg-accent/40', label: 'a run started' },
  asked: { bgClass: 'bg-wait', label: 'asked for something' },
  stopped: { bgClass: 'bg-bad', label: 'stopped at the fence' },
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

  const recordsAllChecked = Boolean(
    recordsSummary &&
    recordsSummary.total > 0 &&
    recordsSummary.verified === recordsSummary.total &&
    recordsSummary.failed === 0
  );

  return (
    <div className="flex flex-col gap-6 font-sans">
      <PageHeader
        titleId="team-headline"
        title={`${running} of ${rows.length} ${teamLabel}agents at work. ${waiting === 0 ? 'Nothing needs you.' : `${waiting} need${waiting === 1 ? 's' : ''} you.`}`}
        subtitle={
          rows.length === 0
            ? 'No runs yet for this team.'
            : top
            ? `Most stops: ${top.agentId}, ${top.stops} ${top.stops === 1 ? 'time' : 'times'} in all.`
            : 'No agent has been stopped at the fence.'
        }
      />

      <section className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
        <MetricCard
          id="kpi-running"
          label="Agents running"
          value={rows.length ? `${running} / ${rows.length}` : '—'}
          note={rows.length ? `${rows.length - running} idle` : 'No agents yet'}
          tone="default"
        />
        <MetricCard
          id="kpi-waiting"
          label="Waiting for you"
          value={String(waiting)}
          note={waiting ? 'review requests below' : 'nothing waiting'}
          tone={waiting > 0 ? 'wait' : 'default'}
        />
        <MetricCard
          id="kpi-stopped"
          label="Stopped at the fence"
          value={String(stoppedToday)}
          note="today, from the record"
          tone={stoppedToday > 0 ? 'bad' : 'default'}
        />
        <MetricCard
          id="kpi-records"
          label="Records checked"
          value={
            !recordsSummary || recordsSummary.total === 0
              ? '—'
              : recordsSummary.failed === 0
                ? `${Math.round((recordsSummary.verified / recordsSummary.total) * 100)}%`
                : `${recordsSummary.failed} failed`
          }
          note={
            !recordsSummary
              ? 'Not available for this role'
              : recordsSummary.total === 0
                ? 'No records yet'
                : `${recordsSummary.verified} of ${recordsSummary.total} records checked`
          }
          tone={recordsSummary && recordsSummary.failed > 0 ? 'bad' : recordsAllChecked ? 'ok' : 'default'}
        />
      </section>

      <section className="p-5 rounded-xl bg-surface-1 border border-line flex flex-col gap-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <h2 className="text-[15px] font-bold text-fg">When each agent hit the fence</h2>
            <span className="text-[12px] text-fg-3">Today, by hour (your local time) · one row per agent</span>
          </div>
          <div className="flex flex-wrap items-center gap-3 text-[12px] text-fg-3">
            {(['quiet', 'asked', 'stopped'] as HourCell[]).map(c => (
              <span key={c} className="flex items-center gap-1.5">
                <span className={`w-2.5 h-2.5 rounded-sm ${CELL[c].bgClass}`} /> {CELL[c].label}
              </span>
            ))}
          </div>
        </div>
        {heat.length === 0 ? (
          <p id="heat-empty" className="m-0 py-6 text-[14px] text-fg-3">
            Nothing to show yet. Rows appear once an agent has run.
          </p>
        ) : (
          <div className="overflow-x-auto mt-2">
            <div id="heatmap" className="min-w-[700px] flex flex-col gap-1.5">
              <div className="grid grid-cols-[160px_repeat(24,1fr)] gap-1 text-[10px] text-fg-3">
                <span />
                {HOURS.map((h, i) => (
                  <span key={h} className="text-center">{i % 6 === 0 ? h : ''}</span>
                ))}
              </div>
              {heat.map(row => (
                <div key={row.agentId} className="grid grid-cols-[160px_repeat(24,1fr)] gap-1 items-center" data-agent={row.agentId}>
                  <div className="font-mono text-[12px] truncate pr-2 text-accent-strong" title={row.agentId}>
                    {row.agentId}
                  </div>
                  {row.cells.map((cell, h) => (
                    <div
                      key={h}
                      data-hour={h}
                      data-cell={cell}
                      title={`${row.agentId} · ${HOURS[h]} · ${CELL[cell].label}`}
                      className={`h-4 rounded-sm ${CELL[cell].bgClass}`}
                    />
                  ))}
                </div>
              ))}
            </div>
          </div>
        )}
      </section>

      <section className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        <div className="lg:col-span-2 p-5 rounded-xl bg-surface-1 border border-line flex flex-col gap-3">
          <h2 className="text-[15px] font-bold text-fg">Team agents</h2>
          {rows.length === 0 ? (
            <EmptyState id="team-agents-empty" title="No agents yet." body="Agents appear here after their initial run." />
          ) : (
            <div className="rounded-xl border border-line bg-surface-1 overflow-hidden">
              <table className="w-full text-left text-[13px] border-collapse">
                <thead>
                  <tr className="bg-surface-2 text-[12px] uppercase tracking-wider text-fg-3 font-semibold border-b border-line">
                    <th className="px-4 py-2.5 font-medium">Agent</th>
                    <th className="px-4 py-2.5 font-medium">Owner</th>
                    <th className="px-4 py-2.5 font-medium">Actions</th>
                    <th className="px-4 py-2.5 font-medium">Stops</th>
                    <th className="px-4 py-2.5 font-medium">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-line">
                  {rows.map(agent => (
                    <tr key={agent.agentId} className="h-11 min-h-[44px] hover:bg-surface-2/50 transition-colors">
                      <td className="px-4 py-2.5 font-mono text-fg font-medium">{agent.agentId}</td>
                      <td className="px-4 py-2.5 text-fg-2">{agent.owner ?? '—'}</td>
                      <td className="px-4 py-2.5 text-fg">{agent.actions.toLocaleString()}</td>
                      <td className={`px-4 py-2.5 font-semibold ${agent.stops > 0 ? 'text-bad' : 'text-fg-3'}`}>
                        {agent.stops}
                      </td>
                      <td className="px-4 py-2.5">
                        <StatusPill tone={agent.running ? 'ok' : 'neutral'} label={agent.running ? 'running' : 'idle'} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        <div className="p-5 rounded-xl bg-surface-1 border border-line flex flex-col gap-3">
          <div className="text-[12px] font-bold text-wait-kpi tracking-wider uppercase">Needs you · {waiting}</div>
          {waiting === 0 ? (
            <p id="needs-you-empty" className="m-0 text-[14px] text-fg-2">
              Nothing is waiting for you.
            </p>
          ) : (
            <div className="rounded-xl border border-line bg-surface-1 overflow-hidden divide-y divide-line">
              {expansions.map(req => (
                <div
                  key={req.request_id}
                  className="min-h-[44px] px-4 py-2.5 flex items-center justify-between gap-3 hover:bg-surface-2/50 transition-colors text-[14px]"
                >
                  <div className="flex-1 min-w-0">
                    <div className="text-[13px] text-fg [overflow-wrap:anywhere]">
                      <span className="font-mono text-accent-strong">{req.agent_id}</span> wants <b>{req.resource_target}</b>
                    </div>
                    <div className="text-[12px] text-fg-2">
                      {needsYouSentence(req)}
                    </div>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <StatusPill tone="wait" label="Waiting" />
                    <Button
                      variant="secondary"
                      size="sm"
                      onClick={() => navigate(`/run/${req.task_id}`)}
                      className="min-h-[36px] px-3 text-[12px]"
                    >
                      Review
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          )}
          <p className="text-[12px] text-fg-3 mt-auto">Requests from other teams go to their own leads, or to Security.</p>
        </div>
      </section>
    </div>
  );
};
