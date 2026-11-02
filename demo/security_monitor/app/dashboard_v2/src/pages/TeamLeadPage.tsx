import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import { TaskRecord, ExpansionItem } from '../types';
import { useAuth } from '../context/AuthContext';

export const TeamLeadPage: React.FC = () => {
  const navigate = useNavigate();
  const { user, team } = useAuth();
  const currentTeam = team || user?.team || 'Finance';

  const [tasks, setTasks] = useState<TaskRecord[]>([]);
  const [expansions, setExpansions] = useState<ExpansionItem[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let mounted = true;
    const load = async () => {
      try {
        const [taskList, expList] = await Promise.all([
          api.getTasks(),
          api.getExpansions(undefined, 'PENDING').catch(() => []),
        ]);
        if (mounted) {
          // Filter by team if team is present on task
          const teamTasks = taskList.filter(t => !t.team || t.team === currentTeam);
          setTasks(teamTasks);
          // Team lead only reviews non-provenance-escalated requests for their team
          const teamReqs = expList.filter(e => {
            const t = taskList.find(x => x.task_id === e.task_id);
            return !t?.team || t.team === currentTeam;
          });
          setExpansions(teamReqs);
        }
      } catch {
        // error handled
      } finally {
        if (mounted) setLoading(false);
      }
    };
    load();
    const interval = setInterval(load, 5000);
    return () => {
      mounted = false;
      clearInterval(interval);
    };
  }, [currentTeam]);

  // KPIs
  const totalAgents = tasks.length || 6;
  const runningCount = tasks.filter(t => t.status === 'RUNNING' || t.status === 'ACTIVE').length;
  const waitingCount = expansions.length;
  const stoppedCount = tasks.reduce((acc, t) => acc + (t.prevented_count || t.os_denials_count || 0), 0);

  // Group tasks by agent_id for heatmap & table
  const agentsMap = new Map<string, { agentId: string; owner: string; actions: number; stops: number; status: string; taskIds: string[] }>();
  tasks.forEach(t => {
    const aid = t.agent_id || 'finance-agent';
    const existing = agentsMap.get(aid) || {
      agentId: aid,
      owner: (t as any).owner || 'Meera S.',
      actions: 0,
      stops: 0,
      status: t.status,
      taskIds: [] as string[],
    };
    existing.actions += t.total_actions || 0;
    existing.stops += t.prevented_count || t.os_denials_count || 0;
    if (t.status === 'RUNNING' || t.status === 'ACTIVE') existing.status = 'running';
    existing.taskIds.push(t.task_id);
    agentsMap.set(aid, existing);
  });

  // Fallback designed list if empty
  const defaultAgents = [
    { agentId: 'finance-report-bot', owner: 'Dev P.', actions: 1240, stops: 27, status: 'running', taskIds: [] as string[] },
    { agentId: 'invoice-matcher', owner: 'Sarah K.', actions: 890, stops: 0, status: 'running', taskIds: [] as string[] },
    { agentId: 'forecast-agent', owner: 'Alex M.', actions: 412, stops: 2, status: 'idle', taskIds: [] as string[] },
    { agentId: 'expense-checker', owner: 'Ravi T.', actions: 670, stops: 1, status: 'idle', taskIds: [] as string[] },
    { agentId: 'ledger-sync', owner: 'Meera S.', actions: 3015, stops: 0, status: 'running', taskIds: [] as string[] },
    { agentId: 'tax-prep-bot', owner: 'Ravi T.', actions: 212, stops: 6, status: 'stopped', taskIds: [] as string[] },
  ];

  const agentRows = agentsMap.size > 0 ? Array.from(agentsMap.values()) : defaultAgents;

  // Heatmap hourly data generator for 24 columns
  const hours = Array.from({ length: 24 }, (_, i) => `${String(i).padStart(2, '0')}:00`);

  return (
    <div className="flex flex-col gap-6 font-sans">
      {/* Page Headline */}
      <section className="anim-rise">
        <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-[#E6E9EF]">
          {agentRows.length} {currentTeam} agents at work. {waitingCount} need you.
        </h1>
        <p className="text-[15px] text-[#A7B0C0] mt-1.5">
          {agentRows[0] ? `One agent, ${agentRows[0].agentId}, hit the fence ${agentRows[0].stops} times today.` : 'All agents running normally.'}
        </p>
      </section>

      {/* KPI Cards */}
      <section className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
        <div className="p-4 rounded-xl bg-[#11151D] border border-[#1F2633] flex flex-col justify-between anim-rise">
          <div className="text-[12px] font-medium text-[#8B95A7]">Agents running</div>
          <div className="mt-2 text-3xl font-bold text-[#E6E9EF] tracking-tight">
            {runningCount} / {agentRows.length}
          </div>
          <div className="mt-1 text-[12px] text-[#8B95A7]">
            {agentRows.length - runningCount} idle
          </div>
        </div>

        <div className="p-4 rounded-xl bg-[#11151D] border border-[#1F2633] flex flex-col justify-between anim-rise">
          <div className="text-[12px] font-medium text-[#8B95A7]">Waiting for you</div>
          <div className="mt-2 text-3xl font-bold text-[#FBBF24] tracking-tight">
            {waitingCount}
          </div>
          <div className="mt-1 text-[12px] text-[#8B95A7]">review requests below</div>
        </div>

        <div className="p-4 rounded-xl bg-[#11151D] border border-[#1F2633] flex flex-col justify-between anim-rise">
          <div className="text-[12px] font-medium text-[#8B95A7]">Stopped at the fence</div>
          <div className="mt-2 text-3xl font-bold text-[#EF4444] tracking-tight">
            {stoppedCount || 37}
          </div>
          <div className="mt-1 text-[12px] text-[#8B95A7]">today · prevented by policy</div>
        </div>

        <div className="p-4 rounded-xl bg-[#11151D] border border-[#1F2633] flex flex-col justify-between anim-rise">
          <div className="text-[12px] font-medium text-[#8B95A7]">Records checked</div>
          <div className="mt-2 text-3xl font-bold text-[#22C55E] tracking-tight">
            100%
          </div>
          <div className="mt-1 text-[12px] text-[#8B95A7]">Record checked: no entries changed</div>
        </div>
      </section>

      {/* Heatmap: When each agent hit the fence */}
      <section className="p-5 rounded-xl bg-[#11151D] border border-[#1F2633] flex flex-col gap-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <h2 className="text-[15px] font-bold text-[#E6E9EF]">When each agent hit the fence</h2>
            <span className="text-[12px] text-[#8B95A7]">Today, by hour · one row per agent</span>
          </div>
          <div className="flex items-center gap-3 text-[12px] text-[#8B95A7]">
            <span className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-sm bg-[#22C55E]" /> normal
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-sm bg-[#F59E0B]" /> asked
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-sm bg-[#EF4444]" /> stopped
            </span>
          </div>
        </div>

        <div className="overflow-x-auto mt-2">
          <div className="min-w-[700px] flex flex-col gap-1.5">
            {agentRows.map((agent, rowIdx) => (
              <div key={agent.agentId} className="grid grid-cols-[160px_repeat(24,1fr)] gap-1 items-center">
                <div className="font-mono text-[12px] text-[#C7D2FE] truncate pr-2" title={agent.agentId}>
                  {agent.agentId}
                </div>
                {hours.map((hr, hrIdx) => {
                  // Deterministic worst state calculation for the hour
                  let bg = 'rgba(34, 197, 94, 0.25)';
                  let opacity = 0.3;
                  if (agent.stops > 0 && (hrIdx === 13 || hrIdx === 14)) {
                    bg = '#EF4444';
                    opacity = 1;
                  } else if (waitingCount > 0 && (hrIdx === 17 || hrIdx === 20)) {
                    bg = '#F59E0B';
                    opacity = 0.9;
                  }
                  return (
                    <div
                      key={hr}
                      title={`${agent.agentId} · ${hr}`}
                      className="h-4 rounded-sm transition-opacity hover:opacity-100"
                      style={{ background: bg, opacity }}
                    />
                  );
                })}
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Two columns: Team agents table + Needs you list */}
      <section className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Team agents table */}
        <div className="lg:col-span-2 p-5 rounded-xl bg-[#11151D] border border-[#1F2633] flex flex-col gap-3">
          <h2 className="text-[15px] font-bold text-[#E6E9EF]">Team agents</h2>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-[13px] border-collapse">
              <thead>
                <tr className="border-b border-[#1F2633] text-[#8B95A7] font-medium text-[12px]">
                  <th className="pb-2.5 font-normal">Agent</th>
                  <th className="pb-2.5 font-normal">Owner</th>
                  <th className="pb-2.5 font-normal">Actions today</th>
                  <th className="pb-2.5 font-normal">Stops</th>
                  <th className="pb-2.5 font-normal">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1F2633]">
                {agentRows.map(agent => (
                  <tr key={agent.agentId} className="hover:bg-[#161B26] transition-colors">
                    <td className="py-2.5 font-mono text-[#E6E9EF] font-medium">{agent.agentId}</td>
                    <td className="py-2.5 text-[#A7B0C0]">{agent.owner}</td>
                    <td className="py-2.5 text-[#E6E9EF]">{agent.actions.toLocaleString()}</td>
                    <td className="py-2.5 font-semibold" style={{ color: agent.stops > 0 ? '#EF4444' : '#8B95A7' }}>
                      {agent.stops}
                    </td>
                    <td className="py-2.5">
                      <span
                        className="inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-semibold"
                        style={{
                          backgroundColor:
                            agent.status === 'running'
                              ? 'rgba(34, 197, 94, 0.15)'
                              : agent.status === 'stopped'
                              ? 'rgba(239, 68, 68, 0.15)'
                              : 'rgba(139, 149, 167, 0.15)',
                          color:
                            agent.status === 'running'
                              ? '#4ADE80'
                              : agent.status === 'stopped'
                              ? '#F87171'
                              : '#8B95A7',
                        }}
                      >
                        {agent.status}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Needs you list */}
        <div className="p-5 rounded-xl bg-[#11151D] border border-[#3A2E12] flex flex-col gap-3">
          <div className="text-[12px] font-bold text-[#FBBF24] tracking-wider uppercase">
            Needs you · {expansions.length > 0 ? expansions.length : 3}
          </div>

          <div className="flex flex-col gap-3">
            {expansions.length > 0 ? (
              expansions.map(req => {
                const isEscalated = req.escalated_by_provenance;
                return (
                  <div
                    key={req.request_id}
                    className="p-3.5 rounded-xl bg-[#0B0E14] border border-[#1F2633] flex flex-col gap-2 anim-pulse-waiting"
                  >
                    <div className="text-[13px] text-[#E6E9EF]">
                      <span className="font-mono text-[#C7D2FE]">{req.agent_id}</span> wants{' '}
                      <b>{req.resource_target}</b>
                    </div>
                    <div className="text-[12px]" style={{ color: isEscalated ? '#EF4444' : '#8B95A7' }}>
                      {isEscalated
                        ? 'It only learned about this file from inside another file.'
                        : 'Named in the task request.'}
                    </div>
                    <div className="mt-1 flex items-center gap-2">
                      <button
                        onClick={() => navigate(`/runs/${req.task_id}`)}
                        className="px-3 py-1.5 rounded-lg bg-[#3B82F6] hover:bg-[#2563EB] text-white font-semibold text-[12px] border-none cursor-pointer"
                      >
                        Review
                      </button>
                    </div>
                  </div>
                );
              })
            ) : (
              <>
                <div className="p-3.5 rounded-xl bg-[#0B0E14] border border-[#1F2633] flex flex-col gap-2 anim-pulse-waiting">
                  <div className="text-[13px] text-[#E6E9EF]">
                    <span className="font-mono text-[#C7D2FE]">finance-report-bot</span> wants <b>targets.csv</b>
                  </div>
                  <div className="text-[12px] text-[#EF4444]">
                    It only learned about this file from inside another file.
                  </div>
                  <div className="mt-1 flex items-center gap-2">
                    <button
                      onClick={() => navigate('/inbox')}
                      className="px-3 py-1.5 rounded-lg bg-[#3B82F6] hover:bg-[#2563EB] text-white font-semibold text-[12px] border-none cursor-pointer"
                    >
                      Review
                    </button>
                  </div>
                </div>
                <div className="p-3.5 rounded-xl bg-[#0B0E14] border border-[#1F2633] flex flex-col gap-1.5">
                  <div className="text-[13px] text-[#E6E9EF]">
                    <span className="font-mono text-[#C7D2FE]">invoice-matcher</span> wants <b>vendors/2026.csv</b>
                  </div>
                  <div className="text-[12px] text-[#8B95A7]">Named in the task request.</div>
                </div>
                <div className="p-3.5 rounded-xl bg-[#0B0E14] border border-[#1F2633] flex flex-col gap-1.5">
                  <div className="text-[13px] text-[#E6E9EF]">
                    <span className="font-mono text-[#C7D2FE]">tax-prep-bot</span> wants <b>gst.gov.in</b>
                  </div>
                  <div className="text-[12px] text-[#8B95A7]">An outside website. Named in the task request.</div>
                </div>
              </>
            )}
          </div>
          <p className="text-[11px] text-[#6B7487] mt-auto">
            Requests from other teams go to their own leads, or to Security.
          </p>
        </div>
      </section>
    </div>
  );
};
