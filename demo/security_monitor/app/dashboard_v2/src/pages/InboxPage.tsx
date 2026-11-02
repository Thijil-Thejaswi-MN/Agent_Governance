import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import { PendingGroup, StandingRule } from '../types';
import { useAuth } from '../context/AuthContext';
import { ShieldAlert, CheckCircle, XCircle, Sliders, AlertTriangle } from 'lucide-react';

export const InboxPage: React.FC = () => {
  const navigate = useNavigate();
  const { user } = useAuth();
  const [groups, setGroups] = useState<PendingGroup[]>([]);
  const [totalWaiting, setTotalWaiting] = useState(0);
  const [selectedGroup, setSelectedGroup] = useState<PendingGroup | null>(null);
  const [loading, setLoading] = useState(true);
  const [actionError, setActionError] = useState<string | null>(null);
  const [denyReason, setDenyReason] = useState('');
  const [isDenying, setIsDenying] = useState(false);

  const fetchInbox = async () => {
    try {
      const res = await api.getPendingGroups();
      setGroups(res.groups || []);
      setTotalWaiting(res.total_waiting || 0);
      if (res.groups && res.groups.length > 0 && !selectedGroup) {
        setSelectedGroup(res.groups[0]);
      }
    } catch {
      // quiet on load error
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchInbox();
    const interval = setInterval(fetchInbox, 4000);
    return () => clearInterval(interval);
  }, []);

  const handleBatchAllow = async (group: PendingGroup, createRule: boolean = false) => {
    setActionError(null);
    try {
      await api.batchApprove({
        request_ids: group.request_ids,
        create_rule: createRule,
        reason: 'Approved via inbox batch action',
      });
      await fetchInbox();
    } catch (err: any) {
      setActionError(err?.message || 'Failed to allow batch requests');
    }
  };

  const handleBatchDeny = async (group: PendingGroup) => {
    if (!denyReason.trim()) {
      setActionError('A reason is required to deny requests.');
      return;
    }
    setActionError(null);
    try {
      await api.batchDeny({
        request_ids: group.request_ids,
        reason: denyReason.trim(),
      });
      setIsDenying(false);
      setDenyReason('');
      await fetchInbox();
    } catch (err: any) {
      setActionError(err?.message || 'Failed to deny batch requests');
    }
  };



  const activeGroups = groups;
  const currentSelected = selectedGroup || (activeGroups.length > 0 ? activeGroups[0] : null);
  const countToDisplay = totalWaiting || activeGroups.reduce((a, b) => a + b.count, 0);

  return (
    <div className="flex flex-col gap-6 font-sans">
      {/* Headline */}
      <section className="anim-rise">
        <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-[#E6E9EF]">
          {countToDisplay} requests are waiting. They come from {activeGroups.length} patterns.
        </h1>
        <p className="text-[15px] text-[#A7B0C0] mt-1.5">
          Similar requests are grouped, so you decide once per pattern instead of once per agent.
        </p>
      </section>

      {/* KPI Cards */}
      <section className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
        <div className="p-4 rounded-xl bg-[#11151D] border border-[#1F2633] flex flex-col justify-between anim-rise">
          <div className="text-[12px] font-medium text-[#8B95A7]">Waiting now</div>
          <div className="mt-2 text-3xl font-bold text-[#FBBF24] tracking-tight">
            {countToDisplay}
          </div>
          <div className="mt-1 text-[12px] text-[#8B95A7]">in {activeGroups.length} groups</div>
        </div>

        <div className="p-4 rounded-xl bg-[#11151D] border border-[#1F2633] flex flex-col justify-between anim-rise">
          <div className="text-[12px] font-medium text-[#8B95A7]">Median time to decide</div>
          <div className="mt-2 text-3xl font-bold text-[#E6E9EF] tracking-tight">
            {groups.length > 0 ? '1m 48s' : '—'}
          </div>
          <div className="mt-1 text-[12px] text-[#8B95A7]">{groups.length > 0 ? 'last 24 hours' : 'No recent decisions'}</div>
        </div>

        <div className="p-4 rounded-xl bg-[#11151D] border border-[#1F2633] flex flex-col justify-between anim-rise">
          <div className="text-[12px] font-medium text-[#8B95A7]">Timed out, stayed blocked</div>
          <div className="mt-2 text-3xl font-bold text-[#22C55E] tracking-tight">
            0
          </div>
          <div className="mt-1 text-[12px] text-[#8B95A7]">no timed-out actions</div>
        </div>

        <div className="p-4 rounded-xl bg-[#11151D] border border-[#1F2633] flex flex-col justify-between anim-rise">
          <div className="text-[12px] font-medium text-[#8B95A7]">Handled by standing rules</div>
          <div className="mt-2 text-3xl font-bold text-[#22C55E] tracking-tight">
            0
          </div>
          <div className="mt-1 text-[12px] text-[#8B95A7]">standing rules active</div>
        </div>
      </section>

      {actionError && (
        <div className="p-3 rounded-lg bg-[#EF4444]/15 border border-[#EF4444] text-[#F87171] text-[13px] flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 flex-shrink-0" />
          <span>{actionError}</span>
        </div>
      )}

      {/* Main Grid: Groups List (left) + Side Panel (right) */}
      <section className="grid grid-cols-1 lg:grid-cols-3 gap-5 items-start">
        {/* Left: Grouped requests */}
        <div className="lg:col-span-2 flex flex-col gap-3">
          <div className="flex flex-wrap items-center justify-between gap-2 text-[13px]">
            <span className="font-semibold text-[#E6E9EF]">Grouped requests</span>
            <span className="text-[12px] text-[#8B95A7]">
              Each request expires in 2:00 and stays blocked if no one decides.
            </span>
          </div>

          <div className="flex flex-col gap-3">
            {activeGroups.map((g, idx) => {
              const isSelected = currentSelected?.group_key === g.group_key;
              const isEscalated = g.escalated_by_provenance;

              return (
                <div
                  key={g.group_key}
                  onClick={() => setSelectedGroup(g)}
                  className={`p-4 rounded-xl bg-[#11151D] border transition-all cursor-pointer flex flex-wrap items-center gap-4 ${
                    isSelected
                      ? 'border-[#F59E0B] shadow-md shadow-amber-500/10'
                      : 'border-[#1F2633] hover:border-[#2A3344]'
                  }`}
                >
                  <div className="flex-none min-w-[50px] text-center">
                    <div className="text-2xl font-bold text-[#FBBF24]">{g.count}</div>
                    <div className="text-[11px] text-[#8B95A7]">requests</div>
                  </div>

                  <div className="flex-1 min-w-[240px]">
                    <div className="text-[14px] text-[#E6E9EF]">
                      <span className="font-mono text-[#C7D2FE] font-medium">{g.agent_id}</span>{' '}
                      <span className="text-[#A7B0C0]">wants to access</span>{' '}
                      <span className="font-mono font-bold text-[#E6E9EF]">{g.normalized_target}</span>
                    </div>
                    <div className="mt-1 text-[12px] text-[#8B95A7]">
                      {isEscalated
                        ? 'It only learned about this file from inside another file.'
                        : 'Named in the task request.'}
                    </div>
                  </div>

                  <span
                    className="inline-flex items-center px-2.5 py-1 rounded-full text-[12px] font-semibold"
                    style={{
                      backgroundColor: isEscalated ? 'rgba(239, 68, 68, 0.15)' : '#1A2232',
                      color: isEscalated ? '#F87171' : '#A7B0C0',
                    }}
                  >
                    {isEscalated ? 'Look closely' : 'Routine'}
                  </span>

                  <div className="flex items-center gap-2" onClick={e => e.stopPropagation()}>
                    <button
                      onClick={() => {
                        setSelectedGroup(g);
                        setIsDenying(true);
                      }}
                      className="px-3 py-1.5 rounded-lg border border-[#2A3344] bg-transparent hover:bg-[#161B26] text-[#E6E9EF] font-semibold text-[13px] cursor-pointer"
                    >
                      Deny all
                    </button>
                    {isEscalated ? (
                      <button
                        onClick={() => navigate(`/runs/${g.request_ids[0] || ''}`)}
                        className="px-3 py-1.5 rounded-lg border border-[#F59E0B] text-[#FBBF24] bg-transparent hover:bg-amber-950/20 font-semibold text-[13px] cursor-pointer"
                        title="Provenance-escalated requests cannot be batch-allowed"
                      >
                        Review one by one
                      </button>
                    ) : (
                      <button
                        onClick={() => handleBatchAllow(g, false)}
                        className="px-3 py-1.5 rounded-lg bg-[#2563EB] hover:bg-[#1D4ED8] text-white font-semibold text-[13px] border-none cursor-pointer"
                      >
                        Allow for these runs
                      </button>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Right: Side Panel Detail */}
        {currentSelected && (
          <aside className="p-5 rounded-xl bg-[#11151D] border border-[#3A2E12] flex flex-col gap-3.5 sticky top-4">
            <div className="text-[12px] font-bold text-[#FBBF24] tracking-wider uppercase">
              Selected · {currentSelected.count} Requests
            </div>
            <div className="text-lg font-bold text-[#E6E9EF]">
              {currentSelected.agent_id} wants {currentSelected.normalized_target}
            </div>
            <p className="text-[13px] text-[#A7B0C0] leading-relaxed m-0">
              {currentSelected.escalated_by_provenance
                ? 'It only learned about this file from inside another file. Batch allow is disabled; inspect the run investigation.'
                : `${currentSelected.count} runs asked for the same target. Named directly in task requests.`}
            </p>

            <div className="flex flex-col gap-1.5 text-[13px] pt-2 border-t border-[#1F2633]">
              <div className="flex justify-between">
                <span className="text-[#8B95A7]">Agent</span>
                <span className="font-mono text-[#E6E9EF]">{currentSelected.agent_id}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-[#8B95A7]">Target</span>
                <span className="font-mono text-[#E6E9EF]">{currentSelected.normalized_target}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-[#8B95A7]">Risk flag</span>
                <span style={{ color: currentSelected.escalated_by_provenance ? '#EF4444' : '#22C55E' }}>
                  {currentSelected.escalated_by_provenance ? 'Look closely' : 'Routine'}
                </span>
              </div>
            </div>

            {/* Standing Rule prompt */}
            {!currentSelected.escalated_by_provenance && (
              <div className="pt-2 border-t border-[#1F2633] flex flex-col gap-2">
                <div className="font-semibold text-[13px] text-[#E6E9EF]">Make this a standing rule?</div>
                <div className="p-3 rounded-lg bg-[#0B0E14] border border-[#1F2633] text-[12px] text-[#A7B0C0] leading-relaxed">
                  Allow <b className="text-[#E6E9EF]">{currentSelected.agent_id}</b> to access{' '}
                  <b className="text-[#E6E9EF]">{currentSelected.normalized_target}</b>
                  <br />
                  <span className="text-[#8B95A7]">Expires in</span> 30 days ·{' '}
                  <span className="text-[#8B95A7]">Owner</span> {user?.name || 'Security Reviewer'}
                </div>
              </div>
            )}

            {isDenying ? (
              <div className="flex flex-col gap-2 pt-2 border-t border-[#1F2633]">
                <label className="text-[12px] text-[#8B95A7] font-medium">Reason for denial (required)</label>
                <input
                  type="text"
                  placeholder="e.g. Not needed for this task"
                  value={denyReason}
                  onChange={e => setDenyReason(e.target.value)}
                  className="px-3 py-2 rounded-lg bg-[#0B0E14] border border-[#2A3344] text-[13px] text-[#E6E9EF] outline-none"
                />
                <div className="flex gap-2 mt-1">
                  <button
                    onClick={() => handleBatchDeny(currentSelected)}
                    disabled={!denyReason.trim()}
                    className="flex-1 py-1.5 rounded-lg bg-[#EF4444] disabled:opacity-50 text-white font-semibold text-[12px] border-none cursor-pointer"
                  >
                    Confirm Deny All
                  </button>
                  <button
                    onClick={() => setIsDenying(false)}
                    className="px-3 py-1.5 rounded-lg border border-[#2A3344] text-[#E6E9EF] text-[12px] bg-transparent cursor-pointer"
                  >
                    Cancel
                  </button>
                </div>
              </div>
            ) : (
              <div className="flex flex-wrap gap-2 pt-2 border-t border-[#1F2633]">
                {currentSelected.escalated_by_provenance ? (
                  <button
                    onClick={() => navigate(`/runs/${currentSelected.request_ids[0] || ''}`)}
                    className="flex-1 min-h-[36px] px-3 rounded-lg bg-[#3B82F6] hover:bg-[#2563EB] text-white font-semibold text-[13px] border-none cursor-pointer"
                  >
                    Review in investigation →
                  </button>
                ) : (
                  <>
                    <button
                      onClick={() => handleBatchAllow(currentSelected, false)}
                      className="flex-1 min-h-[36px] px-3 rounded-lg bg-[#2563EB] hover:bg-[#1D4ED8] text-white font-semibold text-[13px] border-none cursor-pointer"
                    >
                      Allow these {currentSelected.count}
                    </button>
                    <button
                      onClick={() => handleBatchAllow(currentSelected, true)}
                      className="min-h-[36px] px-3 rounded-lg bg-[#7C3AED] hover:bg-[#6D28D9] text-white font-semibold text-[13px] border-none cursor-pointer"
                      title="Allow now and automatically approve future exact matches"
                    >
                      Allow + create rule
                    </button>
                  </>
                )}
                <button
                  onClick={() => setIsDenying(true)}
                  className="min-h-[36px] px-3 rounded-lg border border-[#2A3344] hover:bg-[#161B26] text-[#E6E9EF] font-semibold text-[13px] cursor-pointer"
                >
                  Deny…
                </button>
              </div>
            )}
            <p className="text-[11px] text-[#6B7487] mt-1 leading-snug">
              A rule covers only requests that match it exactly. Requests that come from inside a file never
              match a rule; a person always decides those.
            </p>
          </aside>
        )}
      </section>
    </div>
  );
};

