import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import { ExpansionItem, PendingGroup } from '../types';
import { countDecided, formatDuration, isRule, isTimeout, medianDecisionSeconds } from '../logic/teamStats';
import { useAuth } from '../context/AuthContext';
import { ShieldAlert, CheckCircle, XCircle, Sliders, AlertTriangle } from 'lucide-react';

const groupTarget = (g: PendingGroup) => g.target ?? g.normalized_target ?? '';
const groupRunPath = (g: PendingGroup) => {
  const taskId = g.requests?.[0]?.task_id;
  return taskId ? `/run/${taskId}` : '/fleet';
};

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
  const [decided, setDecided] = useState<ExpansionItem[] | null>(null);

  const fetchInbox = async () => {
    try {
      api
        .getExpansions()
        .then(all => setDecided(all.filter(e => e.status !== 'PENDING')))
        .catch(() => setDecided(null));
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
  const nowMs = Date.now();
  const medianSec = decided ? medianDecisionSeconds(decided, nowMs) : null;
  const timedOut = decided ? countDecided(decided, isTimeout, nowMs) : 0;
  const byRules = decided ? countDecided(decided, isRule, nowMs) : 0;

  return (
    <div className="flex flex-col gap-6 font-sans">
      {/* Headline */}
      <section className="anim-rise">
        <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-fg">
          {countToDisplay} requests are waiting. They come from {activeGroups.length} patterns.
        </h1>
        <p className="text-[15px] text-fg-2 mt-1.5">
          Similar requests are grouped, so you decide once per pattern instead of once per agent.
        </p>
      </section>

      {/* KPI Cards */}
      <section className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
        <div className="p-4 rounded-xl bg-surface-2 border border-line flex flex-col justify-between anim-rise">
          <div className="text-[12px] font-medium text-fg-3">Waiting now</div>
          <div className="mt-2 text-3xl font-bold text-wait-kpi tracking-tight">
            {countToDisplay}
          </div>
          <div className="mt-1 text-[12px] text-fg-3">in {activeGroups.length} groups</div>
        </div>

        <div className="p-4 rounded-xl bg-surface-2 border border-line flex flex-col justify-between anim-rise">
          <div className="text-[12px] font-medium text-fg-3">Median time to decide</div>
          <div id="kpi-median-decision" className="mt-2 text-3xl font-bold text-fg tracking-tight">
            {formatDuration(medianSec)}
          </div>
          <div className="mt-1 text-[12px] text-fg-3">{medianSec == null ? 'No decisions by a person in the last 24 hours' : 'decisions by a person, last 24 hours'}</div>
        </div>

        <div className="p-4 rounded-xl bg-surface-2 border border-line flex flex-col justify-between anim-rise">
          <div className="text-[12px] font-medium text-fg-3">Timed out, stayed blocked</div>
          <div id="kpi-timed-out" className="mt-2 text-3xl font-bold tracking-tight" style={{ color: timedOut ? 'var(--wait-kpi)' : 'var(--text)' }}>
            {decided ? timedOut : '—'}
          </div>
          <div className="mt-1 text-[12px] text-fg-3">last 24 hours</div>
        </div>

        <div className="p-4 rounded-xl bg-surface-2 border border-line flex flex-col justify-between anim-rise">
          <div className="text-[12px] font-medium text-fg-3">Handled by standing rules</div>
          <div id="kpi-by-rules" className="mt-2 text-3xl font-bold text-fg tracking-tight">
            {decided ? byRules : '—'}
          </div>
          <div className="mt-1 text-[12px] text-fg-3">last 24 hours</div>
        </div>
      </section>

      {actionError && (
        <div className="p-3 rounded-lg bg-bad/15 border border-bad text-bad-light text-[13px] flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 flex-shrink-0" />
          <span>{actionError}</span>
        </div>
      )}

      {/* Main Grid: Groups List (left) + Side Panel (right) */}
      <section className="grid grid-cols-1 lg:grid-cols-3 gap-5 items-start">
        {/* Left: Grouped requests */}
        <div className="lg:col-span-2 flex flex-col gap-3">
          <div className="flex flex-wrap items-center justify-between gap-2 text-[13px]">
            <span className="font-semibold text-fg">Grouped requests</span>
            <span className="text-[12px] text-fg-3">
              A request that no one decides in time stays blocked.
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
                  className={`p-4 rounded-xl bg-surface-2 border transition-all cursor-pointer flex flex-wrap items-center gap-4 ${
                    isSelected
                      ? 'border-wait shadow-md shadow-amber-500/10'
                      : 'border-line hover:border-line-strong'
                  }`}
                >
                  <div className="flex-none min-w-[50px] text-center">
                    <div className="text-2xl font-bold text-wait-kpi">{g.count}</div>
                    <div className="text-[11px] text-fg-3">requests</div>
                  </div>

                  <div className="flex-1 min-w-[240px]">
                    <div className="text-[14px] text-fg">
                      <span className="font-mono text-indigoLight font-medium">{g.agent_id}</span>{' '}
                      <span className="text-fg-2">wants to access</span>{' '}
                      <span className="font-mono font-bold text-fg">{groupTarget(g)}</span>
                    </div>
                    <div className="mt-1 text-[12px] text-fg-3">
                      {isEscalated
                        ? 'It only learned about this file from inside another file.'
                        : 'Named in the task request.'}
                    </div>
                  </div>

                  <span
                    className="inline-flex items-center px-2.5 py-1 rounded-full text-[12px] font-semibold"
                    style={{
                      backgroundColor: isEscalated ? 'rgb(var(--bad-rgb) / 0.15)' : 'var(--surface-hover)',
                      color: isEscalated ? 'var(--bad-light)' : 'var(--text-2)',
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
                      className="px-3 py-1.5 rounded-lg border border-line-strong bg-transparent hover:bg-surface-3 text-fg font-semibold text-[13px] cursor-pointer"
                    >
                      Deny all
                    </button>
                    {isEscalated ? (
                      <button
                        onClick={() => navigate(groupRunPath(g))}
                        className="px-3 py-1.5 rounded-lg border border-wait text-wait-kpi bg-transparent hover:bg-amber-950/20 font-semibold text-[13px] cursor-pointer"
                        title="Provenance-escalated requests cannot be batch-allowed"
                      >
                        Review one by one
                      </button>
                    ) : (
                      <button
                        onClick={() => handleBatchAllow(g, false)}
                        className="px-3 py-1.5 rounded-lg bg-accent-strong hover:bg-accent-deep text-white font-semibold text-[13px] border-none cursor-pointer"
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
          <aside className="p-5 rounded-xl bg-surface-2 border border-wait-line flex flex-col gap-3.5 sticky top-4">
            <div className="text-[12px] font-bold text-wait-kpi tracking-wider uppercase">
              Selected · {currentSelected.count} Requests
            </div>
            <div className="text-lg font-bold text-fg">
              {currentSelected.agent_id} wants {groupTarget(currentSelected)}
            </div>
            <p className="text-[13px] text-fg-2 leading-relaxed m-0">
              {currentSelected.escalated_by_provenance
                ? 'It only learned about this file from inside another file. Batch allow is off; open the run to decide.'
                : `${currentSelected.count} ${currentSelected.count === 1 ? 'request asks' : 'requests ask'} for the same target.`}
            </p>

            <div className="flex flex-col gap-1.5 text-[13px] pt-2 border-t border-line">
              <div className="flex justify-between">
                <span className="text-fg-3">Agent</span>
                <span className="font-mono text-fg">{currentSelected.agent_id}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-fg-3">Target</span>
                <span className="font-mono text-fg">{groupTarget(currentSelected)}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-fg-3">Risk flag</span>
                <span style={{ color: currentSelected.escalated_by_provenance ? 'var(--bad)' : 'var(--ok)' }}>
                  {currentSelected.escalated_by_provenance ? 'Look closely' : 'Routine'}
                </span>
              </div>
            </div>

            {/* Standing Rule prompt */}
            {!currentSelected.escalated_by_provenance && (
              <div className="pt-2 border-t border-line flex flex-col gap-2">
                <div className="font-semibold text-[13px] text-fg">Make this a standing rule?</div>
                <div className="p-3 rounded-lg bg-bg border border-line text-[12px] text-fg-2 leading-relaxed">
                  Allow <b className="text-fg">{currentSelected.agent_id}</b> to access{' '}
                  <b className="text-fg">{groupTarget(currentSelected)}</b>
                  <br />
                  <span className="text-fg-3">Expires in</span> 30 days ·{' '}
                  <span className="text-fg-3">Owner</span> {user?.name ?? '—'}
                </div>
              </div>
            )}

            {isDenying ? (
              <div className="flex flex-col gap-2 pt-2 border-t border-line">
                <label className="text-[12px] text-fg-3 font-medium">Reason for denial (required)</label>
                <input
                  type="text"
                  placeholder="e.g. Not needed for this task"
                  value={denyReason}
                  onChange={e => setDenyReason(e.target.value)}
                  className="px-3 py-2 rounded-lg bg-bg border border-line-strong text-[13px] text-fg outline-none"
                />
                <div className="flex gap-2 mt-1">
                  <button
                    onClick={() => handleBatchDeny(currentSelected)}
                    disabled={!denyReason.trim()}
                    className="flex-1 py-1.5 rounded-lg bg-bad disabled:opacity-50 text-white font-semibold text-[12px] border-none cursor-pointer"
                  >
                    Confirm Deny All
                  </button>
                  <button
                    onClick={() => setIsDenying(false)}
                    className="px-3 py-1.5 rounded-lg border border-line-strong text-fg text-[12px] bg-transparent cursor-pointer"
                  >
                    Cancel
                  </button>
                </div>
              </div>
            ) : (
              <div className="flex flex-wrap gap-2 pt-2 border-t border-line">
                {currentSelected.escalated_by_provenance ? (
                  <button
                    onClick={() => navigate(groupRunPath(currentSelected))}
                    className="flex-1 min-h-[36px] px-3 rounded-lg bg-accent hover:bg-accent-strong text-white font-semibold text-[13px] border-none cursor-pointer"
                  >
                    Open the run →
                  </button>
                ) : (
                  <>
                    <button
                      onClick={() => handleBatchAllow(currentSelected, false)}
                      className="flex-1 min-h-[36px] px-3 rounded-lg bg-accent-strong hover:bg-accent-deep text-white font-semibold text-[13px] border-none cursor-pointer"
                    >
                      Allow these {currentSelected.count}
                    </button>
                    <button
                      onClick={() => handleBatchAllow(currentSelected, true)}
                      className="min-h-[36px] px-3 rounded-lg bg-ruleAction hover:bg-ruleActionHover text-white font-semibold text-[13px] border-none cursor-pointer"
                      title="Allow now and automatically approve future exact matches"
                    >
                      Allow + create rule
                    </button>
                  </>
                )}
                <button
                  onClick={() => setIsDenying(true)}
                  className="min-h-[36px] px-3 rounded-lg border border-line-strong hover:bg-surface-3 text-fg font-semibold text-[13px] cursor-pointer"
                >
                  Deny…
                </button>
              </div>
            )}
            <p className="text-[11px] text-fg-dim mt-1 leading-snug">
              A rule covers only requests that match it exactly. Requests that come from inside a file never
              match a rule; a person always decides those.
            </p>
          </aside>
        )}
      </section>
    </div>
  );
};

