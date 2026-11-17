import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import { ExpansionItem, PendingGroup } from '../types';
import { countDecided, formatDuration, isRule, isTimeout, medianDecisionSeconds } from '../logic/teamStats';
import { useAuth } from '../context/AuthContext';
import { AlertTriangle } from 'lucide-react';
import { PageHeader } from '../components/ui/PageHeader';
import { MetricCard } from '../components/ui/MetricCard';
import { StatusPill } from '../components/ui/StatusPill';
import { Button } from '../components/ui/Button';

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
  const [, setLoading] = useState(true);
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
      <PageHeader
        title={`${countToDisplay} requests are waiting. They come from ${activeGroups.length} patterns.`}
        subtitle="Similar requests are grouped, so you decide once per pattern instead of once per agent."
      />

      {/* KPI Cards */}
      <section className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
        <MetricCard
          label="Waiting now"
          value={countToDisplay}
          note={`in ${activeGroups.length} groups`}
          tone="wait"
        />

        <MetricCard
          label="Median time to decide"
          value={formatDuration(medianSec)}
          valueId="kpi-median-decision"
          note={
            medianSec == null
              ? 'No decisions by a person in the last 24 hours'
              : 'decisions by a person, last 24 hours'
          }
        />

        <MetricCard
          label="Timed out, stayed blocked"
          value={decided ? timedOut : '—'}
          valueId="kpi-timed-out"
          note="last 24 hours"
          tone={timedOut ? 'wait' : 'default'}
        />

        <MetricCard
          label="Handled by standing rules"
          value={decided ? byRules : '—'}
          valueId="kpi-by-rules"
          note="last 24 hours"
        />
      </section>

      {actionError && (
        <div className="p-3 rounded-lg bg-bad-tint border border-bad/30 text-bad text-[13px] flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          <span>{actionError}</span>
        </div>
      )}

      {/* Main Grid: Groups Table (left) + Side Panel (right) */}
      <section className="grid grid-cols-1 lg:grid-cols-3 gap-5 items-start">
        {/* Left: Grouped requests table */}
        <div className="lg:col-span-2 flex flex-col gap-3">
          <div className="flex flex-wrap items-center justify-between gap-2 text-[13px]">
            <span className="font-semibold text-fg">Grouped requests</span>
            <span className="text-[12px] text-fg-3">
              A request that no one decides in time stays blocked.
            </span>
          </div>

          <div className="rounded-xl border border-line bg-surface-1 overflow-hidden">
            <div className="hidden md:grid md:grid-cols-[60px_1fr_110px_auto] items-center gap-4 bg-surface-2 px-4 py-2.5 text-[12px] uppercase tracking-wider text-fg-3 font-semibold border-b border-line">
              <span>Count</span>
              <span>Target / Request</span>
              <span>Verdict</span>
              <span className="text-right">Actions</span>
            </div>

            {activeGroups.length === 0 ? (
              <div className="p-8 text-center text-fg-2 text-[14px]">
                No requests are waiting.
              </div>
            ) : (
              <div className="divide-y divide-line">
                {activeGroups.map(g => {
                  const isSelected = currentSelected?.group_key === g.group_key;
                  const isEscalated = g.escalated_by_provenance;

                  return (
                    <div
                      key={g.group_key}
                      onClick={() => setSelectedGroup(g)}
                      className={`min-h-[44px] px-4 py-3 cursor-pointer transition-colors flex flex-col md:grid md:grid-cols-[60px_1fr_110px_auto] items-start md:items-center gap-3 text-[14px] ${
                        isSelected
                          ? 'bg-surface-2 ring-1 ring-inset ring-wait/50'
                          : 'hover:bg-surface-2/50'
                      }`}
                    >
                      {/* Count */}
                      <div className="flex items-center gap-1.5 shrink-0">
                        <span className="font-mono text-[15px] font-semibold text-wait-kpi tabular-nums">
                          {g.count}
                        </span>
                        <span className="text-[12px] text-fg-3 md:hidden">requests</span>
                      </div>

                      {/* Target / Request */}
                      <div className="min-w-0 flex-1">
                        <div className="text-[14px] text-fg break-words">
                          <span className="font-mono text-accent font-medium">{g.agent_id}</span>{' '}
                          <span className="text-fg-2">wants to access</span>{' '}
                          <span className="font-mono font-medium text-fg">{groupTarget(g)}</span>
                        </div>
                        <div className="mt-0.5 text-[12px] text-fg-3">
                          {isEscalated
                            ? 'It only learned about this file from inside another file.'
                            : 'Named in the task request.'}
                        </div>
                      </div>

                      {/* Verdict / StatusPill */}
                      <div className="shrink-0">
                        <StatusPill
                          tone={isEscalated ? 'bad' : 'info'}
                          label={isEscalated ? 'Look closely' : 'Routine'}
                        />
                      </div>

                      {/* Row actions on right */}
                      <div
                        className="flex items-center gap-2 shrink-0 self-end md:self-auto"
                        onClick={e => e.stopPropagation()}
                      >
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => {
                            setSelectedGroup(g);
                            setIsDenying(true);
                          }}
                        >
                          Deny all
                        </Button>
                        {isEscalated ? (
                          <Button
                            variant="secondary"
                            size="sm"
                            onClick={() => navigate(groupRunPath(g))}
                            title="Provenance-escalated requests cannot be batch-allowed"
                            className="text-wait-kpi border-wait/40 hover:border-wait"
                          >
                            Review one by one
                          </Button>
                        ) : (
                          <Button
                            variant="secondary"
                            size="sm"
                            onClick={() => handleBatchAllow(g, false)}
                          >
                            Allow for these runs
                          </Button>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>

        {/* Right: Side Panel Detail */}
        {currentSelected && (
          <aside className="p-5 rounded-xl bg-surface-1 border border-line flex flex-col gap-3.5 sticky top-4">
            <div className="text-[12px] font-bold text-wait-kpi tracking-wider uppercase">
              Selected · {currentSelected.count} Requests
            </div>
            <div className="text-lg font-bold text-fg break-words">
              {currentSelected.agent_id} wants {groupTarget(currentSelected)}
            </div>
            <p className="text-[13px] text-fg-2 leading-relaxed m-0">
              {currentSelected.escalated_by_provenance
                ? 'It only learned about this file from inside another file. Batch allow is off; open the run to decide.'
                : `${currentSelected.count} ${currentSelected.count === 1 ? 'request asks' : 'requests ask'} for the same target.`}
            </p>

            <div className="flex flex-col gap-1.5 text-[13px] pt-2 border-t border-line">
              <div className="flex justify-between items-center py-1 border-b border-line/50">
                <span className="text-fg-3">Agent</span>
                <span className="font-mono text-fg">{currentSelected.agent_id}</span>
              </div>
              <div className="flex justify-between items-center py-1 border-b border-line/50">
                <span className="text-fg-3">Target</span>
                <span className="font-mono text-fg break-all">{groupTarget(currentSelected)}</span>
              </div>
              <div className="flex justify-between items-center py-1">
                <span className="text-fg-3">Risk flag</span>
                <StatusPill
                  tone={currentSelected.escalated_by_provenance ? 'bad' : 'ok'}
                  label={currentSelected.escalated_by_provenance ? 'Look closely' : 'Routine'}
                />
              </div>
            </div>

            {/* Standing Rule prompt */}
            {!currentSelected.escalated_by_provenance && (
              <div className="pt-2 border-t border-line flex flex-col gap-2">
                <div className="font-semibold text-[13px] text-fg">Make this a standing rule?</div>
                <div className="p-3 rounded-lg bg-surface-2 border border-line text-[12px] text-fg-2 leading-relaxed">
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
                  className="px-3 py-2 rounded-lg bg-surface-2 border border-line-strong text-[13px] text-fg outline-none focus:border-accent"
                />
                <div className="flex gap-2 mt-1">
                  <Button
                    variant="danger"
                    size="sm"
                    onClick={() => handleBatchDeny(currentSelected)}
                    disabled={!denyReason.trim()}
                    className="flex-1"
                  >
                    Confirm Deny All
                  </Button>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => setIsDenying(false)}
                  >
                    Cancel
                  </Button>
                </div>
              </div>
            ) : (
              <div className="flex flex-wrap gap-2 pt-2 border-t border-line">
                {currentSelected.escalated_by_provenance ? (
                  <Button
                    variant="primary"
                    size="sm"
                    onClick={() => navigate(groupRunPath(currentSelected))}
                    className="flex-1"
                  >
                    Open the run →
                  </Button>
                ) : (
                  <>
                    <Button
                      variant="primary"
                      size="sm"
                      onClick={() => handleBatchAllow(currentSelected, false)}
                      className="flex-1"
                    >
                      Allow these {currentSelected.count}
                    </Button>
                    <Button
                      variant="secondary"
                      size="sm"
                      onClick={() => handleBatchAllow(currentSelected, true)}
                      title="Allow now and automatically approve future exact matches"
                    >
                      Allow + create rule
                    </Button>
                  </>
                )}
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => setIsDenying(true)}
                >
                  Deny…
                </Button>
              </div>
            )}
            <p className="text-[11px] text-fg-3 mt-1 leading-snug">
              A rule covers only requests that match it exactly. Requests that come from inside a file never
              match a rule; a person always decides those.
            </p>
          </aside>
        )}
      </section>
    </div>
  );
};
