import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Clock,
  ShieldAlert,
  RefreshCw,
  FileText,
  User,
  Info,
} from 'lucide-react';
import { api } from '../api/client';
import { ExpansionItem } from '../types';
import { Badge } from '../components/common/Badge';
import { EmptyState } from '../components/common/EmptyState';
import { useAuth } from '../context/AuthContext';

export const ApprovalsPage: React.FC = () => {
  const { hasToken, openAuthModal } = useAuth();
  const [expansions, setExpansions] = useState<ExpansionItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [now, setNow] = useState(Date.now());

  // Deny modal state
  const [denyModalTarget, setDenyModalTarget] = useState<string | null>(null);
  const [denyReason, setDenyReason] = useState('');
  const [denyReasonError, setDenyReasonError] = useState<string | null>(null);

  const fetchExpansions = async () => {
    try {
      const data = await api.getExpansions();
      setExpansions(data);
    } catch (err) {
      console.error('Failed to load expansions', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchExpansions();
    const pollInterval = setInterval(fetchExpansions, 3000);
    const clockInterval = setInterval(() => setNow(Date.now()), 1000);
    return () => {
      clearInterval(pollInterval);
      clearInterval(clockInterval);
    };
  }, []);

  const handleApprove = async (reqId: string) => {
    if (!hasToken) {
      openAuthModal();
      return;
    }

    setActionLoading(reqId);
    setMessage(null);
    try {
      await api.approveExpansion(reqId, {
        decided_by: 'operator',
        reason: 'Approved via Approvals Console',
      });
      setMessage({ type: 'success', text: `Expansion ${reqId} approved successfully.` });
      await fetchExpansions();
    } catch (e: any) {
      setMessage({ type: 'error', text: e.message || 'Approval failed' });
    } finally {
      setActionLoading(null);
    }
  };

  const openDenyDialog = (reqId: string) => {
    if (!hasToken) {
      openAuthModal();
      return;
    }
    setDenyModalTarget(reqId);
    setDenyReason('Denied by operator: out of allowable task scope');
    setDenyReasonError(null);
  };

  const handleConfirmDeny = async () => {
    if (!denyModalTarget) return;
    if (!denyReason.trim()) {
      setDenyReasonError('A denial reason is required.');
      return;
    }

    const reqId = denyModalTarget;
    setActionLoading(reqId);
    setMessage(null);
    try {
      await api.denyExpansion(reqId, {
        decided_by: 'operator',
        reason: denyReason.trim(),
      });
      setMessage({ type: 'success', text: `Expansion ${reqId} denied.` });
      setDenyModalTarget(null);
      setDenyReason('');
      await fetchExpansions();
    } catch (e: any) {
      setMessage({ type: 'error', text: e.message || 'Denial failed' });
    } finally {
      setActionLoading(null);
    }
  };

  const pending = expansions.filter(e => e.status === 'PENDING');
  const past = expansions.filter(e => e.status !== 'PENDING');

  return (
    <div className="space-y-6 animate-in fade-in duration-300">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-white">
            Expansion Approvals
          </h1>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
            Review live runtime boundary expansion requests with untrusted provenance warnings and fail-closed timeouts.
          </p>
        </div>
        <button
          onClick={fetchExpansions}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-200 bg-white dark:bg-surface-cardDark border border-slate-200 dark:border-slate-800 rounded-xl hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors"
          id="refresh-approvals-btn"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Refresh</span>
        </button>
      </div>

      {message && (
        <div
          className={`p-3 rounded-xl border text-xs font-medium ${
            message.type === 'success'
              ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/30'
              : 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/30'
          }`}
        >
          {message.text}
        </div>
      )}

      {/* Pending Expansions */}
      <div className="space-y-4">
        <h2 className="text-sm font-bold uppercase tracking-wider text-slate-400">
          Pending Operator Review ({pending.length})
        </h2>

        {pending.length === 0 ? (
          <EmptyState
            icon="inbox"
            title="No Pending Approvals"
            description="All runtime boundary expansion requests have been decided. When an agent requests a resource outside its sandbox, it will appear here."
          />
        ) : (
          pending.map(e => {
            const createdMs = new Date(e.created_at).getTime();
            const timeoutSec = e.timeout_seconds || 120;
            const remainingSec = Math.max(0, Math.ceil((createdMs + timeoutSec * 1000 - now) / 1000));
            const isProvenanced = Boolean(e.escalated_by_provenance || e.provenance_escalation);

            return (
              <div
                key={e.request_id}
                id={`approval-card-${e.request_id}`}
                className="p-5 rounded-2xl bg-white dark:bg-surface-cardDark border-2 border-amber-500/80 shadow-[0_0_15px_rgba(245,158,11,0.2)] animate-pulse space-y-4"
              >
                {/* Header row: Request & Target */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-100 dark:border-slate-800 pb-3">
                  <div className="flex items-center gap-2.5 flex-wrap">
                    <span className="font-mono text-xs font-bold text-slate-900 dark:text-white">
                      {e.request_id}
                    </span>
                    <Badge variant="pending">PENDING OPERATOR DECISION</Badge>
                    <span className="font-mono text-xs px-2 py-0.5 rounded bg-amber-500/10 text-amber-600 dark:text-amber-400 border border-amber-500/30 font-semibold">
                      {e.resource_type}: {e.resource_target}
                    </span>
                  </div>

                  {/* Live Fail-Closed Countdown */}
                  <div className="flex items-center gap-1.5 font-mono text-xs text-amber-600 dark:text-amber-400 bg-amber-500/10 px-2.5 py-1 rounded-lg border border-amber-500/20">
                    <Clock className="w-3.5 h-3.5" />
                    <span className="font-bold">{remainingSec}s</span>
                    <span className="text-[11px] text-slate-500 dark:text-slate-400">until fail-closed DENY</span>
                  </div>
                </div>

                {/* Context Details Grid */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                  {/* Task Context */}
                  <div className="p-3 rounded-xl bg-slate-50 dark:bg-slate-900/50 border border-slate-200/80 dark:border-slate-800 space-y-1.5">
                    <div className="flex items-center justify-between text-slate-500">
                      <span className="font-bold uppercase text-[10px] tracking-wider">Context & User Request</span>
                      <Link
                        to={`/tasks/${e.task_id}`}
                        className="text-cyan-600 dark:text-cyan-400 font-mono hover:underline text-[11px]"
                      >
                        view task {e.task_id.slice(0, 12)}...
                      </Link>
                    </div>
                    <div className="flex items-center gap-2 text-slate-700 dark:text-slate-300 font-mono">
                      <User className="w-3.5 h-3.5 text-slate-400" />
                      <span>agent: {e.agent_id}</span>
                    </div>
                    {e.task_request_text && (
                      <p className="text-slate-600 dark:text-slate-400 italic bg-white dark:bg-slate-900 p-2 rounded border border-slate-200 dark:border-slate-800">
                        "{e.task_request_text}"
                      </p>
                    )}
                  </div>

                  {/* Scope & Risk */}
                  <div className="p-3 rounded-xl bg-slate-50 dark:bg-slate-900/50 border border-slate-200/80 dark:border-slate-800 space-y-2">
                    <span className="font-bold uppercase text-[10px] tracking-wider text-slate-500 block">
                      Risk Tier & Scope
                    </span>
                    <div className="flex items-center gap-2 font-mono">
                      <span className="text-slate-500">Risk:</span>
                      <span className="px-1.5 py-0.5 rounded bg-slate-200 dark:bg-slate-800 font-bold text-slate-700 dark:text-slate-300">
                        {e.baseline_risk_tier}
                      </span>
                      <span className="text-slate-400">→</span>
                      <span className="px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-600 dark:text-amber-400 font-bold border border-amber-500/30">
                        {e.effective_risk_tier}
                      </span>
                    </div>
                    <div className="text-slate-600 dark:text-slate-400 font-mono text-[11px]">
                      <span className="text-slate-400">Scope: </span>
                      {e.single_use ? 'Single-use grant (revoked after first access)' : 'Expiring at task end'}
                    </div>
                  </div>
                </div>

                {/* Provenance Warning Card */}
                {isProvenanced && (
                  <div className="p-3.5 rounded-xl bg-amber-500/10 border-2 border-amber-500/40 text-xs space-y-2">
                    <div className="flex items-center gap-2 text-amber-600 dark:text-amber-400 font-bold">
                      <AlertTriangle className="w-4 h-4 shrink-0" />
                      <span>Requested after reading untrusted content</span>
                    </div>
                    <p className="text-slate-600 dark:text-slate-300 text-[11px]">
                      This request was elevated from baseline {e.baseline_risk_tier} to effective {e.effective_risk_tier} risk because the agent previously inspected untrusted content.
                    </p>
                    {e.prior_untrusted_reads && e.prior_untrusted_reads.length > 0 && (
                      <div className="space-y-1.5 pt-1">
                        {e.prior_untrusted_reads.map((pr, idx) => (
                          <div
                            key={idx}
                            className="p-2 rounded bg-white/70 dark:bg-slate-900/80 border border-amber-500/20 font-mono text-[11px] space-y-1"
                          >
                            <div className="text-slate-700 dark:text-slate-200 font-bold">
                              Source file: {pr.source_target}
                            </div>
                            {pr.content_snippet && (
                              <div className="text-slate-500 dark:text-slate-400 truncate text-[10px]">
                                Snippet preview: "{pr.content_snippet.slice(0, 120)}..."
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}

                {/* Agent justification (untrusted) */}
                <div className="p-3 rounded-xl bg-slate-50 dark:bg-slate-900/50 border border-slate-200/80 dark:border-slate-800 space-y-1">
                  <div className="text-[10px] font-bold uppercase tracking-wider text-amber-600 dark:text-amber-400 font-mono">
                    agent's justification (untrusted)
                  </div>
                  <p className="text-xs text-slate-800 dark:text-slate-200 font-mono">
                    {e.justification}
                  </p>
                </div>

                {/* Action Buttons */}
                <div className="flex items-center justify-end gap-3 pt-2">
                  <button
                    onClick={() => handleApprove(e.request_id)}
                    disabled={actionLoading === e.request_id}
                    id={`approve-btn-${e.request_id}`}
                    className="px-4 py-2 text-xs font-semibold text-white bg-emerald-600 hover:bg-emerald-500 rounded-xl transition-colors flex items-center gap-1.5 shadow-sm"
                  >
                    <CheckCircle2 className="w-4 h-4" />
                    <span>Approve</span>
                  </button>
                  <button
                    onClick={() => openDenyDialog(e.request_id)}
                    disabled={actionLoading === e.request_id}
                    id={`deny-btn-${e.request_id}`}
                    className="px-4 py-2 text-xs font-semibold text-white bg-rose-600 hover:bg-rose-500 rounded-xl transition-colors flex items-center gap-1.5 shadow-sm"
                  >
                    <XCircle className="w-4 h-4" />
                    <span>Deny</span>
                  </button>
                </div>
              </div>
            );
          })
        )}
      </div>

      {/* Decision History */}
      {past.length > 0 && (
        <div className="space-y-3 pt-6 border-t border-slate-200 dark:border-slate-800">
          <h2 className="text-sm font-bold uppercase tracking-wider text-slate-400">
            Resolved Decisions ({past.length})
          </h2>
          <div className="space-y-2.5">
            {past.map(e => (
              <div
                key={e.request_id}
                id={`decided-row-${e.request_id}`}
                className="p-4 rounded-xl bg-slate-50 dark:bg-surface-cardDark border border-slate-200 dark:border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs"
              >
                <div className="space-y-1">
                  <div className="flex items-center gap-2.5 flex-wrap">
                    <Badge variant={e.status === 'APPROVED' ? 'allowed' : 'blocked'} size="sm">
                      {e.status}
                    </Badge>
                    <span className="font-mono font-bold text-slate-800 dark:text-slate-200">
                      {e.resource_target}
                    </span>
                    <span className="text-slate-400 font-mono text-[11px]">task: {e.task_id}</span>
                  </div>
                  {(e.reason || e.denial_reason) && (
                    <p className="text-[11px] text-slate-500 dark:text-slate-400 font-mono">
                      Reason: {e.reason || e.denial_reason}
                    </p>
                  )}
                </div>

                <div className="text-slate-500 dark:text-slate-400 font-mono text-[11px] text-right shrink-0">
                  <div>by {e.resolved_by || e.decided_by || 'system'}</div>
                  <div>{new Date(e.resolved_at || e.decided_at || e.created_at).toLocaleString()}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Deny Reason Modal */}
      {denyModalTarget && (
        <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4 animate-in fade-in">
          <div className="w-full max-w-md p-6 rounded-2xl bg-white dark:bg-surface-cardDark border border-slate-200 dark:border-slate-800 space-y-4 shadow-xl">
            <div className="flex items-center gap-2 text-rose-500 font-bold text-base">
              <ShieldAlert className="w-5 h-5" />
              <span>Deny Resource Expansion</span>
            </div>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Provide an audit reason for denying request <strong className="font-mono text-slate-800 dark:text-slate-200">{denyModalTarget}</strong>. A non-empty reason is strictly required.
            </p>

            <div className="space-y-1">
              <label className="text-xs font-semibold text-slate-700 dark:text-slate-300">
                Denial Reason *
              </label>
              <textarea
                value={denyReason}
                onChange={e => {
                  setDenyReason(e.target.value);
                  setDenyReasonError(null);
                }}
                rows={3}
                id="deny-reason-input"
                placeholder="Explain why this request is denied..."
                className="w-full p-2.5 text-xs font-mono bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl focus:outline-none focus:border-rose-500 text-slate-900 dark:text-slate-100"
              />
              {denyReasonError && (
                <span className="text-[11px] text-rose-500 font-medium block">{denyReasonError}</span>
              )}
            </div>

            <div className="flex items-center justify-end gap-2 pt-2">
              <button
                type="button"
                onClick={() => setDenyModalTarget(null)}
                className="px-3.5 py-2 text-xs font-medium text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-xl transition-colors"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleConfirmDeny}
                id="confirm-deny-btn"
                className="px-4 py-2 text-xs font-semibold text-white bg-rose-600 hover:bg-rose-500 rounded-xl transition-colors shadow-sm"
              >
                Confirm Denial
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
