import React, { useEffect, useState } from 'react';
import { CheckCircle2, XCircle, AlertTriangle, KeyRound, ShieldAlert, RefreshCw } from 'lucide-react';
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

  const fetchExpansions = async () => {
    try {
      const data = await api.getExpansions();
      setExpansions(data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchExpansions();
  }, []);

  const handleApprove = async (reqId: string) => {
    if (!hasToken) {
      openAuthModal();
      return;
    }
    const confirmed = window.confirm(`Approve expansion ${reqId}?`);
    if (!confirmed) return;

    setActionLoading(reqId);
    setMessage(null);
    try {
      await api.approveExpansion(reqId, {
        decided_by: 'human_operator',
        reason: 'Approved via Approvals Console',
      });
      setMessage({ type: 'success', text: `Expansion ${reqId} approved successfully.` });
      fetchExpansions();
    } catch (e: any) {
      setMessage({ type: 'error', text: e.message || 'Approval failed' });
    } finally {
      setActionLoading(null);
    }
  };

  const handleDeny = async (reqId: string) => {
    if (!hasToken) {
      openAuthModal();
      return;
    }
    const reason = window.prompt(`Denial reason for ${reqId}:`, 'Out of allowable task scope');
    if (reason === null) return;

    setActionLoading(reqId);
    setMessage(null);
    try {
      await api.denyExpansion(reqId, {
        decided_by: 'human_operator',
        reason: reason.trim() || 'Denied by human operator',
      });
      setMessage({ type: 'success', text: `Expansion ${reqId} denied.` });
      fetchExpansions();
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
            Review mid-task resource requests with provenance-aware risk escalation.
          </p>
        </div>
        <button
          onClick={fetchExpansions}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-200 bg-white dark:bg-surface-cardDark border border-slate-200 dark:border-slate-800 rounded-xl hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors"
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
      <div className="space-y-3">
        <h2 className="text-sm font-bold uppercase tracking-wider text-slate-400">
          Pending Operator Review ({pending.length})
        </h2>

        {pending.length === 0 ? (
          <EmptyState
            icon="inbox"
            title="No Pending Approvals"
            description="All mid-task expansion requests have been decided. When an agent requests a file or tool outside its boundary, it will appear here."
          />
        ) : (
          pending.map(e => (
            <div
              key={e.request_id}
              className="p-5 rounded-2xl bg-white dark:bg-surface-cardDark border border-slate-200 dark:border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-4 shadow-sm"
            >
              <div className="space-y-1.5">
                <div className="flex items-center gap-2.5 flex-wrap">
                  <span className="font-mono text-xs font-bold text-slate-900 dark:text-white">
                    {e.request_id}
                  </span>
                  <Badge variant="pending">PENDING APPROVAL</Badge>
                  <span className="text-xs font-mono text-slate-400">task: {e.task_id}</span>
                  <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300">
                    {e.resource_target}
                  </span>
                </div>

                <p className="text-xs text-slate-600 dark:text-slate-300">
                  <strong>Justification:</strong> {e.justification}
                </p>

                <div className="flex items-center gap-4 text-xs font-mono text-slate-400">
                  <span>Baseline: {e.baseline_risk_tier}</span>
                  <span>Effective: {e.effective_risk_tier}</span>
                  {e.provenance_escalation && (
                    <span className="text-amber-500 font-bold">Provenance Escalated</span>
                  )}
                </div>
              </div>

              <div className="flex items-center gap-2 shrink-0">
                <button
                  onClick={() => handleApprove(e.request_id)}
                  disabled={actionLoading === e.request_id}
                  className="px-3.5 py-2 text-xs font-medium text-white bg-emerald-600 hover:bg-emerald-500 rounded-xl transition-colors flex items-center gap-1.5 shadow-sm"
                >
                  <CheckCircle2 className="w-4 h-4" />
                  <span>Approve</span>
                </button>
                <button
                  onClick={() => handleDeny(e.request_id)}
                  disabled={actionLoading === e.request_id}
                  className="px-3.5 py-2 text-xs font-medium text-white bg-rose-600 hover:bg-rose-500 rounded-xl transition-colors flex items-center gap-1.5 shadow-sm"
                >
                  <XCircle className="w-4 h-4" />
                  <span>Deny</span>
                </button>
              </div>
            </div>
          ))
        )}
      </div>

      {/* Decision History */}
      {past.length > 0 && (
        <div className="space-y-3 pt-4">
          <h2 className="text-sm font-bold uppercase tracking-wider text-slate-400">
            Resolved Decisions ({past.length})
          </h2>
          <div className="space-y-2.5">
            {past.map(e => (
              <div
                key={e.request_id}
                className="p-4 rounded-xl bg-slate-50 dark:bg-slate-900/40 border border-slate-200 dark:border-slate-800 flex items-center justify-between text-xs"
              >
                <div className="flex items-center gap-3">
                  <Badge variant={e.status === 'APPROVED' ? 'allowed' : 'blocked'} size="sm">
                    {e.status}
                  </Badge>
                  <span className="font-mono text-slate-800 dark:text-slate-200">{e.resource_target}</span>
                  <span className="text-slate-400 font-mono">task: {e.task_id}</span>
                </div>
                <div className="text-slate-400 font-mono">
                  {e.decided_by && <span>by {e.decided_by}</span>}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
