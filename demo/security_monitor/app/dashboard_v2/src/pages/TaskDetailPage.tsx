import React, { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import {
  ArrowLeft,
  ShieldCheck,
  ShieldAlert,
  Clock,
  Layers,
  FileCode,
  FileText,
  Activity,
  CheckCircle,
  XCircle,
  AlertTriangle,
  ChevronDown,
  ChevronUp,
  KeyRound,
  FileCheck2,
  FileCheck,
  ExternalLink,
  Copy,
  Check,
  Download,
} from 'lucide-react';
import { api } from '../api/client';
import { TaskRecord, TaskBoundary, TaskEvent, ExpansionItem, ReceiptResponse } from '../types';
import { Badge } from '../components/common/Badge';
import { EmptyState } from '../components/common/EmptyState';
import { useAuth } from '../context/AuthContext';

export const TaskDetailPage: React.FC = () => {
  const { taskId } = useParams<{ taskId: string }>();
  const { hasToken, openAuthModal } = useAuth();

  const [task, setTask] = useState<TaskRecord | null>(null);
  const [boundary, setBoundary] = useState<TaskBoundary | null>(null);
  const [events, setEvents] = useState<TaskEvent[]>([]);
  const [expansions, setExpansions] = useState<ExpansionItem[]>([]);
  const [receiptRes, setReceiptRes] = useState<ReceiptResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [expandedEventId, setExpandedEventId] = useState<string | number | null>(null);
  const [showReceiptJson, setShowReceiptJson] = useState(false);
  const [copiedReceipt, setCopiedReceipt] = useState(false);

  // Approval / Denial action state
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [actionMessage, setActionMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  const loadData = async () => {
    if (!taskId) return;
    try {
      const [detail, evList, expList] = await Promise.all([
        api.getTaskDetail(taskId),
        api.getTaskEvents(taskId).catch(() => []),
        api.getExpansions(taskId).catch(() => []),
      ]);

      setTask(detail.task);
      setBoundary(detail.boundary);
      setEvents(evList);
      setExpansions(expList);

      // Fetch receipt verification
      try {
        const rc = await api.getTaskReceipt(taskId);
        setReceiptRes(rc);
      } catch (e) {
        // Receipt may not exist yet if task was synthetic or running
      }
    } catch (err) {
      console.error('Failed to load task details', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [taskId]);

  const handleApprove = async (requestId: string) => {
    if (!hasToken) {
      openAuthModal();
      return;
    }
    const confirmed = window.confirm(`Approve expansion request ${requestId}? This grants additional file/tool access to the agent.`);
    if (!confirmed) return;

    setActionLoading(requestId);
    setActionMessage(null);
    try {
      const res = await api.approveExpansion(requestId, {
        decided_by: 'human_operator',
        reason: 'Approved via Governance Console v2',
      });
      setActionMessage({ type: 'success', text: `Expansion approved. New boundary active.` });
      setBoundary(res.new_boundary);
      loadData();
    } catch (err: any) {
      setActionMessage({ type: 'error', text: err.message || 'Failed to approve expansion' });
    } finally {
      setActionLoading(null);
    }
  };

  const handleDeny = async (requestId: string) => {
    if (!hasToken) {
      openAuthModal();
      return;
    }
    const reason = window.prompt(`Denial reason for request ${requestId}:`, 'Resource out of permissible task scope');
    if (reason === null) return;

    setActionLoading(requestId);
    setActionMessage(null);
    try {
      await api.denyExpansion(requestId, {
        decided_by: 'human_operator',
        reason: reason.trim() || 'Denied by human operator',
      });
      setActionMessage({ type: 'success', text: `Expansion request denied.` });
      loadData();
    } catch (err: any) {
      setActionMessage({ type: 'error', text: err.message || 'Failed to deny expansion' });
    } finally {
      setActionLoading(null);
    }
  };

  const copyReceiptToClipboard = () => {
    if (!receiptRes?.receipt) return;
    navigator.clipboard.writeText(JSON.stringify(receiptRes.receipt, null, 2));
    setCopiedReceipt(true);
    setTimeout(() => setCopiedReceipt(false), 2000);
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center p-12 text-slate-400 font-mono text-xs">
        Loading task telemetry and boundary...
      </div>
    );
  }

  if (!task) {
    return (
      <EmptyState
        icon="alert"
        title="Task Not Found"
        description={`The requested task ID '${taskId}' could not be located in the governance database.`}
        action={{ label: 'Back to Tasks', onClick: () => window.history.back() }}
      />
    );
  }

  // Determine event layer
  const getEventLayer = (ev: TaskEvent) => {
    const src = (ev.source || '').toLowerCase();
    const ch = (ev.channel || '').toLowerCase();
    if (src.includes('proxy') || ch.includes('proxy')) return 'Egress Proxy';
    if (src.includes('sensor') || src.includes('os') || ch.includes('shell')) return 'OS Sandbox (Landlock)';
    return 'Tool Broker';
  };

  return (
    <div className="space-y-8 animate-in fade-in duration-300">
      {/* Header & Back link */}
      <div>
        <Link
          to="/tasks"
          className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-500 hover:text-cyan-500 dark:hover:text-cyan-400 transition-colors mb-3"
        >
          <ArrowLeft className="w-3.5 h-3.5" />
          <span>Back to Tasks list</span>
        </Link>

        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center gap-3 flex-wrap">
              <h1 className="text-xl sm:text-2xl font-bold font-mono tracking-tight text-slate-900 dark:text-white">
                {task.task_id}
              </h1>
              <Badge variant={task.status === 'COMPLETED' ? 'allowed' : task.status === 'ACTIVE' ? 'cyan' : 'neutral'}>
                {task.status}
              </Badge>
              <span className="text-xs font-mono text-slate-400 bg-slate-100 dark:bg-slate-800 px-2 py-0.5 rounded">
                agent: {task.agent_id}
              </span>
              {(task.llm_provider === 'scripted' || task.llm_provider === 'scripted_mock' || receiptRes?.receipt?.extra?.llm_provider === 'scripted' || receiptRes?.receipt?.extra?.llm_provider === 'scripted_mock') && (
                <span className="text-xs font-medium px-2 py-0.5 rounded-full bg-indigo-500/10 text-indigo-600 dark:text-indigo-400 border border-indigo-500/30">
                  Scripted demo
                </span>
              )}
            </div>
            <p className="text-xs text-slate-400 font-mono">
              Created: {new Date(task.created_at).toLocaleString()} · Workspace: {task.workspace_root}
            </p>
          </div>

          {/* Receipt badge */}
          <div className="flex items-center gap-2 self-start sm:self-auto">
            {receiptRes?.available && receiptRes.verified ? (
              <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/30 text-xs font-medium">
                <CheckCircle className="w-4 h-4 text-emerald-500" />
                <span>Hash Chain Verified</span>
              </div>
            ) : receiptRes?.available && !receiptRes.verified ? (
              <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-rose-500/10 text-rose-600 dark:text-rose-400 border border-rose-500/30 text-xs font-medium">
                <AlertTriangle className="w-4 h-4 text-rose-500" />
                <span>Hash Chain Invalid</span>
              </div>
            ) : (
              <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400 border border-slate-200 dark:border-slate-700 text-xs font-medium">
                <FileCheck2 className="w-4 h-4 text-slate-400" />
                <span>No stored receipt</span>
              </div>
            )}
          </div>
        </div>
      </div>

      {actionMessage && (
        <div
          className={`p-3 rounded-xl border text-xs font-medium ${
            actionMessage.type === 'success'
              ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/30'
              : 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/30'
          }`}
        >
          {actionMessage.text}
        </div>
      )}

      {/* Task Request Prompt */}
      <div className="p-5 rounded-2xl bg-white dark:bg-surface-cardDark border border-slate-200 dark:border-slate-800 space-y-2">
        <div className="flex items-center justify-between">
          <span className="text-xs font-bold uppercase tracking-wider text-slate-400">User Prompt Request</span>
          {task.request_hash && (
            <span className="text-[11px] font-mono text-slate-400 truncate max-w-xs" title={`SHA-256: ${task.request_hash}`}>
              SHA-256: {task.request_hash.slice(0, 16)}...
            </span>
          )}
        </div>
        <p className="text-sm font-medium text-slate-800 dark:text-slate-200 leading-relaxed font-sans bg-slate-50 dark:bg-slate-900/60 p-3.5 rounded-xl border border-slate-100 dark:border-slate-800">
          "{task.request_text}"
        </p>
      </div>

      {/* Derived Boundary Chips */}
      <div className="p-5 rounded-2xl bg-white dark:bg-surface-cardDark border border-slate-200 dark:border-slate-800 space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Layers className="w-4 h-4 text-cyan-500" />
            <h2 className="text-sm font-bold uppercase tracking-wider text-slate-900 dark:text-white">
              Derived Task Boundary
            </h2>
          </div>
          {boundary?.version && (
            <span className="text-xs font-mono text-slate-400">Version: v{boundary.version}</span>
          )}
        </div>

        {boundary ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {/* Files Read */}
            <div className="space-y-2 p-3.5 rounded-xl bg-slate-50 dark:bg-slate-900/40 border border-slate-100 dark:border-slate-800">
              <span className="text-xs font-bold uppercase tracking-wider text-slate-400 block">
                Readable Files ({boundary.files_read?.length || 0})
              </span>
              <div className="flex flex-wrap gap-1.5">
                {boundary.files_read?.length > 0 ? (
                  boundary.files_read.map(f => (
                    <span key={f} className="text-xs font-mono px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20">
                      {f}
                    </span>
                  ))
                ) : (
                  <span className="text-xs text-slate-400 font-mono italic">None</span>
                )}
              </div>
            </div>

            {/* Files Write */}
            <div className="space-y-2 p-3.5 rounded-xl bg-slate-50 dark:bg-slate-900/40 border border-slate-100 dark:border-slate-800">
              <span className="text-xs font-bold uppercase tracking-wider text-slate-400 block">
                Writable Files ({boundary.files_write?.length || 0})
              </span>
              <div className="flex flex-wrap gap-1.5">
                {boundary.files_write?.length > 0 ? (
                  boundary.files_write.map(f => (
                    <span key={f} className="text-xs font-mono px-2 py-0.5 rounded bg-blue-500/10 text-blue-600 dark:text-blue-400 border border-blue-500/20">
                      {f}
                    </span>
                  ))
                ) : (
                  <span className="text-xs text-slate-400 font-mono italic">None</span>
                )}
              </div>
            </div>

            {/* Allowed Tools */}
            <div className="space-y-2 p-3.5 rounded-xl bg-slate-50 dark:bg-slate-900/40 border border-slate-100 dark:border-slate-800">
              <span className="text-xs font-bold uppercase tracking-wider text-slate-400 block">
                Permitted Tools ({boundary.tools?.length || 0})
              </span>
              <div className="flex flex-wrap gap-1.5">
                {boundary.tools?.length > 0 ? (
                  boundary.tools.map(t => (
                    <span key={t} className="text-xs font-mono px-2 py-0.5 rounded bg-indigo-500/10 text-indigo-600 dark:text-indigo-400 border border-indigo-500/20">
                      {t}
                    </span>
                  ))
                ) : (
                  <span className="text-xs text-slate-400 font-mono italic">None</span>
                )}
              </div>
            </div>

            {/* Allowed Network Hosts / Peer Agents */}
            <div className="space-y-2 p-3.5 rounded-xl bg-slate-50 dark:bg-slate-900/40 border border-slate-100 dark:border-slate-800">
              <span className="text-xs font-bold uppercase tracking-wider text-slate-400 block">
                Network & Peers
              </span>
              <div className="flex flex-wrap gap-1.5">
                {boundary.network_hosts && boundary.network_hosts.length > 0 ? (
                  boundary.network_hosts.map(h => (
                    <span key={h} className="text-xs font-mono px-2 py-0.5 rounded bg-amber-500/10 text-amber-600 dark:text-amber-400 border border-amber-500/20">
                      {h}
                    </span>
                  ))
                ) : (
                  <span className="text-xs text-slate-400 font-mono italic">Loopback only</span>
                )}
              </div>
            </div>
          </div>
        ) : (
          <p className="text-xs text-slate-400 italic">No boundary derived for this task.</p>
        )}
      </div>

      {/* Mid-Task Expansions Section */}
      <div className="p-5 rounded-2xl bg-white dark:bg-surface-cardDark border border-slate-200 dark:border-slate-800 space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <KeyRound className="w-4 h-4 text-amber-500" />
            <h2 className="text-sm font-bold uppercase tracking-wider text-slate-900 dark:text-white">
              Resource Expansions ({expansions.length})
            </h2>
          </div>
          <span className="text-xs text-slate-400 font-mono">Requires Operator Token</span>
        </div>

        {expansions.length === 0 ? (
          <p className="text-xs text-slate-400 italic font-mono">
            No mid-task expansions requested. The agent operated strictly within its initial boundary.
          </p>
        ) : (
          <div className="space-y-3">
            {expansions.map(exp => (
              <div
                key={exp.request_id}
                className="p-4 rounded-xl bg-slate-50 dark:bg-slate-900/40 border border-slate-200 dark:border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-4"
              >
                <div className="space-y-1.5">
                  <div className="flex items-center gap-2.5 flex-wrap">
                    <span className="font-mono text-xs font-bold text-slate-800 dark:text-slate-200">
                      {exp.request_id}
                    </span>
                    <Badge variant={exp.status === 'APPROVED' ? 'allowed' : exp.status === 'PENDING' ? 'pending' : 'blocked'}>
                      {exp.status}
                    </Badge>
                    <span className="text-xs font-mono text-slate-500">
                      type: {exp.resource_type}
                    </span>
                    <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-200 dark:bg-slate-800 text-slate-700 dark:text-slate-300">
                      {exp.resource_target}
                    </span>
                  </div>

                  <p className="text-xs text-slate-600 dark:text-slate-300 font-sans">
                    <strong>Justification:</strong> {exp.justification}
                  </p>

                  <div className="flex items-center gap-4 text-[11px] text-slate-400 font-mono">
                    <span>Baseline Risk: {exp.baseline_risk_tier}</span>
                    <span>Effective Risk: {exp.effective_risk_tier}</span>
                    {exp.provenance_escalation && (
                      <span className="text-amber-500 font-bold">Provenance Escalated</span>
                    )}
                  </div>
                </div>

                {exp.status === 'PENDING' && (
                  <div className="flex items-center gap-2 shrink-0">
                    <button
                      onClick={() => handleApprove(exp.request_id)}
                      disabled={actionLoading === exp.request_id}
                      className="px-3 py-1.5 text-xs font-medium text-white bg-emerald-600 hover:bg-emerald-500 rounded-lg transition-colors flex items-center gap-1"
                    >
                      <CheckCircle className="w-3.5 h-3.5" />
                      <span>Approve</span>
                    </button>
                    <button
                      onClick={() => handleDeny(exp.request_id)}
                      disabled={actionLoading === exp.request_id}
                      className="px-3 py-1.5 text-xs font-medium text-white bg-rose-600 hover:bg-rose-500 rounded-lg transition-colors flex items-center gap-1"
                    >
                      <XCircle className="w-3.5 h-3.5" />
                      <span>Deny</span>
                    </button>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Event Timeline */}
      <div className="p-5 rounded-2xl bg-white dark:bg-surface-cardDark border border-slate-200 dark:border-slate-800 space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4 text-cyan-500" />
            <h2 className="text-sm font-bold uppercase tracking-wider text-slate-900 dark:text-white">
              Event Timeline ({events.length} actions)
            </h2>
          </div>
          <span className="text-xs font-mono text-slate-400">Mediated at Broker, OS & Proxy layers</span>
        </div>

        {events.length === 0 ? (
          <EmptyState
            icon="search"
            title="No Events Recorded"
            description="No actions or tool calls were recorded for this task."
          />
        ) : (
          <div className="space-y-2.5">
            {events.map((ev, idx) => {
              const layer = getEventLayer(ev);
              const isBlocked = ev.verdict === 'OUTSIDE' || ev.prevented;
              const isExpanded = expandedEventId === idx;

              return (
                <div
                  key={idx}
                  className={`p-3.5 rounded-xl border transition-all ${
                    isBlocked
                      ? 'border-rose-500/40 bg-rose-500/5 dark:bg-rose-950/20'
                      : 'border-slate-200 dark:border-slate-800/80 bg-slate-50/50 dark:bg-slate-900/30'
                  }`}
                >
                  <div
                    className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 cursor-pointer"
                    onClick={() => setExpandedEventId(isExpanded ? null : idx)}
                  >
                    <div className="flex items-center gap-2.5 flex-wrap">
                      <span className="font-mono text-xs text-slate-400">
                        #{idx + 1}
                      </span>
                      <Badge variant={ev.verdict === 'INSIDE' ? 'allowed' : 'blocked'} size="sm">
                        {ev.verdict}
                      </Badge>
                      <span className="text-xs font-mono font-semibold text-slate-800 dark:text-slate-200">
                        {ev.kind}
                      </span>
                      <span className="text-[11px] font-mono text-slate-400 px-2 py-0.5 rounded bg-slate-200 dark:bg-slate-800">
                        {layer}
                      </span>
                      {ev.target && (
                        <span className="text-xs font-mono text-slate-600 dark:text-slate-300 truncate max-w-sm">
                          {ev.target}
                        </span>
                      )}
                    </div>

                    <div className="flex items-center gap-3 text-xs text-slate-400 font-mono">
                      {ev.prevented_by && ev.prevented_by !== 'none' && (
                        <span className="text-rose-500 font-bold">
                          prevented by {ev.prevented_by}
                        </span>
                      )}
                      <span>{new Date(ev.timestamp).toLocaleTimeString()}</span>
                      {isExpanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                    </div>
                  </div>

                  {isExpanded && (
                    <div className="mt-3 pt-3 border-t border-slate-200 dark:border-slate-800 text-xs font-mono text-slate-600 dark:text-slate-400 space-y-1">
                      <div><strong>Source:</strong> {ev.source}</div>
                      <div><strong>Action Taken:</strong> {ev.action_taken || 'ALLOW'}</div>
                      <div><strong>Rule Matched:</strong> {ev.rule_matched || 'N/A'}</div>
                      {ev.details && (
                        <div className="mt-2">
                          <strong>Details:</strong>
                          <pre className="mt-1 p-2 bg-slate-100 dark:bg-slate-900 rounded text-[11px] overflow-x-auto text-slate-800 dark:text-slate-300">
                            {JSON.stringify(ev.details, null, 2)}
                          </pre>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Task Receipt Section */}
      {receiptRes && receiptRes.available ? (
        <div className="p-5 rounded-2xl bg-white dark:bg-surface-cardDark border border-slate-200 dark:border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <FileCheck2 className="w-5 h-5 text-emerald-500" />
              <div>
                <h2 className="text-base font-bold text-slate-900 dark:text-white">
                  Task Receipt v0 (Hash-Chained)
                </h2>
                <p className="text-xs text-slate-500 dark:text-slate-400">
                  Hash-chained audit record per task. Recomputed via SHA-256.
                </p>
              </div>
            </div>

            <div className="flex items-center gap-2">
              <a
                href={`/api/governance/tasks/${taskId}/receipt/raw`}
                download={`${taskId}_receipt.json`}
                id="download-receipt-btn"
                className="px-3 py-1.5 text-xs font-semibold text-white bg-cyan-600 hover:bg-cyan-500 rounded-lg transition-colors flex items-center gap-1.5 shadow-sm"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Download receipt (JSON)</span>
              </a>
              <button
                onClick={copyReceiptToClipboard}
                className="p-1.5 text-xs text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white bg-slate-100 dark:bg-slate-800 rounded-lg transition-colors flex items-center gap-1"
                title="Copy receipt JSON"
              >
                {copiedReceipt ? <Check className="w-3.5 h-3.5 text-emerald-500" /> : <Copy className="w-3.5 h-3.5" />}
                <span className="hidden sm:inline">{copiedReceipt ? 'Copied' : 'Copy JSON'}</span>
              </button>
              <button
                onClick={() => setShowReceiptJson(!showReceiptJson)}
                className="px-3 py-1.5 text-xs font-medium text-cyan-600 dark:text-cyan-400 border border-cyan-500/30 rounded-lg hover:bg-cyan-500/10 transition-colors"
              >
                {showReceiptJson ? 'Hide JSON' : 'Inspect Raw JSON'}
              </button>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-4 gap-3 p-3.5 bg-slate-50 dark:bg-slate-900/50 rounded-xl border border-slate-200/80 dark:border-slate-800 font-mono text-xs">
            <div>
              <span className="text-slate-400 block text-[11px]">HASH CHAIN STATUS</span>
              <span className={`font-bold ${receiptRes.verified ? 'text-emerald-500' : 'text-rose-500'}`}>
                {receiptRes.verified ? 'VERIFIED (SHA-256)' : 'VERIFICATION FAILED'}
              </span>
            </div>
            <div>
              <span className="text-slate-400 block text-[11px]">CHAINED EVENTS</span>
              <span className="font-bold text-slate-800 dark:text-slate-200">
                {receiptRes.receipt?.hash_chain?.count || receiptRes.receipt?.events?.length || 0} entries
              </span>
            </div>
            <div className="truncate">
              <span className="text-slate-400 block text-[11px]">FINAL HASH</span>
              <span className="font-bold text-slate-800 dark:text-slate-200 truncate block" title={receiptRes.final_hash || receiptRes.receipt?.hash_chain?.final_hash}>
                {(receiptRes.final_hash || receiptRes.receipt?.hash_chain?.final_hash) ? `${(receiptRes.final_hash || receiptRes.receipt?.hash_chain?.final_hash)?.slice(0, 16)}...` : 'N/A'}
              </span>
            </div>
            <div className="truncate">
              <span className="text-slate-400 block text-[11px]">FILE SHA-256</span>
              <span className="font-bold text-slate-800 dark:text-slate-200 truncate block" title={receiptRes.file_sha256 || 'N/A'}>
                {receiptRes.file_sha256 ? `${receiptRes.file_sha256.slice(0, 16)}...` : 'N/A'}
              </span>
            </div>
          </div>
          <div className="flex items-center justify-between text-[11px] font-mono text-slate-500 dark:text-slate-400 px-1">
            <span>Check with <code className="bg-slate-100 dark:bg-slate-800 px-1.5 py-0.5 rounded text-slate-700 dark:text-slate-300">scripts/verify_receipt.py</code></span>
            {receiptRes.receipt_file && <span className="truncate max-w-xs">{receiptRes.receipt_file}</span>}
          </div>

          {showReceiptJson && (
            <pre className="p-4 rounded-xl bg-slate-950 text-slate-200 font-mono text-xs overflow-x-auto max-h-96 border border-slate-800">
              {JSON.stringify(receiptRes.receipt, null, 2)}
            </pre>
          )}
        </div>
      ) : (
        <div className="p-5 rounded-2xl bg-white dark:bg-surface-cardDark border border-slate-200 dark:border-slate-800 space-y-2">
          <div className="flex items-center gap-2">
            <FileCheck2 className="w-5 h-5 text-slate-400" />
            <div>
              <h2 className="text-base font-bold text-slate-900 dark:text-white">
                Task Receipt
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                No stored receipt exists for this task.
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
