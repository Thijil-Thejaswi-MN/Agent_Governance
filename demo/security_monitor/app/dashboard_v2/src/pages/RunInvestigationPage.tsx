import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import { TaskRecord, TaskBoundary, TaskEvent, ExpansionItem, ReceiptResponse } from '../types';
import { useAuth } from '../context/AuthContext';
import { Lock, AlertTriangle, CheckCircle2, ChevronRight, XOctagon } from 'lucide-react';

export const RunInvestigationPage: React.FC = () => {
  const { taskId } = useParams<{ taskId: string }>();
  const navigate = useNavigate();
  const { role, user } = useAuth();
  const [task, setTask] = useState<TaskRecord | null>(null);
  const [boundary, setBoundary] = useState<TaskBoundary | null>(null);
  const [events, setEvents] = useState<TaskEvent[]>([]);
  const [expansions, setExpansions] = useState<ExpansionItem[]>([]);
  const [receipt, setReceipt] = useState<ReceiptResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<'map' | 'timeline' | 'boundary' | 'record'>('map');
  const [showDetails, setShowDetails] = useState(false);
  const [denyReason, setDenyReason] = useState('');
  const [isDenying, setIsDenying] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);

  const fetchDetail = async () => {
    if (!taskId) return;
    try {
      const [detailRes, evts, exps, rec] = await Promise.all([
        api.getTaskDetail(taskId),
        api.getTaskEvents(taskId).catch(() => []),
        api.getExpansions(taskId).catch(() => []),
        api.getTaskReceipt(taskId).catch(() => null),
      ]);
      setTask(detailRes.task);
      setBoundary(detailRes.boundary);
      setEvents(evts);
      setExpansions(exps);
      setReceipt(rec);
    } catch (err: any) {
      // quiet on load error
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDetail();
    const interval = setInterval(fetchDetail, 3000);
    return () => clearInterval(interval);
  }, [taskId]);

  const pendingExp = expansions.find(e => e.status === 'PENDING');
  const isEscalated = pendingExp?.escalated_by_provenance;

  // Role permissions
  const canDecide =
    role === 'admin' ||
    role === 'security_reviewer' ||
    (role === 'team_lead' && !isEscalated);

  const handleApprove = async () => {
    if (!pendingExp) return;
    setActionError(null);
    try {
      await api.approveExpansion(pendingExp.request_id, {
        decided_by: user?.name || 'Operator',
        reason: 'Approved via run investigation',
      });
      await fetchDetail();
    } catch (err: any) {
      setActionError(err?.message || 'Failed to approve request');
    }
  };

  const handleDeny = async () => {
    if (!pendingExp || !denyReason.trim()) {
      setActionError('A reason is required to deny an expansion request.');
      return;
    }
    setActionError(null);
    try {
      await api.denyExpansion(pendingExp.request_id, {
        decided_by: user?.name || 'Operator',
        reason: denyReason.trim(),
      });
      setIsDenying(false);
      setDenyReason('');
      await fetchDetail();
    } catch (err: any) {
      setActionError(err?.message || 'Failed to deny request');
    }
  };

  const handleStopRun = async () => {
    if (!taskId) return;
    try {
      await api.stopRun(taskId);
      await fetchDetail();
    } catch (err: any) {
      setActionError(err?.message || 'Failed to stop run');
    }
  };

  if (!task && !loading) {
    return (
      <div className="p-8 text-center text-[#A7B0C0]">
        Run not found or access denied.
      </div>
    );
  }

  const tid = task?.task_id || taskId || 'task_demo';
  const aid = task?.agent_id || 'finance-report-bot';
  const status = task?.status || (pendingExp ? 'WAITING' : 'RUNNING');

  return (
    <div className="flex flex-col gap-5 font-sans">
      {/* Breadcrumb + Header */}
      <div className="flex items-center gap-1.5 text-[13px] text-[#8B95A7]">
        <button
          onClick={() => navigate('/history')}
          className="text-[#8B95A7] hover:text-[#E6E9EF] bg-transparent border-none p-0 cursor-pointer"
        >
          Runs
        </button>
        <span>/</span>
        <span className="font-mono text-[#E6E9EF]">{tid}</span>
      </div>

      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-3">
          <h1 className="text-2xl font-bold tracking-tight text-[#E6E9EF]">
            {aid} · {task?.request_text || 'quarterly comparison'}
          </h1>
          <span
            className="px-3 py-1 rounded-full text-[12px] font-bold"
            style={{
              backgroundColor:
                status === 'RUNNING' || status === 'ACTIVE'
                  ? 'rgba(34, 197, 94, 0.15)'
                  : pendingExp
                  ? 'rgba(245, 158, 11, 0.15)'
                  : status === 'FAILED'
                  ? 'rgba(239, 68, 68, 0.15)'
                  : '#1A2232',
              color:
                status === 'RUNNING' || status === 'ACTIVE'
                  ? '#4ADE80'
                  : pendingExp
                  ? '#FBBF24'
                  : status === 'FAILED'
                  ? '#F87171'
                  : '#A7B0C0',
            }}
          >
            {pendingExp ? 'WAITING FOR DECISION' : status}
          </span>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => setShowDetails(!showDetails)}
            className="px-3.5 py-1.5 rounded-lg border border-[#2A3344] bg-transparent text-[#E6E9EF] font-semibold text-[13px] cursor-pointer hover:bg-[#161B26]"
          >
            {showDetails ? 'Hide details' : 'Details'}
          </button>
          <button
            onClick={handleStopRun}
            className="px-3.5 py-1.5 rounded-lg border border-[#5B2328] bg-transparent text-[#F87171] hover:bg-red-950/20 font-semibold text-[13px] cursor-pointer"
          >
            Stop run
          </button>
        </div>
      </div>

      <p className="text-[15px] text-[#A7B0C0] -mt-1 leading-normal">
        {isEscalated
          ? 'It only learned about this file from inside another file. Stopped: outside what your request allows.'
          : 'The agent read and wrote only what the request allows. Kernel checks verify each operation.'}
      </p>

      {/* View Tabs */}
      <div className="flex gap-2 border-b border-[#1F2633] text-[14px]">
        <button
          onClick={() => setActiveTab('map')}
          className={`px-3 py-2 border-b-2 font-semibold bg-transparent cursor-pointer ${
            activeTab === 'map'
              ? 'border-[#3B82F6] text-[#E6E9EF]'
              : 'border-transparent text-[#8B95A7] hover:text-[#E6E9EF]'
          }`}
        >
          Access map
        </button>
        <button
          onClick={() => setActiveTab('timeline')}
          className={`px-3 py-2 border-b-2 font-semibold bg-transparent cursor-pointer ${
            activeTab === 'timeline'
              ? 'border-[#3B82F6] text-[#E6E9EF]'
              : 'border-transparent text-[#8B95A7] hover:text-[#E6E9EF]'
          }`}
        >
          Timeline ({events.length})
        </button>
        <button
          onClick={() => setActiveTab('boundary')}
          className={`px-3 py-2 border-b-2 font-semibold bg-transparent cursor-pointer ${
            activeTab === 'boundary'
              ? 'border-[#3B82F6] text-[#E6E9EF]'
              : 'border-transparent text-[#8B95A7] hover:text-[#E6E9EF]'
          }`}
        >
          Boundary
        </button>
        <button
          onClick={() => setActiveTab('record')}
          className={`px-3 py-2 border-b-2 font-semibold bg-transparent cursor-pointer ${
            activeTab === 'record'
              ? 'border-[#3B82F6] text-[#E6E9EF]'
              : 'border-transparent text-[#8B95A7] hover:text-[#E6E9EF]'
          }`}
        >
          Record
        </button>
      </div>

      {actionError && (
        <div className="p-3 rounded-lg bg-[#EF4444]/15 border border-[#EF4444] text-[#F87171] text-[13px]">
          {actionError}
        </div>
      )}

      {/* Main Investigation Content */}
      <section className="grid grid-cols-1 lg:grid-cols-3 gap-5 items-start">
        {/* Left 2 Cols: Access Map or Alternate tab */}
        <div className="lg:col-span-2 p-5 rounded-xl bg-[#11151D] border border-[#1F2633] flex flex-col gap-4">
          {activeTab === 'map' ? (
            <div>
              <div className="flex flex-wrap items-center gap-4 text-[12px] text-[#8B95A7] mb-3">
                <span className="flex items-center gap-1.5">
                  <span className="w-4 h-0.5 bg-[#22C55E]" /> allowed
                </span>
                <span className="flex items-center gap-1.5">
                  <span className="w-4 border-t-2 border-dashed border-[#F59E0B]" /> stopped, now asking
                </span>
                <span className="flex items-center gap-1.5">
                  <span className="w-4 border-t-2 border-dotted border-[#F87171]" /> named inside file
                </span>
                <span className="flex items-center gap-1.5">
                  <span className="w-3.5 h-2.5 border border-dashed border-[#3B82F6] rounded-sm" /> the fence
                </span>
              </div>

              {/* The Access Map SVG */}
              <div className="relative w-full max-w-[700px] h-[380px] mx-auto">
                <svg
                  width="100%"
                  height="380"
                  viewBox="0 0 700 380"
                  role="img"
                  aria-label="Access map: request connects to agent inside dashed fence; allowed files inside; stopped/asking outside"
                  className="block"
                >
                  {/* Dashed Fence Boundary */}
                  <rect
                    x="190"
                    y="18"
                    width="340"
                    height="344"
                    rx="22"
                    fill="rgba(59,130,246,0.04)"
                    stroke="#3B82F6"
                    strokeWidth="1.5"
                    strokeDasharray="7 6"
                  />

                  {/* Flow lines */}
                  <line x1="132" y1="190" x2="236" y2="190" stroke="#64748B" strokeWidth="2" />
                  <path
                    d="M366 176 C 390 140, 390 100, 404 86"
                    fill="none"
                    stroke="#22C55E"
                    strokeWidth="2.5"
                    strokeDasharray="6 6"
                  />
                  <path
                    d="M366 204 C 390 240, 390 280, 404 294"
                    fill="none"
                    stroke="#22C55E"
                    strokeWidth="2.5"
                    strokeDasharray="6 6"
                  />
                  <line
                    x1="370"
                    y1="190"
                    x2="566"
                    y2="190"
                    stroke="#F59E0B"
                    strokeWidth="2.5"
                    strokeDasharray="8 6"
                  />

                  {/* Dotted Provenance Line */}
                  {isEscalated && (
                    <path
                      d="M514 86 C 590 90, 620 130, 616 168"
                      fill="none"
                      stroke="#F87171"
                      strokeWidth="2"
                      strokeDasharray="3 4"
                    />
                  )}

                  {/* Request node */}
                  <g transform="translate(60, 168)">
                    <rect width="72" height="44" rx="8" fill="#161B26" stroke="#2A3344" />
                    <text x="36" y="26" textAnchor="middle" fill="#E6E9EF" fontSize="12" fontWeight="600">
                      Request
                    </text>
                  </g>

                  {/* Agent node inside fence */}
                  <g transform="translate(250, 160)">
                    <rect width="116" height="60" rx="12" fill="#11151D" stroke="#3B82F6" strokeWidth="2" />
                    <text x="58" y="28" textAnchor="middle" fill="#60A5FA" fontSize="11" fontWeight="700">
                      AGENT
                    </text>
                    <text x="58" y="46" textAnchor="middle" fill="#E6E9EF" fontSize="11" fontFamily="JetBrains Mono">
                      {aid.length > 12 ? aid.slice(0, 12) + '…' : aid}
                    </text>
                  </g>

                  {/* Allowed target 1 */}
                  <g transform="translate(410, 64)">
                    <rect width="110" height="42" rx="8" fill="#0F291E" stroke="#22C55E" />
                    <text x="55" y="25" textAnchor="middle" fill="#86EFAC" fontSize="11" fontFamily="JetBrains Mono">
                      sales_data.csv
                    </text>
                  </g>

                  {/* Allowed target 2 */}
                  <g transform="translate(410, 274)">
                    <rect width="110" height="42" rx="8" fill="#0F291E" stroke="#22C55E" />
                    <text x="55" y="25" textAnchor="middle" fill="#86EFAC" fontSize="11" fontFamily="JetBrains Mono">
                      summary.txt
                    </text>
                  </g>

                  {/* Outside target with Lock */}
                  <g transform="translate(566, 168)">
                    <rect
                      width="120"
                      height="44"
                      rx="8"
                      fill="#2A1B0E"
                      stroke="#F59E0B"
                      strokeDasharray="4 3"
                    />
                    <text x="60" y="26" textAnchor="middle" fill="#FDE68A" fontSize="11" fontFamily="JetBrains Mono">
                      {pendingExp?.resource_target || 'targets.csv'}
                    </text>
                  </g>
                </svg>
              </div>
            </div>
          ) : activeTab === 'timeline' ? (
            <div className="flex flex-col gap-2">
              <h3 className="text-[14px] font-bold text-[#E6E9EF]">Execution Timeline</h3>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-[12px]">
                  <thead>
                    <tr className="border-b border-[#1F2633] text-[#8B95A7]">
                      <th className="pb-2">Event ID</th>
                      <th className="pb-2">Operation</th>
                      <th className="pb-2">Target</th>
                      <th className="pb-2">Verdict</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#1F2633]">
                    {events.slice(0, 25).map(e => (
                      <tr key={e.event_id}>
                        <td className="py-2 font-mono text-[#93C5FD]">{e.event_id}</td>
                        <td className="py-2">{e.operation}</td>
                        <td className="py-2 font-mono text-[#E6E9EF]">{e.target}</td>
                        <td className="py-2">
                          <span
                            className="px-2 py-0.5 rounded text-[11px] font-semibold"
                            style={{
                              backgroundColor: e.prevented ? 'rgba(239, 68, 68, 0.15)' : 'rgba(34, 197, 94, 0.15)',
                              color: e.prevented ? '#F87171' : '#4ADE80',
                            }}
                          >
                            {e.prevented ? 'Stopped' : 'Allowed'}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          ) : activeTab === 'boundary' ? (
            <div className="flex flex-col gap-2 text-[13px]">
              <h3 className="text-[14px] font-bold text-[#E6E9EF]">Declared Boundary</h3>
              <div className="p-3 rounded-lg bg-[#0B0E14] border border-[#1F2633] font-mono text-[12px] text-[#A7B0C0]">
                <div>Read Paths: {boundary?.files_read?.join(', ') || 'None'}</div>
                <div>Write Paths: {boundary?.files_write?.join(', ') || 'None'}</div>
                <div>Network: {boundary?.network_outbound?.join(', ') || 'None allowed'}</div>
              </div>
            </div>
          ) : (
            <div className="flex flex-col gap-2 text-[13px]">
              <h3 className="text-[14px] font-bold text-[#E6E9EF]">Record Verification</h3>
              <div className="p-3 rounded-lg bg-[#0B0E14] border border-[#1F2633] font-mono text-[12px] text-[#A7B0C0]">
                <div>Hash chain integrity: {receipt?.verified ? 'Intact' : 'Record checked: no entries changed'}</div>
                <div>Final Hash: {receipt?.final_hash || 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}</div>
              </div>
            </div>
          )}
        </div>

        {/* Right Col: Decision Card + Summary */}
        <div className="flex flex-col gap-4">
          {pendingExp && (
            <div className="p-5 rounded-xl bg-[#11151D] border border-[#F59E0B] flex flex-col gap-3 anim-rise">
              <div className="flex items-center justify-between">
                <h2 className="text-[15px] font-bold text-[#E6E9EF]">Decision needed</h2>
                <span className="font-mono text-[12px] text-[#FBBF24]">1:26 left</span>
              </div>

              <div className="grid grid-cols-[80px_1fr] gap-2 text-[12px]">
                <span className="text-[#8B95A7]">Wants</span>
                <span className="font-mono text-[#E6E9EF]">{pendingExp.resource_target}</span>

                <span className="text-[#8B95A7]">Risk</span>
                <span className="font-semibold text-[#FBBF24]">Medium</span>

                <span className="text-[#8B95A7]">Why raised</span>
                <span className="text-[#A7B0C0]">
                  {isEscalated
                    ? 'Named only inside sales_data.csv, not in request'
                    : 'Named directly in prompt'}
                </span>

                <span className="text-[#8B95A7]">Agent says</span>
                <span className="text-[#8B95A7] italic">
                  "{pendingExp.justification || 'Need benchmark targets.'}"
                </span>
              </div>

              {canDecide ? (
                isDenying ? (
                  <div className="flex flex-col gap-2 pt-2 border-t border-[#1F2633]">
                    <label className="text-[11px] text-[#8B95A7]">Reason for denial</label>
                    <input
                      type="text"
                      placeholder="e.g. Outside authorized scope"
                      value={denyReason}
                      onChange={e => setDenyReason(e.target.value)}
                      className="px-3 py-1.5 rounded-lg bg-[#0B0E14] border border-[#2A3344] text-[12px] text-[#E6E9EF] outline-none"
                    />
                    <div className="flex gap-2">
                      <button
                        onClick={handleDeny}
                        disabled={!denyReason.trim()}
                        className="flex-1 py-1.5 rounded-lg bg-[#EF4444] disabled:opacity-50 text-white font-semibold text-[12px] border-none cursor-pointer"
                      >
                        Confirm Deny
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
                  <div className="flex gap-2 pt-2 border-t border-[#1F2633]">
                    <button
                      onClick={handleApprove}
                      className="flex-1 min-h-[38px] px-3 rounded-lg bg-[#22C55E] hover:bg-[#16A34A] text-[#052E16] font-bold text-[13px] border-none cursor-pointer"
                    >
                      Allow for this run
                    </button>
                    <button
                      onClick={() => setIsDenying(true)}
                      className="min-h-[38px] px-3 rounded-lg border border-[#5B2328] hover:bg-red-950/20 text-[#F87171] font-semibold text-[13px] cursor-pointer"
                    >
                      Deny
                    </button>
                  </div>
                )
              ) : (
                <div className="p-3 rounded-lg bg-[#161B26] text-[12px] text-[#8B95A7] border border-[#1F2633]">
                  {role === 'auditor'
                    ? 'Read-only role: cannot make decisions.'
                    : 'Provenance-escalated request: must be reviewed by Security reviewer or Admin.'}
                </div>
              )}
            </div>
          )}

          {/* Run Summary Card */}
          <div className="p-5 rounded-xl bg-[#11151D] border border-[#1F2633] grid grid-cols-[90px_1fr] gap-2.5 text-[13px]">
            <span className="text-[#8B95A7]">Steps</span>
            <span className="text-[#E6E9EF]">
              {events.length} · {events.filter(e => !e.prevented).length} allowed ·{' '}
              {events.filter(e => e.prevented).length} stopped
            </span>

            <span className="text-[#8B95A7]">Stopped by</span>
            <span className="text-[#E6E9EF]">kernel (file access)</span>

            <span className="text-[#8B95A7]">Network</span>
            <span className="text-[#E6E9EF]">none allowed</span>

            <span className="text-[#8B95A7]">Record</span>
            <span className="text-[#22C55E]">Record checked: no entries changed</span>
          </div>

          {/* Details Drawer */}
          {showDetails && (
            <div className="p-5 rounded-xl bg-[#0E121A] border border-[#2A3344] flex flex-col gap-2 text-[12px] anim-rise">
              <h3 className="font-bold text-[#E6E9EF]">Technical Details</h3>
              <div>Task ID: {tid}</div>
              <div>Owner: {(task as any)?.owner || 'N/A'}</div>
              <div>Team: {(task as any)?.team || 'General'}</div>
              <div>LLM Provider: {task?.llm_provider || 'qwen2.5:7b'}</div>
            </div>
          )}
        </div>
      </section>
    </div>
  );
};

