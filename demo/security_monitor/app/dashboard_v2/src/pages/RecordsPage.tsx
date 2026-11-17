import React, { useState, useEffect } from 'react';
import { api } from '../api/client';
import { TaskRecord, ReceiptResponse, ExpansionItem } from '../types';
import { StatCard } from '../components/stats/StatCard';
import { decisionsLine, recordStats, recordsLine, stoppedLine } from '../logic/recordStats';
import { PALETTE } from '../logic/palette';
import { Download, RefreshCw, CheckCircle2, AlertCircle, FileText, ShieldX, UserCheck, FileCheck2 } from 'lucide-react';
import { PageHeader } from '../components/ui/PageHeader';

interface ChainStep {
  idx: number;
  label: string;
  detail: string;
  color: string;
}

export const RecordsPage: React.FC = () => {
  const [tasks, setTasks] = useState<TaskRecord[]>([]);
  const [expansions, setExpansions] = useState<ExpansionItem[]>([]);
  const [recordsSummary, setRecordsSummary] = useState<{ total: number; verified: number; failed: number; failed_ids: string[] } | null>(null);
  const [selectedTask, setSelectedTask] = useState<TaskRecord | null>(null);
  const [selectedReceipt, setSelectedReceipt] = useState<ReceiptResponse | null>(null);
  const [isChecking, setIsChecking] = useState(false);
  const [loading, setLoading] = useState(true);
  const [filterStop, setFilterStop] = useState(false);

  const fetchTasks = async () => {
    try {
      const [res, summary, exps] = await Promise.all([
        api.getTasks(),
        api.getRecordsSummary().catch(() => null),
        api.getExpansions().catch(() => [] as ExpansionItem[]),
      ]);
      setTasks(res);
      setExpansions(exps);
      if (summary) setRecordsSummary(summary);
      if (res.length > 0 && !selectedTask) {
        setSelectedTask(res[0]);
        loadReceipt(res[0].task_id);
      }
    } catch {
      // quiet on load error
    } finally {
      setLoading(false);
    }
  };

  const loadReceipt = async (taskId: string) => {
    try {
      const r = await api.getTaskReceipt(taskId);
      setSelectedReceipt(r);
    } catch {
      setSelectedReceipt(null);
    }
  };

  useEffect(() => {
    fetchTasks();
  }, []);

  const handleSelectTask = (t: TaskRecord) => {
    setSelectedTask(t);
    loadReceipt(t.task_id);
  };

  const handleCheckAgain = async () => {
    if (!selectedTask) return;
    setIsChecking(true);
    await loadReceipt(selectedTask.task_id);
    setIsChecking(false);
  };

  const handleExportCSV = () => {
    const headers = ['task_id', 'agent_id', 'owner', 'team', 'status', 'total_actions', 'stops', 'created_at'];
    const rows = tasks.map(t => [
      t.task_id,
      t.agent_id,
      (t as any).owner || 'N/A',
      (t as any).team || 'N/A',
      t.status,
      t.total_actions,
      t.prevented_count || t.os_denials_count || 0,
      t.created_at,
    ]);
    const csvContent = 'data:text/csv;charset=utf-8,' + [headers.join(','), ...rows.map(e => e.join(','))].join('\n');
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', `records_export_${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const filteredTasks = filterStop
    ? tasks.filter(t => (t.prevented_count || t.os_denials_count || 0) > 0)
    : tasks;

  // Vertical chain steps calculation
  const getChainSteps = (): ChainStep[] => {
    if (!selectedTask) return [];
    const steps: ChainStep[] = [
      {
        idx: 0,
        label: 'Request',
        detail: `User asked: ${selectedTask.request_text.slice(0, 48)}...`,
        color: PALETTE.ok,
      },
      {
        idx: 1,
        label: 'Fence set',
        detail: `Workspace: ${selectedTask.workspace_root}`,
        color: PALETTE.ok,
      },
    ];

    if ((selectedTask.prevented_count || selectedTask.os_denials_count || 0) > 0) {
      steps.push({
        idx: steps.length,
        label: 'Stopped',
        detail: 'Tried to access target outside boundary',
        color: PALETTE.bad,
      });
    }

    steps.push({
      idx: steps.length,
      label: 'Finished',
      detail: `Status: ${selectedTask.status}`,
      color: selectedTask.status === 'FAILED' ? PALETTE.bad : PALETTE.ok,
    });

    return steps;
  };

  const chainSteps = getChainSteps();
  const stats = recordStats(tasks, expansions, recordsSummary);

  return (
    <div className="flex flex-col gap-6 font-sans">
      {/* Headline */}
      <PageHeader
        title={
          recordsSummary
            ? recordsSummary.total === 0
              ? 'No records yet.'
              : recordsSummary.failed > 0
              ? `${recordsSummary.failed} of ${recordsSummary.total} records failed the check.`
              : `${recordsSummary.total} records. All ${recordsSummary.total} checked: no entries changed.`
            : tasks.length === 0
            ? 'No records yet.'
            : `${tasks.length} records. Checking them…`
        }
        titleClassName={
          recordsSummary
            ? recordsSummary.total === 0
              ? 'text-fg-3'
              : recordsSummary.failed > 0
              ? 'text-bad'
              : 'text-fg'
            : tasks.length === 0
            ? 'text-fg-3'
            : 'text-fg'
        }
        subtitle={
          <>
            {recordsSummary && recordsSummary.failed > 0 && (
              <div className="text-[13px] text-bad-text font-mono mb-1">
                Failed runs: {recordsSummary.failed_ids.join(', ')}
              </div>
            )}
            <span>
              Each run keeps an ordered record where every entry is linked to the one before it, so a changed or
              missing entry shows up.
            </span>
          </>
        }
      />

      {/* What the records show: three numbers, each counted from real records (logic/recordStats.ts). */}
      <section id="records-stats" aria-label="What the records show" className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <StatCard
          id="stat-stopped"
          icon={<ShieldX className="w-3.5 h-3.5" />}
          badge="Stopped at the fence"
          value={stats.stopped}
          suffix={stats.stopped === 1 ? 'action' : 'actions'}
          tone={stats.stopped ? 'var(--bad-text)' : 'var(--text)'}
          sub={stoppedLine(stats)}
          about="Things an agent tried that its task did not allow, refused by the tool broker or the kernel before they happened."
          source="each run's broker and kernel counts (comparison runs left out)"
        />
        <StatCard
          id="stat-decided"
          icon={<UserCheck className="w-3.5 h-3.5" />}
          badge="Decided by a person"
          value={stats.decidedByPerson}
          suffix={stats.decidedByPerson === 1 ? 'request' : 'requests'}
          sub={decisionsLine(stats)}
          about="Requests for more access that waited for someone to choose. Automatic policy, standing rules and timeouts are not counted here."
          source="the approval requests and who resolved each one"
          delayMs={90}
        />
        <StatCard
          id="stat-records"
          icon={<FileCheck2 className="w-3.5 h-3.5" />}
          badge="Records that check out"
          value={stats.verified}
          suffix={`of ${stats.checked.toLocaleString()}`}
          tone={stats.failed ? 'var(--bad-text)' : stats.checked ? 'var(--ok-text)' : 'var(--text)'}
          sub={recordsLine(stats)}
          about="Every entry of a run's record is linked to the one before it, and the server re-checks the whole chain."
          source="the server's check of every stored record"
          delayMs={180}
        />
      </section>

      {/* Main Grid: Records Table (left) + Side Panel Chain (right) */}
      <section className="grid grid-cols-1 lg:grid-cols-3 gap-5 items-start">
        {/* Table */}
        <div className="lg:col-span-2 p-5 rounded-xl bg-surface-2 border border-line flex flex-col gap-3">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <h2 className="text-[15px] font-bold text-fg">Records</h2>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setFilterStop(!filterStop)}
                className={`px-3 py-1.5 rounded-full text-[12px] font-semibold border cursor-pointer ${filterStop
                  ? 'bg-bad/20 border-bad text-bad-light'
                  : 'bg-surface-hover border-line-strong text-fg'
                  }`}
              >
                {filterStop ? 'Showing: Has a stop' : 'Filter: Has a stop'}
              </button>
              <button
                onClick={handleExportCSV}
                className="px-3.5 py-1.5 rounded-lg border border-line-strong bg-transparent hover:bg-surface-3 text-fg font-semibold text-[13px] flex items-center gap-1.5 cursor-pointer"
              >
                <Download className="w-3.5 h-3.5" />
                Export CSV
              </button>
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-[13px] border-collapse">
              <thead>
                <tr className="border-b border-line text-fg-3 font-medium text-[12px]">
                  <th className="pb-2.5 font-normal">Run</th>
                  <th className="pb-2.5 font-normal">Agent</th>
                  <th className="pb-2.5 font-normal">Team</th>
                  <th className="pb-2.5 font-normal">Task</th>
                  <th className="pb-2.5 font-normal">Outcome</th>
                  <th className="pb-2.5 font-normal">Record</th>
                  <th className="pb-2.5 font-normal">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {filteredTasks.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="py-8 text-center text-fg-3">
                      No records found.
                    </td>
                  </tr>
                ) : (
                  filteredTasks.slice(0, 20).map(t => {
                    const isSelected = selectedTask?.task_id === t.task_id;
                    const stops = t.prevented_count || t.os_denials_count || 0;
                    return (
                      <tr
                        key={t.task_id}
                        onClick={() => handleSelectTask(t)}
                        className={`cursor-pointer transition-colors ${isSelected ? 'bg-surface-active' : 'hover:bg-surface-3'
                          }`}
                      >
                        <td className="py-2.5 font-mono text-info-text">
                          {t.task_id.slice(0, 10)}…
                        </td>
                        <td className="py-2.5 font-mono text-fg">{t.agent_id}</td>
                        <td className="py-2.5 text-fg-2">{(t as any).team || 'General'}</td>
                        <td className="py-2.5 text-fg max-w-[160px] truncate">
                          {t.request_text}
                        </td>
                        <td className="py-2.5">
                          {stops > 0 ? (
                            <span className="text-bad-light">{stops} stopped</span>
                          ) : (
                            <span className="text-fg-3">allowed</span>
                          )}
                        </td>
                        <td className="py-2.5">
                          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-ok/[0.14] text-ok-light text-[11px] font-semibold">
                            ✓ Record checked: no entries changed
                          </span>
                        </td>
                        <td className="py-2.5" onClick={e => e.stopPropagation()}>
                          <a
                            href={api.getRawReceiptUrl(t.task_id)}
                            download
                            className="text-info hover:text-info-text flex items-center gap-1 text-[12px]"
                          >
                            <Download className="w-3.5 h-3.5" /> Download
                          </a>
                        </td>
                      </tr>
                    );
                  }))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Side Panel Vertical Chain */}
        {selectedTask && (
          <aside className="p-5 rounded-xl bg-surface-2 border border-line flex flex-col gap-3.5 sticky top-4">
            <div className="text-[12px] font-bold text-role-auditor tracking-wider uppercase">
              RECORD · {selectedTask.task_id.slice(0, 12)}…
            </div>
            <div className="text-[15px] font-bold text-fg">
              {selectedTask.agent_id} · {selectedTask.request_text.slice(0, 32)}…
            </div>

            {/* Vertical Chain */}
            <div className="flex flex-col gap-0 my-2">
              {chainSteps.map((s, idx) => (
                <div key={s.idx} className="flex gap-3 items-start anim-rise">
                  <div className="flex flex-col items-center">
                    <span
                      className="w-3 h-3 rounded-full"
                      style={{
                        background: s.color,
                        boxShadow: `0 0 0 3px ${s.color}33`,
                      }}
                    />
                    {idx < chainSteps.length - 1 && (
                      <span className="w-0.5 h-8 bg-line-strong my-0.5" />
                    )}
                  </div>
                  <div className="pb-2">
                    <div className="font-semibold text-[13px] text-fg">{s.label}</div>
                    <div className="text-[12px] text-fg-2 leading-snug">{s.detail}</div>
                    <div className="font-mono text-[10px] text-fg-dim mt-0.5">
                      #{s.idx} · links to #{s.idx === 0 ? '—' : s.idx - 1}
                    </div>
                  </div>
                </div>
              ))}
            </div>

            {/* Hash chain verification status */}
            <div className="p-3 rounded-lg bg-bg border border-line text-[12px] flex flex-col gap-1">
              <div className="text-fg-3">Hash chain verification:</div>
              {selectedReceipt?.available === false ? (
                <div className="font-mono text-[11px] text-fg-3">
                  No stored receipt
                </div>
              ) : selectedReceipt?.verified === false ? (
                <div className="font-mono text-[11px] text-bad">
                  ? Verification failed: entry changed or hash mismatch
                </div>
              ) : (
                <div className="font-mono text-[11px] text-ok">
                  ? Hash chain verified: no entries changed
                </div>
              )}
            </div>

            {/* Buttons */}
            <div className="flex items-center gap-2 pt-2 border-t border-line">
              <a
                href={api.getRawReceiptUrl(selectedTask.task_id)}
                download
                className="flex-1 min-h-[36px] px-3 rounded-lg bg-accent hover:bg-accent-strong text-white font-semibold text-[13px] flex items-center justify-center gap-1.5 no-underline"
              >
                <Download className="w-4 h-4" /> Download record
              </a>
              <button
                onClick={handleCheckAgain}
                disabled={isChecking}
                className="min-h-[36px] px-3 rounded-lg border border-line-strong bg-transparent hover:bg-surface-3 text-fg font-semibold text-[13px] flex items-center gap-1.5 cursor-pointer"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${isChecking ? 'animate-spin' : ''}`} />
                Check again
              </button>
            </div>

            <p className="text-[11px] text-fg-dim mt-1 leading-snug">
              Read-only role: auditors can inspect and export records but cannot approve, deny, or alter rules.
            </p>
          </aside>
        )}
      </section>
    </div>
  );
};

