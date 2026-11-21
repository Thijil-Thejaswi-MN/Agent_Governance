import React, { useState, useEffect } from 'react';
import { api } from '../api/client';
import { TaskRecord, ReceiptResponse, ExpansionItem, RecordsSummary } from '../types';
import { MetricCard } from '../components/ui/MetricCard';
import { StatusPill } from '../components/ui/StatusPill';
import { Button } from '../components/ui/Button';
import { decisionsLine, recordBadge, recordStats, recordsLine, stoppedLine } from '../logic/recordStats';
import { PALETTE } from '../logic/palette';
import { Download, RefreshCw } from 'lucide-react';
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
  const [recordsSummary, setRecordsSummary] = useState<RecordsSummary | null>(null);
  const [selectedTask, setSelectedTask] = useState<TaskRecord | null>(null);
  const [selectedReceipt, setSelectedReceipt] = useState<ReceiptResponse | null>(null);
  const [isChecking, setIsChecking] = useState(false);
  const [, setLoading] = useState(true);
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
    const headers = ['task_id', 'agent_id', 'owner', 'team', 'status', 'total_actions', 'stops', 'created_at', 'key_id', 'signature_status'];
    const rows = tasks.map(t => {
      const isSigned = recordsSummary?.signed_ids?.includes(t.task_id);
      const isFailed = recordsSummary?.failed_ids?.includes(t.task_id);
      const keyId = recordsSummary?.key_ids?.[t.task_id] || (isSigned ? 'active' : 'N/A');
      const sigStatus = isSigned ? 'signature_verified' : isFailed ? 'failed' : recordsSummary?.verified_ids?.includes(t.task_id) ? 'unsigned' : 'unknown';
      return [
        t.task_id,
        t.agent_id,
        (t as any).owner || 'N/A',
        (t as any).team || 'N/A',
        t.status,
        t.total_actions,
        t.prevented_count || t.os_denials_count || 0,
        t.created_at,
        keyId,
        sigStatus,
      ];
    });
    const csvContent = 'data:text/csv;charset=utf-8,' + [headers.join(','), ...rows.map(e => e.join(','))].join('\n');
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', `records_export_${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const handleExportJSON = () => {
    const data = tasks.map(t => {
      const isSigned = recordsSummary?.signed_ids?.includes(t.task_id);
      const isFailed = recordsSummary?.failed_ids?.includes(t.task_id);
      const keyId = recordsSummary?.key_ids?.[t.task_id] || (isSigned ? 'active' : null);
      const sigStatus = isSigned ? 'signature_verified' : isFailed ? 'failed' : recordsSummary?.verified_ids?.includes(t.task_id) ? 'unsigned' : 'unknown';
      return {
        task_id: t.task_id,
        agent_id: t.agent_id,
        owner: (t as any).owner || null,
        team: (t as any).team || null,
        status: t.status,
        total_actions: t.total_actions,
        stops: t.prevented_count || t.os_denials_count || 0,
        created_at: t.created_at,
        key_id: keyId,
        signature_status: sigStatus,
      };
    });
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.setAttribute('href', url);
    link.setAttribute('download', `records_export_${Date.now()}.json`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
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
            : 'Records'
        }
        subtitle={
          <>
            {recordsSummary && recordsSummary.failed > 0 && (
              <div className="text-[13px] text-bad font-mono mb-1">
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

      {/* What the records show: three numbers, each counted from real records */}
      <section id="records-stats" aria-label="What the records show" className="grid grid-cols-1 md:grid-cols-3 gap-3.5">
        <MetricCard
          id="stat-stopped"
          data-value={stats.stopped}
          label="Stopped at the fence"
          value={`${stats.stopped.toLocaleString()} ${stats.stopped === 1 ? 'action' : 'actions'}`}
          note={stoppedLine(stats)}
          tone={stats.stopped ? 'bad' : 'default'}
        />
        <MetricCard
          id="stat-decided"
          data-value={stats.decidedByPerson}
          label="Decided by a person"
          value={`${stats.decidedByPerson.toLocaleString()} ${stats.decidedByPerson === 1 ? 'request' : 'requests'}`}
          note={decisionsLine(stats)}
          tone="default"
        />
        <MetricCard
          id="stat-records"
          data-value={stats.verified}
          label="Records that check out"
          value={`${stats.verified.toLocaleString()} of ${stats.checked.toLocaleString()}`}
          note={recordsLine(stats)}
          tone={stats.failed ? 'bad' : stats.checked ? 'ok' : 'default'}
        />
      </section>

      {/* Main Grid: Records Table (left) + Side Panel Chain (right) */}
      <section className="grid grid-cols-1 lg:grid-cols-3 gap-5 items-start">
        {/* Table */}
        <div className="lg:col-span-2 rounded-xl border border-line bg-surface-1 overflow-hidden flex flex-col">
          <div className="p-4 border-b border-line flex flex-wrap items-center justify-between gap-3">
            <h2 className="m-0 text-[15px] font-bold text-fg">Records</h2>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setFilterStop(!filterStop)}
                className={`px-3 py-1.5 rounded-lg text-[12px] font-semibold border transition-colors cursor-pointer ${filterStop
                  ? 'bg-bad-tint border-bad/30 text-bad'
                  : 'bg-surface-2 border-line text-fg hover:bg-surface-3'
                  }`}
              >
                {filterStop ? 'Showing: Has a stop' : 'Filter: Has a stop'}
              </button>
              <Button
                variant="secondary"
                size="sm"
                onClick={handleExportCSV}
              >
                <Download className="w-3.5 h-3.5" />
                Export CSV
              </Button>
              <Button
                variant="secondary"
                size="sm"
                onClick={handleExportJSON}
              >
                <Download className="w-3.5 h-3.5" />
                Export JSON
              </Button>
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-[13px] border-collapse">
              <thead>
                <tr className="bg-surface-2 border-b border-line text-fg-3 uppercase text-[12px] tracking-wider font-semibold">
                  <th className="py-2.5 px-4 font-semibold">Run</th>
                  <th className="py-2.5 px-3 font-semibold">Agent</th>
                  <th className="py-2.5 px-3 font-semibold">Team</th>
                  <th className="py-2.5 px-3 font-semibold">Task</th>
                  <th className="py-2.5 px-3 font-semibold">Outcome</th>
                  <th className="py-2.5 px-3 font-semibold">Record</th>
                  <th className="py-2.5 px-4 font-semibold text-right">Action</th>
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
                    const badge = recordBadge(t.task_id, recordsSummary);

                    return (
                      <tr
                        key={t.task_id}
                        onClick={() => handleSelectTask(t)}
                        className={`h-11 min-h-[44px] cursor-pointer transition-colors ${isSelected ? 'bg-surface-2' : 'hover:bg-surface-2/50'
                          }`}
                      >
                        <td className="py-2 px-4 font-mono text-accent font-medium">
                          {t.task_id.slice(0, 10)}…
                        </td>
                        <td className="py-2 px-3 font-mono text-fg">{t.agent_id}</td>
                        <td className="py-2 px-3 text-fg-2">{(t as any).team || 'General'}</td>
                        <td className="py-2 px-3 text-fg max-w-[160px] truncate">
                          {t.request_text}
                        </td>
                        <td className="py-2 px-3">
                          {stops > 0 ? (
                            <span className="text-bad font-medium">{stops} stopped</span>
                          ) : (
                            <span className="text-fg-3">allowed</span>
                          )}
                        </td>
                        <td className="py-2 px-3">
                          {badge === 'failed' ? (
                            <StatusPill tone="bad" label="Verification failed" />
                          ) : badge === 'signature_verified' ? (
                            <StatusPill tone="ok" label={`Record checked: signature verified (key ${recordsSummary?.key_ids?.[t.task_id] || 'active'})`} />
                          ) : badge === 'events_only' ? (
                            <StatusPill tone="info" label="events only" />
                          ) : badge === 'checked' ? (
                            <StatusPill tone="ok" label="Record checked: no entries changed" />
                          ) : badge === 'none' ? (
                            <StatusPill tone="neutral" label="No stored record" />
                          ) : (
                            <StatusPill tone="neutral" label="Open to check" />
                          )}
                        </td>
                        <td className="py-2 px-4 text-right" onClick={e => e.stopPropagation()}>
                          <a
                            href={api.getRawReceiptUrl(t.task_id)}
                            download
                            className="inline-flex items-center gap-1 text-[12px] font-medium text-fg-2 hover:text-fg hover:bg-surface-2 px-2.5 py-1 rounded-lg transition-colors no-underline"
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
          <aside className="p-5 rounded-xl bg-surface-1 border border-line flex flex-col gap-3.5 sticky top-4">
            <div className="text-[12px] font-bold text-accent tracking-wider uppercase">
              RECORD · {selectedTask.task_id.slice(0, 12)}…
            </div>
            <div className="text-[15px] font-bold text-fg break-words">
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
                    <div className="font-mono text-[10px] text-fg-3 mt-0.5">
                      #{s.idx} · links to #{s.idx === 0 ? '—' : s.idx - 1}
                    </div>
                  </div>
                </div>
              ))}
            </div>

            {/* Hash chain verification status */}
            <div className="p-3 rounded-lg bg-surface-2 border border-line text-[12px] flex flex-col gap-1.5">
              <div className="text-fg-3">Hash chain verification:</div>
              {selectedReceipt?.available === false ? (
                <StatusPill tone="neutral" label="No stored record" />
              ) : selectedReceipt?.verified === false ? (
                <StatusPill tone="bad" label="Verification failed: entry changed or hash mismatch" />
              ) : selectedReceipt?.verified_scope === 'signed' ? (
                <StatusPill tone="ok" label={`Record checked: signature verified (key ${selectedReceipt?.key_id || selectedReceipt?.receipt?.signature?.key_id || 'active'})`} />
              ) : selectedReceipt?.verified_scope === 'events_only' ? (
                <StatusPill tone="info" label="events only" />
              ) : (
                <StatusPill tone="ok" label="Record checked: no entries changed" />
              )}
            </div>

            {/* Buttons */}
            <div className="flex items-center gap-2 pt-2 border-t border-line">
              <a
                href={api.getRawReceiptUrl(selectedTask.task_id)}
                download
                className="flex-1 min-h-[36px] h-9 px-3 rounded-lg text-white font-medium text-[13px] flex items-center justify-center gap-1.5 no-underline bg-[image:var(--accent-grad)] hover:brightness-110 active:brightness-95 transition-all"
              >
                <Download className="w-4 h-4" /> Download record
              </a>
              <Button
                variant="secondary"
                size="sm"
                onClick={handleCheckAgain}
                disabled={isChecking}
              >
                <RefreshCw className={`w-3.5 h-3.5 ${isChecking ? 'animate-spin' : ''}`} />
                Check again
              </Button>
            </div>

            <p className="text-[11px] text-fg-3 mt-1 leading-snug">
              Read-only role: auditors can inspect and export records but cannot approve, deny, or alter rules.
            </p>
          </aside>
        )}
      </section>
    </div>
  );
};
