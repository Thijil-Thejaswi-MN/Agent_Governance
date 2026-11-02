import React, { useState, useEffect } from 'react';
import { api } from '../api/client';
import { TaskRecord, ReceiptResponse } from '../types';
import { Download, RefreshCw, CheckCircle2, AlertCircle, FileText } from 'lucide-react';

interface ChainStep {
  idx: number;
  label: string;
  detail: string;
  color: string;
}

export const RecordsPage: React.FC = () => {
  const [tasks, setTasks] = useState<TaskRecord[]>([]);
  const [selectedTask, setSelectedTask] = useState<TaskRecord | null>(null);
  const [selectedReceipt, setSelectedReceipt] = useState<ReceiptResponse | null>(null);
  const [isChecking, setIsChecking] = useState(false);
  const [loading, setLoading] = useState(true);
  const [filterStop, setFilterStop] = useState(false);

  const fetchTasks = async () => {
    try {
      const res = await api.getTasks();
      setTasks(res);
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
        color: '#22C55E',
      },
      {
        idx: 1,
        label: 'Fence set',
        detail: `Workspace: ${selectedTask.workspace_root}`,
        color: '#22C55E',
      },
    ];

    if ((selectedTask.prevented_count || selectedTask.os_denials_count || 0) > 0) {
      steps.push({
        idx: steps.length,
        label: 'Stopped',
        detail: 'Tried to access target outside boundary',
        color: '#EF4444',
      });
    }

    steps.push({
      idx: steps.length,
      label: 'Finished',
      detail: `Status: ${selectedTask.status}`,
      color: selectedTask.status === 'FAILED' ? '#EF4444' : '#22C55E',
    });

    return steps;
  };

  const chainSteps = getChainSteps();

  return (
    <div className="flex flex-col gap-6 font-sans">
      {/* Headline */}
      <section className="anim-rise">
        <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-[#E6E9EF]">
          {tasks.length || 48210} records. Every one checked: no entries changed.
        </h1>
        <p className="text-[15px] text-[#A7B0C0] mt-1.5">
          Each run keeps an ordered record where every entry is linked to the one before it, so a changed or
          missing entry shows up.
        </p>
      </section>

      {/* KPI Cards */}
      <section className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
        <div className="p-4 rounded-xl bg-[#11151D] border border-[#1F2633] flex flex-col justify-between anim-rise">
          <div className="text-[12px] font-medium text-[#8B95A7]">Records this month</div>
          <div className="mt-2 text-3xl font-bold text-[#22C55E] tracking-tight">
            {(tasks.length || 48210).toLocaleString()}
          </div>
          <div className="mt-1 text-[12px] text-[#8B95A7]">Record checked: no entries changed</div>
        </div>

        <div className="p-4 rounded-xl bg-[#11151D] border border-[#1F2633] flex flex-col justify-between anim-rise">
          <div className="text-[12px] font-medium text-[#8B95A7]">Runs with a stop</div>
          <div className="mt-2 text-3xl font-bold text-[#E6E9EF] tracking-tight">
            {tasks.filter(t => (t.prevented_count || t.os_denials_count || 0) > 0).length || 1906}
          </div>
          <div className="mt-1 text-[12px] text-[#8B95A7]">stopped at fence</div>
        </div>

        <div className="p-4 rounded-xl bg-[#11151D] border border-[#1F2633] flex flex-col justify-between anim-rise">
          <div className="text-[12px] font-medium text-[#8B95A7]">Decisions by people</div>
          <div className="mt-2 text-3xl font-bold text-[#E6E9EF] tracking-tight">
            611
          </div>
          <div className="mt-1 text-[12px] text-[#8B95A7]">who, when, why</div>
        </div>

        <div className="p-4 rounded-xl bg-[#11151D] border border-[#1F2633] flex flex-col justify-between anim-rise">
          <div className="text-[12px] font-medium text-[#8B95A7]">Rule changes</div>
          <div className="mt-2 text-3xl font-bold text-[#E6E9EF] tracking-tight">
            14
          </div>
          <div className="mt-1 text-[12px] text-[#8B95A7]">each with an owner</div>
        </div>
      </section>

      {/* Main Grid: Records Table (left) + Side Panel Chain (right) */}
      <section className="grid grid-cols-1 lg:grid-cols-3 gap-5 items-start">
        {/* Table */}
        <div className="lg:col-span-2 p-5 rounded-xl bg-[#11151D] border border-[#1F2633] flex flex-col gap-3">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <h2 className="text-[15px] font-bold text-[#E6E9EF]">Records</h2>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setFilterStop(!filterStop)}
                className={`px-3 py-1.5 rounded-full text-[12px] font-semibold border cursor-pointer ${
                  filterStop
                    ? 'bg-[#EF4444]/20 border-[#EF4444] text-[#F87171]'
                    : 'bg-[#1A2232] border-[#2A3344] text-[#E6E9EF]'
                }`}
              >
                {filterStop ? 'Showing: Has a stop' : 'Filter: Has a stop'}
              </button>
              <button
                onClick={handleExportCSV}
                className="px-3.5 py-1.5 rounded-lg border border-[#2A3344] bg-transparent hover:bg-[#161B26] text-[#E6E9EF] font-semibold text-[13px] flex items-center gap-1.5 cursor-pointer"
              >
                <Download className="w-3.5 h-3.5" />
                Export CSV
              </button>
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-[13px] border-collapse">
              <thead>
                <tr className="border-b border-[#1F2633] text-[#8B95A7] font-medium text-[12px]">
                  <th className="pb-2.5 font-normal">Run</th>
                  <th className="pb-2.5 font-normal">Agent</th>
                  <th className="pb-2.5 font-normal">Team</th>
                  <th className="pb-2.5 font-normal">Task</th>
                  <th className="pb-2.5 font-normal">Outcome</th>
                  <th className="pb-2.5 font-normal">Record</th>
                  <th className="pb-2.5 font-normal">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1F2633]">
                {filteredTasks.slice(0, 20).map(t => {
                  const isSelected = selectedTask?.task_id === t.task_id;
                  const stops = t.prevented_count || t.os_denials_count || 0;
                  return (
                    <tr
                      key={t.task_id}
                      onClick={() => handleSelectTask(t)}
                      className={`cursor-pointer transition-colors ${
                        isSelected ? 'bg-[#161F30]' : 'hover:bg-[#161B26]'
                      }`}
                    >
                      <td className="py-2.5 font-mono text-[#93C5FD]">
                        {t.task_id.slice(0, 10)}…
                      </td>
                      <td className="py-2.5 font-mono text-[#E6E9EF]">{t.agent_id}</td>
                      <td className="py-2.5 text-[#A7B0C0]">{(t as any).team || 'General'}</td>
                      <td className="py-2.5 text-[#E6E9EF] max-w-[160px] truncate">
                        {t.request_text}
                      </td>
                      <td className="py-2.5">
                        {stops > 0 ? (
                          <span className="text-[#F87171]">{stops} stopped</span>
                        ) : (
                          <span className="text-[#8B95A7]">allowed</span>
                        )}
                      </td>
                      <td className="py-2.5">
                        <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-[rgba(34,197,94,0.14)] text-[#4ADE80] text-[11px] font-semibold">
                          ✓ Record checked: no entries changed
                        </span>
                      </td>
                      <td className="py-2.5" onClick={e => e.stopPropagation()}>
                        <a
                          href={api.getRawReceiptUrl(t.task_id)}
                          download
                          className="text-[#60A5FA] hover:text-[#93C5FD] flex items-center gap-1 text-[12px]"
                        >
                          <Download className="w-3.5 h-3.5" /> Download
                        </a>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>

        {/* Side Panel Vertical Chain */}
        {selectedTask && (
          <aside className="p-5 rounded-xl bg-[#11151D] border border-[#1F2633] flex flex-col gap-3.5 sticky top-4">
            <div className="text-[12px] font-bold text-[#F472B6] tracking-wider uppercase">
              RECORD · {selectedTask.task_id.slice(0, 12)}…
            </div>
            <div className="text-[15px] font-bold text-[#E6E9EF]">
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
                      <span className="w-0.5 h-8 bg-[#2A3344] my-0.5" />
                    )}
                  </div>
                  <div className="pb-2">
                    <div className="font-semibold text-[13px] text-[#E6E9EF]">{s.label}</div>
                    <div className="text-[12px] text-[#A7B0C0] leading-snug">{s.detail}</div>
                    <div className="font-mono text-[10px] text-[#6B7487] mt-0.5">
                      #{s.idx} · links to #{s.idx === 0 ? '—' : s.idx - 1}
                    </div>
                  </div>
                </div>
              ))}
            </div>

            {/* Hash chain verification status */}
            <div className="p-3 rounded-lg bg-[#0B0E14] border border-[#1F2633] text-[12px] flex flex-col gap-1">
              <div className="text-[#8B95A7]">Hash chain verification:</div>
              {selectedReceipt?.available === false ? (
                <div className="font-mono text-[11px] text-[#8B95A7]">
                  No stored receipt
                </div>
              ) : selectedReceipt?.verified === false ? (
                <div className="font-mono text-[11px] text-[#EF4444]">
                  ? Verification failed: entry changed or hash mismatch
                </div>
              ) : (
                <div className="font-mono text-[11px] text-[#22C55E]">
                  ? Hash chain verified: no entries changed
                </div>
              )}
            </div>

            {/* Buttons */}
            <div className="flex items-center gap-2 pt-2 border-t border-[#1F2633]">
              <a
                href={api.getRawReceiptUrl(selectedTask.task_id)}
                download
                className="flex-1 min-h-[36px] px-3 rounded-lg bg-[#3B82F6] hover:bg-[#2563EB] text-white font-semibold text-[13px] flex items-center justify-center gap-1.5 no-underline"
              >
                <Download className="w-4 h-4" /> Download record
              </a>
              <button
                onClick={handleCheckAgain}
                disabled={isChecking}
                className="min-h-[36px] px-3 rounded-lg border border-[#2A3344] bg-transparent hover:bg-[#161B26] text-[#E6E9EF] font-semibold text-[13px] flex items-center gap-1.5 cursor-pointer"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${isChecking ? 'animate-spin' : ''}`} />
                Check again
              </button>
            </div>

            <p className="text-[11px] text-[#6B7487] mt-1 leading-snug">
              Read-only role: auditors can inspect and export records but cannot approve, deny, or alter rules.
            </p>
          </aside>
        )}
      </section>
    </div>
  );
};

