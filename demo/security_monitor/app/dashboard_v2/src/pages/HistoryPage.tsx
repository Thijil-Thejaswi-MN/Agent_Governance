import React, { useEffect, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { api } from '../api/client';
import { TaskRecord } from '../types';
import { outcomeLabel, relativeTime } from '../logic/plain';
import { getTone } from '../logic/tones';
import { PageHeader } from '../components/ui/PageHeader';
import { StatusPill } from '../components/ui/StatusPill';

const stoppedCount = (t: TaskRecord) => Math.max(t.prevented_count || 0, t.os_denials_count || 0);

export const HistoryPage: React.FC = () => {
  const [params] = useSearchParams();
  const onlyBlocked = params.get('filter') === 'blocked';
  const [tasks, setTasks] = useState<TaskRecord[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const now = Date.now();

  useEffect(() => {
    api
      .getTasks()
      .then(ts => setTasks([...ts].sort((a, b) => (b.created_at || '').localeCompare(a.created_at || ''))))
      .catch(err => setError(err.message || 'Could not load past runs.'));
  }, []);

  const shown = (tasks || []).filter(t => !onlyBlocked || stoppedCount(t) > 0);

  return (
    <div className="max-w-[1080px] pb-12 flex flex-col gap-5 font-sans">
      <PageHeader
        title={onlyBlocked ? 'Runs where something was stopped.' : 'Past runs.'}
      />
      <nav aria-label="Filter" className="inline-flex self-start flex-wrap gap-1 p-1 rounded-xl bg-surface-2 border border-line">
        {[
          { to: '/history', label: 'All', active: !onlyBlocked },
          { to: '/history?filter=blocked', label: 'Something was stopped', active: onlyBlocked },
        ].map(f => (
          <Link
            key={f.label}
            to={f.to}
            aria-current={f.active ? 'page' : undefined}
            className={`inline-flex items-center min-h-[44px] sm:min-h-[36px] px-3.5 rounded-lg text-[14px] no-underline transition-colors ${
              f.active ? 'bg-surface-3 text-fg font-semibold shadow-sm' : 'text-fg-2 hover:text-fg hover:bg-surface-3/50'
            }`}
          >
            {f.label}
          </Link>
        ))}
      </nav>

      {error && (
        <p role="alert" className="text-bad">
          {error}
        </p>
      )}
      {tasks && shown.length === 0 && (
        <p id="history-empty" className="text-[17px] text-fg-2">
          {onlyBlocked ? 'Nothing has been stopped yet.' : 'No runs yet.'}{' '}
          <Link to="/run" className="text-info hover:underline">
            Try one
          </Link>
        </p>
      )}
      {!tasks && !error && <p className="text-fg-2">Loading…</p>}

      <div className="overflow-x-auto rounded-xl border border-line bg-surface-1">
        <div className="min-w-[760px]">
          <div className="bg-surface-2 px-4 py-2.5 text-[12px] uppercase tracking-wider text-fg-3 font-semibold grid grid-cols-[130px_130px_1fr_130px_90px_70px] gap-3 border-b border-line items-center">
            <span>When</span>
            <span>Agent</span>
            <span>Task</span>
            <span>Outcome</span>
            <span>Stops</span>
            <span className="text-right">Action</span>
          </div>
          <ul id="history-list" className="list-none p-0 m-0 divide-y divide-line empty:hidden">
            {shown.map(t => {
              const o = outcomeLabel(t.status);
              const stopped = stoppedCount(t);
              const tone = getTone(t.status);
              return (
                <li key={t.task_id}>
                  <Link
                    to={`/history/${t.task_id}`}
                    data-task-id={t.task_id}
                    className="min-h-[44px] px-4 py-2 grid grid-cols-[130px_130px_1fr_130px_90px_70px] gap-3 items-center hover:bg-surface-2/50 transition-colors text-[13px] no-underline text-fg group"
                  >
                    <span className="text-fg-3 whitespace-nowrap text-[12px]">
                      {relativeTime(t.created_at, now)}
                    </span>
                    <span className="font-mono text-fg text-[13px] truncate" title={t.agent_id}>
                      {t.agent_id || '—'}
                    </span>
                    <div className="min-w-0 truncate text-fg flex items-center gap-2" title={t.request_text}>
                      <span className="truncate">{t.request_text || '(no request text)'}</span>
                      {(t.comparison_mode || t.condition === 'B') && (
                        <span
                          data-badge="comparison"
                          className="text-[11px] font-semibold px-2 py-0.5 rounded-full whitespace-nowrap bg-wait/15 text-wait-kpi border border-wait/30 shrink-0"
                        >
                          Comparison
                        </span>
                      )}
                      {(t.benchmark_label || (t.bench_mode && t.sensor_disabled) || t.condition === 'C-nosensor' || t.condition === 'C-ebpf') && (
                        <span
                          data-badge="bench-sensor-off"
                          className="text-[11px] font-semibold px-2 py-0.5 rounded-full whitespace-nowrap bg-wait/15 text-wait-kpi border border-wait/30 shrink-0"
                        >
                          benchmark: sensor off
                        </span>
                      )}
                    </div>
                    <div>
                      <StatusPill tone={tone} label={o.text} />
                    </div>
                    <span className={`font-medium ${stopped > 0 ? 'text-bad font-semibold' : 'text-fg-3'}`}>
                      {stopped > 0 ? `${stopped} ${stopped === 1 ? 'refusal' : 'refusals'}` : '—'}
                    </span>
                    <div className="text-right">
                      <span className="inline-flex items-center justify-center h-8 px-2.5 text-[12px] font-medium rounded-lg text-fg-2 group-hover:text-fg group-hover:bg-surface-2 transition-colors">
                        Open
                      </span>
                    </div>
                  </Link>
                </li>
              );
            })}
          </ul>
        </div>
      </div>
    </div>
  );
};
