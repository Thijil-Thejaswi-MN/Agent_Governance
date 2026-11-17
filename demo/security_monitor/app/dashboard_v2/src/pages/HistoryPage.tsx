import React, { useEffect, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { api } from '../api/client';
import { TaskRecord } from '../types';
import { outcomeLabel, relativeTime } from '../logic/plain';
import { PageHeader } from '../components/ui/PageHeader';

const TONE: Record<string, React.CSSProperties> = {
  ok: { color: 'var(--ok-text)', background: 'var(--ok-tint)' },
  bad: { color: 'var(--bad-text)', background: 'var(--bad-tint)' },
  wait: { color: 'var(--info-text)', background: 'rgba(59,130,246,0.14)' },
  none: { color: 'var(--text-2)', background: 'var(--surface-hover)' },
};

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
    <div className="max-w-[960px] pb-12 flex flex-col gap-5">
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
            className={`inline-flex items-center min-h-[44px] sm:min-h-[36px] px-3.5 rounded-lg text-[14px] no-underline ${f.active ? 'bg-surface-hover text-fg font-semibold' : 'text-fg-2 hover:text-fg'
              }`}
          >
            {f.label}
          </Link>
        ))}
      </nav>

      {error && (
        <p role="alert" style={{ color: 'var(--bad-text)' }}>
          {error}
        </p>
      )}
      {tasks && shown.length === 0 && (
        <p id="history-empty" className="text-[17px]" style={{ color: 'var(--text-2)' }}>
          {onlyBlocked ? 'Nothing has been stopped yet.' : 'No runs yet.'} <Link to="/run">Try one</Link>
        </p>
      )}
      {!tasks && !error && <p style={{ color: 'var(--text-2)' }}>Loading…</p>}

      <ul className="list-none p-0 m-0 flex flex-col rounded-xl overflow-hidden border border-line bg-surface-2 divide-y divide-line empty:hidden" id="history-list">
        {shown.map(t => {
          const o = outcomeLabel(t.status);
          const stopped = stoppedCount(t);
          return (
            <li key={t.task_id}>
              <Link
                to={`/history/${t.task_id}`}
                data-task-id={t.task_id}
                className="flex flex-wrap sm:flex-nowrap items-center gap-x-4 gap-y-1.5 px-4 sm:px-5 py-3.5 min-h-[56px] no-underline text-fg hover:text-fg hover:bg-surface-3 transition-colors"
              >
                <span className="basis-full sm:basis-auto sm:flex-1 min-w-0 truncate text-[15px]" title={t.request_text}>
                  {t.request_text || '(no request text)'}
                </span>
                {stopped > 0 && (
                  <span className="text-[13px] whitespace-nowrap" style={{ color: 'var(--bad-text)' }}>
                    {stopped} {stopped === 1 ? 'refusal' : 'refusals'}
                  </span>
                )}
                {(t.comparison_mode || t.condition === 'B') && (
                  <span
                    data-badge="comparison"
                    className="text-[12px] font-semibold px-2.5 py-0.5 rounded-full whitespace-nowrap bg-wait/15 text-wait-kpi border border-wait/30"
                  >
                    Comparison
                  </span>
                )}
                <span className="text-[12px] font-semibold px-2.5 py-0.5 rounded-full whitespace-nowrap" style={TONE[o.tone]}>
                  {o.text}
                </span>
                <span className="text-[13px] whitespace-nowrap sm:min-w-[84px] sm:text-right" style={{ color: 'var(--text-3)' }}>
                  {relativeTime(t.created_at, now)}
                </span>
              </Link>
            </li>
          );
        })}
      </ul>
    </div>
  );
};
