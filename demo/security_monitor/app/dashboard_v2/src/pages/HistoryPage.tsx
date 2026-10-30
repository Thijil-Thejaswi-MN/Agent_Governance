import React, { useEffect, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { api } from '../api/client';
import { TaskRecord } from '../types';
import { outcomeLabel, relativeTime } from '../logic/plain';

const TONE: Record<string, React.CSSProperties> = {
  ok: { color: '#A7F3D0', border: '1px solid rgba(52,211,153,0.45)' },
  bad: { color: '#FECDD3', border: '1px solid rgba(251,113,133,0.45)' },
  wait: { color: '#A5F3FC', border: '1px solid rgba(34,211,238,0.45)' },
  none: { color: 'var(--text-2)', border: '1px solid var(--line)' },
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
    <div className="max-w-[880px] mx-auto px-4 sm:px-6 pt-8 pb-16 flex flex-col gap-6">
      <h1 className="m-0 font-display font-bold text-[36px] sm:text-[44px] leading-[1.1] tracking-[-1px]">
        {onlyBlocked ? 'Runs where something was stopped.' : 'Past runs.'}
      </h1>
      <nav aria-label="Filter" className="flex gap-2">
        {[
          { to: '/history', label: 'All', active: !onlyBlocked },
          { to: '/history?filter=blocked', label: 'Something was stopped', active: onlyBlocked },
        ].map(f => (
          <Link
            key={f.label}
            to={f.to}
            aria-current={f.active ? 'page' : undefined}
            className="inline-flex items-center min-h-[44px] px-4 rounded-full text-[14px] no-underline"
            style={f.active ? { background: 'rgba(34,211,238,0.14)', color: '#A5F3FC', fontWeight: 600 } : { color: 'var(--text-3)', border: '1px solid var(--line)' }}
          >
            {f.label}
          </Link>
        ))}
      </nav>

      {error && (
        <p role="alert" style={{ color: '#FDA4AF' }}>
          {error}
        </p>
      )}
      {tasks && shown.length === 0 && (
        <p id="history-empty" className="text-[17px]" style={{ color: 'var(--text-2)' }}>
          {onlyBlocked ? 'Nothing has been stopped yet.' : 'No runs yet.'} <Link to="/run">Try one</Link>
        </p>
      )}
      {!tasks && !error && <p style={{ color: 'var(--text-2)' }}>Loading…</p>}

      <ul className="list-none p-0 m-0 flex flex-col gap-2" id="history-list">
        {shown.map(t => {
          const o = outcomeLabel(t.status);
          const stopped = stoppedCount(t);
          return (
            <li key={t.task_id}>
              <Link
                to={`/history/${t.task_id}`}
                data-task-id={t.task_id}
                className="flex flex-wrap sm:flex-nowrap items-center gap-x-4 gap-y-1 px-4 sm:px-5 py-4 rounded-[18px] no-underline"
                style={{ background: 'var(--card)', border: '1px solid var(--line)', color: 'var(--text)' }}
              >
                <span className="basis-full sm:basis-auto sm:flex-1 min-w-0 truncate text-[16px]" title={t.request_text}>
                  {t.request_text || '(no request text)'}
                </span>
                {stopped > 0 && (
                  <span className="text-[14px] whitespace-nowrap" style={{ color: '#FDA4AF' }}>
                    {stopped} stopped
                  </span>
                )}
                <span className="text-[13px] font-semibold px-3 py-1 rounded-full whitespace-nowrap" style={TONE[o.tone]}>
                  {o.text}
                </span>
                <span className="text-[14px] whitespace-nowrap" style={{ color: 'var(--text-3)' }}>
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
