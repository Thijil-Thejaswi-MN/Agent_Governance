import React, { useState } from 'react';
import { TaskEvent, TaskStep } from '../../types';
import { technicalLabel } from '../../logic/plain';

const verdictColor = (v: string) =>
  v === 'BLOCK_ACTION' || v === 'DENY' || v === 'BLOCKED' || v === 'FAILED'
    ? '#FDA4AF'
    : v === 'PENDING'
    ? '#FDE68A'
    : v === 'ALLOW' || v === 'APPROVED' || v === 'COMPLETED'
    ? '#6EE7B7'
    : 'var(--text-2)';

// Every stored step with its source label and layer, exactly as the server recorded it.
export const TechnicalTimeline: React.FC<{ steps: TaskStep[] }> = ({ steps }) => {
  const [open, setOpen] = useState<Record<number, boolean>>({});
  if (steps.length === 0) {
    return <p style={{ color: 'var(--text-2)' }}>No steps recorded yet.</p>;
  }
  return (
    <ol className="space-y-2 list-none p-0 m-0" id="technical-timeline">
      {steps.map(step => (
        <li
          key={step.step_number}
          className="p-3 rounded-[14px]"
          style={{ background: 'var(--card-2)', border: '1px solid var(--line)' }}
        >
          <div className="flex flex-wrap items-center gap-2 mono text-[12px]">
            <span style={{ color: 'var(--text-3)' }}>#{step.step_number}</span>
            <span className="px-2 py-0.5 rounded-md" style={{ background: 'rgba(34,211,238,0.1)', color: '#A5F3FC' }}>
              {technicalLabel(step.source_label, step.layer)}
            </span>
            <span style={{ color: verdictColor(step.verdict) }}>{step.verdict}</span>
            <span className="ml-auto" style={{ color: 'var(--text-3)' }}>
              {step.timestamp.split('T')[1]?.slice(0, 8) || step.timestamp}
            </span>
          </div>
          <div className="mt-1.5 text-[14px]" style={{ color: 'var(--text)' }}>
            {step.summary}
          </div>
          {step.detail && step.detail.trim().length > 0 && (
            <>
              <button
                className="link-btn !min-h-[32px] text-[13px]"
                onClick={() => setOpen(o => ({ ...o, [step.step_number]: !o[step.step_number] }))}
                aria-expanded={!!open[step.step_number]}
              >
                {open[step.step_number] ? 'Hide step detail' : 'Step detail'}
              </button>
              {open[step.step_number] && (
                <pre
                  className="mono text-[12px] whitespace-pre-wrap overflow-x-auto max-h-60 overflow-y-auto p-2 rounded-lg m-0"
                  style={{ background: 'var(--field)', color: 'var(--text-2)' }}
                >
                  {step.detail}
                </pre>
              )}
            </>
          )}
        </li>
      ))}
    </ol>
  );
};

// The governance events of a task (broker, proxy, OS sensor), as stored.
export const EventTable: React.FC<{ events: TaskEvent[] }> = ({ events }) => {
  if (events.length === 0) return <p style={{ color: 'var(--text-2)' }}>No governance events stored for this task.</p>;
  return (
    <div className="overflow-x-auto">
      <table className="w-full mono text-[12px] border-collapse" id="event-table">
        <thead>
          <tr style={{ color: 'var(--text-3)' }}>
            {['time', 'source', 'kind', 'target', 'verdict', 'prevented_by'].map(h => (
              <th key={h} className="text-left font-normal py-1.5 pr-3" style={{ borderBottom: '1px solid var(--line)' }}>
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {events.map((ev, i) => (
            <tr key={ev.event_id || i}>
              <td className="py-1.5 pr-3 whitespace-nowrap" style={{ color: 'var(--text-3)' }}>
                {(ev.timestamp || '').split('T')[1]?.slice(0, 8) || ev.timestamp}
              </td>
              <td className="py-1.5 pr-3">{ev.source}</td>
              <td className="py-1.5 pr-3">{ev.kind}</td>
              <td className="py-1.5 pr-3 break-all">{ev.target}</td>
              <td className="py-1.5 pr-3" style={{ color: ev.prevented ? '#FDA4AF' : ev.verdict === 'INSIDE' ? '#6EE7B7' : 'var(--text)' }}>
                {ev.verdict}
                {ev.prevented ? ' (prevented)' : ''}
              </td>
              <td className="py-1.5 pr-3">{ev.prevented_by || (ev.details as any)?.prevented_by || ''}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};
