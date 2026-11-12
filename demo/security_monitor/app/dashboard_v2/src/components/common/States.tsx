import React from 'react';

// One look for loading, empty and error states on the product pages.

export const LoadingState: React.FC<{ label?: string; id?: string }> = ({ label = 'Loading…', id }) => (
  <div
    id={id}
    role="status"
    aria-live="polite"
    className="card px-5 py-8 flex items-center gap-3 text-[15px]"
    style={{ color: 'var(--text-2)' }}
  >
    <span
      aria-hidden="true"
      className="inline-block w-4 h-4 rounded-full border-2 border-[#2A3344] border-t-[#60A5FA] motion-safe:animate-spin"
    />
    {label}
  </div>
);

export const EmptyState: React.FC<{
  title: string;
  body?: React.ReactNode;
  action?: React.ReactNode;
  id?: string;
}> = ({ title, body, action, id }) => (
  <div id={id} className="card px-5 py-8 flex flex-col items-start gap-2">
    <p className="m-0 text-[16px] font-semibold text-[#E6E9EF]">{title}</p>
    {body && (
      <p className="m-0 text-[15px] leading-relaxed" style={{ color: 'var(--text-2)' }}>
        {body}
      </p>
    )}
    {action && <div className="mt-2">{action}</div>}
  </div>
);

export const ErrorState: React.FC<{ message: string; onRetry?: () => void; id?: string }> = ({ message, onRetry, id }) => (
  <div
    id={id}
    role="alert"
    className="rounded-xl px-5 py-4 flex flex-wrap items-center gap-3 text-[15px]"
    style={{ background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.35)', color: '#FCA5A5' }}
  >
    <span className="min-w-0 [overflow-wrap:anywhere]">{message}</span>
    {onRetry && (
      <button type="button" className="btn-ghost min-h-[36px]" onClick={onRetry}>
        Try again
      </button>
    )}
  </div>
);
