import React, { useEffect, useRef } from 'react';
import { createPortal } from 'react-dom';
import { X } from 'lucide-react';

// The technical layer of every screen. Everything inside carries data-details, so the
// first-screen jargon check (tests) leaves it out.
export const DetailsDrawer: React.FC<{
  open: boolean;
  title: string;
  onClose: () => void;
  children: React.ReactNode;
  id?: string;
}> = ({ open, title, onClose, children, id = 'details-drawer' }) => {
  const closeRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (!open) return;
    closeRef.current?.focus();
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose();
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  if (!open) return null;
  // Rendered into <body>: an animated page wrapper would otherwise become the containing block
  // of this fixed overlay and cut the drawer off at the page's height.
  return createPortal(
    <div className="fixed inset-0 z-40 flex items-end sm:items-stretch justify-end" data-details>
      <div className="absolute inset-0" style={{ background: 'rgba(3,6,12,0.6)' }} onClick={onClose} aria-hidden="true" />
      <aside
        id={id}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        className="details-sheet relative h-[88vh] sm:h-full max-h-screen w-full sm:w-[640px] max-w-full overflow-y-auto overscroll-contain rounded-t-2xl sm:rounded-none border-t sm:border-t-0 sm:border-l border-[#2A3344] sm:border-[#1F2633]"
        style={{ background: 'var(--card)' }}
      >
        <div className="sticky top-0 z-10 flex items-center justify-between gap-3 px-5 py-3" style={{ background: 'var(--card)', borderBottom: '1px solid var(--line)' }}>
          <h2 className="font-display text-[20px] font-bold m-0">{title}</h2>
          <button
            ref={closeRef}
            onClick={onClose}
            aria-label="Close details"
            className="inline-flex items-center justify-center w-11 h-11 rounded-xl"
            style={{ color: 'var(--text-2)', background: 'transparent', border: '1px solid var(--line)', cursor: 'pointer' }}
          >
            <X className="w-5 h-5" />
          </button>
        </div>
        <div className="p-5 space-y-6 text-[14px]">{children}</div>
      </aside>
    </div>,
    document.body,
  );
};

export const DetailsSection: React.FC<{ title: string; children: React.ReactNode }> = ({ title, children }) => (
  <section className="space-y-2">
    <h3 className="text-[13px] font-semibold uppercase tracking-wider m-0" style={{ color: 'var(--text-3)' }}>
      {title}
    </h3>
    {children}
  </section>
);

export const KV: React.FC<{ k: string; v: React.ReactNode; id?: string }> = ({ k, v, id }) => (
  <div className="flex flex-wrap gap-x-3 gap-y-0.5 py-1.5" style={{ borderBottom: '1px solid rgba(148,163,184,0.08)' }}>
    <span className="min-w-[140px]" style={{ color: 'var(--text-3)' }}>
      {k}
    </span>
    <span id={id} className="mono text-[13px] min-w-0 [overflow-wrap:anywhere]" style={{ color: 'var(--text)' }}>
      {v}
    </span>
  </div>
);
