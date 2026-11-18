/**
 * Trace primitives inspired by the ReUI c-trace-2 pattern.
 * Ported by hand (no shadcn, no Radix). Collapsible = button + region.
 * Shimmer is CSS-only and off with prefers-reduced-motion.
 *
 * MIT License — adapted from https://reui.io
 */
import React, { useState, useCallback } from 'react';

/* ---- Trace root ---- */
export const Trace: React.FC<React.HTMLAttributes<HTMLDivElement>> = ({ children, ...rest }) => (
  <div {...rest}>{children}</div>
);

/* ---- TraceLine: one row ---- */
export interface TraceLineProps extends React.HTMLAttributes<HTMLDivElement> {
  children: React.ReactNode;
  live?: boolean;
}

export const TraceLine: React.FC<TraceLineProps> = ({ children, live, className = '', ...rest }) => (
  <div
    className={`group flex items-start gap-3 py-2.5 px-3 ${live ? 'trace-shimmer' : ''} ${className}`}
    {...rest}
  >
    {children}
  </div>
);

/* ---- TraceIcon ---- */
export interface TraceIconProps extends React.HTMLAttributes<HTMLSpanElement> {
  children: React.ReactNode;
}

export const TraceIcon: React.FC<TraceIconProps> = ({ children, className = '', ...rest }) => (
  <span className={`mt-0.5 shrink-0 flex items-center justify-center w-5 h-5 ${className}`} {...rest}>
    {children}
  </span>
);

/* ---- TraceTitle ---- */
export const TraceTitle: React.FC<React.HTMLAttributes<HTMLSpanElement>> = ({
  children,
  className = '',
  ...rest
}) => (
  <span className={`text-[13px] leading-snug font-medium text-fg ${className}`} {...rest}>
    {children}
  </span>
);

/* ---- TraceDescription ---- */
export const TraceDescription: React.FC<React.HTMLAttributes<HTMLSpanElement>> = ({
  children,
  className = '',
  ...rest
}) => (
  <span className={`text-[12px] leading-snug text-fg-3 ${className}`} {...rest}>
    {children}
  </span>
);

/* ---- TraceCollapsible ---- */
export interface TraceCollapsibleProps {
  defaultOpen?: boolean;
  children: React.ReactNode;
  detail: React.ReactNode;
  /** Controlled open override; user click always wins. */
  controlledOpen?: boolean;
}

export const TraceCollapsible: React.FC<TraceCollapsibleProps> = ({
  defaultOpen = false,
  controlledOpen,
  children,
  detail,
}) => {
  const [explicitOpen, setExplicitOpen] = useState<boolean | null>(null);

  const open = explicitOpen !== null ? explicitOpen : (controlledOpen ?? defaultOpen);

  const toggle = useCallback(() => {
    setExplicitOpen(prev => {
      const current = prev !== null ? prev : (controlledOpen ?? defaultOpen);
      return !current;
    });
  }, [controlledOpen, defaultOpen]);

  return (
    <div className="flex-1 min-w-0">
      <button
        type="button"
        aria-expanded={open}
        onClick={toggle}
        className="flex w-full items-start gap-1.5 text-left bg-transparent border-none p-0 cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent focus-visible:ring-offset-1 focus-visible:ring-offset-bg rounded"
      >
        <span className="flex-1 min-w-0">{children}</span>
        <svg
          aria-hidden="true"
          className={`w-3.5 h-3.5 mt-0.5 shrink-0 text-fg-3 transition-transform duration-150 ${open ? 'rotate-90' : ''}`}
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
          strokeWidth={2}
        >
          <path strokeLinecap="round" strokeLinejoin="round" d="m9 5 7 7-7 7" />
        </svg>
      </button>
      {open && (
        <div role="region" className="mt-1.5 ml-0">
          {detail}
        </div>
      )}
    </div>
  );
};
