/**
 * AgentTrace: live trace list for the Watch page, in the style of ReUI c-trace-2.
 * One line per step with an icon, past-tense title, muted description, and
 * expandable detail. The live step shimmers. After the run it stays collapsed.
 */
import React, { useEffect, useRef, useMemo } from 'react';
import {
  Brain,
  FileText,
  Pencil,
  Globe,
  Bot,
  Terminal,
  Cpu,
  Hand,
  FilePen,
  Play,
  FileOutput,
  FileCheck,
  StopCircle,
  CircleStop,
  CheckCircle2,
  Circle,
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import { TaskStep } from '../../types';
import { buildTraceRows, TraceRow } from '../../logic/traceSteps';
import {
  Trace,
  TraceLine,
  TraceIcon,
  TraceTitle,
  TraceDescription,
  TraceCollapsible,
} from './Trace';

const ICON_MAP: Record<string, LucideIcon> = {
  Brain,
  FileText,
  Pencil,
  Globe,
  Bot,
  Terminal,
  Cpu,
  Hand,
  FilePen,
  Play,
  FileOutput,
  FileCheck,
  StopCircle,
  CircleStop,
  CheckCircle2,
  Circle,
};

const TONE_ICON_CLASSES: Record<string, string> = {
  ok: 'text-ok',
  bad: 'text-bad',
  wait: 'text-wait',
  info: 'text-info',
  neutral: 'text-fg-3',
};

const TONE_DESC_CLASSES: Record<string, string> = {
  ok: 'text-ok',
  bad: 'text-bad',
  wait: 'text-wait',
  info: 'text-info',
  neutral: 'text-fg-3',
};

function RowIcon({ row }: { row: TraceRow }) {
  const Icon = ICON_MAP[row.icon] || Circle;
  const colorClass = TONE_ICON_CLASSES[row.tone] || 'text-fg-3';
  return <Icon className={`w-4 h-4 ${colorClass}`} />;
}

export interface AgentTraceProps {
  steps: TaskStep[];
  runState: string;
}

const MAX_VISIBLE = 12;

export const AgentTrace: React.FC<AgentTraceProps> = ({ steps, runState }) => {
  const rows = useMemo(() => buildTraceRows(steps, runState), [steps, runState]);
  const listRef = useRef<HTMLDivElement>(null);
  const userScrolledUp = useRef(false);
  const lastRowCount = useRef(0);

  // Auto-scroll to newest row unless user scrolled up.
  useEffect(() => {
    const el = listRef.current;
    if (!el) return;

    if (rows.length > lastRowCount.current && !userScrolledUp.current) {
      el.scrollTop = el.scrollHeight;
    }
    lastRowCount.current = rows.length;
  }, [rows.length]);

  // Detect user scroll-up.
  useEffect(() => {
    const el = listRef.current;
    if (!el) return;
    const handler = () => {
      const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 24;
      userScrolledUp.current = !atBottom;
    };
    el.addEventListener('scroll', handler, { passive: true });
    return () => el.removeEventListener('scroll', handler);
  }, []);

  if (rows.length === 0) return null;

  const needsScroll = rows.length > MAX_VISIBLE;

  return (
    <div
      id="agent-trace"
      className="rounded-xl border border-line bg-surface-1 overflow-hidden"
    >
      <Trace>
        <div
          ref={listRef}
          role="list"
          aria-live="polite"
          className={needsScroll ? 'max-h-[480px] overflow-y-auto' : ''}
        >
          {rows.map((row) => (
            <TraceRowItem key={row.id} row={row} />
          ))}
        </div>
      </Trace>
    </div>
  );
};

function TraceRowItem({ row }: { row: TraceRow }) {
  const hasDetail = !!row.detail;

  if (!hasDetail) {
    return (
      <TraceLine live={row.live} role="listitem" aria-busy={row.live || undefined}>
        <TraceIcon>
          <RowIcon row={row} />
        </TraceIcon>
        <div className="flex-1 min-w-0 flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
          <TraceTitle>{row.title}</TraceTitle>
          {row.description && (
            <TraceDescription className={TONE_DESC_CLASSES[row.tone] || ''}>
              {row.description}
            </TraceDescription>
          )}
        </div>
      </TraceLine>
    );
  }

  return (
    <TraceLine live={row.live} role="listitem" aria-busy={row.live || undefined}>
      <TraceIcon>
        <RowIcon row={row} />
      </TraceIcon>
      <TraceCollapsible
        defaultOpen={row.live}
        controlledOpen={row.live ? true : undefined}
        detail={
          <pre className="font-mono text-[11px] leading-relaxed text-fg-2 whitespace-pre-wrap break-words max-h-48 overflow-y-auto m-0 p-2 rounded-lg bg-surface-2 border border-line">
            {row.detail}
          </pre>
        }
      >
        <div className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
          <TraceTitle>{row.title}</TraceTitle>
          {row.description && (
            <TraceDescription className={TONE_DESC_CLASSES[row.tone] || ''}>
              {row.description}
            </TraceDescription>
          )}
        </div>
      </TraceCollapsible>
    </TraceLine>
  );
}
