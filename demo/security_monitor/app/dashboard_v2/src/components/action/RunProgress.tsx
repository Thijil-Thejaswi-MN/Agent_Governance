import React from 'react';
import { Bot, Check, FileText, Hand, Loader2, Settings2, X } from 'lucide-react';
import { AnimatedLabel } from './AnimatedLabel';
import type { PhaseId, RunPhaseView } from '../../logic/runPhase';

const ICONS: Record<PhaseId, React.ComponentType<{ className?: string }>> = {
  setup: Settings2,
  working: Bot,
  waiting: Hand,
  record: FileText,
  end: Check,
};

const TONE: Record<RunPhaseView['tone'], { color: string; background: string; border: string }> = {
  busy: { color: 'var(--info-lighter)', background: 'rgba(59,130,246,0.10)', border: 'rgba(59,130,246,0.35)' },
  ask: { color: 'var(--wait-lighter)', background: 'rgba(245,158,11,0.10)', border: 'rgba(245,158,11,0.40)' },
  ok: { color: 'var(--ok-lighter)', background: 'rgba(34,197,94,0.10)', border: 'rgba(34,197,94,0.35)' },
  bad: { color: 'var(--bad-lighter)', background: 'rgba(239,68,68,0.10)', border: 'rgba(239,68,68,0.35)' },
};

/** The run's phase as one pill with step dots. Moves only when the run's real state does. */
export const RunProgress: React.FC<{ view: RunPhaseView }> = ({ view }) => {
  const phase = view.phases[view.current];
  const tone = TONE[view.tone];
  const Icon = view.finished && view.tone === 'bad' ? X : ICONS[phase.id];
  const spinning = !view.finished && phase.id !== 'waiting';
  return (
    <div
      id="run-progress"
      role="status"
      aria-label="Progress"
      data-phase={phase.id}
      data-finished={view.finished ? 'true' : 'false'}
      className="inline-flex items-center gap-3 min-h-[44px] pl-2 pr-4 rounded-full border transition-colors duration-300"
      style={{ color: tone.color, background: tone.background, borderColor: tone.border }}
    >
      <span
        className="relative inline-flex items-center justify-center w-8 h-8 rounded-full shrink-0"
        style={{ background: 'rgba(14,18,26,0.6)' }}
        aria-hidden="true"
      >
        {spinning && <Loader2 className="absolute w-8 h-8 opacity-40 motion-safe:animate-spin" />}
        <Icon className="w-4 h-4" />
      </span>
      <AnimatedLabel text={view.label} className="text-[14px] font-semibold whitespace-nowrap" />
      <span className="hidden sm:inline-flex items-center gap-1.5 ml-1" aria-hidden="true">
        {view.phases.map((p, i) => (
          <span
            key={p.id}
            title={p.label}
            className="block rounded-full transition-all duration-300"
            style={{
              width: i === view.current ? 14 : 6,
              height: 6,
              background: i <= view.current ? tone.color : 'var(--line-strong)',
              opacity: i < view.current ? 0.6 : 1,
            }}
          />
        ))}
      </span>
    </div>
  );
};
