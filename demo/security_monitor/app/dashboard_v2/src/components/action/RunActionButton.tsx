import React from 'react';
import { Loader2, Play } from 'lucide-react';
import { AnimatedLabel } from './AnimatedLabel';

/**
 * The Start button as an action pill (after watermelon's Run Action Button, without its
 * timer): idle it reads "Start"; while the server starts the run it widens and says what is
 * happening. It never shows a step the server has not reached.
 */
export const RunActionButton: React.FC<{
  id?: string;
  busy: boolean;
  disabled?: boolean;
  idleLabel?: string;
  busyLabel?: string;
  onClick: () => void;
}> = ({ id, busy, disabled, idleLabel = 'Start', busyLabel = 'Setting up the task…', onClick }) => (
  <button
    id={id}
    type="button"
    onClick={onClick}
    disabled={disabled || busy}
    aria-busy={busy}
    data-state={busy ? 'running' : 'idle'}
    className="btn-primary min-h-[44px] sm:min-h-[40px] px-6 inline-flex items-center justify-center gap-2 rounded-full overflow-hidden transition-[min-width,background-color] duration-300 ease-out"
    style={{ minWidth: busy ? 230 : 120 }}
  >
    {busy ? (
      <Loader2 className="w-4 h-4 shrink-0 motion-safe:animate-spin" aria-hidden="true" />
    ) : (
      <Play className="w-4 h-4 shrink-0" aria-hidden="true" />
    )}
    <AnimatedLabel text={busy ? busyLabel : idleLabel} />
  </button>
);
