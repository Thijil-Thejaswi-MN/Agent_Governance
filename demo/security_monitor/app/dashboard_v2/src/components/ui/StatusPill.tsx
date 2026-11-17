import React from 'react';
import { Tone } from '../../logic/tones';

export interface StatusPillProps extends React.HTMLAttributes<HTMLSpanElement> {
  tone: Tone;
  label?: React.ReactNode;
  dot?: boolean;
  children?: React.ReactNode;
}

const toneStyles: Record<Tone, { pill: string; dot: string }> = {
  ok: {
    pill: 'bg-ok-tint text-ok border border-ok/20',
    dot: 'bg-ok',
  },
  bad: {
    pill: 'bg-bad-tint text-bad border border-bad/20',
    dot: 'bg-bad',
  },
  wait: {
    pill: 'bg-wait-tint text-wait border border-wait/20',
    dot: 'bg-wait',
  },
  info: {
    pill: 'bg-info-tint text-info border border-info/20',
    dot: 'bg-info',
  },
  neutral: {
    pill: 'bg-surface-3 text-fg-2 border border-line',
    dot: 'bg-fg-3',
  },
};

export const StatusPill: React.FC<StatusPillProps> = ({
  tone = 'neutral',
  label,
  dot = true,
  children,
  className = '',
  ...rest
}) => {
  const styles = toneStyles[tone] || toneStyles.neutral;
  const content = children !== undefined ? children : label;

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full h-7 px-2.5 text-[12px] font-medium select-none ${styles.pill} ${className}`}
      {...rest}
    >
      {dot && <span aria-hidden="true" className={`w-1.5 h-1.5 rounded-full shrink-0 ${styles.dot}`} />}
      {content !== undefined && content !== null && <span>{content}</span>}
    </span>
  );
};
