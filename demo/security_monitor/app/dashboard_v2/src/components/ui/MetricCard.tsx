import React from 'react';

export interface MetricCardProps extends React.HTMLAttributes<HTMLDivElement> {
  id?: string;
  label: React.ReactNode;
  value: React.ReactNode;
  note?: React.ReactNode;
  valueId?: string;
  tone?: 'default' | 'wait' | 'bad' | 'ok';
  className?: string;
}

const toneValueStyles: Record<'default' | 'wait' | 'bad' | 'ok', string> = {
  default: 'text-fg',
  wait: 'text-wait-kpi',
  bad: 'text-bad',
  ok: 'text-ok',
};

export const MetricCard: React.FC<MetricCardProps> = ({
  id,
  label,
  value,
  note,
  valueId,
  tone = 'default',
  className = '',
  ...rest
}) => {
  return (
    <div
      id={id}
      className={`h-36 rounded-xl border border-line bg-surface-1 p-4 flex flex-col justify-between ${className}`}
      {...rest}
    >
      <div className="text-[12px] sm:text-[13px] font-medium text-fg-3">{label}</div>
      <div
        id={valueId}
        className={`text-3xl font-semibold leading-none tabular-nums tracking-tight ${toneValueStyles[tone]}`}
      >
        {value}
      </div>
      {note !== undefined && note !== null && (
        <div className="text-[12px] text-fg-3 leading-tight">{note}</div>
      )}
    </div>
  );
};
