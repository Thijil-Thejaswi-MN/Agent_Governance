import React from 'react';
import { formatCount, useCountUp } from '../../hooks/useCountUp';

/**
 * A large number card (after watermelon's stats-1 layout): icon badge, the number, a line
 * under it, what it means, and where the number comes from. The number counts up once
 * and always lands on the real value.
 */
export const StatCard: React.FC<{
  id?: string;
  icon: React.ReactNode;
  badge: string;
  value: number;
  suffix?: string;
  decimals?: number;
  tone?: string;
  sub: string;
  about: string;
  source: string;
  delayMs?: number;
}> = ({ id, icon, badge, value, suffix, decimals = 0, tone = '#E6E9EF', sub, about, source, delayMs = 0 }) => {
  const { ref, value: shown } = useCountUp<HTMLDivElement>(value, 1400, delayMs);
  return (
    <div
      id={id}
      ref={ref}
      data-value={value}
      className="relative overflow-hidden rounded-[28px] border border-[#1F2633] bg-[#11151D] p-5 sm:p-6 flex flex-col gap-3 transition-shadow duration-300 hover:shadow-[0_18px_50px_rgba(0,0,0,0.45)]"
      style={{
        backgroundImage:
          'repeating-linear-gradient(135deg, rgba(255,255,255,0.025) 0 1px, transparent 1px 11px), radial-gradient(120% 80% at 0% 0%, rgba(59,130,246,0.08), transparent 60%)',
      }}
    >
      <span className="inline-flex items-center gap-2 self-start rounded-full border border-[#2A3344] bg-[#0E121A] pl-1.5 pr-3 py-1 text-[12px] font-semibold text-[#A7B0C0]">
        <span className="inline-flex items-center justify-center w-6 h-6 rounded-full bg-[#161B26] text-[#93C5FD]" aria-hidden="true">
          {icon}
        </span>
        {badge}
      </span>
      <div className="flex items-baseline gap-1.5">
        <span className="font-display font-bold text-[40px] sm:text-[44px] leading-none tabular-nums" style={{ color: tone }} data-shown>
          {formatCount(shown, decimals)}
        </span>
        {suffix && (
          <span className="text-[16px] font-semibold" style={{ color: 'var(--text-2)' }}>
            {suffix}
          </span>
        )}
      </div>
      <p className="m-0 text-[14px] font-medium text-[#E6E9EF]" data-sub>
        {sub}
      </p>
      <p className="m-0 text-[13px] leading-relaxed" style={{ color: 'var(--text-2)' }}>
        {about}
      </p>
      <p className="m-0 mt-auto pt-1 text-[12px]" style={{ color: 'var(--text-3)' }}>
        From: {source}
      </p>
    </div>
  );
};
