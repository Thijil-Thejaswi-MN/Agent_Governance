import React from 'react';
import { LucideIcon, Sparkles } from 'lucide-react';

export interface EyebrowProps {
  text: string;
  icon?: LucideIcon;
  className?: string;
  id?: string;
}

export const Eyebrow: React.FC<EyebrowProps> = ({
  text,
  icon: Icon = Sparkles,
  className = '',
  id,
}) => {
  return (
    <span
      id={id}
      data-testid="eyebrow"
      className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full border border-[#3B82F6]/35 bg-[#3B82F6]/10 text-[11px] font-semibold tracking-[0.1em] uppercase text-[#93C5FD] select-none ${className}`}
    >
      <Icon className="w-3 h-3 text-[#60A5FA] shrink-0" aria-hidden="true" data-testid="eyebrow-icon" />
      <span>{text}</span>
    </span>
  );
};