import React from 'react';

type BadgeVariant =
  | 'allowed'
  | 'blocked'
  | 'pending'
  | 'frozen'
  | 'enforce'
  | 'observe'
  | 'neutral'
  | 'cyan';

interface BadgeProps {
  variant?: BadgeVariant;
  children: React.ReactNode;
  className?: string;
  size?: 'sm' | 'md';
}

export const Badge: React.FC<BadgeProps> = ({
  variant = 'neutral',
  children,
  className = '',
  size = 'md',
}) => {
  const styles: Record<BadgeVariant, string> = {
    allowed: 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/30',
    blocked: 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/30',
    pending: 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/30',
    frozen: 'bg-blue-500/10 text-blue-600 dark:text-blue-400 border-blue-500/30',
    enforce: 'bg-purple-500/10 text-purple-600 dark:text-purple-400 border-purple-500/30',
    observe: 'bg-slate-500/10 text-slate-600 dark:text-slate-400 border-slate-500/30',
    neutral: 'bg-slate-200/50 dark:bg-slate-800/60 text-slate-700 dark:text-slate-300 border-slate-300 dark:border-slate-700',
    cyan: 'bg-cyan-500/10 text-cyan-600 dark:text-cyan-400 border-cyan-500/30',
  };

  const sizes = {
    sm: 'px-2 py-0.5 text-xs',
    md: 'px-2.5 py-1 text-xs font-medium',
  };

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border font-mono tracking-wide ${styles[variant]} ${sizes[size]} ${className}`}
    >
      <span className="w-1.5 h-1.5 rounded-full bg-current opacity-80" />
      {children}
    </span>
  );
};
