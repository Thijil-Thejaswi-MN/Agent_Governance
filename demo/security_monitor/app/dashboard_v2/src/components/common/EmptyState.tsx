import React from 'react';
import { ShieldAlert, Inbox, FolderSearch, AlertCircle } from 'lucide-react';

interface EmptyStateProps {
  icon?: 'inbox' | 'shield' | 'search' | 'alert';
  title: string;
  description: string;
  action?: {
    label: string;
    onClick: () => void;
  };
  className?: string;
}

export const EmptyState: React.FC<EmptyStateProps> = ({
  icon = 'inbox',
  title,
  description,
  action,
  className = '',
}) => {
  const icons = {
    inbox: <Inbox className="w-8 h-8 text-slate-400 dark:text-slate-500" />,
    shield: <ShieldAlert className="w-8 h-8 text-cyan-500/70" />,
    search: <FolderSearch className="w-8 h-8 text-slate-400 dark:text-slate-500" />,
    alert: <AlertCircle className="w-8 h-8 text-amber-500/70" />,
  };

  return (
    <div
      className={`flex flex-col items-center justify-center p-8 text-center rounded-xl border border-dashed border-slate-300 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-900/30 ${className}`}
    >
      <div className="p-3 mb-3 rounded-full bg-slate-100 dark:bg-slate-800/80">
        {icons[icon]}
      </div>
      <h3 className="text-sm font-semibold text-slate-800 dark:text-slate-200 mb-1">
        {title}
      </h3>
      <p className="text-xs text-slate-500 dark:text-slate-400 max-w-sm mb-4 leading-relaxed">
        {description}
      </p>
      {action && (
        <button
          onClick={action.onClick}
          className="px-3 py-1.5 text-xs font-medium text-cyan-600 dark:text-cyan-400 hover:text-cyan-500 border border-cyan-500/30 rounded-lg hover:bg-cyan-500/10 transition-colors"
        >
          {action.label}
        </button>
      )}
    </div>
  );
};
