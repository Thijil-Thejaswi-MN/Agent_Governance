import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  ListTodo,
  Bot,
  Activity,
  CheckCircle2,
  BarChart3,
  Network,
  ChevronLeft,
  ChevronRight,
  ShieldAlert,
  ExternalLink,
} from 'lucide-react';

interface SidebarProps {
  collapsed: boolean;
  onToggle: () => void;
  mobileOpen: boolean;
  onMobileClose: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
  collapsed,
  onToggle,
  mobileOpen,
  onMobileClose,
}) => {
  const navItems = [
    { to: '/', label: 'Overview', icon: LayoutDashboard, exact: true },
    { to: '/tasks', label: 'Tasks', icon: ListTodo },
    { to: '/agents', label: 'Agents', icon: Bot },
    { to: '/activity', label: 'Live Activity', icon: Activity },
    { to: '/approvals', label: 'Approvals', icon: CheckCircle2 },
    { to: '/evaluation', label: 'Evaluation', icon: BarChart3 },
    { to: '/architecture', label: 'Architecture', icon: Network },
  ];

  const content = (
    <div className="flex flex-col h-full bg-white dark:bg-surface-cardDark border-r border-slate-200 dark:border-slate-800 transition-all duration-300">
      {/* Brand Header */}
      <div className="flex items-center justify-between p-4 h-16 border-b border-slate-100 dark:border-slate-800/80">
        <div className="flex items-center gap-3 overflow-hidden">
          <div className="w-8 h-8 rounded-lg bg-gradient-to-tr from-cyan-600 to-cyan-400 flex items-center justify-center text-white shrink-0 shadow-sm shadow-cyan-500/20">
            <ShieldAlert className="w-5 h-5" />
          </div>
          {!collapsed && (
            <div className="flex flex-col truncate">
              <span className="text-sm font-bold tracking-tight text-slate-900 dark:text-white leading-tight">
                Agent Governance
              </span>
              <span className="text-[10px] text-cyan-600 dark:text-cyan-400 font-mono tracking-wider uppercase">
                Runtime Console v2
              </span>
            </div>
          )}
        </div>
        <button
          onClick={onToggle}
          className="hidden md:flex p-1.5 rounded-lg text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800/80 transition-colors active:scale-95"
          aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        >
          {collapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
        </button>
      </div>

      {/* Nav List */}
      <nav className="flex-1 p-3 space-y-1 overflow-y-auto">
        {navItems.map(item => {
          const Icon = item.icon;
          return (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.exact}
              onClick={onMobileClose}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2 rounded-xl text-sm font-medium transition-all duration-150 active:scale-[0.98] ${
                  isActive
                    ? 'bg-cyan-500/10 text-cyan-600 dark:text-cyan-400 font-semibold'
                    : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800/60'
                }`
              }
              title={collapsed ? item.label : undefined}
            >
              <Icon className="w-4 h-4 shrink-0" />
              {!collapsed && <span>{item.label}</span>}
            </NavLink>
          );
        })}
      </nav>

      {/* Legacy Dashboard Link */}
      <div className="p-3 border-t border-slate-100 dark:border-slate-800/80">
        <a
          href="/legacy-dashboard"
          className="flex items-center gap-2.5 px-3 py-2 text-xs text-slate-500 hover:text-slate-700 dark:hover:text-slate-300 rounded-xl hover:bg-slate-100 dark:hover:bg-slate-800/60 transition-colors"
          title="Switch to original A2A dashboard"
        >
          <ExternalLink className="w-3.5 h-3.5 shrink-0" />
          {!collapsed && <span>Legacy Dashboard</span>}
        </a>
      </div>
    </div>
  );

  return (
    <>
      {/* Desktop Sidebar */}
      <aside
        className={`hidden md:block shrink-0 transition-all duration-300 ${
          collapsed ? 'w-18' : 'w-60'
        }`}
      >
        <div className={`fixed top-0 bottom-0 left-0 z-30 transition-all duration-300 ${
          collapsed ? 'w-18' : 'w-60'
        }`}>
          {content}
        </div>
      </aside>

      {/* Mobile Drawer */}
      {mobileOpen && (
        <div className="fixed inset-0 z-50 md:hidden flex">
          <div
            className="fixed inset-0 bg-black/50 backdrop-blur-xs"
            onClick={onMobileClose}
          />
          <div className="relative w-64 h-full z-10 animate-in slide-in-from-left duration-200">
            {content}
          </div>
        </div>
      )}
    </>
  );
};
