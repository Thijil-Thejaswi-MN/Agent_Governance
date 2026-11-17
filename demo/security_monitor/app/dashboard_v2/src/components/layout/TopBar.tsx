import React from 'react';
import { Menu, Shield } from 'lucide-react';
import { useLocation } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import { Button } from '../ui/Button';
import { StatusPill } from '../ui/StatusPill';

interface TopBarProps {
  breadcrumb?: string;
  activeAgentsCount?: number;
  /** Opens the sidebar as a drawer below md (768 px). */
  onMenu?: () => void;
  menuOpen?: boolean;
}

export const TopBar: React.FC<TopBarProps> = ({ breadcrumb, activeAgentsCount = 0, onMenu, menuOpen = false }) => {
  const location = useLocation();
  const { team } = useAuth();

  const getContextAndTitle = () => {
    if (breadcrumb) {
      if (breadcrumb.includes(' / ')) {
        const parts = breadcrumb.split(' / ').map(s => s.trim());
        const title = parts.pop() || '';
        const context = parts.join(' / ');
        return { context, title };
      }
      return { context: team ? `${team} team` : '', title: breadcrumb };
    }

    const path = location.pathname.replace(/^\/+/g, '');
    let title = 'Overview';
    let context = team ? `${team} team` : '';

    if (!path || path.startsWith('overview')) {
      title = 'Overview';
    } else if (path.startsWith('team')) {
      title = 'Team overview';
    } else if (path.startsWith('inbox')) {
      title = 'Approvals';
      context = context || 'Governance';
    } else if (path.startsWith('standing-rules')) {
      title = 'Policies';
      context = context || 'Governance';
    } else if (path.startsWith('records')) {
      title = 'Records';
      context = context || 'Audit & Reports';
    } else if (path.startsWith('runs/')) {
      title = 'Run investigation';
      context = context || 'Runtime';
    } else if (path.startsWith('run')) {
      title = 'Run';
      context = context || 'Runtime';
    } else if (path.startsWith('report/')) {
      title = 'Task report';
      context = context || 'Audit & Reports';
    } else if (path.startsWith('incidents')) {
      title = 'Incidents';
    } else if (path.startsWith('inventory')) {
      title = 'Agent Inventory';
    } else if (path.startsWith('history/')) {
      title = 'Past run';
      context = context || 'Runtime';
    } else if (path.startsWith('history')) {
      title = 'History';
      context = context || 'Runtime';
    } else if (path.startsWith('fleet')) {
      title = 'Fleet';
      context = context || 'Runtime';
    } else if (path.startsWith('results')) {
      title = 'Results';
      context = context || 'Audit & Reports';
    } else {
      title = path;
    }

    return { context, title };
  };

  const { context, title } = getContextAndTitle();

  return (
    <header
      data-topbar
      className="sticky top-0 z-30 flex items-center justify-between gap-3 px-4 md:px-8 h-14 border-b border-line bg-surface-1 select-none relative"
    >
      {/* 2px accent gradient line at the top of the header */}
      <div className="absolute top-0 left-0 right-0 h-[2px] bg-[image:var(--accent-grad)] pointer-events-none" />

      {/* Below md: menu button and brand (the sidebar is a drawer there) */}
      <div className="flex md:hidden items-center gap-2 min-w-0">
        <Button
          id="open-menu-btn"
          variant="ghost"
          size="icon-sm"
          onClick={onMenu}
          aria-label="Open menu"
          aria-expanded={menuOpen}
          className="-ml-2 text-fg-2 hover:text-fg"
        >
          <Menu className="w-5 h-5" />
        </Button>
        <span className="w-7 h-7 rounded-lg bg-[image:var(--accent-grad)] flex items-center justify-center text-white flex-shrink-0" aria-hidden="true">
          <Shield className="w-3.5 h-3.5" />
        </span>
        <span className="font-semibold text-[15px] text-fg tracking-tight truncate">Agent Governance</span>
      </div>

      {/* Desktop breadcrumb / context & page title in Instrument Serif */}
      <div className="hidden md:flex items-baseline gap-2 min-w-0">
        {context ? (
          <span className="text-[13px] text-fg-3 font-normal truncate">
            {context} <span className="mx-1 text-fg-3/60">/</span>
          </span>
        ) : null}
        <div className="text-[22px] font-serif text-fg font-normal leading-none tracking-tight truncate">
          {title}
        </div>
      </div>

      {/* Right controls: active agents status badge */}
      <div className="flex items-center gap-3 ml-auto">
        {activeAgentsCount > 0 && (
          <StatusPill tone="ok" label={`${activeAgentsCount} running`} />
        )}
      </div>
    </header>
  );
};
