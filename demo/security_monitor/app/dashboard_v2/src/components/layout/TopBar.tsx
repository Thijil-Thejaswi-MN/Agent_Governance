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
      if (breadcrumb.includes(' / ') || breadcrumb.includes(' › ')) {
        const parts = breadcrumb.split(/\s*[/›]\s*/).map(s => s.trim());
        const title = parts.pop() || '';
        const context = parts.join(' › ');
        return { context, title };
      }
      return { context: team ? `${team} team` : '', title: breadcrumb };
    }

    const path = location.pathname.replace(/^\/+/g, '').replace(/\/+$/, '');
    let title = 'Overview';
    let context = team ? `${team} team` : 'Overview';

    if (!path || path === 'overview') {
      title = 'Overview';
      context = team ? `${team} team` : 'Overview';
    } else if (path.startsWith('team')) {
      title = 'Team overview';
      context = team ? `${team} team` : 'Overview';
    } else if (path.startsWith('inbox')) {
      title = 'Approvals';
      context = 'Governance';
    } else if (path.startsWith('standing-rules')) {
      title = 'Policies';
      context = 'Governance';
    } else if (path.startsWith('records')) {
      title = 'Records';
      context = 'Audit & Reports';
    } else if (path.startsWith('runs/')) {
      title = 'Run investigation';
      context = 'Runtime';
    } else if (path.startsWith('run')) {
      title = 'Run';
      context = 'Runtime';
    } else if (path.startsWith('report/')) {
      title = 'Task report';
      context = 'Audit & Reports';
    } else if (path.startsWith('incidents')) {
      title = 'Incidents';
      context = 'Incidents';
    } else if (path.startsWith('inventory')) {
      title = 'Agents';
      context = 'Agent Inventory';
    } else if (path.startsWith('history/')) {
      title = 'Past run';
      context = 'Runtime';
    } else if (path.startsWith('history')) {
      title = 'History';
      context = 'Runtime';
    } else if (path.startsWith('fleet')) {
      title = 'Fleet';
      context = 'Runtime';
    } else if (path.startsWith('results')) {
      title = 'Results';
      context = 'Audit & Reports';
    } else if (path.startsWith('evidence')) {
      title = 'Evidence';
      context = 'Audit & Reports';
    } else {
      title = 'Page not found';
      context = 'Console';
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

      {/* Desktop breadcrumb only: context › page name, Inter text-[13px] */}
      <nav aria-label="Breadcrumb" className="hidden md:flex items-center gap-1.5 min-w-0 text-[13px]">
        {context ? (
          <>
            <span className="text-fg-3 truncate">{context}</span>
            <span className="text-fg-3 select-none" aria-hidden="true">›</span>
          </>
        ) : null}
        <span className="text-fg-2 truncate font-normal">{title}</span>
      </nav>

      {/* Right controls: active agents status badge */}
      <div className="flex items-center gap-3 ml-auto">
        {activeAgentsCount > 0 && (
          <StatusPill tone="info" label={`${activeAgentsCount} running`} />
        )}
      </div>
    </header>
  );
};
