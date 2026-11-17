import React from 'react';
import { Link, NavLink, useNavigate } from 'react-router-dom';
import {
  Shield,
  Layers,
  Inbox,
  FileText,
  Play,
  Sliders,
  LogOut,
  AlertOctagon,
  History,
  LayoutGrid,
  BarChart3,
  KeyRound,
  X,
  PanelLeftClose,
  PanelLeftOpen,
  ShieldX,
  Bot,
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { Role } from '../../types';
import { Button } from '../ui/Button';

type GroupKey = 'overview' | 'inventory' | 'governance' | 'runtime' | 'incidents' | 'audit' | 'settings';

// The order and names of the sidebar groups. Settings has no page yet, so it never shows.
const GROUPS: { key: GroupKey; label: string }[] = [
  { key: 'overview', label: 'Overview' },
  { key: 'inventory', label: 'Agent Inventory' },
  { key: 'governance', label: 'Governance' },
  { key: 'runtime', label: 'Runtime Monitoring' },
  { key: 'incidents', label: 'Incidents' },
  { key: 'audit', label: 'Audit & Reports' },
  { key: 'settings', label: 'Settings' },
];

interface NavItem {
  to: string;
  label: string;
  icon: React.ReactNode;
  badge?: string | number;
  badgeColor?: string;
  end?: boolean;
}

const ROLE_COLORS: Record<Role, { text: string; bg: string; dot: string; title: string }> = {
  developer: { text: 'var(--role-developer)', bg: 'rgba(var(--role-developer-rgb) / 0.15)', dot: 'var(--role-developer)', title: 'Developer' },
  team_lead: { text: 'var(--role-team-lead)', bg: 'rgba(var(--role-team-lead-rgb) / 0.15)', dot: 'var(--role-team-lead)', title: 'Team lead' },
  security_reviewer: { text: 'var(--role-security-reviewer)', bg: 'rgba(var(--role-security-reviewer-rgb) / 0.15)', dot: 'var(--role-security-reviewer)', title: 'Security reviewer' },
  admin: { text: 'var(--role-admin)', bg: 'rgba(var(--role-admin-rgb) / 0.15)', dot: 'var(--role-admin)', title: 'Admin' },
  auditor: { text: 'var(--role-auditor)', bg: 'rgba(var(--role-auditor-rgb) / 0.15)', dot: 'var(--role-auditor)', title: 'Auditor' },
};

// Roles the server lets start a run (PermissionMatrix.can_start_run).
const CAN_START_RUN: Role[] = ['developer', 'team_lead', 'admin'];

const icon = (I: React.ComponentType<{ className?: string }>) => <I className="w-4 h-4" />;

export const Sidebar: React.FC<{
  waitingCount?: number;
  totalTasks?: number;
  /** 'rail': the fixed column from md up. 'drawer': the same list in the mobile menu. */
  variant?: 'rail' | 'drawer';
  onClose?: () => void;
  /** Rail only: icons-only mode (about 64 px). */
  collapsed?: boolean;
  onToggleCollapsed?: () => void;
}> = ({ waitingCount = 0, totalTasks = 0, variant = 'rail', onClose, collapsed: collapsedProp = false, onToggleCollapsed }) => {
  const { role, user, team, hasToken, removeToken } = useAuth();
  const navigate = useNavigate();
  // Signing out goes back to the landing page.
  const signOut = () => {
    onClose?.();
    navigate('/signin', { replace: true });
    removeToken();
  };
  const currentRole = role || 'admin';
  const roleCfg = ROLE_COLORS[currentRole] || ROLE_COLORS.admin;
  const isDrawer = variant === 'drawer';
  // The mobile drawer always shows labels.
  const collapsed = !isDrawer && collapsedProp;

  const initials = (user?.name || 'Admin')
    .split(' ')
    .map(p => p[0])
    .join('')
    .toUpperCase()
    .slice(0, 2);

  // One list, grouped. Each role sees only the items it had before (plus Agents and Incidents);
  // routes are unchanged. Groups with no items for a role are not shown.
  const waitingBadge = (color: string) => ({ badge: waitingCount > 0 ? waitingCount : undefined, badgeColor: color });
  const items: (NavItem & { group: GroupKey })[] = [];
  const add = (group: GroupKey, item: NavItem) => items.push({ ...item, group });
  const signedIn = hasToken;
  if (signedIn && currentRole === 'admin') add('overview', { to: '/overview', label: 'Overview', icon: icon(Layers), end: true });
  if (signedIn && currentRole === 'team_lead') add('overview', { to: '/team', label: 'Team overview', icon: icon(Layers), end: true });
  if (signedIn) add('inventory', { to: '/inventory', label: 'Agents', icon: icon(Bot) });
  if (signedIn && currentRole === 'admin') add('governance', { to: '/inbox', label: 'Approvals', icon: icon(Inbox), ...waitingBadge('var(--wait)') });
  if (signedIn && currentRole === 'team_lead') add('governance', { to: '/inbox', label: 'Needs you', icon: icon(AlertOctagon), ...waitingBadge('var(--wait)') });
  if (signedIn && currentRole === 'security_reviewer') add('governance', { to: '/inbox', label: 'Inbox', icon: icon(Inbox), end: true, ...waitingBadge('var(--wait-kpi)') });
  if (signedIn && ['admin', 'security_reviewer', 'auditor'].includes(currentRole))
    add('governance', { to: '/standing-rules', label: 'Policies', icon: icon(Sliders) });
  // Run only where the server lets the role start one.
  if (!signedIn || CAN_START_RUN.includes(currentRole)) add('runtime', { to: '/run', label: 'Run', icon: icon(Play) });
  add('runtime', { to: '/fleet', label: 'Fleet', icon: icon(LayoutGrid) });
  add('runtime', { to: '/history', label: 'History', icon: icon(History) });
  add('incidents', { to: '/incidents', label: 'Incidents', icon: icon(ShieldX) });
  // No Records for team leads: the server does not serve the records summary to them.
  if (signedIn && ['admin', 'security_reviewer', 'auditor'].includes(currentRole))
    add('audit', {
      to: '/records',
      label: 'Records',
      icon: icon(FileText),
      ...(currentRole === 'auditor' ? { badge: totalTasks > 0 ? totalTasks : undefined, badgeColor: 'var(--text-3)', end: true } : {}),
    });
  add('audit', { to: '/results', label: 'Results', icon: icon(BarChart3) });

  const groups = GROUPS.map(g => ({ ...g, items: items.filter(i => i.group === g.key) })).filter(g => g.items.length > 0);

  // Collapsed: a tooltip beside the icon, shown on hover and on keyboard focus.
  const tooltip = (text: string) => (
    <span
      aria-hidden="true"
      className="pointer-events-none absolute left-full top-1/2 -translate-y-1/2 ml-3 z-50 whitespace-nowrap rounded-md border border-line-strong bg-surface-2 px-2 py-1 text-[12px] font-medium text-fg opacity-0 shadow-lg transition-opacity group-hover:opacity-100 group-focus-visible:opacity-100"
    >
      {text}
    </span>
  );

  const renderItem = (item: NavItem) => {
    const label = item.badge !== undefined ? `${item.label}, ${item.badge}` : item.label;
    return (
      <NavLink
        key={item.to}
        to={item.to}
        end={item.end}
        onClick={onClose}
        aria-label={collapsed ? label : undefined}
        className={({ isActive }) =>
          `group relative flex items-center rounded-lg text-[14px] transition-colors no-underline ${
            collapsed ? 'justify-center w-10 h-10 mx-auto p-0' : 'h-10 px-3 gap-2.5'
          } ${
            isActive
              ? 'bg-surface-2 text-fg font-medium before:absolute before:left-0 before:top-2 before:bottom-2 before:w-[2px] before:rounded-full before:bg-[image:var(--accent-grad)]'
              : 'text-fg-2 hover:bg-surface-2/50 hover:text-fg'
          }`
        }
      >
        {({ isActive }) => (
          <>
            <span className={`relative flex-shrink-0 flex items-center justify-center ${isActive ? 'text-fg' : 'text-fg-3 group-hover:text-fg-2'}`}>
              {item.icon}
              {collapsed && item.badge !== undefined && (
                <span
                  aria-hidden="true"
                  className="absolute -top-1.5 -right-2 min-w-[16px] h-4 px-1 rounded-full text-[10px] leading-4 font-bold text-center bg-wait text-wait-badge"
                >
                  {item.badge}
                </span>
              )}
            </span>
            {collapsed ? (
              tooltip(label)
            ) : (
              <>
                <span className="truncate">{item.label}</span>
                {item.badge !== undefined && (
                  <span
                    className="ml-auto px-2 py-0.5 rounded-full text-[11px] font-semibold bg-wait-tint text-wait border border-wait/20"
                  >
                    {item.badge}
                  </span>
                )}
              </>
            )}
          </>
        )}
      </NavLink>
    );
  };

  const toggleLabel = collapsed ? 'Expand sidebar' : 'Collapse sidebar';

  return (
    <aside
      id={isDrawer ? undefined : 'sidebar-rail'}
      className={
        isDrawer
          ? 'relative flex w-[280px] max-w-[85vw] h-full bg-surface-1 border-r border-line p-4 flex-col gap-4 overflow-y-auto anim-drawer-left'
          : `hidden md:flex flex-shrink-0 sticky top-0 z-40 h-screen bg-surface-1 border-r border-line flex-col transition-[width] duration-200 ${
              collapsed ? 'w-16 p-2 overflow-visible' : 'w-64 p-3 overflow-y-auto'
            }`
      }
      aria-label="Sidebar navigation"
      data-sidebar={variant}
      data-collapsed={collapsed ? 'true' : 'false'}
    >
      {/* Brand header; h-16 as in Tallie */}
      <div className={`h-16 flex items-center shrink-0 border-b border-line/60 ${collapsed ? 'flex-col justify-center py-1 gap-1' : 'justify-between px-2 gap-2'}`}>
        <div className={`flex items-center gap-2.5 min-w-0 ${collapsed ? 'order-2' : ''}`}>
          <div className="w-8 h-8 rounded-lg bg-[image:var(--accent-grad)] flex items-center justify-center text-white shadow-sm flex-shrink-0" aria-hidden={collapsed ? 'true' : undefined}>
            <Shield className="w-4 h-4" />
          </div>
          {!collapsed && (
            <div className="min-w-0 flex-1">
              <div className="font-semibold text-[14px] text-fg tracking-tight truncate">Agent Governance</div>
              <div className="text-[12px] text-fg-3 truncate">{team ? `${team} team` : 'Organization'}</div>
            </div>
          )}
        </div>

        {!isDrawer && (
          <Button
            id="sidebar-toggle"
            variant="ghost"
            size="icon-sm"
            onClick={onToggleCollapsed}
            aria-label={toggleLabel}
            aria-expanded={!collapsed}
            aria-controls="sidebar-rail"
            className={`text-fg-3 hover:text-fg relative group ${collapsed ? 'order-1 h-7 w-7' : 'ml-auto'}`}
          >
            {collapsed ? <PanelLeftOpen className="w-4 h-4" /> : <PanelLeftClose className="w-4 h-4" />}
            {collapsed && tooltip(toggleLabel)}
          </Button>
        )}

        {isDrawer && (
          <Button
            variant="ghost"
            size="icon-sm"
            onClick={onClose}
            aria-label="Close menu"
            className="text-fg-2 hover:text-fg"
          >
            <X className="w-5 h-5" />
          </Button>
        )}
      </div>

      {/* Nav list, in groups */}
      <nav aria-label="Main" className={`flex flex-col flex-1 py-3 ${collapsed ? 'items-stretch gap-1' : 'gap-2'}`}>
        {groups.map((g, gi) => (
          <div key={g.key} role="group" aria-label={g.label} data-nav-group={g.key} className="flex flex-col gap-0.5">
            {collapsed ? (
              gi > 0 && <div aria-hidden="true" className="mx-2 my-1.5 border-t border-line" />
            ) : (
              <div className="px-3 pt-2 pb-1 text-[11px] font-semibold uppercase tracking-wider text-fg-3" aria-hidden="true">
                {g.label}
              </div>
            )}
            {g.items.map(renderItem)}
          </div>
        ))}
      </nav>

      {/* Footer: User Chip, or sign-in when there is no session */}
      {hasToken ? (
        <div
          className={`mt-auto shrink-0 flex items-center rounded-xl bg-surface-2 border border-line ${
            collapsed ? 'flex-col p-1.5 gap-2' : 'justify-between p-2.5 gap-2'
          }`}
        >
          <div className="group relative flex items-center gap-2.5 min-w-0">
            <span
              aria-hidden="true"
              className="flex-none w-8 h-8 rounded-full flex items-center justify-center text-[12px] font-bold text-bg"
              style={{ background: roleCfg.dot }}
            >
              {initials}
            </span>
            {collapsed ? (
              <>
                <span className="sr-only">
                  {user?.name || 'Local Operator'}, {roleCfg.title}
                </span>
                {tooltip(`${user?.name || 'Local Operator'} · ${roleCfg.title}`)}
              </>
            ) : (
              <div className="min-w-0">
                <div className="font-semibold text-[13px] text-fg truncate">{user?.name || 'Local Operator'}</div>
                <div className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[11px] font-medium mt-0.5" style={{ color: roleCfg.text, background: roleCfg.bg }}>
                  <span className="w-1.5 h-1.5 rounded-full" style={{ background: roleCfg.dot }} />
                  <span className="truncate">{roleCfg.title} {team ? `· ${team}` : ''}</span>
                </div>
              </div>
            )}
          </div>
          <Button
            id={isDrawer ? undefined : 'sign-out-btn'}
            variant="ghost"
            size="icon-sm"
            onClick={signOut}
            aria-label="Sign out"
            title="Sign out"
            className="text-fg-3 hover:text-fg hover:bg-surface-3"
          >
            <LogOut className="w-4 h-4" />
          </Button>
        </div>
      ) : (
        <Link
          id={isDrawer ? undefined : 'header-sign-in-btn'}
          to="/signin"
          onClick={onClose}
          aria-label={collapsed ? 'Sign in' : undefined}
          className={`group relative mt-auto flex items-center justify-center gap-2 rounded-lg border border-line bg-surface-2 text-fg-2 hover:bg-surface-3 hover:text-fg text-[13px] font-medium transition-colors no-underline ${
            collapsed ? 'w-10 h-10 mx-auto p-0' : 'h-10 px-3 w-full'
          }`}
        >
          <KeyRound className="w-4 h-4" />
          {collapsed ? tooltip('Sign in') : 'Sign in'}
        </Link>
      )}
    </aside>
  );
};
