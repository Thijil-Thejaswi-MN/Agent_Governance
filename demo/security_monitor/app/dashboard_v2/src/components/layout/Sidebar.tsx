import React from 'react';
import { Link, NavLink } from 'react-router-dom';
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
  PanelLeftOpen, ShieldX } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { Role } from '../../types';

interface NavItem {
  to: string;
  label: string;
  icon: React.ReactNode;
  badge?: string | number;
  badgeColor?: string;
  end?: boolean;
}

const ROLE_COLORS: Record<Role, { text: string; bg: string; dot: string; title: string }> = {
  developer: { text: '#60A5FA', bg: 'rgba(96,165,250,0.15)', dot: '#60A5FA', title: 'Developer' },
  team_lead: { text: '#A78BFA', bg: 'rgba(167,139,250,0.15)', dot: '#A78BFA', title: 'Team lead' },
  security_reviewer: { text: '#FBBF24', bg: 'rgba(251,191,36,0.15)', dot: '#FBBF24', title: 'Security reviewer' },
  admin: { text: '#34D399', bg: 'rgba(52,211,153,0.15)', dot: '#34D399', title: 'Admin' },
  auditor: { text: '#F472B6', bg: 'rgba(244,114,182,0.15)', dot: '#F472B6', title: 'Auditor' },
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

  // The role homes each role already had (Run and History now live in the console list below).
  const getRoleItems = (): NavItem[] => {
    if (!hasToken) return [];
    switch (currentRole) {
      case 'developer':
        return [];
      case 'team_lead':
        return [
          { to: '/team', label: 'Team overview', icon: icon(Layers), end: true },
          {
            to: '/inbox',
            label: 'Needs you',
            icon: icon(AlertOctagon),
            badge: waitingCount > 0 ? waitingCount : undefined,
            badgeColor: '#F59E0B',
          },
          // No Records: the server does not serve the records summary to team leads.
        ];
      case 'security_reviewer':
        return [
          {
            to: '/inbox',
            label: 'Inbox',
            icon: icon(Inbox),
            badge: waitingCount > 0 ? waitingCount : undefined,
            badgeColor: '#FBBF24',
            end: true,
          },
          { to: '/standing-rules', label: 'Policies', icon: icon(Sliders) },
          { to: '/records', label: 'Records', icon: icon(FileText) },
        ];
      case 'auditor':
        return [
          {
            to: '/records',
            label: 'Records',
            icon: icon(FileText),
            badge: totalTasks > 0 ? totalTasks : undefined,
            badgeColor: '#8B95A7',
            end: true,
          },
          { to: '/standing-rules', label: 'Policies', icon: icon(Sliders) },
        ];
      case 'admin':
      default:
        return [
          { to: '/overview', label: 'Overview', icon: icon(Layers), end: true },
          {
            to: '/inbox',
            label: 'Approvals',
            icon: icon(Inbox),
            badge: waitingCount > 0 ? waitingCount : undefined,
            badgeColor: '#F59E0B',
          },
          { to: '/standing-rules', label: 'Policies', icon: icon(Sliders) },
          { to: '/records', label: 'Records', icon: icon(FileText) },
        ];
    }
  };

  // The developer pages, the same for every role; Run only where the server lets the role start one.
  const consoleItems: NavItem[] = [
    ...(!hasToken || CAN_START_RUN.includes(currentRole) ? [{ to: '/run', label: 'Run', icon: icon(Play) }] : []),
    { to: '/history', label: 'History', icon: icon(History) },
    { to: '/incidents', label: 'Incidents', icon: icon(ShieldX) },
    { to: '/fleet', label: 'Fleet', icon: icon(LayoutGrid) },
    { to: '/results', label: 'Results', icon: icon(BarChart3) },
  ];

  const roleItems = getRoleItems();

  // Collapsed: a tooltip beside the icon, shown on hover and on keyboard focus.
  const tooltip = (text: string) => (
    <span
      aria-hidden="true"
      className="pointer-events-none absolute left-full top-1/2 -translate-y-1/2 ml-3 z-50 whitespace-nowrap rounded-md border border-[#2A3344] bg-[#1A2232] px-2 py-1 text-[12px] font-medium text-[#E6E9EF] opacity-0 shadow-lg transition-opacity group-hover:opacity-100 group-focus-visible:opacity-100"
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
            collapsed ? 'justify-center w-11 h-11 mx-auto' : 'gap-3 px-3 min-h-[44px] md:min-h-[40px]'
          } ${
            isActive
              ? 'bg-[#1A2232] text-[#E6E9EF] font-semibold'
              : 'text-[#A7B0C0] hover:bg-[#141A24] hover:text-[#E6E9EF]'
          }`
        }
      >
        {({ isActive }) => (
          <>
            {collapsed && isActive && (
              <span aria-hidden="true" className="absolute left-[-8px] top-2 bottom-2 w-[3px] rounded-full bg-[#3B82F6]" />
            )}
            <span className={`relative flex-shrink-0 ${isActive ? 'text-[#E6E9EF]' : 'text-[#8B95A7]'}`}>
              {item.icon}
              {collapsed && item.badge !== undefined && (
                <span
                  aria-hidden="true"
                  className="absolute -top-2 -right-2.5 min-w-[16px] h-4 px-1 rounded-full text-[10px] leading-4 font-bold text-center"
                  style={{
                    background: item.badgeColor || '#2A3344',
                    color: item.badgeColor === '#F59E0B' || item.badgeColor === '#FBBF24' ? '#1A1203' : '#0B0E14',
                  }}
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
                    className="ml-auto px-2 py-0.5 rounded-full text-[11px] font-bold"
                    style={{
                      background: item.badgeColor || '#2A3344',
                      color: item.badgeColor === '#F59E0B' || item.badgeColor === '#FBBF24' ? '#1A1203' : '#0B0E14',
                    }}
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
          ? 'relative flex w-[280px] max-w-[85vw] h-full bg-[#0E121A] border-r border-[#1F2633] p-4 flex-col gap-4 overflow-y-auto anim-drawer-left'
          : `hidden md:flex flex-shrink-0 sticky top-0 z-40 h-screen bg-[#0E121A] border-r border-[#1F2633] flex-col gap-4 transition-[width] duration-200 ${
              collapsed ? 'w-16 px-2 py-4 overflow-visible' : 'w-64 p-4 overflow-y-auto'
            }`
      }
      aria-label="Sidebar navigation"
      data-sidebar={variant}
      data-collapsed={collapsed ? 'true' : 'false'}
    >
      {/* Brand header; the collapse toggle is the first control (same element in both states, so focus stays on it) */}
      <div className={collapsed ? 'flex flex-col items-center gap-3' : 'flex items-center gap-2.5 pl-2 py-1'}>
        {!isDrawer && (
          <button
            type="button"
            id="sidebar-toggle"
            onClick={onToggleCollapsed}
            aria-label={toggleLabel}
            aria-expanded={!collapsed}
            aria-controls="sidebar-rail"
            className={`group relative inline-flex items-center justify-center w-10 h-10 md:w-9 md:h-9 rounded-lg text-[#A7B0C0] hover:text-[#E6E9EF] hover:bg-[#1A2232] bg-transparent border-none cursor-pointer flex-shrink-0 ${
              collapsed ? '' : 'order-last ml-auto'
            }`}
          >
            {collapsed ? <PanelLeftOpen className="w-[18px] h-[18px]" /> : <PanelLeftClose className="w-[18px] h-[18px]" />}
            {collapsed && tooltip(toggleLabel)}
          </button>
        )}
        <div className="w-8 h-8 rounded-lg bg-[#3B82F6] flex items-center justify-center text-white shadow-sm flex-shrink-0" aria-hidden={collapsed ? 'true' : undefined}>
          <Shield className="w-4 h-4" />
        </div>
        {!collapsed && (
          <div className="min-w-0 flex-1">
            <div className="font-bold text-[14px] text-[#E6E9EF] tracking-tight truncate">Agent Governance</div>
            <div className="text-[12px] text-[#8B95A7] truncate">{team ? `${team} team` : 'Organization'}</div>
          </div>
        )}
        {isDrawer && (
          <button
            type="button"
            onClick={onClose}
            aria-label="Close menu"
            className="inline-flex items-center justify-center w-11 h-11 rounded-lg text-[#A7B0C0] hover:text-[#E6E9EF] hover:bg-[#1A2232] bg-transparent border-none cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        )}
      </div>

      {/* Nav List */}
      <nav aria-label="Main" className={`flex flex-col gap-1 mt-2 ${collapsed ? 'items-stretch' : ''}`}>
        {roleItems.map(renderItem)}
        {roleItems.length > 0 &&
          (collapsed ? (
            <div aria-hidden="true" className="mx-3 my-2 border-t border-[#1F2633]" />
          ) : (
            <div className="px-3 pt-4 pb-1 text-[11px] font-semibold uppercase tracking-wider text-[#8B95A7]" aria-hidden="true">
              Agents
            </div>
          ))}
        {consoleItems.map(renderItem)}
      </nav>

      {/* User Chip, or sign-in when there is no session */}
      {hasToken ? (
        <div
          className={`mt-auto flex items-center gap-2 rounded-xl bg-[#11151D] border border-[#1F2633] ${
            collapsed ? 'flex-col p-1.5' : 'justify-between p-2'
          }`}
        >
          <div className="group relative flex items-center gap-2.5 min-w-0">
            <span
              aria-hidden="true"
              className="flex-none w-8 h-8 rounded-full flex items-center justify-center text-[12px] font-bold text-[#0B0E14]"
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
                <div className="font-semibold text-[13px] text-[#E6E9EF] truncate">{user?.name || 'Local Operator'}</div>
                <div className="text-[11px] font-medium truncate" style={{ color: roleCfg.text }}>
                  {roleCfg.title} {team ? `· ${team}` : ''}
                </div>
              </div>
            )}
          </div>
          <button
            onClick={removeToken}
            id={isDrawer ? undefined : 'sign-out-btn'}
            aria-label="Sign out"
            title="Sign out"
            className="inline-flex items-center justify-center w-11 h-11 md:w-9 md:h-9 rounded-lg text-[#8B95A7] hover:text-[#E6E9EF] hover:bg-[#1A2232] transition-colors border-none bg-transparent cursor-pointer"
          >
            <LogOut className="w-4 h-4" />
          </button>
        </div>
      ) : (
        <Link
          id={isDrawer ? undefined : 'header-sign-in-btn'}
          to="/signin"
          onClick={onClose}
          aria-label={collapsed ? 'Sign in' : undefined}
          className={`group relative mt-auto btn-ghost min-h-[44px] ${collapsed ? 'w-11 px-0 mx-auto' : 'w-full'}`}
          style={{ borderColor: 'rgba(245,158,11,0.45)', color: '#FCD34D' }}
        >
          <KeyRound className="w-4 h-4" />
          {collapsed ? tooltip('Sign in') : 'Sign in'}
        </Link>
      )}
    </aside>
  );
};
