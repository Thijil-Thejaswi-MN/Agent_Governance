import React from 'react';
import { NavLink } from 'react-router-dom';
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
  Home,
  KeyRound,
  X,
} from 'lucide-react';
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
}> = ({ waitingCount = 0, totalTasks = 0, variant = 'rail', onClose }) => {
  const { role, user, team, hasToken, removeToken, openAuthModal } = useAuth();
  const currentRole = role || 'admin';
  const roleCfg = ROLE_COLORS[currentRole] || ROLE_COLORS.admin;
  const isDrawer = variant === 'drawer';

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
          { to: '/records', label: 'Records', icon: icon(FileText) },
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
          { to: '/standing-rules', label: 'Standing rules', icon: icon(Sliders) },
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
          { to: '/standing-rules', label: 'Standing rules', icon: icon(Sliders) },
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
          { to: '/standing-rules', label: 'Standing rules', icon: icon(Sliders) },
          { to: '/records', label: 'Records', icon: icon(FileText) },
        ];
    }
  };

  // The developer pages, the same for every role; Run only where the server lets the role start one.
  const consoleItems: NavItem[] = [
    ...(!hasToken || CAN_START_RUN.includes(currentRole) ? [{ to: '/run', label: 'Run', icon: icon(Play) }] : []),
    { to: '/history', label: 'History', icon: icon(History) },
    { to: '/fleet', label: 'Fleet', icon: icon(LayoutGrid) },
    { to: '/results', label: 'Results', icon: icon(BarChart3) },
    { to: '/', label: 'Home', icon: icon(Home), end: true },
  ];

  const roleItems = getRoleItems();

  const renderItem = (item: NavItem) => (
    <NavLink
      key={item.to}
      to={item.to}
      end={item.end}
      onClick={onClose}
      className={({ isActive }) =>
        `flex items-center gap-3 px-3 min-h-[44px] md:min-h-[40px] rounded-lg text-[14px] transition-colors no-underline ${
          isActive
            ? 'bg-[#1A2232] text-[#E6E9EF] font-semibold'
            : 'text-[#A7B0C0] hover:bg-[#141A24] hover:text-[#E6E9EF]'
        }`
      }
    >
      <span className="flex-shrink-0 text-[#8B95A7]">{item.icon}</span>
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
    </NavLink>
  );

  return (
    <aside
      className={
        isDrawer
          ? 'relative flex w-[280px] max-w-[85vw] h-full bg-[#0E121A] border-r border-[#1F2633] p-4 flex-col gap-4 overflow-y-auto anim-drawer-left'
          : 'hidden md:flex flex-shrink-0 w-64 sticky top-0 h-screen bg-[#0E121A] border-r border-[#1F2633] p-4 flex-col gap-4 overflow-y-auto'
      }
      aria-label="Sidebar navigation"
      data-sidebar={variant}
    >
      {/* Brand Header */}
      <div className="flex items-center gap-3 px-2 py-1">
        <div className="w-8 h-8 rounded-lg bg-[#3B82F6] flex items-center justify-center text-white shadow-sm flex-shrink-0">
          <Shield className="w-4 h-4" />
        </div>
        <div className="min-w-0 flex-1">
          <div className="font-bold text-[15px] text-[#E6E9EF] tracking-tight truncate">Agent Governance</div>
          <div className="text-[12px] text-[#8B95A7] truncate">{team ? `${team} team` : 'Organization'}</div>
        </div>
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
      <nav aria-label="Main" className="flex flex-col gap-1 mt-2">
        {roleItems.map(renderItem)}
        {roleItems.length > 0 && (
          <div className="px-3 pt-4 pb-1 text-[11px] font-semibold uppercase tracking-wider text-[#8B95A7]" aria-hidden="true">
            Agents
          </div>
        )}
        {consoleItems.map(renderItem)}
      </nav>

      {/* User Chip, or sign-in when there is no session */}
      {hasToken ? (
        <div className="mt-auto flex items-center justify-between gap-2 p-2 rounded-xl bg-[#11151D] border border-[#1F2633]">
          <div className="flex items-center gap-2.5 min-w-0">
            <span
              aria-hidden="true"
              className="flex-none w-8 h-8 rounded-full flex items-center justify-center text-[12px] font-bold text-[#0B0E14]"
              style={{ background: roleCfg.dot }}
            >
              {initials}
            </span>
            <div className="min-w-0">
              <div className="font-semibold text-[13px] text-[#E6E9EF] truncate">{user?.name || 'Local Operator'}</div>
              <div className="text-[11px] font-medium truncate" style={{ color: roleCfg.text }}>
                {roleCfg.title} {team ? `· ${team}` : ''}
              </div>
            </div>
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
        <button
          id={isDrawer ? undefined : 'header-sign-in-btn'}
          onClick={() => {
            onClose?.();
            openAuthModal();
          }}
          className="mt-auto btn-ghost w-full min-h-[44px]"
          style={{ borderColor: 'rgba(245,158,11,0.45)', color: '#FCD34D' }}
        >
          <KeyRound className="w-4 h-4" />
          Sign in
        </button>
      )}
    </aside>
  );
};
