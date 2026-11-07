import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  Shield,
  Layers,
  Inbox,
  CheckCircle2,
  FileText,
  Users,
  Play,
  Sliders,
  LogOut,
  AlertOctagon,
  FileCode2,
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

export const Sidebar: React.FC<{ waitingCount?: number; totalTasks?: number }> = ({
  waitingCount = 0,
  totalTasks = 0,
}) => {
  const { role, user, team, removeToken } = useAuth();
  const currentRole = role || 'admin';
  const roleCfg = ROLE_COLORS[currentRole] || ROLE_COLORS.admin;

  const initials = (user?.name || 'Admin')
    .split(' ')
    .map(p => p[0])
    .join('')
    .toUpperCase()
    .slice(0, 2);

  // Define nav links tailored to each role
  const getNavItems = (): NavItem[] => {
    switch (currentRole) {
      case 'developer':
        return [
          { to: '/run', label: 'Ask & Watch', icon: <Play className="w-4 h-4" />, end: true },
          { to: '/history', label: 'My runs', icon: <FileText className="w-4 h-4" /> },
        ];
      case 'team_lead':
        return [
          { to: '/team', label: 'Team overview', icon: <Layers className="w-4 h-4" />, end: true },
          {
            to: '/inbox',
            label: 'Needs you',
            icon: <AlertOctagon className="w-4 h-4" />,
            badge: waitingCount > 0 ? waitingCount : undefined,
            badgeColor: '#F59E0B',
          },
          { to: '/history', label: 'Team runs', icon: <Play className="w-4 h-4" /> },
          { to: '/records', label: 'Records', icon: <FileText className="w-4 h-4" /> },
        ];
      case 'security_reviewer':
        return [
          {
            to: '/inbox',
            label: 'Inbox',
            icon: <Inbox className="w-4 h-4" />,
            badge: waitingCount > 0 ? waitingCount : undefined,
            badgeColor: '#FBBF24',
            end: true,
          },
          { to: '/standing-rules', label: 'Standing rules', icon: <Sliders className="w-4 h-4" /> },
          { to: '/history', label: 'Runs', icon: <Play className="w-4 h-4" /> },
          { to: '/records', label: 'Records', icon: <FileText className="w-4 h-4" /> },
        ];
      case 'auditor':
        return [
          {
            to: '/records',
            label: 'Records',
            icon: <FileText className="w-4 h-4" />,
            badge: totalTasks > 0 ? totalTasks : undefined,
            badgeColor: '#8B95A7',
            end: true,
          },
          { to: '/standing-rules', label: 'Standing rules', icon: <Sliders className="w-4 h-4" /> },
          { to: '/history', label: 'Runs', icon: <Play className="w-4 h-4" /> },
        ];
      case 'admin':
      default:
        return [
          { to: '/overview', label: 'Overview', icon: <Layers className="w-4 h-4" />, end: true },
          {
            to: '/inbox',
            label: 'Approvals',
            icon: <Inbox className="w-4 h-4" />,
            badge: waitingCount > 0 ? waitingCount : undefined,
            badgeColor: '#F59E0B',
          },
          { to: '/run', label: 'Run demo', icon: <Play className="w-4 h-4" /> },
          { to: '/history', label: 'Runs', icon: <FileCode2 className="w-4 h-4" /> },
          { to: '/standing-rules', label: 'Standing rules', icon: <Sliders className="w-4 h-4" /> },
          { to: '/records', label: 'Records', icon: <FileText className="w-4 h-4" /> },
        ];
    }
  };

  const navItems = getNavItems();

  return (
    <aside
      className="flex-shrink-0 w-64 bg-[#0E121A] border-r border-[#1F2633] p-4 flex flex-col gap-4 select-none min-h-screen"
      aria-label="Sidebar navigation"
    >
      {/* Brand Header */}
      <div className="flex items-center gap-3 px-2 py-1">
        <div className="w-8 h-8 rounded-lg bg-[#3B82F6] flex items-center justify-center text-white shadow-sm flex-shrink-0">
          <Shield className="w-4 h-4" />
        </div>
        <div className="min-w-0">
          <div className="font-bold text-[15px] text-[#E6E9EF] tracking-tight truncate">Agent Governance</div>
          <div className="text-[12px] text-[#8B95A7] truncate">
            {team ? `${team} team` : 'Organization'}
          </div>
        </div>
      </div>

      {/* Nav List */}
      <nav aria-label="Main" className="flex flex-col gap-1 mt-2">
        {navItems.map(item => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.end}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2 rounded-lg text-[14px] transition-colors no-underline ${
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
                  color: item.badgeColor === '#F59E0B' || item.badgeColor === '#FBBF24' ? '#1A1203' : '#E6E9EF',
                }}
              >
                {item.badge}
              </span>
            )}
          </NavLink>
        ))}
      </nav>

      {/* User Chip */}
      <div className="mt-auto pt-3 border-t border-[#1F2633] flex items-center justify-between gap-2 p-2 rounded-xl bg-[#11151D] border border-[#1F2633]">
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
          id="sign-out-btn"
          aria-label="Sign out"
          title="Sign out"
          className="p-1.5 rounded-lg text-[#8B95A7] hover:text-[#E6E9EF] hover:bg-[#1A2232] transition-colors border-none bg-transparent cursor-pointer"
        >
          <LogOut className="w-4 h-4" />
        </button>
      </div>
    </aside>
  );
};

