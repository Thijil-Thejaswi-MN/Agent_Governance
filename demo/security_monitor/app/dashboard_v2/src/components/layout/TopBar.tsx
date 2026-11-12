import React from 'react';
import { Menu, Shield } from 'lucide-react';
import { useLocation } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';

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

  // Compute breadcrumb fallback if not passed
  const getBreadcrumb = () => {
    if (breadcrumb) return breadcrumb;
    const path = location.pathname.replace(/^\/+/g, '');
    const page = (() => {
      if (!path) return 'Organization overview';
      if (path.startsWith('team')) return 'Team overview';
      if (path.startsWith('inbox')) return 'Security / Approvals inbox';
      if (path.startsWith('records')) return 'Compliance / Records';
      if (path.startsWith('runs/')) return 'Run investigation';
      if (path.startsWith('run')) return 'Run';
      if (path.startsWith('standing-rules')) return 'Security / Policies';
      if (path.startsWith('history/')) return 'History / One run';
      if (path.startsWith('history')) return 'History';
      if (path.startsWith('fleet')) return 'Fleet';
      if (path.startsWith('results')) return 'Results';
      return path;
    })();
    // The session's team when there is one; no organisation name is invented.
    return team ? `${team} / ${page}` : page;
  };

  return (
    <header className="sticky top-0 z-30 flex items-center justify-between gap-3 px-4 md:px-6 min-h-[56px] py-2 border-b border-[#1F2633] bg-[#0E121A] md:bg-gradient-to-b md:from-[#0E121A] md:to-[#0B0E14] select-none">
      {/* Below md: menu button and brand (the sidebar is a drawer there) */}
      <div className="flex md:hidden items-center gap-2 min-w-0">
        <button
          type="button"
          id="open-menu-btn"
          onClick={onMenu}
          aria-label="Open menu"
          aria-expanded={menuOpen}
          className="inline-flex items-center justify-center w-11 h-11 -ml-2 rounded-lg text-[#A7B0C0] hover:text-[#E6E9EF] hover:bg-[#1A2232] bg-transparent border-none cursor-pointer"
        >
          <Menu className="w-5 h-5" />
        </button>
        <span className="w-7 h-7 rounded-lg bg-[#3B82F6] flex items-center justify-center text-white flex-shrink-0" aria-hidden="true">
          <Shield className="w-3.5 h-3.5" />
        </span>
        <span className="font-bold text-[15px] text-[#E6E9EF] tracking-tight truncate">Agent Governance</span>
      </div>

      {/* Breadcrumb */}
      <div className="hidden md:flex text-[13px] text-[#8B95A7] items-center gap-1.5 truncate">
        {getBreadcrumb()}
      </div>

      {/* Active badge (the search box is not shown until search is wired to something) */}
      <div className="flex items-center gap-3 ml-auto">
        {activeAgentsCount > 0 && (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-[rgba(34,197,94,0.14)] text-[#4ADE80] text-[12px] font-semibold flex-shrink-0">
            <span className="w-1.5 h-1.5 rounded-full bg-[#22C55E]" />
            {activeAgentsCount} running
          </span>
        )}
      </div>
    </header>
  );
};

