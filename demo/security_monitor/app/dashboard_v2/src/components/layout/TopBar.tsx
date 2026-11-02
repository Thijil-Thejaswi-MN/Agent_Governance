import React, { useState, useEffect } from 'react';
import { Search } from 'lucide-react';
import { useLocation } from 'react-router-dom';

interface TopBarProps {
  breadcrumb?: string;
  activeAgentsCount?: number;
}

export const TopBar: React.FC<TopBarProps> = ({ breadcrumb, activeAgentsCount = 0 }) => {
  const location = useLocation();
  const [searchValue, setSearchValue] = useState('');

  // Shortcut key '/' focuses search input
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === '/' && document.activeElement?.tagName !== 'INPUT' && document.activeElement?.tagName !== 'TEXTAREA') {
        e.preventDefault();
        const input = document.getElementById('global-search-input');
        if (input) input.focus();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  // Compute breadcrumb fallback if not passed
  const getBreadcrumb = () => {
    if (breadcrumb) return breadcrumb;
    const path = location.pathname.replace(/^\/+/g, '');
    if (!path) return 'Acme Corp / Organization overview';
    if (path.startsWith('team')) return 'Acme Corp / Finance / Team overview';
    if (path.startsWith('inbox')) return 'Acme Corp / Security / Approvals inbox';
    if (path.startsWith('records')) return 'Acme Corp / Compliance / Records';
    if (path.startsWith('run')) return 'Acme Corp / Developer / Ask & Watch';
    if (path.startsWith('standing-rules')) return 'Acme Corp / Security / Standing rules';
    if (path.startsWith('runs/') || path.startsWith('history/')) return 'Acme Corp / Run investigation';
    return `Acme Corp / ${path}`;
  };

  return (
    <header className="flex flex-wrap items-center justify-between gap-3 px-6 py-3 border-b border-[#1F2633] bg-gradient-to-b from-[#0E121A] to-[#0B0E14] select-none">
      {/* Breadcrumb */}
      <div className="text-[13px] text-[#8B95A7] flex items-center gap-1.5 truncate">
        {getBreadcrumb()}
      </div>

      {/* Search Bar + Active Badge */}
      <div className="flex items-center gap-3 ml-auto">
        <div className="relative flex items-center min-w-[240px] max-w-[380px] bg-[#11151D] border border-[#1F2633] rounded-lg px-3 py-1.5 text-[13px] text-[#E6E9EF]">
          <Search className="w-3.5 h-3.5 text-[#8B95A7] mr-2 flex-shrink-0" />
          <input
            id="global-search-input"
            type="text"
            placeholder="Search agents, runs, files…"
            value={searchValue}
            onChange={e => setSearchValue(e.target.value)}
            className="w-full bg-transparent border-none text-[#E6E9EF] placeholder-[#6B7487] text-[13px] outline-none"
          />
          <kbd className="ml-2 font-mono text-[11px] text-[#8B95A7] bg-[#1A2232] px-1.5 py-0.5 rounded border border-[#2A3344] select-none">
            /
          </kbd>
        </div>

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

