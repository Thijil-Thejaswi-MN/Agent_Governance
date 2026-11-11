import React, { useState, useEffect, useRef } from 'react';
import { Outlet, useLocation } from 'react-router-dom';
import { Sidebar } from './Sidebar';
import { TopBar } from './TopBar';
import { OperatorAuthModal } from '../common/OperatorAuthModal';
import { SignInRequired } from '../common/SignInRequired';
import { useAuth } from '../../context/AuthContext';
import { api } from '../../api/client';
import { onCountsRefresh } from '../../logic/countsRefresh';
import { readCollapsed, safeLocalStorage, writeCollapsed } from '../../logic/sidebarState';

const PUBLIC_PATHS = ['/signin', '/results'];

export const AppLayout: React.FC = () => {
  const location = useLocation();
  const { needsSignIn, authEpoch, isDemoDataActive } = useAuth();
  const [waitingCount, setWaitingCount] = useState(0);
  const [totalTasks, setTotalTasks] = useState(0);
  const [activeCount, setActiveCount] = useState(0);

  const [menuOpen, setMenuOpen] = useState(false);
  // Desktop sidebar: icons only when collapsed; remembered in localStorage when it is available.
  const [collapsed, setCollapsed] = useState<boolean>(() => readCollapsed(safeLocalStorage()));
  const toggleCollapsed = () =>
    setCollapsed(c => {
      writeCollapsed(safeLocalStorage(), !c);
      return !c;
    });
  const drawerRef = useRef<HTMLDivElement>(null);

  const cleanPath = location.pathname.replace(/\/+$/, '') || '/';
  // Sign-in, and /dashboard itself while it redirects, render without the shell.
  const isSignInPage = cleanPath === '/signin' || cleanPath === '/';
  const isPublic = PUBLIC_PATHS.includes(cleanPath);

  // Poll pending count and active runs periodically
  useEffect(() => {
    let mounted = true;
    const fetchCounts = async () => {
      try {
        const [pendingRes, tasksRes] = await Promise.allSettled([
          api.getPendingGroups(),
          api.getTasks(),
        ]);
        if (!mounted) return;
        if (pendingRes.status === 'fulfilled') {
          setWaitingCount(pendingRes.value.total_waiting || 0);
        }
        if (tasksRes.status === 'fulfilled') {
          setTotalTasks(tasksRes.value.length);
          setActiveCount(tasksRes.value.filter(t => t.status === 'RUNNING' || t.status === 'ACTIVE').length);
        }
      } catch {
        // quiet error on unauth or network error
      }
    };

    fetchCounts();
    const interval = setInterval(fetchCounts, 5000);
    // Also refresh at once when a run changes state or a decision is made.
    const off = onCountsRefresh(fetchCounts);
    return () => {
      mounted = false;
      clearInterval(interval);
      off();
    };
  }, [authEpoch]);

  // The mobile menu closes on navigation and on Escape, and takes focus when it opens.
  useEffect(() => setMenuOpen(false), [location.pathname]);
  useEffect(() => {
    if (!menuOpen) return;
    drawerRef.current?.querySelector<HTMLElement>('button, a')?.focus();
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && setMenuOpen(false);
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [menuOpen]);

  if (isSignInPage) {
    return (
      <div className="min-h-screen bg-[#0B0E14] text-[#E6E9EF]">
        {isDemoDataActive && (
          <div className="bg-[#EF4444] text-white text-[12px] font-bold text-center py-1 select-none tracking-wide z-50">
            Demo data: not real activity
          </div>
        )}
        <Outlet />
      </div>
    );
  }

  // Every page sits in the v4 sidebar shell.
  const content = (
    <div key={`${location.pathname}#${authEpoch}`} className="anim-rise">
      {needsSignIn && !isPublic ? <SignInRequired /> : <Outlet />}
    </div>
  );

  return (
    <div className="relative min-h-screen bg-[#0B0E14] text-[#E6E9EF] flex flex-col font-sans overflow-x-clip">
      {/* Demo Data Banner when active */}
      {isDemoDataActive && (
        <div className="bg-[#EF4444] text-white text-[12px] font-bold text-center py-1 select-none tracking-wide z-50">
          Demo data: not real activity
        </div>
      )}

      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-50 focus:px-4 focus:py-2 focus:rounded-xl focus:bg-[#11151D] focus:text-[#E6E9EF] focus:border focus:border-[#3B82F6]"
      >
        Skip to content
      </a>

      <div className="flex flex-1 min-h-screen">
        <Sidebar
          waitingCount={waitingCount}
          totalTasks={totalTasks}
          collapsed={collapsed}
          onToggleCollapsed={toggleCollapsed}
        />
        <div className="flex-1 flex flex-col min-w-0">
          <TopBar activeAgentsCount={activeCount} onMenu={() => setMenuOpen(true)} menuOpen={menuOpen} />
          <main id="main" className="flex-1 px-4 py-6 md:p-8 min-w-0">
            {content}
          </main>
        </div>

        {menuOpen && (
          <div className="fixed inset-0 z-50 flex md:hidden" role="dialog" aria-modal="true" aria-label="Menu" ref={drawerRef}>
            <div className="absolute inset-0 bg-[rgba(3,6,12,0.65)]" onClick={() => setMenuOpen(false)} aria-hidden="true" />
            <Sidebar
              variant="drawer"
              waitingCount={waitingCount}
              totalTasks={totalTasks}
              onClose={() => setMenuOpen(false)}
            />
          </div>
        )}
      </div>

      <OperatorAuthModal />
    </div>
  );
};
