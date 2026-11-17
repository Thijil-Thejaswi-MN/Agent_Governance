import React, { useState, useEffect, useRef } from 'react';
import { Navigate, Outlet, useLocation } from 'react-router-dom';
import { Sidebar } from './Sidebar';
import { TopBar } from './TopBar';
import ClickSpark from '../effects/ClickSpark';
import { OperatorAuthModal } from '../common/OperatorAuthModal';
import { useAuth } from '../../context/AuthContext';
import { api } from '../../api/client';
import { onCountsRefresh } from '../../logic/countsRefresh';
import { readCollapsed, safeLocalStorage, writeCollapsed } from '../../logic/sidebarState';

const PROTECTED_PATHS = [
  '/overview',
  '/team',
  '/inbox',
  '/records',
  '/standing-rules',
  '/run',
  '/runs',
  '/fleet',
  '/history',
  '/evidence',
  '/report',
  '/incidents',
  '/inventory',
];

const isProtectedPath = (path: string): boolean =>
  PROTECTED_PATHS.some(p => path === p || path.startsWith(`${p}/`));

export const AppLayout: React.FC = () => {
  const location = useLocation();
  const { needsSignIn, authEpoch, isDemoDataActive, hasToken, user } = useAuth();
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
  const isProtected = isProtectedPath(cleanPath);

  // Poll pending count and active runs periodically, only while signed in and in the shell
  // (on the sign-in page, or signed out, every poll would be a 401 in the server log).
  const signedIn = (hasToken || !!user) && !needsSignIn;
  const pollCounts = signedIn && !isSignInPage;
  useEffect(() => {
    if (!pollCounts) return;
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
  }, [authEpoch, pollCounts]);

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
      {needsSignIn && isProtected ? (
        // Signed out on a page that needs sign-in: go to the landing page, and come back here after.
        <Navigate to={`/signin?next=${encodeURIComponent(location.pathname + location.search)}`} replace />
      ) : (
        <Outlet />
      )}
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

      {/* A small spark where you click (React Bits ClickSpark); a short still burst with reduced motion. */}
      <ClickSpark sparkColor={['#60A5FA', '#93C5FD']} sparkCount={8} sparkSize={9} sparkRadius={20} duration={420} className="flex flex-1 flex-col" style={{ height: 'auto' }}>
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
      </ClickSpark>

      <OperatorAuthModal />
    </div>
  );
};
