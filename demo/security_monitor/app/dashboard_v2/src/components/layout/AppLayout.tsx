import React, { useState, useEffect, useRef } from 'react';
import { NavLink, Outlet, useLocation } from 'react-router-dom';
import { LogOut, KeyRound, Shield } from 'lucide-react';
import { Sidebar } from './Sidebar';
import { TopBar } from './TopBar';
import { OperatorAuthModal } from '../common/OperatorAuthModal';
import { SignInRequired } from '../common/SignInRequired';
import { useAuth } from '../../context/AuthContext';
import { api } from '../../api/client';

// Home's top bar (Home is the one signed-in page without the sidebar; see test_top_navigation)
const TOP_NAV = [
  { to: '/run', label: 'Run', end: false },
  { to: '/fleet', label: 'Fleet', end: false },
  { to: '/history', label: 'History', end: false },
  { to: '/', label: 'Home', end: true },
];

const PUBLIC_PATHS = ['/', '/signin', '/results'];

export const AppLayout: React.FC = () => {
  const location = useLocation();
  const { needsSignIn, authEpoch, isDemoDataActive, hasToken, openAuthModal, removeToken } = useAuth();
  const [waitingCount, setWaitingCount] = useState(0);
  const [totalTasks, setTotalTasks] = useState(0);
  const [activeCount, setActiveCount] = useState(0);

  const [menuOpen, setMenuOpen] = useState(false);
  const drawerRef = useRef<HTMLDivElement>(null);

  const cleanPath = location.pathname.replace(/\/+$/, '') || '/';
  const isSignInPage = cleanPath === '/signin';
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
    return () => {
      mounted = false;
      clearInterval(interval);
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

  // Home keeps its own top bar; every other page sits in the v4 sidebar shell.
  const isHome = cleanPath === '/';
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

      {!isHome ? (
        <div className="flex flex-1 min-h-screen">
          <Sidebar waitingCount={waitingCount} totalTasks={totalTasks} />
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
      ) : (
        <div className="flex-1 flex flex-col min-h-screen">
          <header className="relative z-20 flex flex-wrap items-center justify-between gap-x-4 gap-y-2 px-4 sm:px-8 py-2.5 sm:py-3 border-b border-[#1F2633] bg-[#0E121A]">
            <NavLink to="/" className="flex items-center gap-2.5 min-h-[44px] no-underline text-[#E6E9EF] hover:text-[#E6E9EF]">
              <span className="w-8 h-8 rounded-lg bg-[#3B82F6] flex items-center justify-center text-white flex-shrink-0" aria-hidden="true">
                <Shield className="w-4 h-4" />
              </span>
              <span className="font-bold text-[15px] tracking-tight">Agent Governance</span>
            </NavLink>
            <nav aria-label="Main" className="order-3 sm:order-2 w-full sm:w-auto flex gap-1 overflow-x-auto">
              {TOP_NAV.map(item => (
                <NavLink
                  key={item.to}
                  to={item.to}
                  end={item.end}
                  className={({ isActive }) =>
                    `inline-flex items-center min-h-[44px] sm:min-h-[40px] px-3.5 rounded-lg text-[14px] no-underline whitespace-nowrap transition-colors ${
                      isActive
                        ? 'font-semibold bg-[#1A2232] text-[#E6E9EF]'
                        : 'text-[#A7B0C0] hover:bg-[#141A24] hover:text-[#E6E9EF]'
                    }`
                  }
                >
                  {item.label}
                </NavLink>
              ))}
            </nav>
            <div className="order-2 sm:order-3 flex items-center gap-2">
              {hasToken ? (
                <>
                  <NavLink
                    to="/overview"
                    className="inline-flex items-center min-h-[44px] px-2 text-[13px] text-[#60A5FA] hover:text-[#93C5FD] no-underline"
                  >
                    Role homes →
                  </NavLink>
                  <button
                    id="sign-out-btn"
                    onClick={removeToken}
                    className="inline-flex items-center justify-center w-11 h-11 rounded-lg text-[#8B95A7] hover:text-[#E6E9EF] hover:bg-[#1A2232] bg-transparent border-none cursor-pointer"
                    aria-label="Sign out"
                    title="Sign out"
                  >
                    <LogOut className="w-4 h-4" />
                  </button>
                </>
              ) : (
                <button
                  id="header-sign-in-btn"
                  onClick={openAuthModal}
                  className="btn-ghost min-h-[44px]"
                  style={{ borderColor: 'rgba(245,158,11,0.45)', color: '#FCD34D' }}
                >
                  <KeyRound className="w-4 h-4" />
                  Sign in
                </button>
              )}
            </div>
          </header>

          <main id="main" className="flex-1 px-4 py-6 sm:px-8 sm:py-8 min-w-0">
            {content}
          </main>
        </div>
      )}

      <OperatorAuthModal />
    </div>
  );
};
