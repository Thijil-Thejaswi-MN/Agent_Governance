import React, { useState, useEffect } from 'react';
import { NavLink, Outlet, useLocation } from 'react-router-dom';
import { LogOut, KeyRound } from 'lucide-react';
import { Sidebar } from './Sidebar';
import { TopBar } from './TopBar';
import { OperatorAuthModal } from '../common/OperatorAuthModal';
import { SignInRequired } from '../common/SignInRequired';
import { useAuth } from '../../context/AuthContext';
import { api } from '../../api/client';

// Top nav items matching console v3
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

  // Determine if we should show the full role sidebar (v4 views) or top nav (demo v3 views like Home, Run, Results)
  const isRoleView = ['/overview', '/team', '/inbox', '/records', '/standing-rules'].includes(cleanPath) || cleanPath.startsWith('/runs/');

  return (
    <div className="relative min-h-screen bg-[#0B0E14] text-[#E6E9EF] flex flex-col font-sans overflow-x-hidden">
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

      {isRoleView ? (
        <div className="flex flex-1 min-h-screen overflow-x-hidden">
          <Sidebar waitingCount={waitingCount} totalTasks={totalTasks} />
          <div className="flex-1 flex flex-col min-w-0">
            <TopBar activeAgentsCount={activeCount} />
            <main id="main" className="flex-1 p-6 md:p-8 overflow-y-auto">
              <div key={`${location.pathname}#${authEpoch}`} className="anim-rise">
                {needsSignIn && !isPublic ? <SignInRequired /> : <Outlet />}
              </div>
            </main>
          </div>
        </div>
      ) : (
        <div className="flex-1 flex flex-col min-h-screen overflow-x-hidden">
          <header className="relative z-20 flex flex-wrap items-center justify-between gap-x-4 gap-y-2 px-4 sm:px-10 pt-4 pb-2 sm:py-5 border-b border-[#1F2633] bg-[#0E121A]">
            <NavLink to="/" className="font-display font-bold text-[18px] no-underline text-[#E6E9EF]">
              Agent Governance
            </NavLink>
            <nav aria-label="Main" className="order-3 sm:order-2 w-full sm:w-auto flex gap-1 overflow-x-auto">
              {TOP_NAV.map(item => (
                <NavLink
                  key={item.to}
                  to={item.to}
                  end={item.end}
                  className={({ isActive }) =>
                    `inline-flex items-center min-h-[44px] px-4 rounded-full text-[15px] no-underline whitespace-nowrap ${
                      isActive ? 'font-semibold bg-[#1A2232] text-[#E6E9EF]' : 'text-[#8B95A7] hover:text-[#E6E9EF]'
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
                    className="text-[13px] text-[#60A5FA] hover:underline mr-2"
                  >
                    Role homes →
                  </NavLink>
                  <button
                    id="sign-out-btn"
                    onClick={removeToken}
                    className="inline-flex items-center justify-center w-10 h-10 rounded-full text-[#8B95A7] hover:text-[#E6E9EF] bg-transparent border-none cursor-pointer"
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
                  className="inline-flex items-center gap-2 min-h-[40px] px-4 rounded-full text-[13px] font-semibold text-[#FDE68A] bg-amber-500/10 border border-amber-500/40 cursor-pointer"
                >
                  <KeyRound className="w-4 h-4" />
                  Sign in
                </button>
              )}
            </div>
          </header>

          <main id="main" className="flex-1 px-4 py-6 sm:p-8 overflow-x-hidden">
            <div key={`${location.pathname}#${authEpoch}`} className="anim-rise">
              {needsSignIn && !isPublic ? <SignInRequired /> : <Outlet />}
            </div>
          </main>
        </div>
      )}

      <OperatorAuthModal />
    </div>
  );
};
