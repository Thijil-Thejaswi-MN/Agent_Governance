import React from 'react';
import { NavLink, Outlet, useLocation } from 'react-router-dom';
import { KeyRound, LogOut } from 'lucide-react';
import { OperatorAuthModal } from '../common/OperatorAuthModal';
import { SignInRequired } from '../common/SignInRequired';
import { useAuth } from '../../context/AuthContext';

const NAV = [
  { to: '/', label: 'Home', end: true },
  { to: '/run', label: 'Run', end: false },
  { to: '/fleet', label: 'Fleet', end: false },
  { to: '/history', label: 'History', end: false },
];

// Pages that show no task data and so never need a sign-in.
const PUBLIC_PATHS = ['/', '/results'];

export const AppLayout: React.FC = () => {
  const location = useLocation();
  const { needsSignIn, authEpoch, hasToken, openAuthModal, removeToken } = useAuth();
  const isPublic = PUBLIC_PATHS.includes(location.pathname.replace(/\/+$/, '') || '/');

  return (
    <div className="relative min-h-screen" style={{ overflowX: 'clip', background: 'var(--bg)', color: 'var(--text)' }}>
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-50 focus:px-4 focus:py-2 focus:rounded-xl"
        style={{ background: 'var(--card)' }}
      >
        Skip to content
      </a>
      <header className="relative z-20 flex flex-wrap items-center justify-between gap-x-4 gap-y-2 px-4 sm:px-10 pt-4 pb-2 sm:py-5">
        <NavLink to="/" className="font-display font-bold text-[18px] no-underline" style={{ color: 'var(--text)' }}>
          Agent Governance
        </NavLink>
        <nav aria-label="Main" className="order-3 sm:order-2 w-full sm:w-auto flex gap-1 overflow-x-auto">
          {NAV.map(item => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              className={({ isActive }) =>
                `inline-flex items-center min-h-[44px] px-4 rounded-full text-[15px] no-underline whitespace-nowrap ${
                  isActive ? 'font-semibold' : ''
                }`
              }
              style={({ isActive }) =>
                isActive
                  ? { background: 'rgba(34,211,238,0.14)', color: '#A5F3FC' }
                  : { color: 'var(--text-3)' }
              }
            >
              {item.label}
            </NavLink>
          ))}
        </nav>
        <div className="order-2 sm:order-3 flex items-center gap-1">
          {hasToken ? (
            <>
              <span className="text-[14px] hidden sm:inline" style={{ color: 'var(--text-2)' }}>
                Signed in
              </span>
              <button
                id="sign-out-btn"
                onClick={removeToken}
                className="inline-flex items-center justify-center w-11 h-11 rounded-full"
                style={{ color: 'var(--text-3)', background: 'transparent', border: 'none', cursor: 'pointer' }}
                aria-label="Sign out"
                title="Sign out"
              >
                <LogOut className="w-[18px] h-[18px]" />
              </button>
            </>
          ) : (
            <button
              id="header-sign-in-btn"
              onClick={openAuthModal}
              className="inline-flex items-center gap-2 min-h-[44px] px-4 rounded-full text-[14px] font-semibold"
              style={{ color: '#FDE68A', background: 'rgba(251,191,36,0.10)', border: '1px solid rgba(251,191,36,0.4)', cursor: 'pointer' }}
            >
              <KeyRound className="w-4 h-4" />
              Sign in
            </button>
          )}
        </div>
      </header>

      <main id="main" className="relative z-10">
        <div key={`${location.pathname}#${authEpoch}`} className="page-fade">
          {needsSignIn && !isPublic ? <SignInRequired /> : <Outlet />}
        </div>
      </main>

      <OperatorAuthModal />
    </div>
  );
};
