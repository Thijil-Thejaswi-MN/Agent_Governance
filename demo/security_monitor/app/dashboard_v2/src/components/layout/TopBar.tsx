import React, { useEffect, useState } from 'react';
import { Menu, Sun, Moon, KeyRound, CheckCircle } from 'lucide-react';
import { useTheme } from '../../context/ThemeContext';
import { useAuth } from '../../context/AuthContext';
import { api } from '../../api/client';
import { SystemStatusResponse } from '../../types';

interface TopBarProps {
  onMobileMenuOpen: () => void;
}

export const TopBar: React.FC<TopBarProps> = ({ onMobileMenuOpen }) => {
  const { theme, toggleTheme } = useTheme();
  const { hasToken, openAuthModal, isConfigured } = useAuth();
  const [sysStatus, setSysStatus] = useState<SystemStatusResponse | null>(null);
  const [statusState, setStatusState] = useState<'healthy' | 'partial' | 'unknown'>('unknown');

  useEffect(() => {
    let mounted = true;
    const checkStatus = async () => {
      try {
        const res = await api.getSystemStatus();
        if (!mounted) return;
        setSysStatus(res);
        if (res.status === 'healthy') {
          setStatusState('healthy');
        } else if (res.status === 'partial') {
          setStatusState('partial');
        } else {
          setStatusState('unknown');
        }
      } catch {
        if (!mounted) return;
        setStatusState('unknown');
      }
    };
    checkStatus();
    const interval = setInterval(checkStatus, 15000);
    return () => {
      mounted = false;
      clearInterval(interval);
    };
  }, []);

  return (
    <header className="sticky top-0 z-20 h-16 border-b border-slate-200 dark:border-slate-800 bg-white/80 dark:bg-surface-bgDark/80 backdrop-blur-md px-4 md:px-6 flex items-center justify-between">
      <div className="flex items-center gap-3">
        <button
          onClick={onMobileMenuOpen}
          className="md:hidden p-2 text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-lg transition-colors active:scale-95"
          aria-label="Open mobile navigation"
        >
          <Menu className="w-5 h-5" />
        </button>

        {/* Live system status indicator */}
        <div className="flex items-center gap-2 text-xs font-mono text-slate-500 dark:text-slate-400">
          {statusState === 'healthy' ? (
            <>
              <span className="inline-block w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
              <span className="hidden sm:inline">OS SANDBOX:</span>
              <span className="font-semibold text-emerald-600 dark:text-emerald-400">
                LANDLOCK v{sysStatus?.landlock_abi ?? 7} + SECCOMP
              </span>
            </>
          ) : statusState === 'partial' ? (
            <>
              <span className="inline-block w-2 h-2 rounded-full bg-amber-500 animate-pulse" />
              <span className="hidden sm:inline">OS SANDBOX:</span>
              <span className="font-semibold text-amber-600 dark:text-amber-400">
                PARTIAL ENFORCEMENT
              </span>
            </>
          ) : (
            <>
              <span className="inline-block w-2 h-2 rounded-full bg-slate-400" />
              <span className="hidden sm:inline">OS SANDBOX:</span>
              <span className="font-semibold text-slate-500 dark:text-slate-400">
                STATUS UNKNOWN
              </span>
            </>
          )}
        </div>
      </div>

      <div className="flex items-center gap-2.5">
        {/* Operator Token Pill */}
        <button
          onClick={openAuthModal}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-medium border transition-all active:scale-95 ${
            hasToken
              ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/30 hover:bg-emerald-500/20'
              : isConfigured === false
              ? 'bg-slate-100 dark:bg-slate-800 text-slate-400 border-slate-300 dark:border-slate-700 hover:bg-slate-200'
              : 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/30 hover:bg-amber-500/20'
          }`}
          title={hasToken ? 'Operator token configured in session' : 'Set operator token for approvals'}
        >
          <KeyRound className="w-3.5 h-3.5" />
          <span className="hidden sm:inline">
            {hasToken ? 'Operator Authenticated' : 'Operator Token Required'}
          </span>
          {hasToken && <CheckCircle className="w-3 h-3 text-emerald-500" />}
        </button>

        {/* Theme Toggle */}
        <button
          onClick={toggleTheme}
          className="p-2 text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-800 transition-colors active:scale-95 duration-300"
          aria-label={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'}
        >
          {theme === 'dark' ? (
            <Sun className="w-4 h-4 text-amber-400 transition-transform duration-300" />
          ) : (
            <Moon className="w-4 h-4 text-slate-600 transition-transform duration-300" />
          )}
        </button>
      </div>
    </header>
  );
};
