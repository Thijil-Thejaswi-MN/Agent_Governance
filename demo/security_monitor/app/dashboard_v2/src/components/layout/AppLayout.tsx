import React, { useState } from 'react';
import { Outlet, useLocation } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { Sidebar } from './Sidebar';
import { TopBar } from './TopBar';
import { OperatorAuthModal } from '../common/OperatorAuthModal';
import { SignInRequired } from '../common/SignInRequired';
import { useAuth } from '../../context/AuthContext';

export const AppLayout: React.FC = () => {
  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const location = useLocation();
  const { needsSignIn, authEpoch } = useAuth();

  const isReducedMotion = typeof window !== 'undefined' && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  return (
    <div className="min-h-screen flex bg-surface-bgLight dark:bg-surface-bgDark text-slate-900 dark:text-slate-100 transition-colors duration-200">
      <Sidebar
        collapsed={collapsed}
        onToggle={() => setCollapsed(!collapsed)}
        mobileOpen={mobileOpen}
        onMobileClose={() => setMobileOpen(false)}
      />

      <div className="flex-1 flex flex-col min-w-0">
        <TopBar onMobileMenuOpen={() => setMobileOpen(true)} />
        <main className="flex-1 p-4 md:p-8 max-w-7xl w-full mx-auto">
          <AnimatePresence mode="wait">
            <motion.div
              key={`${location.pathname}#${authEpoch}`}
              initial={isReducedMotion ? undefined : { opacity: 0, y: 6 }}
              animate={isReducedMotion ? undefined : { opacity: 1, y: 0 }}
              exit={isReducedMotion ? undefined : { opacity: 0, y: -6 }}
              transition={{ duration: 0.18, ease: 'easeOut' }}
            >
              {needsSignIn ? <SignInRequired /> : <Outlet />}
            </motion.div>
          </AnimatePresence>
        </main>
      </div>

      <OperatorAuthModal />
    </div>
  );
};
