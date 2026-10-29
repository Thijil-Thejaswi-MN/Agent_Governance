import React from 'react';
import { KeyRound, Lock } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';

// Shown in place of any page whose data request returned 401.
export const SignInRequired: React.FC = () => {
  const { openAuthModal, isConfigured } = useAuth();

  return (
    <div
      id="sign-in-required"
      className="max-w-lg mx-auto mt-16 p-8 rounded-2xl bg-white dark:bg-surface-cardDark border border-slate-200 dark:border-slate-800 text-center space-y-4"
    >
      <div className="mx-auto w-12 h-12 rounded-xl bg-amber-500/10 text-amber-500 flex items-center justify-center">
        <Lock className="w-6 h-6" />
      </div>
      <h1 className="text-lg font-semibold text-slate-900 dark:text-white">Sign in to view governance data</h1>
      <p className="text-sm text-slate-500 dark:text-slate-400">
        Tasks, prompts, events, receipts and outputs are only served to an authenticated operator.
      </p>
      {isConfigured === false ? (
        <p className="text-xs text-amber-600 dark:text-amber-400">
          The server has no <code>GOVERNANCE_OPERATOR_TOKEN</code> set, so nobody can sign in. Set it and restart the server.
        </p>
      ) : (
        <button
          id="sign-in-btn"
          onClick={openAuthModal}
          className="inline-flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-cyan-600 hover:bg-cyan-500 rounded-xl"
        >
          <KeyRound className="w-4 h-4" />
          Sign in
        </button>
      )}
    </div>
  );
};
