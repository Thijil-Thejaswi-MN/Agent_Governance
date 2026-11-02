import React from 'react';
import { KeyRound, Lock } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';

// Shown in place of any page whose data request returned 401.
export const SignInRequired: React.FC = () => {
  const { openAuthModal, isConfigured } = useAuth();

  return (
    <div id="sign-in-required" className="card max-w-lg mx-4 sm:mx-auto mt-16 p-8 text-center space-y-4">
      <div className="mx-auto w-12 h-12 rounded-2xl flex items-center justify-center" style={{ background: 'rgba(251,191,36,0.1)', color: 'var(--waiting)' }}>
        <Lock className="w-6 h-6" />
      </div>
      <h1 className="font-display text-[26px] font-bold m-0">Sign in to see your agents</h1>
      <p className="text-[16px] m-0" style={{ color: 'var(--text-2)' }}>
        Tasks, prompts, events, receipts and outputs are only served to an authenticated operator.
      </p>
      {isConfigured === false ? (
        <p className="text-[14px]" style={{ color: '#FDE68A' }}>
          The server has no <code>GOVERNANCE_OPERATOR_TOKEN</code> set, so nobody can sign in. Set it and restart the server.
        </p>
      ) : (
        <button id="sign-in-btn" onClick={openAuthModal} className="btn-primary">
          <KeyRound className="w-4 h-4" />
          Sign in
        </button>
      )}
    </div>
  );
};
