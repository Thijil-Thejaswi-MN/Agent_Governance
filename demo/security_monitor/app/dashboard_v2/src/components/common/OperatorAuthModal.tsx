import React, { useState } from 'react';
import { useAuth } from '../../context/AuthContext';
import { KeyRound, X, ShieldCheck, AlertTriangle } from 'lucide-react';

export const OperatorAuthModal: React.FC = () => {
  const { isModalOpen, closeAuthModal, saveToken, isConfigured, token } = useAuth();
  const [inputVal, setInputVal] = useState(token || '');
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  if (!isModalOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!inputVal.trim()) {
      setError('Please enter a valid operator token');
      return;
    }
    setSubmitting(true);
    try {
      await saveToken(inputVal.trim());
      setError(null);
    } catch (err: any) {
      setError(err?.status === 401 ? 'The server rejected this token.' : err?.message || 'Sign-in failed');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 page-fade" style={{ background: 'rgba(3,6,12,0.72)', backdropFilter: 'blur(6px)' }}>
      <div
        className="w-full max-w-md overflow-hidden"
        style={{ background: 'var(--card)', border: '1px solid var(--border-strong)', borderRadius: 12, boxShadow: '0 24px 64px rgba(0,0,0,0.5)' }}
        role="dialog"
        aria-modal="true"
        aria-labelledby="operator-auth-title"
      >
        <div className="flex items-center justify-between gap-3 p-5" style={{ borderBottom: '1px solid var(--line)' }}>
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-lg" style={{ background: 'rgba(59,130,246,0.14)', color: '#60A5FA' }}>
              <KeyRound className="w-5 h-5" />
            </div>
            <div>
              <h3 id="operator-auth-title" className="font-display text-[18px] font-bold m-0">
                Operator Authentication
              </h3>
              <p className="text-[13px] m-0" style={{ color: 'var(--text-2)' }}>
                Required to view tasks, runs and receipts, and to decide approvals
              </p>
            </div>
          </div>
          <button
            onClick={closeAuthModal}
            className="inline-flex items-center justify-center w-11 h-11 rounded-xl"
            style={{ color: 'var(--text-3)', background: 'transparent', border: 'none', cursor: 'pointer' }}
            aria-label="Close modal"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-5 space-y-4">
          {isConfigured === false && (
            <div className="flex items-start gap-2.5 p-3 rounded-xl text-[13px]" style={{ background: 'rgba(251,191,36,0.08)', border: '1px solid rgba(251,191,36,0.35)', color: '#FDE68A' }}>
              <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
              <span>
                Note: Server currently has <code>GOVERNANCE_OPERATOR_TOKEN</code> unset. All task data and actions refuse with HTTP 403 until it is set.
              </span>
            </div>
          )}

          <div>
            <label htmlFor="operator-token-input" className="block text-[14px] font-medium mb-1.5">
              Operator Bearer Token
            </label>
            <input
              id="operator-token-input"
              type="password"
              value={inputVal}
              onChange={e => {
                setInputVal(e.target.value);
                if (error) setError(null);
              }}
              placeholder="Paste GOVERNANCE_OPERATOR_TOKEN..."
              className="w-full min-h-[44px] px-3 text-[15px] mono rounded-lg outline-none focus:border-[#3B82F6]"
              style={{ background: 'var(--field)', border: '1px solid var(--border-strong)', color: 'var(--text)' }}
              autoFocus
            />
            {error && (
              <p className="mt-1.5 text-[13px]" style={{ color: '#FDA4AF' }}>
                {error}
              </p>
            )}
          </div>

          <p className="text-[13px] leading-relaxed m-0" style={{ color: 'var(--text-2)' }}>
            Signing in sets an HttpOnly read-session cookie (8 h) for this console. The token itself is kept in your
            browser's <code>sessionStorage</code> and sent with every action (run, stop, approve, deny, grant).
          </p>

          <div className="flex justify-end gap-2.5 pt-1">
            <button type="button" onClick={closeAuthModal} className="btn-ghost min-h-[44px] sm:min-h-[40px]">
              Cancel
            </button>
            <button id="operator-signin-btn" type="submit" disabled={submitting} className="btn-primary min-h-[44px] sm:min-h-[40px]">
              <ShieldCheck className="w-4 h-4" />
              {submitting ? 'Signing in…' : 'Sign in'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
