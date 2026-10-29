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
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm animate-in fade-in duration-200">
      <div
        className="w-full max-w-md bg-white dark:bg-surface-cardDark rounded-2xl border border-slate-200 dark:border-slate-800 shadow-2xl overflow-hidden"
        role="dialog"
        aria-modal="true"
        aria-labelledby="operator-auth-title"
      >
        <div className="flex items-center justify-between p-5 border-b border-slate-100 dark:border-slate-800/80">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-cyan-500/10 text-cyan-500">
              <KeyRound className="w-5 h-5" />
            </div>
            <div>
              <h3 id="operator-auth-title" className="text-base font-semibold text-slate-900 dark:text-slate-100">
                Operator Authentication
              </h3>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Required to view tasks, runs and receipts, and to decide approvals
              </p>
            </div>
          </div>
          <button
            onClick={closeAuthModal}
            className="p-1.5 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 rounded-lg transition-colors"
            aria-label="Close modal"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-5 space-y-4">
          {isConfigured === false && (
            <div className="flex items-start gap-2.5 p-3 rounded-lg bg-amber-500/10 border border-amber-500/20 text-xs text-amber-600 dark:text-amber-400">
              <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
              <span>
                Note: Server currently has <code>GOVERNANCE_OPERATOR_TOKEN</code> unset. All task data and actions refuse with HTTP 403 until it is set.
              </span>
            </div>
          )}

          <div>
            <label htmlFor="operator-token-input" className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1.5">
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
              className="w-full px-3.5 py-2 text-sm bg-slate-50 dark:bg-slate-900/60 border border-slate-200 dark:border-slate-700/80 rounded-xl focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 font-mono text-slate-900 dark:text-slate-100 placeholder:text-slate-400 dark:placeholder:text-slate-500"
              autoFocus
            />
            {error && <p className="mt-1 text-xs text-rose-500">{error}</p>}
          </div>

          <p className="text-xs text-slate-500 dark:text-slate-400 leading-relaxed">
            Signing in sets an HttpOnly read-session cookie (8 h) for this console. The token itself is kept in your
            browser's <code>sessionStorage</code> and sent with every action (run, stop, approve, deny, grant).
          </p>

          <div className="flex justify-end gap-2.5 pt-2">
            <button
              type="button"
              onClick={closeAuthModal}
              className="px-4 py-2 text-xs font-medium text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-xl transition-colors"
            >
              Cancel
            </button>
            <button
              id="operator-signin-btn"
              type="submit"
              disabled={submitting}
              className="px-4 py-2 disabled:opacity-60 text-xs font-medium text-white bg-cyan-600 hover:bg-cyan-500 dark:bg-cyan-500 dark:hover:bg-cyan-400 rounded-xl shadow-sm transition-colors flex items-center gap-1.5"
            >
              <ShieldCheck className="w-4 h-4" />
              {submitting ? 'Signing in…' : 'Sign in'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
