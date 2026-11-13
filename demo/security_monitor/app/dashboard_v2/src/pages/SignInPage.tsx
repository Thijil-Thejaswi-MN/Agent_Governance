import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, Bot, Users, CheckCircle2, LayoutGrid, FileText } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { Role } from '../types';
import { roleHome } from '../logic/journey';
import DotField from '../components/effects/DotField';

interface RoleCard {
  role: Role;
  title: string;
  desc: string;
  landingText: string;
  icon: React.ReactNode;
}

const ROLES: RoleCard[] = [
  {
    role: 'developer',
    title: 'Developer',
    desc: 'Give tasks to your agents and watch them work.',
    landingText: 'Lands on: Run →',
    icon: <Bot className="w-4 h-4" />,
  },
  {
    role: 'team_lead',
    title: 'Team lead',
    desc: "See your team's agents. Approve their requests.",
    landingText: 'Lands on: Team overview →',
    icon: <Users className="w-4 h-4" />,
  },
  {
    role: 'security_reviewer',
    title: 'Security reviewer',
    desc: 'Decide on requests. Turn repeats into rules.',
    landingText: 'Lands on: Approvals inbox →',
    icon: <CheckCircle2 className="w-4 h-4" />,
  },
  {
    role: 'admin',
    title: 'Admin',
    desc: 'Every agent, team and rule in one place.',
    landingText: 'Lands on: Run →',
    icon: <LayoutGrid className="w-4 h-4" />,
  },
  {
    role: 'auditor',
    title: 'Auditor',
    desc: 'Check hash chains, export activity, review decisions.',
    landingText: 'Lands on: Records →',
    icon: <FileText className="w-4 h-4" />,
  },
];

export const SignInPage: React.FC = () => {
  const navigate = useNavigate();
  const { saveToken } = useAuth();
  const [tokenInput, setTokenInput] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [highlightedRole, setHighlightedRole] = useState<Role | null>(null);
  const [prefersReducedMotion, setPrefersReducedMotion] = useState(false);
  const [isLightMode, setIsLightMode] = useState(false);

  useEffect(() => {
    if (typeof window === 'undefined' || !window.matchMedia) return;
    const motionQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
    setPrefersReducedMotion(motionQuery.matches);
    const motionHandler = (e: MediaQueryListEvent) => setPrefersReducedMotion(e.matches);
    motionQuery.addEventListener('change', motionHandler);

    const colorQuery = window.matchMedia('(prefers-color-scheme: light)');
    setIsLightMode(colorQuery.matches);
    const colorHandler = (e: MediaQueryListEvent) => setIsLightMode(e.matches);
    colorQuery.addEventListener('change', colorHandler);

    return () => {
      motionQuery.removeEventListener('change', motionHandler);
      colorQuery.removeEventListener('change', colorHandler);
    };
  }, []);

  const handleSignIn = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!tokenInput.trim()) return;

    setIsSubmitting(true);
    setError(null);

    try {
      const res = await saveToken(tokenInput.trim());
      const userRole: Role = (res?.user?.role as Role) || 'admin';
      const destination = roleHome(userRole);

      // Highlight the matching role card for 1 second, then redirect
      setHighlightedRole(userRole);
      setTimeout(() => {
        navigate(destination);
      }, 1000);
    } catch (err: any) {
      setError(err?.message || 'Invalid token or server refused connection');
      setIsSubmitting(false);
    }
  };

  return (
    <div className="signin-root relative overflow-x-hidden min-h-screen font-sans flex flex-col items-center px-4 sm:px-6 py-10 sm:py-14">
      <style>{`
        .signin-root {
          --sn-bg: #0B0E14;
          --sn-card: #11151D;
          --sn-raised: #161B26;
          --sn-border: #1F2633;
          --sn-border-focus: #3B82F6;
          --sn-text: #E6E9EF;
          --sn-text-secondary: #949DB0;
          --sn-text-muted: #646E82;
          --sn-input-bg: #080A0F;
          --sn-sso-bg: #131722;
          --sn-role-bg: #11151D;
          --sn-role-icon-bg: #161B26;
          background-color: var(--sn-bg);
          color: var(--sn-text);
        }
        @media (prefers-color-scheme: light) {
          .signin-root {
            --sn-bg: #F8FAFC;
            --sn-card: #FFFFFF;
            --sn-raised: #F1F5F9;
            --sn-border: #E2E8F0;
            --sn-border-focus: #2563EB;
            --sn-text: #0F172A;
            --sn-text-secondary: #475569;
            --sn-text-muted: #64748B;
            --sn-input-bg: #FFFFFF;
            --sn-sso-bg: #F8FAFC;
            --sn-role-bg: #FFFFFF;
            --sn-role-icon-bg: #F1F5F9;
          }
        }
      `}</style>

      {/* Background DotField (disabled under prefers-reduced-motion) */}
      {!prefersReducedMotion && (
        <div
          style={{
            position: 'absolute',
            inset: 0,
            pointerEvents: 'none',
            zIndex: 0,
          }}
        >
          <DotField
            gradientFrom={isLightMode ? '#2563EB' : '#3B82F6'}
            gradientTo={isLightMode ? '#3B82F6' : '#60A5FA'}
            baseOpacity={isLightMode ? 0.16 : 0.12}
            glowIntensity={0.06}
            lightMode={isLightMode}
            holdToZoom={false}
          />
        </div>
      )}

      {/* Hero Header & content */}
      <div
        className="flex flex-col items-center gap-3 max-w-4xl w-full"
        style={{
          position: 'relative',
          zIndex: 1,
        }}
      >
        <div className="w-10 h-10 rounded-xl bg-[var(--sn-raised)] border border-[var(--sn-border)] flex items-center justify-center text-[#3B82F6] transition-colors">
          <Shield className="w-5 h-5" strokeWidth={1.75} />
        </div>
        <h1 className="text-2xl sm:text-[28px] font-semibold tracking-tight text-center text-[var(--sn-text)]">
          Sign in to Agent Governance
        </h1>
        <p className="text-[var(--sn-text-secondary)] text-[13px] sm:text-[14px] text-center max-w-md leading-relaxed">
          Every agent only touches what its task needs. Choose how you work today.
        </p>

        {/* Sign In Box */}
        <div className="mt-5 w-full max-w-[420px] p-6 rounded-2xl bg-[var(--sn-card)] border border-[var(--sn-border)] flex flex-col gap-4 shadow-sm transition-colors">
          {/* SSO button - disabled as specified */}
          <button
            type="button"
            disabled
            className="w-full min-h-[44px] rounded-xl border border-[var(--sn-border)] bg-[var(--sn-sso-bg)] text-[var(--sn-text-muted)] font-medium text-[13px] flex items-center justify-center gap-2 cursor-not-allowed opacity-75"
            title="Not configured on this install"
          >
            <Shield className="w-4 h-4 text-[var(--sn-text-muted)]" />
            Continue with company sign-in (SSO)
          </button>
          <div className="text-[11px] text-center text-[var(--sn-text-muted)] -mt-2">
            Not configured on this install
          </div>

          <div className="flex items-center gap-3 text-[11px] text-[var(--sn-text-muted)] my-0.5 font-mono tracking-wider uppercase">
            <span className="flex-1 h-px bg-[var(--sn-border)]" />
            <span>or, on a local install</span>
            <span className="flex-1 h-px bg-[var(--sn-border)]" />
          </div>

          {/* Operator Token Form */}
          <form onSubmit={handleSignIn} className="flex flex-col gap-2">
            <label htmlFor="operator-token-input" className="text-[12px] font-medium text-[var(--sn-text-secondary)]">
              Operator token
            </label>
            {/* Below 640 px the button sits under the field, so "Sign in" never wraps */}
            <div className="flex flex-col sm:flex-row gap-2">
              <input
                id="operator-token-input"
                type="password"
                placeholder="Paste token or GOVERNANCE_OPERATOR_TOKEN..."
                value={tokenInput}
                onChange={e => setTokenInput(e.target.value)}
                disabled={isSubmitting || highlightedRole !== null}
                className="flex-1 min-w-0 min-h-[44px] sm:min-h-[42px] px-3.5 rounded-xl border border-[var(--sn-border)] bg-[var(--sn-input-bg)] text-[var(--sn-text)] font-mono text-[13px] placeholder:text-[var(--sn-text-muted)] outline-none focus:border-[var(--sn-border-focus)] focus:ring-1 focus:ring-[var(--sn-border-focus)] transition-colors"
              />
              <button
                type="submit"
                id="sign-in-submit-btn"
                disabled={isSubmitting || !tokenInput.trim() || highlightedRole !== null}
                className="w-full sm:w-auto whitespace-nowrap px-5 min-h-[44px] sm:min-h-[42px] rounded-xl bg-[#2563EB] hover:bg-[#1D4ED8] disabled:opacity-50 text-white font-medium text-[13px] transition-colors flex items-center justify-center cursor-pointer shadow-sm"
              >
                {isSubmitting ? 'Signing in…' : 'Sign in'}
              </button>
            </div>
            {error && (
              <div className="text-[12px] text-red-500 mt-1 font-medium">
                {error}
              </div>
            )}
          </form>
        </div>

        {/* Role Explanation Section */}
        <div className="mt-8 w-full max-w-4xl flex flex-col gap-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <h2 className="text-[14px] font-semibold text-[var(--sn-text)]">Your role</h2>
            <span className="text-[12px] text-[var(--sn-text-muted)]">
              Each role opens on a different home. Your admin assigns roles.
            </span>
          </div>

          {/* Role Cards Grid */}
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-3 mt-1">
            {ROLES.map(r => {
              const isMatch = highlightedRole === r.role;
              return (
                <div
                  key={r.role}
                  className={`relative p-4 rounded-xl border transition-all duration-200 flex flex-col gap-2.5 select-none ${
                    isMatch
                      ? 'border-[#2563EB] ring-1 ring-[#2563EB] bg-[var(--sn-raised)]'
                      : 'border-[var(--sn-border)] bg-[var(--sn-role-bg)] hover:border-[var(--sn-border-focus)]'
                  }`}
                >
                  <div className="w-8 h-8 rounded-lg bg-[var(--sn-role-icon-bg)] text-[var(--sn-text-secondary)] border border-[var(--sn-border)] flex items-center justify-center flex-shrink-0 transition-colors">
                    {r.icon}
                  </div>
                  <div>
                    <div className="font-semibold text-[14px] text-[var(--sn-text)]">{r.title}</div>
                    <div className="text-[12px] text-[var(--sn-text-secondary)] leading-snug mt-1">{r.desc}</div>
                  </div>
                  <div className={`mt-auto pt-2 text-[11px] font-medium transition-colors ${
                    isMatch ? 'text-[#2563EB]' : 'text-[var(--sn-text-muted)]'
                  }`}>
                    {r.landingText}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
};
