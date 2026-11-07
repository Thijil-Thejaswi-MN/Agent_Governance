import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, KeyRound, Bot, Users, CheckCircle2, LayoutGrid, FileText } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { Role } from '../types';

interface RoleCard {
  role: Role;
  title: string;
  desc: string;
  landingText: string;
  color: string;
  icon: React.ReactNode;
}

const ROLES: RoleCard[] = [
  {
    role: 'developer',
    title: 'Developer',
    desc: 'Give tasks to your agents and watch them work.',
    landingText: 'Lands on: Ask & Watch →',
    color: '#60A5FA',
    icon: <Bot className="w-5 h-5" />,
  },
  {
    role: 'team_lead',
    title: 'Team lead',
    desc: "See your team's agents. Approve their requests.",
    landingText: 'Lands on: Team overview →',
    color: '#A78BFA',
    icon: <Users className="w-5 h-5" />,
  },
  {
    role: 'security_reviewer',
    title: 'Security reviewer',
    desc: 'Decide on requests. Turn repeats into rules.',
    landingText: 'Lands on: Approvals inbox →',
    color: '#FBBF24',
    icon: <CheckCircle2 className="w-5 h-5" />,
  },
  {
    role: 'admin',
    title: 'Admin',
    desc: 'Every agent, team and rule in one place.',
    landingText: 'Lands on: Organization overview →',
    color: '#34D399',
    icon: <LayoutGrid className="w-5 h-5" />,
  },
  {
    role: 'auditor',
    title: 'Auditor',
    desc: 'Check hash chains, export activity, review decisions.',
    landingText: 'Lands on: Records →',
    color: '#F472B6',
    icon: <FileText className="w-5 h-5" />,
  },
];

export const SignInPage: React.FC = () => {
  const navigate = useNavigate();
  const { saveToken } = useAuth();
  const [tokenInput, setTokenInput] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [highlightedRole, setHighlightedRole] = useState<Role | null>(null);

  const handleSignIn = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!tokenInput.trim()) return;

    setIsSubmitting(true);
    setError(null);

    try {
      const res = await saveToken(tokenInput.trim());
      const userRole: Role = (res?.user?.role as Role) || 'admin';
      const destination = res?.landing_route || (userRole === 'team_lead' ? '/team' : userRole === 'security_reviewer' ? '/inbox' : userRole === 'auditor' ? '/records' : userRole === 'developer' ? '/run' : '/');

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
    <div className="relative overflow-hidden min-h-screen bg-[#0B0E14] text-[#E6E9EF] font-sans flex flex-col items-center px-6 py-12">
      {/* Subtle background glow */}
      <div
        className="absolute top-0 left-1/2 -translate-x-1/2 w-[900px] h-[500px] pointer-events-none opacity-20"
        style={{
          background: 'radial-gradient(ellipse at center, rgba(59,130,246,0.3) 0%, transparent 70%)',
        }}
      />

      {/* Hero Header */}
      <div className="relative z-10 flex flex-col items-center gap-3.5 max-w-4xl w-full">
        <div className="w-14 h-14 rounded-2xl bg-gradient-to-br from-[#3B82F6] to-[#6366F1] flex items-center justify-center text-white shadow-xl shadow-blue-500/25">
          <Shield className="w-7 h-7" />
        </div>
        <h1 className="text-3xl sm:text-4xl font-bold tracking-tight text-center">
          Sign in to Agent Governance
        </h1>
        <p className="text-[#A7B0C0] text-base text-center max-w-lg">
          Every agent only touches what its task needs. Choose how you work today.
        </p>

        {/* Sign In Box */}
        <div className="mt-6 w-full max-w-md p-6 rounded-2xl bg-[#11151D] border border-[#1F2633] shadow-2xl flex flex-col gap-4">
          {/* SSO button - disabled as specified */}
          <button
            type="button"
            disabled
            className="w-full min-h-[44px] rounded-xl border border-[#2A3344] bg-[#161B26] text-[#8B95A7] font-semibold text-[14px] flex items-center justify-center gap-2 cursor-not-allowed opacity-60"
            title="Not configured on this install"
          >
            <Shield className="w-4 h-4" />
            Continue with company sign-in (SSO)
          </button>
          <div className="text-[11px] text-center text-[#6B7487] -mt-2">
            Not configured on this install
          </div>

          <div className="flex items-center gap-3 text-[12px] text-[#6B7487] my-1">
            <span className="flex-1 h-px bg-[#1F2633]" />
            <span>or, on a local install</span>
            <span className="flex-1 h-px bg-[#1F2633]" />
          </div>

          {/* Operator Token Form */}
          <form onSubmit={handleSignIn} className="flex flex-col gap-2">
            <label htmlFor="operator-token-input" className="text-[12px] font-medium text-[#8B95A7]">
              Operator token
            </label>
            <div className="flex gap-2">
              <input
                id="operator-token-input"
                type="password"
                placeholder="Paste token or GOVERNANCE_OPERATOR_TOKEN..."
                value={tokenInput}
                onChange={e => setTokenInput(e.target.value)}
                disabled={isSubmitting || highlightedRole !== null}
                className="flex-1 min-h-[42px] px-3.5 rounded-xl border border-[#2A3344] bg-[#0B0E14] text-[#E6E9EF] font-mono text-[13px] outline-none focus:border-[#3B82F6] transition-colors"
              />
              <button
                type="submit"
                id="sign-in-submit-btn"
                disabled={isSubmitting || !tokenInput.trim() || highlightedRole !== null}
                className="px-5 min-h-[42px] rounded-xl bg-[#3B82F6] hover:bg-[#2563EB] disabled:opacity-50 text-white font-semibold text-[14px] transition-colors flex items-center justify-center cursor-pointer"
              >
                {isSubmitting ? 'Signing in…' : 'Sign in'}
              </button>
            </div>
            {error && (
              <div className="text-[12px] text-[#EF4444] mt-1 font-medium">
                {error}
              </div>
            )}
          </form>
        </div>

        {/* Role Explanation Section */}
        <div className="mt-10 w-full flex flex-col gap-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <h2 className="text-[15px] font-bold text-[#E6E9EF]">Your role in Acme Corp</h2>
            <span className="text-[12px] text-[#8B95A7]">
              Each role opens on a different home. Your admin assigns roles.
            </span>
          </div>

          {/* Role Cards Grid */}
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-3.5 mt-1">
            {ROLES.map(r => {
              const isMatch = highlightedRole === r.role;
              return (
                <div
                  key={r.role}
                  className={`relative p-5 rounded-xl bg-[#11151D] border transition-all duration-300 flex flex-col gap-3 select-none ${
                    isMatch
                      ? 'border-[#3B82F6] ring-2 ring-[#3B82F6] shadow-lg shadow-blue-500/20 scale-105 bg-[#161F30]'
                      : 'border-[#1F2633] hover:border-[#2A3344]'
                  }`}
                >
                  <div
                    className="w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0"
                    style={{ backgroundColor: `${r.color}22`, color: r.color }}
                  >
                    {r.icon}
                  </div>
                  <div>
                    <div className="font-bold text-[15px] text-[#E6E9EF]">{r.title}</div>
                    <div className="text-[13px] text-[#A7B0C0] leading-snug mt-1.5">{r.desc}</div>
                  </div>
                  <div className="mt-auto pt-2 text-[12px] font-semibold" style={{ color: r.color }}>
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

