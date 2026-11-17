import React, { useState, useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { Shield, Bot, Users, CheckCircle2, LayoutGrid, FileText, Cpu, ShieldCheck, FileCheck2, Sparkles, Star } from 'lucide-react';
import { HeroBeam } from '../components/landing/HeroBeam';
import { Eyebrow } from '../components/landing/Eyebrow';
import { GlowButton } from '../components/landing/GlowButton';
import { useAuth } from '../context/AuthContext';
import { ResultsSummary, Role } from '../types';
import { api } from '../api/client';
import { LandingResult, landingHarm, landingResults } from '../logic/landingResults';
import { roleHome, safeNext } from '../logic/journey';
import DotField from '../components/effects/DotField';
import { formatCount, useCountUp } from '../hooks/useCountUp';
import { FeatureMosaic } from '../components/landing/FeatureMosaic';

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

const delay = (d: string) => ({ '--d': d }) as React.CSSProperties;

const TRUST = [
  { icon: <Cpu className="w-[15px] h-[15px]" />, title: 'Linux kernel (Landlock, seccomp)' },
  { icon: <ShieldCheck className="w-[15px] h-[15px]" />, title: 'Tool broker' },
  { icon: <FileCheck2 className="w-[15px] h-[15px]" />, title: 'Hash-chained record' },
];

const ResultStat: React.FC<{ r: LandingResult; i: number }> = ({ r, i }) => {
  const { ref, value } = useCountUp<HTMLDivElement>(r.value, 1500 + i * 80, 480 + i * 90);
  return (
    <div ref={ref} className="landing-anim flex flex-col items-center text-center gap-1.5" style={delay(`${0.5 + i * 0.08}s`)} data-result={i}>
      <span className="dot-matrix text-[clamp(22px,3vw,33px)] leading-none" aria-hidden="true">
        {r.glyph}
      </span>
      <span className="text-white text-[clamp(18px,2.2vw,26px)] font-medium tracking-[-0.025em] tabular-nums">
        {formatCount(value, r.decimals || 0)}
        {r.suffix}
      </span>
      <span className="text-[#8e8e8e] text-[clamp(11px,1.2vw,12.5px)] leading-snug max-w-[200px]">{r.label}</span>
    </div>
  );
};

export const SignInPage: React.FC = () => {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const { saveToken } = useAuth();
  const [tokenInput, setTokenInput] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [highlightedRole, setHighlightedRole] = useState<Role | null>(null);
  const [prefersReducedMotion, setPrefersReducedMotion] = useState(false);
  // Evaluation figures come from results_summary.json (recomputed from the raw trials), not from this file.
  const [summary, setSummary] = useState<ResultsSummary | null | undefined>(undefined);
  useEffect(() => {
    let live = true;
    api
      .getResultsSummary()
      .then(s => live && setSummary(s))
      .catch(() => live && setSummary(null));
    return () => {
      live = false;
    };
  }, []);
  const results = landingResults(summary);

  useEffect(() => {
    if (typeof window === 'undefined' || !window.matchMedia) return;
    const motionQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
    setPrefersReducedMotion(motionQuery.matches);
    const motionHandler = (e: MediaQueryListEvent) => setPrefersReducedMotion(e.matches);
    motionQuery.addEventListener('change', motionHandler);
    return () => motionQuery.removeEventListener('change', motionHandler);
  }, []);

  const handleSignIn = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!tokenInput.trim()) return;

    setIsSubmitting(true);
    setError(null);

    try {
      const res = await saveToken(tokenInput.trim());
      const userRole: Role = (res?.user?.role as Role) || 'admin';
      // Back to the page that needed sign-in, if any; otherwise the role's home.
      const destination = safeNext(params.get('next')) || roleHome(userRole);

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

  const navLink = (href: string, label: string, active = false) => (
    <a
      href={href}
      aria-current={active ? 'page' : undefined}
      className={`relative px-3 sm:px-4 py-2 text-[clamp(13px,1.4vw,15px)] font-medium tracking-[-0.01em] text-[#2e2e2e] no-underline transition-opacity ${
        active
          ? "opacity-100 after:content-[''] after:absolute after:left-1/2 after:bottom-[5px] after:w-[3px] after:h-[3px] after:-ml-[1.5px] after:rounded-full after:bg-black after:shadow-[-5px_0_0_#000,5px_0_0_#000]"
          : 'opacity-50 hover:opacity-75'
      }`}
    >
      {label}
    </a>
  );

  return (
    <div className="relative min-h-screen bg-black text-white font-sans overflow-x-hidden">
      {/* Background: the console's own dot field over a soft glow (no external video). */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none" aria-hidden="true">
        <div
          className="absolute inset-0"
          style={{
            background:
              'radial-gradient(70% 45% at 50% 18%, rgba(147,197,253,0.18), transparent 70%), radial-gradient(90% 55% at 50% 78%, rgba(99,102,241,0.30), rgba(59,130,246,0.10) 45%, transparent 75%)',
          }}
        />
        <HeroBeam prefersReducedMotion={prefersReducedMotion} />
        {!prefersReducedMotion && (
          <div className="absolute inset-0">
            <DotField gradientFrom="#3B82F6" gradientTo="#A5B4FC" baseOpacity={0.16} glowIntensity={0.08} holdToZoom={false} />
          </div>
        )}
        <div className="absolute inset-x-0 bottom-0 h-[45%]" style={{ background: 'linear-gradient(to bottom, transparent, #000 85%)' }} />
      </div>

      <div className="relative z-[1] flex flex-col items-center px-[clamp(14px,3vw,32px)] pt-[clamp(16px,2.4vh,28px)]">
        {/* Header */}
        <header className="landing-slide w-full max-w-[720px] flex items-center justify-between sm:justify-center gap-[clamp(18px,2.8vw,28px)]">
          <a
            href="#signin"
            aria-label="Agent Governance"
            className="grid place-items-center w-[clamp(40px,4.4vw,46px)] h-[clamp(40px,4.4vw,46px)] rounded-full bg-white shadow-[0_4px_14px_rgba(0,0,0,0.16)] transition-transform hover:scale-[1.04] shrink-0"
          >
            <Shield className="w-[60%] h-[60%] text-[#2563EB]" strokeWidth={2} />
          </a>
          <nav
            aria-label="This page"
            className="hidden sm:flex flex-1 max-w-[430px] h-[clamp(44px,5.2vw,48px)] items-center justify-around rounded-full bg-white px-2 py-1 shadow-[0_4px_14px_rgba(0,0,0,0.16)]"
          >
            {navLink('#signin', 'Sign in', true)}
            {navLink('#features', 'How it works')}
            {navLink('#results', 'Results')}
            {navLink('#roles', 'Roles')}
          </nav>
          <span className="sm:hidden text-[14px] font-semibold text-[#c8c8c8]">Agent Governance</span>
        </header>

        {/* Hero */}
        <section className="w-full max-w-[900px] flex flex-col items-center text-center pt-[clamp(28px,7vh,72px)] pb-8">
          <div className="landing-anim inline-flex items-center mb-[clamp(16px,2.5vh,26px)]" style={delay('0.05s')} id="trust-row">
            {TRUST.map((t, i) => (
              <span
                key={t.title}
                title={t.title}
                className="relative grid place-items-center w-[38px] h-[38px] sm:w-[42px] sm:h-[42px] rounded-full bg-[#28282a] border border-white/40 p-[5px] transition-transform duration-300 hover:-translate-y-1"
                style={{ marginLeft: i ? -16 : 0, zIndex: [1, 2, 4][i] }}
              >
                <span className="grid place-items-center w-full h-full rounded-full bg-white text-[#111]">{t.icon}</span>
              </span>
            ))}
            <span className="inline-flex items-center h-[38px] sm:h-[42px] rounded-full bg-[#28282a] border border-white/40 -ml-4 pl-6 pr-4 text-[12px] sm:text-[13.5px] font-medium text-[#c4c2c3]">
              One boundary, three layers
            </span>
          </div>

          <h1 className="m-0 font-mono font-semibold text-white text-[clamp(28px,6.2vw,80px)] leading-[1.12] tracking-[-0.04em] max-sm:tracking-[-0.06em]">
            <span className="landing-anim dot-matrix block whitespace-nowrap" style={delay('0.12s')}>
              Agents, <span className="dot-matrix-gradient">Governed</span>
            </span>
            <span className="landing-anim dot-matrix block whitespace-nowrap" style={delay('0.3s')}>
              At Runtime
            </span>
          </h1>

          <p
            className="landing-anim mt-5 mb-0 max-w-[min(520px,92%)] text-[clamp(15px,1.55vw,18px)] leading-[1.55] text-[#d0d0d0] opacity-80"
            style={delay('0.28s')}
          >
            Each AI agent touches only what its task needs. The tool broker and the Linux kernel enforce the same list,
            and every decision lands in a record you can check.
          </p>

          <div className="landing-anim mt-5" style={delay('0.34s')}>
            <GlowButton variant="outline" href="#features" id="see-how-it-works-btn">
              See how it works
            </GlowButton>
          </div>

          {/* Sign-in panel */}
          <div
            id="signin"
            className="landing-anim mt-8 w-full max-w-[440px] p-5 sm:p-6 rounded-[28px] border border-white/15 bg-[rgba(20,20,22,0.72)] backdrop-blur-md flex flex-col gap-4 text-left shadow-[0_20px_60px_rgba(0,0,0,0.45)]"
            style={delay('0.4s')}
          >
            <h2 id="signin-heading" className="m-0 text-[17px] font-semibold text-white text-center">
              Sign in to Agent Governance
            </h2>
            {/* SSO button - disabled as specified */}
            <button
              type="button"
              disabled
              className="w-full min-h-[44px] rounded-full border border-white/15 bg-white/5 text-[#8e8e8e] font-medium text-[13px] flex items-center justify-center gap-2 cursor-not-allowed"
              title="Not configured on this install"
            >
              <Shield className="w-4 h-4" />
              Continue with company sign-in (SSO)
            </button>
            <div className="text-[11px] text-center text-[#8e8e8e] -mt-2">Not configured on this install</div>

            <div className="flex items-center gap-3 text-[11px] text-[#8e8e8e] font-mono tracking-wider uppercase">
              <span className="flex-1 h-px bg-white/15" />
              <span>or, on a local install</span>
              <span className="flex-1 h-px bg-white/15" />
            </div>

            {/* Operator Token Form */}
            <form onSubmit={handleSignIn} className="flex flex-col gap-2">
              <label htmlFor="operator-token-input" className="text-[12px] font-medium text-[#c8c8c8]">
                Operator token
              </label>
              <div className="flex flex-col sm:flex-row gap-2">
                <input
                  id="operator-token-input"
                  type="password"
                  placeholder="Paste token or GOVERNANCE_OPERATOR_TOKEN..."
                  value={tokenInput}
                  onChange={e => setTokenInput(e.target.value)}
                  disabled={isSubmitting || highlightedRole !== null}
                  className="flex-1 min-w-0 min-h-[44px] px-4 rounded-full border border-white/15 bg-black/60 text-white font-mono text-[13px] placeholder:text-[#6b6b6b] outline-none focus:border-white/60 transition-colors"
                />
                <GlowButton
                  type="submit"
                  id="sign-in-submit-btn"
                  variant="solid"
                  disabled={isSubmitting || !tokenInput.trim() || highlightedRole !== null}
                  className="w-full sm:w-auto whitespace-nowrap"
                >
                  {isSubmitting ? 'Signing in…' : 'Sign in'}
                </GlowButton>
              </div>
              {error && <div className="text-[12px] text-red-400 mt-1 font-medium">{error}</div>}
            </form>
          </div>
        </section>

        {/* Results from the evaluation */}
        <section id="results" aria-label="Results from our evaluation" className="w-full max-w-[920px] pt-4 pb-10 flex flex-col items-center gap-4">
          <Eyebrow text="FROM OUR EVALUATION" icon={Shield} id="eyebrow-results" />
          {results ? (
            <div className="grid grid-cols-2 md:grid-cols-4 gap-x-4 gap-y-7">
              {results.map((r, i) => (
                <ResultStat key={r.glyph} r={r} i={i} />
              ))}
            </div>
          ) : (
            <p className="m-0 text-center text-[13px] text-[#8e8e8e]">
              {summary === undefined ? 'Loading the evaluation results…' : 'The evaluation results are not available on this install.'}
            </p>
          )}
          <p className="m-0 text-center text-[11.5px] text-[#6b6b6b] leading-relaxed">
            From our evaluation: qwen2.5:7b on one machine, our own 32-task sets (16 scenarios, twice each), normal tasks
            run with the reviewed boundary, a simulated approver. Not live numbers; the trial records are on the Evidence
            page after you sign in.
          </p>
        </section>

        {/* What it does (feature mosaic) */}
        <section aria-labelledby="features-heading" className="w-full max-w-[1180px] flex flex-col items-center gap-4 pb-14">
          <Eyebrow text="WHAT IT DOES" icon={Sparkles} id="eyebrow-features" />
          <h2 id="features-heading" className="m-0 text-center text-[clamp(20px,2.4vw,28px)] font-semibold tracking-[-0.02em] text-white">
            How it works
          </h2>
          <FeatureMosaic harm={landingHarm(summary)} />
        </section>

        {/* Role Explanation Section */}
        <section id="roles" className="w-full max-w-4xl flex flex-col gap-3 pb-14">
          <div className="flex flex-col gap-1.5">
            <Eyebrow text="ROLES" icon={Star} id="eyebrow-roles" className="self-start" />
            <div className="flex flex-wrap items-center justify-between gap-2">
              <h2 className="text-[14px] font-semibold text-white m-0">Your role</h2>
              <span className="text-[12px] text-[#8e8e8e]">Each role opens on a different home. Your admin assigns roles.</span>
            </div>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-3 mt-1">
            {ROLES.map(r => {
              const isMatch = highlightedRole === r.role;
              return (
                <div
                  key={r.role}
                  className={`relative p-4 rounded-2xl border transition-all duration-200 flex flex-col gap-2.5 select-none backdrop-blur-sm ${
                    isMatch ? 'border-white ring-1 ring-white bg-white/10' : 'border-white/15 bg-[rgba(20,20,22,0.6)] hover:border-white/40'
                  }`}
                >
                  <div className="w-8 h-8 rounded-full bg-white text-[#111] flex items-center justify-center flex-shrink-0">{r.icon}</div>
                  <div>
                    <div className="font-semibold text-[14px] text-white">{r.title}</div>
                    <div className="text-[12px] text-[#a8a8a8] leading-snug mt-1">{r.desc}</div>
                  </div>
                  <div className={`mt-auto pt-2 text-[11px] font-medium ${isMatch ? 'text-white' : 'text-[#8e8e8e]'}`}>{r.landingText}</div>
                </div>
              );
            })}
          </div>
        </section>
      </div>
    </div>
  );
};
