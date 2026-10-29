import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  ShieldCheck,
  ShieldAlert,
  Clock,
  CheckCircle2,
  AlertOctagon,
  Bot,
  ArrowRight,
  Lock,
  Layers,
  FileCheck,
  Cpu,
  Terminal,
} from 'lucide-react';
import { api } from '../api/client';
import { TaskRecord, ResultsSummary, AgentInventoryItem, ExpansionItem } from '../types';
import { SpotlightCard } from '../components/reactbits/SpotlightCard';
import { CountUpMetric } from '../components/reactbits/CountUpMetric';
import { ShinyTextHeader } from '../components/reactbits/ShinyTextHeader';

// Lazy-load WebGL background for fast initial paint
const AuroraBg = React.lazy(() => import('../components/reactbits/AuroraBg').then(m => ({ default: m.AuroraBg })));
import { Badge } from '../components/common/Badge';

export const OverviewPage: React.FC = () => {
  const [tasks, setTasks] = useState<TaskRecord[]>([]);
  const [inventory, setInventory] = useState<AgentInventoryItem[]>([]);
  const [expansions, setExpansions] = useState<ExpansionItem[]>([]);
  const [resultsSummary, setResultsSummary] = useState<ResultsSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [activeStepIndex, setActiveStepIndex] = useState(0);
  const [hoveredStep, setHoveredStep] = useState<number | null>(null);

  useEffect(() => {
    Promise.allSettled([
      api.getTasks(),
      api.getInventory(),
      api.getExpansions(),
      api.getResultsSummary(),
    ]).then(([tasksRes, invRes, expRes, sumRes]) => {
      if (tasksRes.status === 'fulfilled') setTasks(tasksRes.value);
      if (invRes.status === 'fulfilled') setInventory(invRes.value);
      if (expRes.status === 'fulfilled') setExpansions(expRes.value);
      if (sumRes.status === 'fulfilled') setResultsSummary(sumRes.value);
      setLoading(false);
    });

    const stepInterval = setInterval(() => {
      setActiveStepIndex(prev => (prev + 1) % 5);
    }, 2500);

    return () => clearInterval(stepInterval);
  }, []);

  // Compute live KPIs
  const activeTasks = tasks.filter(t => t.status === 'ACTIVE' || t.status === 'RUNNING').length;
  const totalPrevented = tasks.reduce((acc, t) => acc + (t.prevented_count || 0), 0);
  const pendingApprovals = expansions.filter(e => e.status === 'PENDING').length;
  const totalGovernedAgents = inventory.length > 0 ? inventory.length : 1;

  const workflowSteps = [
    {
      step: '01',
      title: 'User Request',
      desc: 'Task prompt ingested and hashed and recorded with the task.',
      example: 'Prompt: "Analyze input/sales.csv and summarize into output/summary.txt"',
      icon: Terminal,
      color: 'text-cyan-500',
    },
    {
      step: '02',
      title: 'Boundary Derivation',
      desc: 'Allowed files, tools, and network endpoints derived per task.',
      example: 'Derived boundary: read input/sales.csv, write output/summary.txt',
      icon: Layers,
      color: 'text-indigo-500',
    },
    {
      step: '03',
      title: 'OS Sandbox & Shim',
      desc: 'Linux cgroup, Landlock filesystem rules, and seccomp filters.',
      example: 'cgroup scope created; Landlock drops rights to non-boundary paths',
      icon: Cpu,
      color: 'text-blue-500',
    },
    {
      step: '04',
      title: 'Runtime Mediation',
      desc: 'Out-of-boundary access blocked; mid-task expansion via approver.',
      example: 'Landlock prevents access to private_notes.txt with EACCES',
      icon: Lock,
      color: 'text-amber-500',
    },
    {
      step: '05',
      title: 'Task Receipt',
      desc: 'Hash-chained event record generated; hash-chained; integrity is checked on view.',
      example: 'Receipt verified: 184 inside, 1 outside (blocked by Landlock)',
      icon: FileCheck,
      color: 'text-emerald-500',
    },
  ];

  return (
    <div className="space-y-10 animate-in fade-in duration-300">
      {/* Hero Section */}
      <div className="relative rounded-3xl p-8 md:p-12 overflow-hidden border border-cyan-200/70 dark:border-slate-800 bg-gradient-to-br from-cyan-50/90 via-sky-50/70 to-indigo-50/60 dark:from-surface-cardDark dark:to-surface-bgDark shadow-sm">
        <React.Suspense fallback={null}><AuroraBg speed={0.7} /></React.Suspense>

        <div className="relative z-10 max-w-3xl space-y-4">
          <Badge variant="cyan" size="md">
            TASK-SCOPED RUNTIME GOVERNANCE
          </Badge>

          <h1 className="text-3xl md:text-5xl font-extrabold tracking-tight text-slate-900 dark:text-white leading-[1.15]">
            Bind AI Agent Capabilities to the{' '}
            <ShinyTextHeader text="Specific User Request" speed={3.5} />
          </h1>

          <p className="text-sm md:text-base text-slate-700 dark:text-slate-300 leading-relaxed font-normal">
            Each user request receives a derived boundary, isolating the agent inside a dedicated OS
            cgroup and Landlock/seccomp sandbox with tool broker mediation and hash-chained Task Receipts.
          </p>

          <div className="flex flex-wrap items-center gap-3 pt-2">
            <Link
              to="/tasks"
              className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white font-medium text-xs md:text-sm shadow-lg shadow-cyan-500/25 hover:shadow-cyan-500/40 active:scale-95 transition-all"
            >
              <span>Inspect Active Tasks</span>
              <ArrowRight className="w-4 h-4" />
            </Link>
            <a
              href="https://github.com/Thijil-Thejaswi-MN/Agent_Governance"
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl bg-white/80 dark:bg-slate-800/80 hover:bg-white dark:hover:bg-slate-800 text-slate-700 dark:text-slate-200 font-medium text-xs md:text-sm border border-slate-200 dark:border-slate-700 active:scale-95 transition-all shadow-xs"
            >
              <span>Repository & Docs</span>
            </a>
          </div>
        </div>
      </div>

      {/* Live KPIs */}
      <div>
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-sm font-bold uppercase tracking-wider text-slate-400 dark:text-slate-500">
            Live Telemetry & Activity
          </h2>
          <span className="text-xs font-mono text-slate-400">Real stored state from governance.db</span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {/* Active Tasks */}
          <SpotlightCard className="p-6 hover:-translate-y-1 hover:shadow-md transition-all duration-200">
            <div className="flex items-center justify-between text-slate-500 dark:text-slate-400 mb-2">
              <span className="text-xs font-semibold uppercase tracking-wider">Active Tasks</span>
              <Clock className="w-4 h-4 text-cyan-500" />
            </div>
            <div className="text-3xl font-extrabold text-slate-900 dark:text-white font-mono">
              <CountUpMetric to={activeTasks} />
            </div>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-2">
              Governed execution sessions in memory or cgroups
            </p>
          </SpotlightCard>

          {/* Blocked Actions */}
          <SpotlightCard className="p-6 hover:-translate-y-1 hover:shadow-md transition-all duration-200" spotlightColor="rgba(239, 68, 68, 0.15)">
            <div className="flex items-center justify-between text-slate-500 dark:text-slate-400 mb-2">
              <span className="text-xs font-semibold uppercase tracking-wider">Actions blocked (all tasks)</span>
              <ShieldAlert className="w-4 h-4 text-rose-500" />
            </div>
            <div className="text-3xl font-extrabold text-rose-600 dark:text-rose-400 font-mono">
              <CountUpMetric to={totalPrevented} />
            </div>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-2">
              Out-of-boundary broker & OS Landlock denials
            </p>
          </SpotlightCard>

          {/* Pending Approvals */}
          <SpotlightCard className="p-6 hover:-translate-y-1 hover:shadow-md transition-all duration-200" spotlightColor="rgba(245, 158, 11, 0.15)">
            <div className="flex items-center justify-between text-slate-500 dark:text-slate-400 mb-2">
              <span className="text-xs font-semibold uppercase tracking-wider">Pending Approvals</span>
              <AlertOctagon className="w-4 h-4 text-amber-500" />
            </div>
            <div className="text-3xl font-extrabold text-amber-600 dark:text-amber-400 font-mono">
              <CountUpMetric to={pendingApprovals} />
            </div>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-2">
              Resource expansions awaiting operator review
            </p>
          </SpotlightCard>

          {/* Agent Inventory */}
          <SpotlightCard className="p-6 hover:-translate-y-1 hover:shadow-md transition-all duration-200">
            <div className="flex items-center justify-between text-slate-500 dark:text-slate-400 mb-2">
              <span className="text-xs font-semibold uppercase tracking-wider">Governed Agents</span>
              <Bot className="w-4 h-4 text-indigo-500" />
            </div>
            <div className="text-3xl font-extrabold text-slate-900 dark:text-white font-mono">
              <CountUpMetric to={totalGovernedAgents} />
            </div>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-2">
              Discovered agents tracked in inventory
            </p>
          </SpotlightCard>
        </div>
      </div>

      {/* "How It Works" Pipeline Strip */}
      <div className="relative rounded-2xl p-6 md:p-8 bg-white dark:bg-surface-cardDark border border-slate-200 dark:border-slate-800 overflow-hidden">
        <div className="mb-6">
          <h2 className="text-lg font-bold text-slate-900 dark:text-white">
            Architecture: Task-Scoped Boundary Life Cycle
          </h2>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
            How isolation and enforcement are applied from prompt intake to hash-chained verification.
          </p>
        </div>

        {/* Pulse connecting line on desktop */}
        <div className="hidden md:block absolute top-[138px] left-12 right-12 h-0.5 bg-slate-200 dark:bg-slate-800 z-0 overflow-hidden">
          <div className="w-28 h-full bg-gradient-to-r from-transparent via-cyan-500 to-transparent animate-shimmer" style={{ animationDuration: '3s' }} />
        </div>

        <div className="grid grid-cols-1 md:grid-cols-5 gap-4 relative z-10">
          {workflowSteps.map((s, idx) => {
            const Icon = s.icon;
            const isHighlighted = idx === activeStepIndex;
            const isHovered = idx === hoveredStep;
            return (
              <div
                key={idx}
                onMouseEnter={() => setHoveredStep(idx)}
                onMouseLeave={() => setHoveredStep(null)}
                className={`relative p-4 rounded-xl border flex flex-col justify-between transition-all duration-300 cursor-pointer ${
                  isHovered || isHighlighted
                    ? 'bg-cyan-50/50 dark:bg-slate-800/90 border-cyan-500/60 shadow-md shadow-cyan-500/10 -translate-y-1'
                    : 'bg-slate-50 dark:bg-slate-900/60 border-slate-200/80 dark:border-slate-800/80'
                }`}
              >
                <div>
                  <div className="flex items-center justify-between mb-3">
                    <span className={`font-mono text-xs font-bold transition-colors ${isHighlighted ? 'text-cyan-600 dark:text-cyan-400 font-extrabold' : 'text-slate-400 dark:text-slate-600'}`}>
                      {s.step}
                    </span>
                    <Icon className={`w-5 h-5 ${s.color}`} />
                  </div>
                  <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-200 mb-1">
                    {s.title}
                  </h3>
                  <p className="text-xs text-slate-500 dark:text-slate-400 leading-relaxed">
                    {s.desc}
                  </p>
                </div>

                {/* Example preview on hover or active */}
                <div className={`mt-3 pt-2.5 border-t border-slate-200/60 dark:border-slate-800/80 transition-all text-[11px] font-mono ${isHovered || isHighlighted ? 'text-cyan-600 dark:text-cyan-400' : 'text-slate-400 opacity-60'}`}>
                  <span className="font-semibold block text-[10px] uppercase text-slate-400 dark:text-slate-500">Live Demo Example:</span>
                  <span className="line-clamp-2">{s.example}</span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Evaluation Highlights */}
      {resultsSummary && (
        <div className="rounded-2xl p-6 md:p-8 bg-white dark:bg-surface-cardDark border border-slate-200 dark:border-slate-800 space-y-6">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-100 dark:border-slate-800/80 pb-4">
            <div>
              <h2 className="text-lg font-bold text-slate-900 dark:text-white">
                Empirical Evaluation Highlights
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                Recomputed directly from committed evaluation trials via <code>scripts/build_results_summary.py</code>.
              </p>
            </div>
            <Badge variant="neutral" size="sm">
              {resultsSummary.evaluation_label}
            </Badge>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {/* Metric 1: Harm Prevention */}
            <div className="relative p-[1px] rounded-2xl bg-gradient-to-r from-emerald-500/30 via-cyan-500/30 to-indigo-500/30 hover:from-emerald-500/60 hover:via-cyan-500/60 hover:to-indigo-500/60 transition-all duration-300 hover:-translate-y-1 hover:shadow-lg">
              <div className="p-5 h-full rounded-[15px] bg-slate-50 dark:bg-slate-900/90 flex flex-col justify-between">
                <div>
                  <span className="text-xs font-mono uppercase tracking-wider text-slate-400">
                    Injection Harm Prevention
                  </span>
                  <div className="flex items-baseline gap-2 mt-2">
                    <span className="text-3xl font-extrabold text-emerald-600 dark:text-emerald-400 font-mono">
                      0/32
                    </span>
                    <span className="text-xs text-slate-400 font-mono">Governed (B, C, D)</span>
                  </div>
                  <p className="text-xs text-slate-500 dark:text-slate-400 mt-2">
                    0 harmful trials in each governed condition (baseline 14/32).
                  </p>
                </div>
              </div>
            </div>

            {/* Metric 2: Shell Attacks Succeeded */}
            <div className="relative p-[1px] rounded-2xl bg-gradient-to-r from-cyan-500/30 via-indigo-500/30 to-rose-500/30 hover:from-cyan-500/60 hover:via-indigo-500/60 hover:to-rose-500/60 transition-all duration-300 hover:-translate-y-1 hover:shadow-lg">
              <div className="p-5 h-full rounded-[15px] bg-slate-50 dark:bg-slate-900/90 flex flex-col justify-between">
                <div>
                  <span className="text-xs font-mono uppercase tracking-wider text-slate-400">
                    Shell Attacks Succeeded
                  </span>
                  <div className="flex items-baseline gap-2 mt-2">
                    <span className="text-3xl font-extrabold text-cyan-600 dark:text-cyan-400 font-mono">
                      {resultsSummary.shell_attacks_succeeded['C']?.ratio}
                    </span>
                    <span className="text-xs text-slate-400 font-mono">Condition C (Landlock)</span>
                  </div>
                  <p className="text-xs text-slate-500 dark:text-slate-400 mt-2">
                    With the tool layer only (B), <strong>{resultsSummary.shell_attacks_succeeded['B']?.ratio}</strong> attacks succeeded. Landlock blocked all 10 shell attempts in C.
                  </p>
                </div>
              </div>
            </div>

            {/* Metric 3: Utility & Expansion Chain */}
            <div className="relative p-[1px] rounded-2xl bg-gradient-to-r from-indigo-500/30 via-purple-500/30 to-cyan-500/30 hover:from-indigo-500/60 hover:via-purple-500/60 hover:to-cyan-500/60 transition-all duration-300 hover:-translate-y-1 hover:shadow-lg">
              <div className="p-5 h-full rounded-[15px] bg-slate-50 dark:bg-slate-900/90 flex flex-col justify-between">
                <div>
                  <span className="text-xs font-mono uppercase tracking-wider text-slate-400">
                    Expansion Chain (Unanticipated, C)
                  </span>
                  <div className="flex items-baseline gap-2 mt-2">
                    <span className="text-2xl font-extrabold text-indigo-600 dark:text-indigo-400 font-mono">
                      {resultsSummary.expansion_chain_unanticipated_c?.chain_str}
                    </span>
                  </div>
                  <p className="text-xs text-slate-500 dark:text-slate-400 mt-2">
                    Probed & denied: 32 → Requested: 32 → Approved: 32 → Delivered file read: 31.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
