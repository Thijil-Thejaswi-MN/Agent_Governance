import React from 'react';
import { Layers, Cpu, Shield, Lock, FileCheck2, ArrowDown, ArrowRight, Eye, UserCheck, Terminal } from 'lucide-react';

export const ArchitecturePage: React.FC = () => {
  return (
    <div className="space-y-8 animate-in fade-in duration-300">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-white">
          System Architecture
        </h1>
        <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
          Dual-layer runtime governance combining application tool mediation with kernel-level Landlock and seccomp confinement.
        </p>
      </div>

      {/* Experimental Conditions Compared */}
      <div className="p-6 rounded-3xl bg-white dark:bg-surface-cardDark border border-slate-200 dark:border-slate-800 space-y-4">
        <h2 className="text-base font-bold text-slate-900 dark:text-white flex items-center gap-2">
          <Layers className="w-4 h-4 text-cyan-500" />
          <span>Governance Isolation Conditions</span>
        </h2>
        <p className="text-xs text-slate-500 dark:text-slate-400">
          The system evaluates four distinct isolation conditions under identical task workloads:
        </p>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs">
          <div className="p-4 rounded-2xl bg-slate-50 dark:bg-slate-900/40 border border-slate-200 dark:border-slate-800 space-y-1.5">
            <span className="font-mono text-xs font-bold text-slate-500 block">Condition A</span>
            <span className="font-semibold text-slate-900 dark:text-white text-sm block">No governance</span>
            <p className="text-slate-500 text-[11px]">Direct execution without tool mediation or OS confinement.</p>
          </div>

          <div className="p-4 rounded-2xl bg-slate-50 dark:bg-slate-900/40 border border-slate-200 dark:border-slate-800 space-y-1.5">
            <span className="font-mono text-xs font-bold text-cyan-500 block">Condition B</span>
            <span className="font-semibold text-slate-900 dark:text-white text-sm block">Tool layer only</span>
            <p className="text-slate-500 text-[11px]">Tool mediation and broker checks without OS sandboxing.</p>
          </div>

          <div className="p-4 rounded-2xl bg-slate-50 dark:bg-slate-900/40 border border-indigo-500/30 bg-indigo-500/5 space-y-1.5">
            <span className="font-mono text-xs font-bold text-indigo-500 block">Condition C</span>
            <span className="font-semibold text-slate-900 dark:text-white text-sm block">Tool + OS layer</span>
            <p className="text-slate-500 text-[11px]">Tool mediation combined with Landlock, seccomp, and observation sensor.</p>
          </div>

          <div className="p-4 rounded-2xl bg-slate-50 dark:bg-slate-900/40 border border-slate-200 dark:border-slate-800 space-y-1.5">
            <span className="font-mono text-xs font-bold text-purple-500 block">Condition D</span>
            <span className="font-semibold text-slate-900 dark:text-white text-sm block">Per-task container</span>
            <p className="text-slate-500 text-[11px]">Full container boundary isolation per task invocation.</p>
          </div>
        </div>
      </div>

      {/* Runtime Architecture Flow */}
      <div className="p-8 rounded-3xl bg-white dark:bg-surface-cardDark border border-slate-200 dark:border-slate-800 space-y-8">
        <div className="flex flex-col items-center space-y-6 max-w-2xl mx-auto">
          {/* User Request */}
          <div className="w-full p-4 rounded-xl border border-cyan-500/30 bg-cyan-500/5 text-center">
            <span className="font-mono text-xs font-bold text-cyan-500 uppercase block">Input</span>
            <span className="text-sm font-semibold text-slate-900 dark:text-white">User Prompt Request (Intake)</span>
          </div>

          <ArrowDown className="w-5 h-5 text-slate-400" />

          {/* Intake & Boundary Derivation */}
          <div className="w-full p-4 rounded-xl border border-indigo-500/30 bg-indigo-500/5 text-center">
            <span className="font-mono text-xs font-bold text-indigo-500 uppercase block">Derivation</span>
            <span className="text-sm font-semibold text-slate-900 dark:text-white">Task-Scoped Boundary Derivation</span>
            <p className="text-xs text-slate-500 mt-1">Derives allowable files, permitted tools, and network egress rules</p>
          </div>

          <ArrowDown className="w-5 h-5 text-slate-400" />

          {/* OS Layer Box */}
          <div className="w-full p-6 rounded-2xl border-2 border-blue-500/30 bg-blue-500/5 relative space-y-4">
            <div className="flex items-center justify-between border-b border-blue-500/20 pb-2">
              <span className="text-xs font-mono font-bold text-blue-500 uppercase">OS Sandbox Confinement (Linux/WSL2)</span>
              <span className="text-[11px] font-mono text-slate-400">cgroup v2 scope</span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-mono">
              <div className="p-3 rounded-lg bg-white/60 dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800">
                <span className="text-blue-500 font-bold block mb-1">Landlock LSM</span>
                <span>Restricts kernel filesystem access to derived paths and pre-authorized granted/ directory</span>
              </div>
              <div className="p-3 rounded-lg bg-white/60 dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800">
                <span className="text-blue-500 font-bold block mb-1">Seccomp Filter</span>
                <span>Restricts syscalls, mounts, raw sockets, and prevents sandbox escapes</span>
              </div>
              <div className="p-3 rounded-lg bg-white/60 dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800">
                <span className="text-amber-500 font-bold block mb-1">Observation Sensor</span>
                <span>Observation-only sensor tracing child process lifecycle and syscall telemetry</span>
              </div>
            </div>

            {/* Agent Shim inside Sandbox */}
            <div className="p-4 rounded-xl bg-white dark:bg-surface-cardDark border border-slate-300 dark:border-slate-700 text-center">
              <span className="text-xs font-mono text-slate-400 uppercase block">Untrusted Execution</span>
              <span className="text-sm font-bold text-slate-900 dark:text-white">AI Agent Shim & Model (e.g. Qwen2.5 / Llama3.1)</span>
            </div>
          </div>

          <ArrowDown className="w-5 h-5 text-slate-400" />

          {/* Mediation & Receipt */}
          <div className="w-full grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div className="p-4 rounded-xl border border-amber-500/30 bg-amber-500/5 text-center">
              <span className="font-mono text-xs font-bold text-amber-500 uppercase block">Tool Layer</span>
              <span className="text-sm font-semibold text-slate-900 dark:text-white">Broker Unix Socket</span>
              <p className="text-xs text-slate-500 mt-1">7 agent-facing RPC methods; egress proxy for HTTP</p>
            </div>
            <div className="p-4 rounded-xl border border-emerald-500/30 bg-emerald-500/5 text-center">
              <span className="font-mono text-xs font-bold text-emerald-500 uppercase block">Audit & Chain</span>
              <span className="text-sm font-semibold text-slate-900 dark:text-white">Task Receipt</span>
              <p className="text-xs text-slate-500 mt-1">SHA-256 hash-chained log of allowed and denied actions</p>
            </div>
          </div>
        </div>
      </div>

      {/* Verified Claims & Approval Policies */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="p-6 rounded-2xl bg-white dark:bg-surface-cardDark border border-slate-200 dark:border-slate-800 space-y-3">
          <h3 className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2">
            <Shield className="w-4 h-4 text-emerald-500" />
            <span>Architectural Properties</span>
          </h3>
          <ul className="space-y-2 text-xs text-slate-600 dark:text-slate-300">
            <li className="flex items-start gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 mt-1.5 shrink-0" />
              <span><strong>Hash-Chained Receipts:</strong> Receipt entries are linked by a SHA-256 hash chain; this detects edits to individual entries but is not signed — someone able to rewrite the whole file can recompute the chain.</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 mt-1.5 shrink-0" />
              <span><strong>Observation-Only Sensor:</strong> The background telemetry sensor operates strictly for runtime observation; enforcement barriers are enforced directly by the Linux kernel via Landlock and seccomp.</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 mt-1.5 shrink-0" />
              <span><strong>Exact Resource Boundaries:</strong> Boundaries require exact path matches; wildcards are strictly rejected during compilation and runtime requests.</span>
            </li>
          </ul>
        </div>

        <div className="p-6 rounded-2xl bg-white dark:bg-surface-cardDark border border-slate-200 dark:border-slate-800 space-y-3">
          <h3 className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2">
            <UserCheck className="w-4 h-4 text-cyan-500" />
            <span>Dynamic Approval Policies</span>
          </h3>
          <ul className="space-y-2 text-xs text-slate-600 dark:text-slate-300">
            <li className="flex items-start gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-cyan-500 mt-1.5 shrink-0" />
              <span><strong>Oracle Approval Path (Evaluation):</strong> In empirical benchmark trials, an automated oracle decides boundary expansion requests deterministically based on test specifications.</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-cyan-500 mt-1.5 shrink-0" />
              <span><strong>Operator Approval Path (Console):</strong> In interactive operations and demos, requests remain PENDING until an authenticated human operator reviews provenance and decides via the dashboard.</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-cyan-500 mt-1.5 shrink-0" />
              <span><strong>Fail-Closed Timeouts:</strong> When operator requests remain undecided upon reaching the configured timeout, they fail closed to DENY automatically.</span>
            </li>
          </ul>
        </div>
      </div>
    </div>
  );
};
