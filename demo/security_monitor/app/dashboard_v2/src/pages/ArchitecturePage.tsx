import React from 'react';
import { Layers, Cpu, Shield, Lock, FileCheck2, ArrowDown, ArrowRight } from 'lucide-react';

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

      <div className="p-8 rounded-3xl bg-white dark:bg-surface-cardDark border border-slate-200 dark:border-slate-800 space-y-8">
        {/* Flow Diagram */}
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
            <span className="text-sm font-semibold text-slate-900 dark:text-white">Task-Scoped Boundary Derivation (v1 Templates)</span>
            <p className="text-xs text-slate-500 mt-1">Derives allowable files, permitted tools, network endpoints</p>
          </div>

          <ArrowDown className="w-5 h-5 text-slate-400" />

          {/* OS Layer Box */}
          <div className="w-full p-6 rounded-2xl border-2 border-blue-500/30 bg-blue-500/5 relative space-y-4">
            <div className="flex items-center justify-between border-b border-blue-500/20 pb-2">
              <span className="text-xs font-mono font-bold text-blue-500 uppercase">OS Sandbox Confinement (Linux/WSL2)</span>
              <span className="text-[11px] font-mono text-slate-400">cgroup v2 scope</span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs font-mono">
              <div className="p-3 rounded-lg bg-white/60 dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800">
                <span className="text-blue-500 font-bold block mb-1">Landlock LSM</span>
                <span>Restricts kernel file openat/read/write to derived paths and read-only granted/</span>
              </div>
              <div className="p-3 rounded-lg bg-white/60 dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800">
                <span className="text-blue-500 font-bold block mb-1">Seccomp Filter</span>
                <span>Restricts syscalls, mounts, raw sockets, and prevents sandbox escapes</span>
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
              <span className="text-sm font-semibold text-slate-900 dark:text-white">Task Receipt v0</span>
              <p className="text-xs text-slate-500 mt-1">SHA-256 hash-chained log of allowed & blocked actions</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
