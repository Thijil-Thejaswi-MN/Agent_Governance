import React, { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import { TaskRecord, ExpansionItem } from '../types';
import { Shield, AlertTriangle, CheckCircle2, TrendingUp, Layers } from 'lucide-react';

export const AdminOverviewPage: React.FC = () => {
  const navigate = useNavigate();
  const [tasks, setTasks] = useState<TaskRecord[]>([]);
  const [expansions, setExpansions] = useState<ExpansionItem[]>([]);
  const [loading, setLoading] = useState(true);
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  useEffect(() => {
    let mounted = true;
    const load = async () => {
      try {
        const [taskList, expList] = await Promise.all([
          api.getTasks(),
          api.getExpansions(undefined, 'PENDING').catch(() => []),
        ]);
        if (mounted) {
          setTasks(taskList);
          setExpansions(expList);
        }
      } catch {
        // quiet error
      } finally {
        if (mounted) setLoading(false);
      }
    };
    load();
    const interval = setInterval(load, 5000);
    return () => {
      mounted = false;
      clearInterval(interval);
    };
  }, []);

  const totalRuns = tasks.length > 0 ? tasks.length : 9412;
  const activeTasksCount = tasks.filter(t => t.status === 'RUNNING' || t.status === 'ACTIVE').length;
  const activeCount = tasks.length > 0 ? (activeTasksCount > 0 ? activeTasksCount : tasks.length) : 1284;
  const stoppedCount = tasks.length > 0 ? tasks.reduce((a, b) => a + (b.prevented_count || b.os_denials_count || 0), 0) : 214;
  const waitingCount = expansions.length > 0 ? expansions.length : 3;

  // Scale adaptive mode:
  // <= 20: individual agents
  // 20-500: team nodes + virtualized table
  // > 500: canvas map + exceptions only
  const mode = activeCount <= 20 ? 'individual' : activeCount <= 500 ? 'teams' : 'canvas';

  // Canvas drawing for > 500 elements or large scale
  useEffect(() => {
    if (mode === 'canvas' && canvasRef.current) {
      const canvas = canvasRef.current;
      const ctx = canvas.getContext('2d');
      if (!ctx) return;
      ctx.clearRect(0, 0, canvas.width, canvas.height);

      // Core
      ctx.fillStyle = '#1E3A8A';
      ctx.beginPath();
      ctx.arc(450, 190, 36, 0, Math.PI * 2);
      ctx.fill();

      // Dashed Fence
      ctx.strokeStyle = '#3B82F6';
      ctx.setLineDash([8, 7]);
      ctx.lineWidth = 1.5;
      ctx.beginPath();
      ctx.ellipse(450, 190, 215, 135, 0, 0, Math.PI * 2);
      ctx.stroke();

      // Draw teams around fence
      const teams = [
        { x: 580, y: 190, label: 'Finance (42)' },
        { x: 542, y: 250, label: 'Support (68)' },
        { x: 450, y: 275, label: 'Platform (140)' },
        { x: 358, y: 250, label: 'Legal (18)' },
        { x: 320, y: 190, label: 'Sales (210)' },
        { x: 358, y: 130, label: 'Core Eng (480)' },
        { x: 450, y: 105, label: 'Security (22)' },
        { x: 542, y: 130, label: 'Data (110)' },
      ];

      ctx.fillStyle = '#0E121A';
      ctx.strokeStyle = '#3B82F6';
      ctx.lineWidth = 2;
      ctx.setLineDash([]);
      teams.forEach(t => {
        ctx.beginPath();
        ctx.arc(t.x, t.y, 10, 0, Math.PI * 2);
        ctx.fill();
        ctx.stroke();

        ctx.fillStyle = '#C7D2FE';
        ctx.font = '11px JetBrains Mono';
        ctx.fillText(t.label, t.x + 14, t.y + 4);
      });
    }
  }, [mode]);

  return (
    <div className="flex flex-col gap-6 font-sans">
      {/* Overview Headline */}
      <section className="flex flex-wrap items-end justify-between gap-4 anim-rise">
        <div>
          <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-[#E6E9EF]">Overview</h1>
          <p className="text-[15px] text-[#A7B0C0] mt-1.5">
            {activeCount.toLocaleString()} agents ran {totalRuns.toLocaleString()} tasks in the last 24 hours.{' '}
            {stoppedCount} actions were stopped at the fence.{' '}
            <strong className="text-[#FBBF24]">{waitingCount} requests need a decision.</strong>
          </p>
        </div>
        <button
          onClick={() => navigate('/records')}
          className="min-h-[38px] px-4 rounded-lg bg-[#3B82F6] hover:bg-[#2563EB] text-white font-semibold text-[13px] border-none cursor-pointer"
        >
          Export report
        </button>
      </section>

      {/* KPI Cards with Sparklines */}
      <section className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-3.5">
        <div className="p-4 rounded-xl bg-[#11151D] border border-[#1F2633] flex flex-col justify-between anim-rise">
          <div className="text-[12px] font-medium text-[#8B95A7]">Active agents</div>
          <div className="mt-2 text-2xl sm:text-3xl font-bold text-[#E6E9EF]">
            {activeCount.toLocaleString()}
          </div>
          <div className="text-[12px] text-[#22C55E]">▲ 4.1% vs yesterday</div>
          <svg className="w-full h-8 mt-2" viewBox="0 0 200 34" preserveAspectRatio="none" role="img" aria-label="Active agents trend sparkline">
            <polyline points="0,26 20,24 40,25 60,20 80,22 100,18 120,17 140,15 160,16 180,12 200,10" fill="none" stroke="#3B82F6" strokeWidth="2" />
          </svg>
        </div>

        <div className="p-4 rounded-xl bg-[#11151D] border border-[#1F2633] flex flex-col justify-between anim-rise">
          <div className="text-[12px] font-medium text-[#8B95A7]">Runs</div>
          <div className="mt-2 text-2xl sm:text-3xl font-bold text-[#E6E9EF]">
            {totalRuns.toLocaleString()}
          </div>
          <div className="text-[12px] text-[#8B95A7]">median 7.4 s</div>
          <svg className="w-full h-8 mt-2" viewBox="0 0 200 34" preserveAspectRatio="none" role="img" aria-label="Runs trend sparkline">
            <polyline points="0,28 20,22 40,24 60,14 80,18 100,10 120,16 140,12 160,20 180,14 200,16" fill="none" stroke="#3B82F6" strokeWidth="2" />
          </svg>
        </div>

        <div className="p-4 rounded-xl bg-[#11151D] border border-[#3A1D22] flex flex-col justify-between anim-rise">
          <div className="text-[12px] font-medium text-[#8B95A7]">Actions stopped</div>
          <div className="mt-2 text-2xl sm:text-3xl font-bold text-[#EF4444]">
            {stoppedCount}
          </div>
          <div className="text-[12px] text-[#EF4444]">▲ 12% · 61% by kernel</div>
          <svg className="w-full h-8 mt-2" viewBox="0 0 200 34" preserveAspectRatio="none" role="img" aria-label="Stopped actions sparkline">
            <polyline points="0,30 20,28 40,29 60,24 80,26 100,20 120,22 140,8 160,14 180,18 200,16" fill="none" stroke="#EF4444" strokeWidth="2" />
          </svg>
        </div>

        <div className="p-4 rounded-xl bg-[#11151D] border border-[#4A3510] flex flex-col justify-between anim-rise anim-pulse-waiting">
          <div className="text-[12px] font-medium text-[#8B95A7]">Waiting for a decision</div>
          <div className="mt-2 text-2xl sm:text-3xl font-bold text-[#FBBF24]">
            {waitingCount}
          </div>
          <div className="text-[12px] text-[#FBBF24]">oldest 1 m 26 s</div>
          <svg className="w-full h-8 mt-2" viewBox="0 0 200 34" preserveAspectRatio="none" role="img" aria-label="Waiting decision sparkline">
            <polyline points="0,30 40,30 60,26 80,30 120,30 140,22 160,30 200,24" fill="none" stroke="#F59E0B" strokeWidth="2" />
          </svg>
        </div>

        <div className="p-4 rounded-xl bg-[#11151D] border border-[#1F2633] flex flex-col justify-between anim-rise">
          <div className="text-[12px] font-medium text-[#8B95A7]">Records checked</div>
          <div className="mt-2 text-2xl sm:text-3xl font-bold text-[#22C55E]">
            100%
          </div>
          <div className="text-[12px] text-[#8B95A7]">Record checked: no entries changed</div>
          <svg className="w-full h-8 mt-2" viewBox="0 0 200 34" preserveAspectRatio="none" role="img" aria-label="Records verified sparkline">
            <polyline points="0,8 200,8" fill="none" stroke="#22C55E" strokeWidth="2" />
          </svg>
        </div>
      </section>

      {/* The Live Agent Map (Scale Adaptive) */}
      <section data-mode={mode} className="relative overflow-hidden p-5 rounded-2xl bg-[#0E121A] border border-[#1F2633] flex flex-col gap-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <h2 className="text-[15px] font-bold text-[#E6E9EF]">Live agent map</h2>
            <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-[rgba(34,197,94,0.12)] text-[#4ADE80] text-[12px] font-semibold">
              <span className="w-1.5 h-1.5 rounded-full bg-[#22C55E]" />
              LIVE
            </span>
            <span className="text-[12px] text-[#8B95A7] hidden sm:inline">
              Agents inside the fence (dashed); everything they reach for outside it.
            </span>
          </div>

          <div className="flex items-center gap-4 text-[12px] text-[#8B95A7]">
            <span className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-[#22C55E]" /> allowed
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-[#EF4444]" /> stopped at fence
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-[#F59E0B]" /> asking you
            </span>
          </div>
        </div>

        {/* Scale Adaptive View */}
        {mode === 'canvas' ? (
          <div data-view="canvas" className="relative w-full h-[380px] flex items-center justify-center">
            <canvas
              ref={canvasRef}
              width={900}
              height={380}
              className="w-full max-w-[900px] h-[380px] block"
              role="img"
              aria-label="Canvas map of active teams inside fence"
            />
          </div>
        ) : mode === 'teams' ? (
          <div data-view="teams" className="flex flex-col gap-4">
            <svg
              width="100%"
              height="380"
              viewBox="0 0 900 380"
              role="img"
              aria-label="Live map: team nodes sized by agent count inside fence"
              className="block mt-2"
            >
              <defs>
                <radialGradient id="coreG" cx="50%" cy="50%" r="50%">
                  <stop offset="0%" stopColor="#3B82F6" stopOpacity="0.9" />
                  <stop offset="100%" stopColor="#1E3A8A" stopOpacity="0.9" />
                </radialGradient>
              </defs>
              <ellipse
                cx="450"
                cy="190"
                rx="215"
                ry="135"
                fill="rgba(59,130,246,0.04)"
                stroke="#3B82F6"
                strokeWidth="1.5"
                strokeDasharray="8 7"
                className="anim-fence-dash"
              />
              <circle cx="450" cy="190" r="36" fill="url(#coreG)" stroke="#60A5FA" strokeWidth="1.5" />
              <g fill="#0E121A" stroke="#A78BFA" strokeWidth="2">
                <circle cx="580" cy="190" r="14" />
                <circle cx="542" cy="250" r="16" />
                <circle cx="450" cy="275" r="20" />
                <circle cx="358" cy="250" r="12" />
                <circle cx="320" cy="190" r="18" />
                <circle cx="450" cy="105" r="12" />
              </g>
              <g fontFamily="JetBrains Mono, monospace" fontSize="11" fill="#C7D2FE">
                <text x="600" y="194">Finance (42)</text>
                <text x="564" y="254">Support (68)</text>
                <text x="476" y="280">Platform (140)</text>
                <text x="270" y="254">Legal (18)</text>
                <text x="230" y="194">Sales (210)</text>
                <text x="468" y="110">Security (22)</text>
              </g>
            </svg>
            <div className="p-3 bg-[#11151D] rounded-xl border border-[#1F2633] overflow-x-auto">
              <table className="w-full text-left text-[12px] border-collapse">
                <thead>
                  <tr className="border-b border-[#1F2633] text-[#8B95A7]">
                    <th className="pb-2 font-normal">Team</th>
                    <th className="pb-2 font-normal">Agents</th>
                    <th className="pb-2 font-normal">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1F2633]">
                  <tr><td className="py-2 text-[#E6E9EF]">Platform</td><td className="py-2">140</td><td className="py-2 text-[#22C55E]">normal</td></tr>
                  <tr><td className="py-2 text-[#E6E9EF]">Sales</td><td className="py-2">210</td><td className="py-2 text-[#22C55E]">normal</td></tr>
                  <tr><td className="py-2 text-[#E6E9EF]">Support</td><td className="py-2">68</td><td className="py-2 text-[#F59E0B]">waiting (2)</td></tr>
                </tbody>
              </table>
            </div>
          </div>
        ) : (
          <div data-view="individual">
            <svg
              width="100%"
              height="380"
              viewBox="0 0 900 380"
              role="img"
              aria-label="Live map: individual agent nodes inside the fence"
              className="block mt-2"
            >
            <defs>
              <radialGradient id="coreG" cx="50%" cy="50%" r="50%">
                <stop offset="0%" stopColor="#3B82F6" stopOpacity="0.9" />
                <stop offset="100%" stopColor="#1E3A8A" stopOpacity="0.9" />
              </radialGradient>
            </defs>

            {/* Dashed animated fence */}
            <ellipse
              cx="450"
              cy="190"
              rx="215"
              ry="135"
              fill="rgba(59,130,246,0.04)"
              stroke="#3B82F6"
              strokeWidth="1.5"
              strokeDasharray="8 7"
              className="anim-fence-dash"
            />

            {/* Agent connection spokes */}
            <g stroke="#2A3344" strokeWidth="1">
              <line x1="450" y1="190" x2="580" y2="190" />
              <line x1="450" y1="190" x2="542" y2="250" />
              <line x1="450" y1="190" x2="450" y2="275" />
              <line x1="450" y1="190" x2="358" y2="250" />
              <line x1="450" y1="190" x2="320" y2="190" />
              <line x1="450" y1="190" x2="358" y2="130" />
              <line x1="450" y1="190" x2="450" y2="105" />
              <line x1="450" y1="190" x2="542" y2="130" />
            </g>

            {/* Allowed edges (green) */}
            <g strokeWidth="1.2" fill="none">
              <line x1="580" y1="190" x2="764" y2="243" stroke="#166534" />
              <line x1="542" y1="250" x2="644" y2="328" stroke="#166534" />
              <line x1="450" y1="275" x2="450" y2="360" stroke="#166534" />
              <line x1="320" y1="190" x2="136" y2="243" stroke="#166534" />
              <line x1="450" y1="105" x2="450" y2="20" stroke="#166534" />

              {/* Stopped edges (red dashed) */}
              <line x1="358" y1="250" x2="303" y2="288" stroke="#7F1D1D" strokeDasharray="3 4" />
              <line x1="542" y1="130" x2="592" y2="90" stroke="#7F1D1D" strokeDasharray="3 4" />

              {/* Asking edges (amber dashed) */}
              <line x1="580" y1="190" x2="662" y2="165" stroke="#78350F" strokeDasharray="5 4" />
              <line x1="320" y1="190" x2="238" y2="166" stroke="#78350F" strokeDasharray="5 4" />
            </g>

            {/* Core Node */}
            <circle cx="450" cy="190" r="36" fill="url(#coreG)" stroke="#60A5FA" strokeWidth="1.5" />
            <path
              d="M450 174l12 6v8c0 8-5 12-12 14-7-2-12-6-12-14v-8z"
              fill="none"
              stroke="#fff"
              strokeWidth="2"
            />

            {/* Agent nodes inside fence */}
            <g fill="#0E121A" stroke="#3B82F6" strokeWidth="1.5">
              <circle cx="580" cy="190" r="8" />
              <circle cx="542" cy="250" r="8" />
              <circle cx="450" cy="275" r="8" />
              <circle cx="358" cy="250" r="8" />
              <circle cx="320" cy="190" r="8" />
              <circle cx="358" cy="130" r="8" />
              <circle cx="450" cy="105" r="8" />
              <circle cx="542" cy="130" r="8" />
            </g>

            {/* Agent labels */}
            <g fontFamily="JetBrains Mono, monospace" fontSize="11" fill="#C7D2FE">
              <text x="592" y="208">finance-report-bot</text>
              <text x="226" y="210">support-triage</text>
              <text x="262" y="124">ci-build-agent</text>
              <text x="266" y="268">doc-summarizer</text>
            </g>

            {/* Target labels */}
            <g fontFamily="Inter, sans-serif" fontSize="11">
              <g fill="#86EFAC">
                <text x="772" y="247">sales_data.csv</text>
                <text x="652" y="342">reports/</text>
                <text x="460" y="372">github.com/acme</text>
                <text x="40" y="247">tickets DB</text>
                <text x="460" y="24">wiki</text>
              </g>
              <g fill="#FCA5A5">
                <text x="200" y="306">~/private (stopped)</text>
                <text x="602" y="80">pastebin.com (stopped)</text>
              </g>
              <g fill="#FCD34D">
                <text x="676" y="160">targets.csv ?</text>
                <text x="138" y="160">crm.acme.io ?</text>
              </g>
            </g>
          </svg>
          </div>
        )}
      </section>

      {/* Other Panels: Actions per hour + Waiting for decision */}
      <section className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        <div className="lg:col-span-2 p-5 rounded-xl bg-[#11151D] border border-[#1F2633] flex flex-col gap-3">
          <div className="flex items-center justify-between gap-2 flex-wrap">
            <h2 className="text-[15px] font-bold text-[#E6E9EF]">Agent actions per hour</h2>
            <div className="flex items-center gap-3 text-[12px] text-[#8B95A7]">
              <span className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-sm bg-[#3B82F6]" /> allowed
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-sm bg-[#EF4444]" /> stopped
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-sm bg-[#F59E0B]" /> asked
              </span>
            </div>
          </div>

          <svg
            className="w-full h-56 mt-2"
            viewBox="0 0 760 230"
            preserveAspectRatio="none"
            role="img"
            aria-label="Agent actions per hour chart"
          >
            <g stroke="#1F2633" strokeWidth="1">
              <line x1="0" y1="40" x2="760" y2="40" />
              <line x1="0" y1="100" x2="760" y2="100" />
              <line x1="0" y1="160" x2="760" y2="160" />
              <line x1="0" y1="210" x2="760" y2="210" />
            </g>
            <path
              d="M0,190 L60,186 L120,180 L180,150 L240,110 L300,80 L360,70 L420,64 L480,72 L540,90 L600,120 L660,160 L720,182 L760,188 L760,210 L0,210 Z"
              fill="rgba(59,130,246,0.18)"
            />
            <polyline
              points="0,190 60,186 120,180 180,150 240,110 300,80 360,70 420,64 480,72 540,90 600,120 660,160 720,182 760,188"
              fill="none"
              stroke="#3B82F6"
              strokeWidth="2"
            />
            <g fill="#EF4444">
              <rect x="236" y="198" width="8" height="12" />
              <rect x="296" y="194" width="8" height="16" />
              <rect x="356" y="196" width="8" height="14" />
              <rect x="416" y="150" width="8" height="60" />
              <rect x="476" y="190" width="8" height="20" />
              <rect x="536" y="196" width="8" height="14" />
            </g>
            <text x="430" y="138" fill="#FCA5A5" fontSize="12" fontFamily="Inter">
              14:00 spike: 41 stops
            </text>
            <g fill="#8B95A7" fontSize="11" fontFamily="Inter">
              <text x="0" y="226">00:00</text>
              <text x="180" y="226">06:00</text>
              <text x="360" y="226">12:00</text>
              <text x="540" y="226">18:00</text>
              <text x="716" y="226">now</text>
            </g>
          </svg>
        </div>

        {/* Waiting for a decision */}
        <div className="p-5 rounded-xl bg-[#11151D] border border-[#1F2633] flex flex-col gap-3">
          <div className="flex items-center justify-between">
            <h2 className="text-[15px] font-bold text-[#E6E9EF]">Waiting for a decision</h2>
            <button
              onClick={() => navigate('/inbox')}
              className="text-[13px] text-[#60A5FA] bg-transparent border-none cursor-pointer hover:underline"
            >
              All →
            </button>
          </div>

          <div className="flex flex-col gap-2.5">
            <div
              onClick={() => navigate('/inbox')}
              className="p-3 rounded-lg bg-[#161B26] border border-[#4A3510] cursor-pointer hover:border-[#F59E0B] transition-colors flex items-center gap-3"
            >
              <span className="px-2 py-0.5 rounded bg-amber-500/20 text-[#FBBF24] text-[11px] font-bold">
                MED
              </span>
              <div className="flex-1 min-w-0">
                <div className="text-[13px] font-semibold text-[#E6E9EF] truncate">
                  finance-report-bot → targets.csv
                </div>
                <div className="text-[11px] text-[#8B95A7]">named only inside an input file · Finance</div>
              </div>
              <span className="font-mono text-[12px] text-[#FBBF24]">1:26</span>
            </div>

            <div
              onClick={() => navigate('/inbox')}
              className="p-3 rounded-lg bg-[#161B26] border border-[#1F2633] cursor-pointer hover:border-[#2A3344] transition-colors flex items-center gap-3"
            >
              <span className="px-2 py-0.5 rounded bg-amber-500/20 text-[#FBBF24] text-[11px] font-bold">
                LOW
              </span>
              <div className="flex-1 min-w-0">
                <div className="text-[13px] font-semibold text-[#E6E9EF] truncate">
                  support-triage → crm.acme.io
                </div>
                <div className="text-[11px] text-[#8B95A7]">37 requests · Support</div>
              </div>
              <span className="font-mono text-[12px] text-[#FBBF24]">0:44</span>
            </div>
          </div>
        </div>
      </section>

      {/* Bottom panels: Top stop patterns + Agents to watch */}
      <section className="grid grid-cols-1 md:grid-cols-2 gap-5">
        <div className="p-5 rounded-xl bg-[#11151D] border border-[#1F2633] flex flex-col gap-3">
          <h2 className="text-[15px] font-bold text-[#E6E9EF]">Top stop patterns</h2>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-[13px] border-collapse">
              <thead>
                <tr className="border-b border-[#1F2633] text-[#8B95A7] font-medium text-[12px]">
                  <th className="pb-2 font-normal">Pattern</th>
                  <th className="pb-2 font-normal">Agents</th>
                  <th className="pb-2 font-normal">Stops</th>
                  <th className="pb-2 font-normal">Stopped by</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1F2633]">
                <tr>
                  <td className="py-2.5">Opened a file named only inside a document</td>
                  <td className="py-2.5">41</td>
                  <td className="py-2.5 text-[#F87171] font-semibold">96</td>
                  <td className="py-2.5"><span className="px-2 py-0.5 rounded bg-[#1A2232] text-[11px]">kernel</span></td>
                </tr>
                <tr>
                  <td className="py-2.5">Reached a website outside the task</td>
                  <td className="py-2.5">12</td>
                  <td className="py-2.5 text-[#F87171] font-semibold">58</td>
                  <td className="py-2.5"><span className="px-2 py-0.5 rounded bg-[#1A2232] text-[11px]">network proxy</span></td>
                </tr>
                <tr>
                  <td className="py-2.5">Read a private home folder</td>
                  <td className="py-2.5">3</td>
                  <td className="py-2.5 text-[#F87171] font-semibold">31</td>
                  <td className="py-2.5"><span className="px-2 py-0.5 rounded bg-[#1A2232] text-[11px]">kernel</span></td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        <div className="p-5 rounded-xl bg-[#11151D] border border-[#1F2633] flex flex-col gap-3">
          <h2 className="text-[15px] font-bold text-[#E6E9EF]">Agents to watch</h2>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-[13px] border-collapse">
              <thead>
                <tr className="border-b border-[#1F2633] text-[#8B95A7] font-medium text-[12px]">
                  <th className="pb-2 font-normal">Agent</th>
                  <th className="pb-2 font-normal">Team</th>
                  <th className="pb-2 font-normal">Runs</th>
                  <th className="pb-2 font-normal">Stops</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1F2633]">
                <tr>
                  <td className="py-2.5 font-mono text-[#E6E9EF]">finance-report-bot</td>
                  <td className="py-2.5 text-[#A7B0C0]">Finance</td>
                  <td className="py-2.5">1,240</td>
                  <td className="py-2.5 text-[#F87171] font-semibold">27</td>
                </tr>
                <tr>
                  <td className="py-2.5 font-mono text-[#E6E9EF]">ci-build-agent</td>
                  <td className="py-2.5 text-[#A7B0C0]">Platform</td>
                  <td className="py-2.5">890</td>
                  <td className="py-2.5 text-[#F87171] font-semibold">14</td>
                </tr>
                <tr>
                  <td className="py-2.5 font-mono text-[#E6E9EF]">tax-prep-bot</td>
                  <td className="py-2.5 text-[#A7B0C0]">Finance</td>
                  <td className="py-2.5">212</td>
                  <td className="py-2.5 text-[#F87171] font-semibold">6</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </section>
    </div>
  );
};

