import React, { useEffect, useState, useRef } from 'react';
import { Activity, ShieldAlert, ShieldCheck, Filter, Search, Radio, User, Layers } from 'lucide-react';
import { api } from '../api/client';
import { TaskEvent } from '../types';
import { Badge } from '../components/common/Badge';
import { EmptyState } from '../components/common/EmptyState';
import { AnimatedListFeed } from '../components/reactbits/AnimatedListFeed';

export const ActivityPage: React.FC = () => {
  const [events, setEvents] = useState<TaskEvent[]>([]);
  const [cursor, setCursor] = useState<string | null>(null);
  const [layerFilter, setLayerFilter] = useState('ALL');
  const [verdictFilter, setVerdictFilter] = useState('ALL');
  const [agentFilter, setAgentFilter] = useState('ALL');
  const [search, setSearch] = useState('');
  const [initialLoading, setInitialLoading] = useState(true);

  const cursorRef = useRef<string | null>(null);
  cursorRef.current = cursor;

  const fetchEventsStream = async () => {
    try {
      const data = await api.getEvents(cursorRef.current || undefined, 100);
      if (data && data.events && data.events.length > 0) {
        setEvents(prev => {
          const map = new Map<string, TaskEvent>();
          // New events from poll
          for (const ev of data.events) {
            const id = ev.event_id || `${ev.timestamp}_${ev.task_id}_${ev.target}_${ev.kind}`;
            map.set(id, ev);
          }
          // Prior events
          for (const ev of prev) {
            const id = ev.event_id || `${ev.timestamp}_${ev.task_id}_${ev.target}_${ev.kind}`;
            if (!map.has(id)) {
              map.set(id, ev);
            }
          }
          const merged = Array.from(map.values());
          // Ensure strictly newest order
          merged.sort((a, b) => (b.timestamp || '').localeCompare(a.timestamp || ''));
          return merged;
        });
        if (data.cursor) {
          setCursor(data.cursor);
        }
      }
    } catch (err) {
      console.error('Failed to fetch events stream', err);
    } finally {
      setInitialLoading(false);
    }
  };

  useEffect(() => {
    fetchEventsStream();
    // Poll every 3 seconds with since cursor
    const interval = setInterval(fetchEventsStream, 3000);
    return () => clearInterval(interval);
  }, []);

  const getLayer = (ev: TaskEvent) => {
    const src = (ev.source || '').toLowerCase();
    const ch = (ev.channel || '').toLowerCase();
    if (src.includes('proxy') || ch.includes('proxy')) return 'PROXY';
    if (src.includes('sensor') || src.includes('os') || ch.includes('shell') || ev.prevented_by === 'landlock' || ev.prevented_by === 'seccomp') return 'OS';
    return 'BROKER';
  };

  // Extract distinct agents for filter
  const distinctAgents = Array.from(new Set(events.map(e => e.agent_id).filter((a): a is string => Boolean(a))));

  const filtered = events.filter(e => {
    const layer = getLayer(e);
    const matchesLayer = layerFilter === 'ALL' || layer === layerFilter;
    const matchesVerdict = verdictFilter === 'ALL' || e.verdict === verdictFilter;
    const matchesAgent = agentFilter === 'ALL' || e.agent_id === agentFilter;
    const matchesSearch =
      !search ||
      (e.target || '').toLowerCase().includes(search.toLowerCase()) ||
      (e.kind || '').toLowerCase().includes(search.toLowerCase()) ||
      (e.task_id || '').toLowerCase().includes(search.toLowerCase()) ||
      (e.agent_id || '').toLowerCase().includes(search.toLowerCase());
    return matchesLayer && matchesVerdict && matchesAgent && matchesSearch;
  });

  return (
    <div className="space-y-6 animate-in fade-in duration-300">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-white">
              Live Event Activity
            </h1>
            <span className="flex items-center gap-1 px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-500 font-mono text-[10px] font-bold">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-ping" />
              STREAMING (cursor poll)
            </span>
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
            Real-time multi-layer audit stream across tool broker, Landlock OS layer, and egress proxy with cursor deduplication.
          </p>
        </div>
        <div className="font-mono text-xs text-slate-400">
          Total Captured: <span className="font-bold text-slate-700 dark:text-slate-200">{events.length}</span>
        </div>
      </div>

      {/* Filter Toolbar */}
      <div className="space-y-3">
        <div className="relative flex-1">
          <Search className="w-4 h-4 absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-400" />
          <input
            type="text"
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search by target path, tool, agent, or task ID..."
            className="w-full pl-9 pr-4 py-2 text-xs bg-white dark:bg-surface-cardDark border border-slate-200 dark:border-slate-800 rounded-xl focus:outline-none focus:border-cyan-500 text-slate-900 dark:text-slate-100 placeholder:text-slate-400"
          />
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {/* Layer Filter */}
          <div className="flex items-center gap-1 overflow-x-auto">
            {['ALL', 'BROKER', 'OS', 'PROXY'].map(l => (
              <button
                key={l}
                onClick={() => setLayerFilter(l)}
                className={`px-2.5 py-1 text-xs font-medium rounded-lg whitespace-nowrap transition-colors ${
                  layerFilter === l
                    ? 'bg-cyan-500/10 text-cyan-600 dark:text-cyan-400 border border-cyan-500/30'
                    : 'bg-white dark:bg-surface-cardDark text-slate-600 dark:text-slate-400 border border-slate-200 dark:border-slate-800'
                }`}
              >
                {l === 'ALL' ? 'All Layers' : l}
              </button>
            ))}
          </div>

          <div className="h-4 w-px bg-slate-200 dark:bg-slate-800 hidden sm:block" />

          {/* Verdict Filter */}
          <div className="flex items-center gap-1">
            {['ALL', 'INSIDE', 'OUTSIDE'].map(v => (
              <button
                key={v}
                onClick={() => setVerdictFilter(v)}
                className={`px-2.5 py-1 text-xs font-medium rounded-lg whitespace-nowrap transition-colors ${
                  verdictFilter === v
                    ? 'bg-indigo-500/10 text-indigo-600 dark:text-indigo-400 border border-indigo-500/30'
                    : 'bg-white dark:bg-surface-cardDark text-slate-600 dark:text-slate-400 border border-slate-200 dark:border-slate-800'
                }`}
              >
                {v === 'ALL' ? 'All Verdicts' : v}
              </button>
            ))}
          </div>

          <div className="h-4 w-px bg-slate-200 dark:bg-slate-800 hidden sm:block" />

          {/* Agent Filter */}
          {distinctAgents.length > 1 && (
            <div className="flex items-center gap-1">
              <span className="text-[11px] font-mono text-slate-400 mr-1">Agent:</span>
              <button
                onClick={() => setAgentFilter('ALL')}
                className={`px-2 py-1 text-xs font-mono rounded-lg transition-colors ${
                  agentFilter === 'ALL'
                    ? 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border border-amber-500/30'
                    : 'bg-white dark:bg-surface-cardDark text-slate-600 dark:text-slate-400 border border-slate-200 dark:border-slate-800'
                }`}
              >
                All
              </button>
              {distinctAgents.slice(0, 4).map(ag => (
                <button
                  key={ag}
                  onClick={() => setAgentFilter(ag)}
                  className={`px-2 py-1 text-xs font-mono rounded-lg transition-colors ${
                    agentFilter === ag
                      ? 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border border-amber-500/30'
                      : 'bg-white dark:bg-surface-cardDark text-slate-600 dark:text-slate-400 border border-slate-200 dark:border-slate-800'
                  }`}
                >
                  {ag}
                </button>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Events List */}
      {filtered.length === 0 ? (
        <EmptyState
          icon="search"
          title="No Matching Events"
          description="No telemetry events match your selected filters."
        />
      ) : (
        <AnimatedListFeed className="space-y-2.5">
          {filtered.map((ev, i) => {
            const isBlocked = ev.verdict === 'OUTSIDE' || ev.prevented;
            const isApproval = ev.kind === 'request_access' || ev.action_taken === 'EXPAND' || (ev.details && ev.details.expansion_requested);
            const keyId = ev.event_id || `${ev.timestamp}_${i}`;

            return (
              <div
                key={keyId}
                id={`activity-event-${ev.event_id || i}`}
                className={`p-3.5 rounded-xl border transition-all ${
                  isBlocked
                    ? 'border-rose-500/80 bg-rose-500/10 dark:bg-rose-950/40 shadow-[0_0_12px_rgba(244,63,94,0.2)] animate-pulse'
                    : isApproval
                    ? 'border-amber-500/80 bg-amber-500/10 dark:bg-amber-950/40 shadow-[0_0_12px_rgba(245,158,11,0.2)] animate-pulse'
                    : 'border-slate-200 dark:border-slate-800 bg-white dark:bg-surface-cardDark hover:border-slate-300 dark:hover:border-slate-700'
                }`}
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="flex items-center gap-2.5 flex-wrap">
                    <Badge variant={ev.verdict === 'INSIDE' ? 'allowed' : 'blocked'} size="sm">
                      {ev.verdict}
                    </Badge>
                    <span className="font-mono text-xs font-bold text-slate-900 dark:text-slate-100">
                      {ev.kind}
                    </span>
                    <span className="text-[11px] font-mono text-slate-400 px-2 py-0.5 rounded bg-slate-100 dark:bg-slate-800">
                      layer: {getLayer(ev)}
                    </span>
                    {ev.target && (
                      <span className="text-xs font-mono text-slate-700 dark:text-slate-300 truncate max-w-sm">
                        {ev.target}
                      </span>
                    )}
                    {ev.agent_id && (
                      <span className="text-[11px] font-mono text-slate-500">
                        ({ev.agent_id})
                      </span>
                    )}
                  </div>

                  <div className="flex items-center gap-3 text-xs font-mono text-slate-400">
                    {ev.prevented_by && ev.prevented_by !== 'none' && (
                      <span className="text-rose-500 font-bold">
                        BLOCKED BY {ev.prevented_by.toUpperCase()}
                      </span>
                    )}
                    <span>{new Date(ev.timestamp).toLocaleTimeString()}</span>
                  </div>
                </div>
              </div>
            );
          })}
        </AnimatedListFeed>
      )}
    </div>
  );
};
