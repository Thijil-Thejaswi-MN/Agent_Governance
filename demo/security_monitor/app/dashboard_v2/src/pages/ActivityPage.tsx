import React, { useEffect, useState } from 'react';
import { Activity, ShieldAlert, ShieldCheck, Filter, Search, Radio } from 'lucide-react';
import { api } from '../api/client';
import { TaskEvent } from '../types';
import { Badge } from '../components/common/Badge';
import { EmptyState } from '../components/common/EmptyState';
import { AnimatedListFeed } from '../components/reactbits/AnimatedListFeed';

export const ActivityPage: React.FC = () => {
  const [events, setEvents] = useState<TaskEvent[]>([]);
  const [layerFilter, setLayerFilter] = useState('ALL');
  const [verdictFilter, setVerdictFilter] = useState('ALL');
  const [search, setSearch] = useState('');

  const fetchLiveEvents = async () => {
    try {
      const tasks = await api.getTasks();
      const allEvents: TaskEvent[] = [];
      // Grab events from top 5 tasks
      for (const t of tasks.slice(0, 5)) {
        try {
          const evs = await api.getTaskEvents(t.task_id);
          allEvents.push(...evs);
        } catch {}
      }
      // Sort newest first
      allEvents.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
      setEvents(allEvents);
    } catch (err) {
      console.error(err);
    }
  };

  useEffect(() => {
    fetchLiveEvents();
    // Poll every 3 seconds for live streaming telemetry
    const interval = setInterval(fetchLiveEvents, 3000);
    return () => clearInterval(interval);
  }, []);

  const getLayer = (ev: TaskEvent) => {
    const src = (ev.source || '').toLowerCase();
    const ch = (ev.channel || '').toLowerCase();
    if (src.includes('proxy') || ch.includes('proxy')) return 'PROXY';
    if (src.includes('sensor') || src.includes('os') || ch.includes('shell')) return 'OS';
    return 'BROKER';
  };

  const filtered = events.filter(e => {
    const layer = getLayer(e);
    const matchesLayer = layerFilter === 'ALL' || layer === layerFilter;
    const matchesVerdict = verdictFilter === 'ALL' || e.verdict === verdictFilter;
    const matchesSearch =
      !search ||
      (e.target || '').toLowerCase().includes(search.toLowerCase()) ||
      (e.kind || '').toLowerCase().includes(search.toLowerCase()) ||
      e.task_id.toLowerCase().includes(search.toLowerCase());
    return matchesLayer && matchesVerdict && matchesSearch;
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
              POLLING (3s)
            </span>
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
            Real-time multi-layer audit stream across tool broker, Landlock OS layer, and egress proxy.
          </p>
        </div>
      </div>

      {/* Filter Toolbar */}
      <div className="flex flex-col sm:flex-row gap-3">
        <div className="relative flex-1">
          <Search className="w-4 h-4 absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-400" />
          <input
            type="text"
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search by target path, tool, or task ID..."
            className="w-full pl-9 pr-4 py-2 text-xs bg-white dark:bg-surface-cardDark border border-slate-200 dark:border-slate-800 rounded-xl focus:outline-none focus:border-cyan-500 text-slate-900 dark:text-slate-100 placeholder:text-slate-400"
          />
        </div>

        <div className="flex items-center gap-1.5 overflow-x-auto">
          {['ALL', 'BROKER', 'OS', 'PROXY'].map(l => (
            <button
              key={l}
              onClick={() => setLayerFilter(l)}
              className={`px-3 py-1.5 text-xs font-medium rounded-xl whitespace-nowrap transition-colors ${
                layerFilter === l
                  ? 'bg-cyan-500/10 text-cyan-600 dark:text-cyan-400 border border-cyan-500/30'
                  : 'bg-white dark:bg-surface-cardDark text-slate-600 dark:text-slate-400 border border-slate-200 dark:border-slate-800'
              }`}
            >
              {l === 'ALL' ? 'All Layers' : l}
            </button>
          ))}
          {['ALL', 'INSIDE', 'OUTSIDE'].map(v => (
            <button
              key={v}
              onClick={() => setVerdictFilter(v)}
              className={`px-3 py-1.5 text-xs font-medium rounded-xl whitespace-nowrap transition-colors ${
                verdictFilter === v
                  ? 'bg-indigo-500/10 text-indigo-600 dark:text-indigo-400 border border-indigo-500/30'
                  : 'bg-white dark:bg-surface-cardDark text-slate-600 dark:text-slate-400 border border-slate-200 dark:border-slate-800'
              }`}
            >
              {v === 'ALL' ? 'All Verdicts' : v}
            </button>
          ))}
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
            return (
              <div
                key={i}
                className={`p-3.5 rounded-xl border transition-all ${
                  isBlocked
                    ? 'border-rose-500/50 bg-rose-500/10 dark:bg-rose-950/30 shadow-sm animate-pulse-fast'
                    : 'border-slate-200 dark:border-slate-800 bg-white dark:bg-surface-cardDark'
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
