import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { Search, Filter, ShieldCheck, ShieldAlert, ArrowRight, Clock, RefreshCw } from 'lucide-react';
import { api } from '../api/client';
import { TaskRecord, TaskLifecycle } from '../types';
import { Badge } from '../components/common/Badge';
import { EmptyState } from '../components/common/EmptyState';

export const TasksPage: React.FC = () => {
  const [tasks, setTasks] = useState<TaskRecord[]>([]);
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  const fetchTasks = async () => {
    try {
      const data = await api.getTasks();
      setTasks(data);
    } catch (err) {
      console.error('Failed to load tasks', err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    fetchTasks();
  }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    fetchTasks();
  };

  const filteredTasks = tasks.filter(t => {
    const matchesSearch =
      t.task_id.toLowerCase().includes(search.toLowerCase()) ||
      t.request_text.toLowerCase().includes(search.toLowerCase()) ||
      t.agent_id.toLowerCase().includes(search.toLowerCase());
    const matchesStatus = statusFilter === 'ALL' || t.status === statusFilter;
    return matchesSearch && matchesStatus;
  });

  const getStatusBadge = (status: TaskLifecycle) => {
    switch (status) {
      case 'ACTIVE':
      case 'RUNNING':
        return <Badge variant="cyan">{status}</Badge>;
      case 'COMPLETED':
        return <Badge variant="allowed">{status}</Badge>;
      case 'FROZEN':
        return <Badge variant="frozen">{status}</Badge>;
      case 'FAILED':
      case 'TERMINATED':
        return <Badge variant="blocked">{status}</Badge>;
      default:
        return <Badge variant="neutral">{status}</Badge>;
    }
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-300">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-white">
            Governed Tasks
          </h1>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
            Real-time inspection of active and completed agent tasks, derived boundaries, and compliance.
          </p>
        </div>

        <button
          onClick={handleRefresh}
          disabled={refreshing}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-200 bg-white dark:bg-surface-cardDark border border-slate-200 dark:border-slate-800 rounded-xl hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors self-start sm:self-auto"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
          <span>Refresh</span>
        </button>
      </div>

      {/* Filters Bar */}
      <div className="flex flex-col sm:flex-row gap-3">
        <div className="relative flex-1">
          <Search className="w-4 h-4 absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-400" />
          <input
            type="text"
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search by Task ID, prompt text, or agent..."
            className="w-full pl-9 pr-4 py-2 text-xs bg-white dark:bg-surface-cardDark border border-slate-200 dark:border-slate-800 rounded-xl focus:outline-none focus:border-cyan-500 text-slate-900 dark:text-slate-100 placeholder:text-slate-400"
          />
        </div>

        <div className="flex items-center gap-1.5 overflow-x-auto pb-1 sm:pb-0">
          {['ALL', 'ACTIVE', 'COMPLETED', 'FROZEN', 'FAILED'].map(st => (
            <button
              key={st}
              onClick={() => setStatusFilter(st)}
              className={`px-3 py-2 text-xs font-medium rounded-xl whitespace-nowrap transition-colors ${
                statusFilter === st
                  ? 'bg-cyan-500/10 text-cyan-600 dark:text-cyan-400 border border-cyan-500/30'
                  : 'bg-white dark:bg-surface-cardDark text-slate-600 dark:text-slate-400 border border-slate-200 dark:border-slate-800 hover:bg-slate-50 dark:hover:bg-slate-800/60'
              }`}
            >
              {st}
            </button>
          ))}
        </div>
      </div>

      {/* Tasks Table / Card List */}
      {filteredTasks.length === 0 ? (
        <EmptyState
          icon="inbox"
          title="No Governed Tasks Found"
          description={
            search || statusFilter !== 'ALL'
              ? 'No tasks match your current filter parameters. Try clearing the search or status filter.'
              : 'No tasks have been launched yet. Launch an agent task using launcher.py to view live execution here.'
          }
        />
      ) : (
        <div className="space-y-3">
          {filteredTasks.map(t => (
            <Link
              key={t.task_id}
              to={`/tasks/${t.task_id}`}
              className="block p-5 rounded-2xl bg-white dark:bg-surface-cardDark border border-slate-200 dark:border-slate-800/80 hover:border-cyan-500/50 dark:hover:border-cyan-500/50 hover:shadow-md transition-all group"
            >
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div className="space-y-1.5 flex-1 min-w-0">
                  <div className="flex items-center gap-2.5 flex-wrap">
                    <span className="font-mono text-xs font-bold text-slate-900 dark:text-slate-100 group-hover:text-cyan-500 transition-colors">
                      {t.task_id}
                    </span>
                    {getStatusBadge(t.status)}
                    <span className="text-xs font-mono text-slate-400 bg-slate-100 dark:bg-slate-800/60 px-2 py-0.5 rounded-md">
                      agent: {t.agent_id}
                    </span>
                    {(t.agent_id.includes('demo') || t.agent_id.includes('slice') || t.agent_id.includes('scripted')) && (
                      <span className="text-[11px] font-medium px-2 py-0.5 rounded-full bg-indigo-500/10 text-indigo-600 dark:text-indigo-400 border border-indigo-500/30">
                        Scripted demo
                      </span>
                    )}
                  </div>

                  <p className="text-sm font-medium text-slate-700 dark:text-slate-300 truncate">
                    {t.request_text}
                  </p>

                  <div className="flex items-center gap-4 text-xs text-slate-400 font-mono">
                    <span>Created: {new Date(t.created_at).toLocaleString()}</span>
                    <span>Workspace: {t.workspace_root}</span>
                  </div>
                </div>

                <div className="flex items-center gap-6 self-end md:self-center shrink-0">
                  {/* Compliance & Actions */}
                  <div className="text-right">
                    <div className="flex items-center gap-1.5 justify-end">
                      <span className="text-xs text-slate-400 font-mono">Compliance:</span>
                      <span
                        className={`text-xs font-mono font-bold ${
                          t.compliance_pct === 100
                            ? 'text-emerald-500'
                            : t.compliance_pct >= 80
                            ? 'text-amber-500'
                            : 'text-rose-500'
                        }`}
                      >
                        {t.compliance_pct}%
                      </span>
                    </div>
                    <div className="text-[11px] text-slate-400 font-mono mt-0.5">
                      {t.total_actions} actions ({t.actions_inside} allowed
                      {t.prevented_count > 0 && (
                        <span className="text-rose-500 font-bold ml-1">
                          · {t.prevented_count} blocked
                        </span>
                      )}
                      )
                    </div>
                  </div>

                  <div className="w-8 h-8 rounded-full bg-slate-100 dark:bg-slate-800 flex items-center justify-center text-slate-400 group-hover:text-cyan-500 group-hover:bg-cyan-500/10 transition-colors">
                    <ArrowRight className="w-4 h-4" />
                  </div>
                </div>
              </div>
            </Link>
          ))}
        </div>
      )}
    </div>
  );
};
