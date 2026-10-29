import React, { useEffect, useState } from 'react';
import { Bot, Shield, ShieldAlert, Clock, RefreshCw } from 'lucide-react';
import { api } from '../api/client';
import { AgentInventoryItem } from '../types';
import { Badge } from '../components/common/Badge';
import { EmptyState } from '../components/common/EmptyState';

export const AgentsPage: React.FC = () => {
  const [agents, setAgents] = useState<AgentInventoryItem[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchAgents = async () => {
    try {
      const data = await api.getInventory();
      setAgents(data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAgents();
  }, []);

  return (
    <div className="space-y-6 animate-in fade-in duration-300">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-white">
            Agent Inventory
          </h1>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
            Governed vs shadow agents tracked from runtime observation and declared registrations.
          </p>
        </div>
        <button
          onClick={fetchAgents}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-200 bg-white dark:bg-surface-cardDark border border-slate-200 dark:border-slate-800 rounded-xl hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Refresh</span>
        </button>
      </div>

      {agents.length === 0 ? (
        <EmptyState
          icon="inbox"
          title="No Agents Registered"
          description="No active or observed agents discovered in inventory. Agents are discovered through declared registration or observed tool broker calls."
        />
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {agents.map(a => (
            <div
              key={a.agent_id}
              className="p-5 rounded-2xl bg-white dark:bg-surface-cardDark border border-slate-200 dark:border-slate-800/80 space-y-3"
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <div className="p-2 rounded-lg bg-indigo-500/10 text-indigo-500">
                    <Bot className="w-4 h-4" />
                  </div>
                  <span className="font-mono text-sm font-bold text-slate-900 dark:text-white">
                    {a.agent_id}
                  </span>
                </div>
                <Badge variant={a.status === 'GOVERNED' ? 'allowed' : 'blocked'}>
                  {a.status}
                </Badge>
              </div>

              <div className="space-y-1 text-xs font-mono text-slate-500 dark:text-slate-400">
                <div>Role: {a.declared_role || 'General Assistant'}</div>
                <div>Active Task: {a.active_task_id || 'None'}</div>
                {a.last_seen && <div>Last Seen: {new Date(a.last_seen).toLocaleTimeString()}</div>}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
