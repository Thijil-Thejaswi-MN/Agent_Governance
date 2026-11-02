import React, { useState, useEffect } from 'react';
import { api } from '../api/client';
import { StandingRule } from '../types';
import { Sliders, Clock, Trash2, AlertCircle } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

export const StandingRulesPage: React.FC = () => {
  const { role } = useAuth();
  const [rules, setRules] = useState<StandingRule[]>([]);
  const [enabled, setEnabled] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchRules = async () => {
    try {
      const res = await api.getStandingRules();
      setRules(res.rules || []);
      setEnabled(res.enabled);
    } catch {
      // quiet on load error
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchRules();
  }, []);

  const handleExpire = async (ruleId: string) => {
    setError(null);
    try {
      await api.expireStandingRule(ruleId);
      await fetchRules();
    } catch (err: any) {
      setError(err?.message || 'Failed to expire standing rule');
    }
  };

  const canExpire = role === 'admin' || role === 'security_reviewer';

  return (
    <div className="flex flex-col gap-6 font-sans">
      <section className="anim-rise">
        <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-[#E6E9EF]">
          Standing rules
        </h1>
        <p className="text-[15px] text-[#A7B0C0] mt-1.5">
          Exact-match allowances created by reviewers to handle routine requests automatically. Never apply to
          provenance-escalated requests or high risk tiers.
        </p>
      </section>

      {!enabled && (
        <div className="p-4 rounded-xl bg-[#161B26] border border-[#2A3344] text-[13px] text-[#8B95A7] flex items-center gap-2">
          <AlertCircle className="w-4 h-4 text-[#FBBF24]" />
          <span>
            Standing rules engine is currently disabled (set GOVERNANCE_STANDING_RULES=1 to enable). Rules below
            are shown for reference.
          </span>
        </div>
      )}

      {error && (
        <div className="p-3 rounded-lg bg-[#EF4444]/15 border border-[#EF4444] text-[#F87171] text-[13px]">
          {error}
        </div>
      )}

      <div className="p-5 rounded-xl bg-[#11151D] border border-[#1F2633] flex flex-col gap-4">
        <div className="flex items-center justify-between">
          <h2 className="text-[15px] font-bold text-[#E6E9EF]">Active standing rules ({rules.length})</h2>
        </div>

        {rules.length === 0 ? (
          <div className="py-8 text-center text-[#8B95A7] text-[13px]">
            No standing rules active. Turn routine inbox patterns into rules from the Approvals inbox.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-[13px] border-collapse">
              <thead>
                <tr className="border-b border-[#1F2633] text-[#8B95A7] font-medium text-[12px]">
                  <th className="pb-2.5 font-normal">Agent</th>
                  <th className="pb-2.5 font-normal">Action</th>
                  <th className="pb-2.5 font-normal">Target</th>
                  <th className="pb-2.5 font-normal">Owner</th>
                  <th className="pb-2.5 font-normal">Expires</th>
                  {canExpire && <th className="pb-2.5 font-normal">Action</th>}
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1F2633]">
                {rules.map(r => (
                  <tr key={r.rule_id} className="hover:bg-[#161B26] transition-colors">
                    <td className="py-3 font-mono text-[#C7D2FE]">{r.agent_id}</td>
                    <td className="py-3 text-[#A7B0C0]">{r.resource_type}</td>
                    <td className="py-3 font-mono text-[#E6E9EF]">{r.normalized_target}</td>
                    <td className="py-3 text-[#A7B0C0]">{r.owner}</td>
                    <td className="py-3 text-[12px] text-[#8B95A7]">
                      {new Date(r.expires_at).toLocaleDateString()}
                    </td>
                    {canExpire && (
                      <td className="py-3">
                        <button
                          onClick={() => handleExpire(r.rule_id)}
                          className="px-2.5 py-1 rounded bg-transparent hover:bg-red-950/20 text-[#F87171] border border-[#5B2328] text-[12px] font-semibold cursor-pointer"
                        >
                          Expire now
                        </button>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};

