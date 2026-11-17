import React from 'react';
import { ExpansionItem } from '../../types';
import { fileName } from '../../logic/runView';

/** Approvals a person can still take back while the run is going (a saved write cannot be). */
export function cancellableGrants(expansions: ExpansionItem[]): ExpansionItem[] {
  const seen = new Set<string>();
  const out: ExpansionItem[] = [];
  for (const e of expansions) {
    if (e.status !== 'APPROVED' || e.resource_type === 'file_write') continue;
    if (String(e.resolved_by || '').startsWith('duplicate_of:') || String(e.resolved_by || '').startsWith('repeat_of:')) continue;
    const key = `${e.resource_type}:${e.resource_target}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(e);
  }
  return out;
}

/** The local clock time a timed grant ends, e.g. "10:42". */
export function untilTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

const KIND: Record<string, string> = { file_read: 'read a file', network: 'reach a website', peer_agent: 'talk to an agent' };

export const GrantList: React.FC<{
  grants: ExpansionItem[];
  deciding: boolean;
  onCancel: (requestId: string) => void;
}> = ({ grants, deciding, onCancel }) => {
  if (grants.length === 0) return null;
  return (
    <div id="grant-list" className="flex flex-col gap-2">
      <span className="text-[13px] font-semibold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>
        Allowed during this run
      </span>
      {grants.map(g => (
        <div key={g.request_id} className="flex items-center gap-3 rounded-xl px-3 py-2 border border-[#1F2633] bg-[#0E121A]">
          <span className="flex-1 min-w-0 text-[14px]" style={{ color: 'var(--text-2)' }}>
            <span className="mono [overflow-wrap:anywhere]" style={{ color: '#E6E9EF' }}>
              {g.resource_type === 'file_read' ? fileName(g.resource_target) : g.resource_target}
            </span>
            {` · ${KIND[g.resource_type] || 'extra access'}`}
            {g.expires_at && <span data-expires="true">{` · until ${untilTime(g.expires_at)}`}</span>}
          </span>
          <button
            id={`revoke-btn-${g.request_id}`}
            type="button"
            disabled={deciding}
            onClick={() => onCancel(g.request_id)}
            className="btn-ghost min-h-[40px] px-3 disabled:opacity-50"
            style={{ borderColor: 'rgba(239,68,68,0.5)', color: '#FCA5A5' }}
            title="Take this access back now. The agent cannot open it again in this run."
          >
            Cancel access
          </button>
        </div>
      ))}
    </div>
  );
};
