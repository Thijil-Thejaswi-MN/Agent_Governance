// Approval card: plain wording for the preview and the four decisions. No I/O.

export type ApprovalScope = 'once' | 'run' | 'always';

export interface ExpansionPreview {
  request_id: string;
  kind: 'file' | 'address' | 'agent' | 'other';
  name: string;
  folder: string | null;
  size_bytes: number | null;
  exists: boolean | null;
  inside_workspace: boolean | null;
  risk_tier: 'LOW' | 'MEDIUM' | 'HIGH' | string;
  escalated: boolean;
  learned_from: string | null;
  rule_possible: boolean;
  once_possible?: boolean;
  once_blocked_by?: string | null;
}

export function formatBytes(n: number | null | undefined): string | null {
  if (n == null || !Number.isFinite(n) || n < 0) return null;
  if (n < 1024) return `${n} ${n === 1 ? 'byte' : 'bytes'}`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(n < 10 * 1024 ? 1 : 0)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

/** The facts line under the file name: "in docs · 1.2 KB", "in docs · size unknown". */
export function previewFacts(p: Pick<ExpansionPreview, 'kind' | 'folder' | 'size_bytes' | 'exists' | 'inside_workspace'>): string[] {
  const out: string[] = [];
  if (p.kind === 'file') {
    out.push(p.folder ? `in ${p.folder}` : 'in the task folder');
    if (p.inside_workspace === false) out.push('outside the task folder, size unknown');
    else if (p.exists === false) out.push('not found in the task folder');
    else out.push(formatBytes(p.size_bytes) ?? 'size unknown');
  } else if (p.kind === 'address') {
    out.push('a network address');
  } else if (p.kind === 'agent') {
    out.push('another agent');
  }
  return out;
}

const TIER: Record<string, { label: string; hint: string }> = {
  LOW: { label: 'Low risk', hint: 'An ordinary input file.' },
  MEDIUM: { label: 'Medium risk', hint: 'Outside what the request named, so a person decides.' },
  HIGH: { label: 'High risk', hint: 'Sensitive or outside the task folder.' },
};

export function riskLabel(tier: string | null | undefined): { label: string; hint: string } {
  return TIER[(tier || '').toUpperCase()] ?? { label: 'Risk unknown', hint: '' };
}

/** Why "Always for this agent" is unavailable, or null when it can be used. */
export function alwaysBlockedReason(opts: { canManageRules: boolean; rulePossible: boolean | null }): string | null {
  if (opts.rulePossible === false)
    return 'A rule can’t cover this one: requests prompted by a file the agent read, and high-risk requests, always go to a person.';
  if (!opts.canManageRules) return 'Only a security reviewer or an admin can make a standing rule.';
  return null;
}

export const SCOPE_REASON: Record<ApprovalScope, string> = {
  once: 'Allowed once in the console',
  run: 'Allowed for this run in the console',
  always: 'Allowed for this run; a standing rule now covers it for this agent',
};

export const ONCE_HOVER = 'The copy is removed after the agent’s first read (detected by the monitor).';

/** Why "Allow once" is unavailable, or null when it can be used. */
export function onceBlockedReason(p: Pick<ExpansionPreview, 'once_possible' | 'once_blocked_by'> | null): string | null {
  if (!p || p.once_possible !== false) return null;
  const what = p.once_blocked_by ? p.once_blocked_by.split('/').pop() : 'another file';
  return `Allow once is off: the one-time grant for ${what} in this run hasn’t been used yet, and only one can be tracked at a time.`;
}
