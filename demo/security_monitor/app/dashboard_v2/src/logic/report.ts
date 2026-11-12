// Task report: types and plain wording. No I/O.

export interface ReportBoundary {
  version: number;
  files_read: string[];
  files_write: string[];
  network: string[];
  tools: string[];
}

export interface ReportApproval {
  request_id: string;
  resource_type: string;
  target: string;
  status: string;
  scope: 'once' | 'run' | 'rule' | 'policy' | 'timeout' | 'blocked' | 'waiting' | string;
  asked_at: string | null;
  decided_at: string | null;
  decided_by: string | null;
  decided_by_label: string;
  risk_tier: string;
  prompted_by_file: boolean;
  reason: string | null;
}

export interface ReportBlocked {
  timestamp: string | null;
  kind: string | null;
  target: string | null;
  layer: string;
  rule: string | null;
}

export interface TaskReport {
  generated_at: string;
  task: {
    task_id: string;
    request_text: string;
    agent_id: string;
    requester: string | null;
    team: string | null;
    status: string;
    created_at: string | null;
    started_at: string | null;
    completed_at: string | null;
  };
  boundary: { initial: ReportBoundary | null; final: ReportBoundary | null };
  approvals: ReportApproval[];
  blocked: ReportBlocked[];
  record: { available: boolean; verified: boolean; message: string | null; final_hash: string | null; event_count: number };
}

export function decisionLabel(a: Pick<ReportApproval, 'status' | 'scope'>): string {
  if (a.status === 'PENDING') return 'Waiting';
  if (a.status === 'APPROVED') {
    if (a.scope === 'once') return 'Allowed once';
    if (a.scope === 'rule') return 'Allowed by a rule';
    if (a.scope === 'policy') return 'Allowed by the built-in policy';
    return 'Allowed for this run';
  }
  if (a.scope === 'timeout') return 'Not decided in time: stayed blocked';
  if (a.scope === 'rule') return 'Blocked by a rule';
  if (a.scope === 'policy') return 'Blocked by the built-in policy';
  return 'Blocked';
}

const LAYERS: Record<string, string> = {
  landlock: 'Operating system (Landlock)',
  seccomp: 'Operating system (seccomp)',
  broker: 'Tool broker',
  proxy: 'Network proxy',
  gateway: 'Agent gateway',
  sensor: 'Operating system monitor',
};

export function layerLabel(layer: string | null | undefined): string {
  return LAYERS[(layer || '').toLowerCase()] ?? (layer ? layer : 'Unknown');
}

/** Files and addresses added after the start (final minus initial). */
export function addedLater(b: TaskReport['boundary']): string[] {
  if (!b.initial || !b.final) return [];
  const before = new Set([...b.initial.files_read, ...b.initial.files_write, ...b.initial.network]);
  return [...b.final.files_read, ...b.final.files_write, ...b.final.network].filter(x => !before.has(x));
}

export function recordLine(r: TaskReport['record']): { text: string; tone: 'ok' | 'bad' | 'none' } {
  if (!r.available) return { text: 'No record was saved for this run.', tone: 'none' };
  if (r.verified) return { text: 'Record checked: no entries changed', tone: 'ok' };
  return { text: `Record check failed: ${r.message || "the entries don't match"}.`, tone: 'bad' };
}

/** Rows to print on one page, and how many more are only in the CSV/JSON. */
export function capRows<T>(rows: T[], max: number): { shown: T[]; more: number } {
  return rows.length <= max ? { shown: rows, more: 0 } : { shown: rows.slice(0, max), more: rows.length - max };
}

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

/** Compact local time, 24-hour: "12 Nov 2026, 16:30:42". */
export function formatWhen(iso: string | null | undefined): string {
  if (!iso) return '—';
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return '—';
  const d = new Date(t);
  const p = (n: number) => String(n).padStart(2, '0');
  return `${d.getDate()} ${MONTHS[d.getMonth()]} ${d.getFullYear()}, ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}
