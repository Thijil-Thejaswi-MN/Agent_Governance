// Incidents page: types and plain wording. No I/O.
import { layerLabel } from './report';
import { actionVerb, RuleAction } from './rules';

export interface Incident {
  incident_id: string;
  task_id: string;
  agent_id: string;
  request_text: string;
  timestamp: string | null;
  kind: string;
  target: string;
  layer: string;
  rule_matched: string | null;
  result: 'attempted_not_successful';
  rule_action: RuleAction | null;
}

export interface IncidentDetail extends Incident {
  mention: { file: string; line_number: number; line: string } | null;
  files_searched: number;
  followup: {
    request_id: string;
    status: string;
    decided_by: string | null;
    decided_by_label: string;
    decided_at: string | null;
    single_use: boolean;
  } | null;
  can_make_rule: boolean;
  rule_unavailable_reason: string | null;
}

const KIND_VERB: Record<string, string> = {
  file_read: 'read',
  file_write: 'write',
  network: 'reach',
  network_http: 'reach',
  http_get: 'reach',
  network_connect: 'reach',
  peer_agent: 'message',
  run_command: 'run',
};

/** "brief_bot tried to read input/payroll.csv" (target shown separately). */
export function triedLead(i: Pick<Incident, 'agent_id' | 'kind' | 'rule_action'>): string {
  const verb = KIND_VERB[i.kind] ?? (i.rule_action ? actionVerb(i.rule_action) : 'use');
  return `${i.agent_id} tried to ${verb}`;
}

export function stoppedBy(layer: string): string {
  return layerLabel(layer);
}

const REFUSED_BY: Record<string, string> = {
  landlock: 'the operating system (Landlock)',
  seccomp: 'the operating system (seccomp)',
  broker: 'the tool broker',
  proxy: 'the network proxy',
  gateway: 'the agent gateway',
  sensor: 'the operating system monitor',
};

/** What the system did, in order: refused, then (maybe) a person or rule decided. */
export function responseTaken(d: Pick<IncidentDetail, 'layer' | 'followup'>): string {
  const by = REFUSED_BY[(d.layer || '').toLowerCase()];
  const first = by ? `Refused by ${by}.` : 'Refused.';
  const f = d.followup;
  if (!f) return `${first} It did not ask for it.`;
  if (f.status === 'PENDING') return `${first} Then it asked; the request is waiting.`;
  if (f.status === 'APPROVED')
    return `${first} Then it asked, and it was ${f.single_use ? 'allowed once' : 'allowed for this run'} by ${f.decided_by_label}.`;
  return `${first} Then it asked, and it stayed blocked (${f.decided_by_label}).`;
}

export function mentionText(d: Pick<IncidentDetail, 'mention' | 'files_searched'>): { known: boolean; text: string } {
  if (d.mention) return { known: true, text: `${d.mention.file}, line ${d.mention.line_number}` };
  if (d.files_searched === 0) return { known: false, text: 'Unknown: it had not read any file before this.' };
  return { known: false, text: `Unknown: no line in the ${d.files_searched} ${d.files_searched === 1 ? 'file' : 'files'} it read before this names it.` };
}

/** Query string that opens the Policies form prefilled with a Block rule for this incident. */
export function ruleLink(i: Pick<Incident, 'agent_id' | 'rule_action' | 'target'>): string | null {
  if (!i.rule_action) return null;
  const q = new URLSearchParams({ agent: i.agent_id, action: i.rule_action, target: i.target, response: 'block' });
  return `/standing-rules?${q.toString()}`;
}
