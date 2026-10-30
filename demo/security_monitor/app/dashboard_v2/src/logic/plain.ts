// Plain-language copy for every first screen. Technical labels stay in the Details panels.
// See plain.test.ts.
import { ExpansionItem, ReceiptResponse } from '../types';
import { BlockedAttempt, RunState, fileName } from './runView';

// Never on a first screen (outside Details): asserted by the browser tests.
export const FIRST_SCREEN_JARGON = [
  'Landlock',
  'seccomp',
  'cgroup',
  'provenance',
  'hash chain',
  'hash-chain',
  'boundary v1',
  'boundary v2',
  'broker',
  'SSE',
  'ABI',
];

// Never anywhere in the console's own copy.
export const NEVER_SAY = ['safe', 'secure', 'guaranteed', 'tamper-proof', 'first'];

const n = (count: number, one: string, many: string) => (count === 1 ? one : many);

export function attemptVerb(a: Pick<BlockedAttempt, 'action'>): string {
  switch (a.action) {
    case 'write':
      return 'write to';
    case 'run':
      return 'run';
    case 'reach':
      return 'reach';
    default:
      return 'open';
  }
}

export function attemptObject(a: Pick<BlockedAttempt, 'action' | 'name'>): string {
  return a.action === 'run' ? 'a command' : a.name;
}

export interface SentenceInput {
  state: RunState;
  blocked: BlockedAttempt[];
  justBlocked?: BlockedAttempt | null;
  pending?: Pick<ExpansionItem, 'resource_type'> | null;
  agentStarted?: boolean;
  endReason?: string | null;
}

export function wantsHeadline(resourceType?: string): string {
  const t = (resourceType || '').toLowerCase();
  if (t === 'network') return 'The agent wants to reach one more website.';
  if (t === 'peer_agent') return 'The agent wants to talk to one more agent.';
  if (t === 'file_write') return 'The agent wants to write one more file.';
  return 'The agent wants one more file.';
}

// The one status sentence of the Watch / Done screen.
export function statusSentence(v: SentenceInput): string {
  switch (v.state) {
    case 'idle':
      return 'Nothing is running.';
    case 'preparing':
      return 'Setting up a fenced space for the agent…';
    case 'running': {
      const b = v.justBlocked;
      if (b) {
        return `The agent tried to ${attemptVerb(b)} ${attemptObject(b)}. Your request doesn't include it, so it was stopped.`;
      }
      return 'The agent is working.';
    }
    case 'waiting_approval':
      return wantsHeadline(v.pending?.resource_type);
    case 'stopping':
      return 'Stopping the agent…';
    case 'completed': {
      const count = v.blocked.length;
      if (count === 0) return 'Done. The agent stayed inside its fence.';
      return `Done. ${count} ${n(count, 'attempt was', 'attempts were')} stopped.`;
    }
    case 'stopped': {
      const byYou = (v.endReason || '').includes('operator_stop');
      if (byYou && !v.agentStarted) return 'Stopped before the agent started. It never ran.';
      if (byYou) return 'Stopped. You ended the run and the agent was shut down.';
      return 'The run was stopped before it finished. "Show what happened" has the reason.';
    }
    case 'timed_out':
      return 'The run took too long, so it was stopped before it finished.';
    case 'failed':
      return 'The run ended with an error before it finished. "Show what happened" has the reason.';
  }
}

export function resourceVerb(resourceType?: string): string {
  const t = (resourceType || '').toLowerCase();
  if (t === 'network') return 'reach';
  if (t === 'file_write') return 'write to';
  if (t === 'peer_agent') return 'talk to';
  return 'open';
}

// The sentence under "The agent wants one more file."
export function decisionLead(exp: Pick<ExpansionItem, 'resource_type' | 'resource_target'>, triedBefore: boolean): string {
  const name = fileName(exp.resource_target);
  const verb = resourceVerb(exp.resource_type);
  const what = exp.resource_type === 'network' ? 'website' : exp.resource_type === 'peer_agent' ? 'agent' : 'file';
  if (triedBefore) {
    return `It tried to ${verb} ${name}. You didn't ask for that ${what}, so it was stopped. Now it's asking you.`;
  }
  return `It's asking to ${verb} ${name}. Your request doesn't include it.`;
}

function learnedFrom(exp: Pick<ExpansionItem, 'prior_untrusted_reads'> & { learned_from?: string | null }): string | null {
  if (exp.learned_from) return exp.learned_from;
  const linked = (exp.prior_untrusted_reads || []).find(r => r.linked);
  return linked ? linked.source_target : null;
}

const escalated = (exp: Pick<ExpansionItem, 'escalated_by_provenance' | 'provenance_escalation'>) =>
  !!(exp.escalated_by_provenance || exp.provenance_escalation);

// The one plain warning on the decision card, or null when there is nothing to warn about.
export function decisionWarning(
  exp: Pick<ExpansionItem, 'resource_type' | 'escalated_by_provenance' | 'provenance_escalation' | 'prior_untrusted_reads'> & {
    learned_from?: string | null;
  },
): string | null {
  const what = exp.resource_type === 'network' ? 'website' : exp.resource_type === 'peer_agent' ? 'agent' : 'file';
  const src = learnedFrom(exp);
  if (src) return `It only learned about this ${what} from inside ${fileName(src)}.`;
  if (escalated(exp)) return "It asked for this after reading content that didn't come from you.";
  return null;
}

// Fleet "Needs you" line: what it wants, and why it needs a person.
export function needsYouTitle(agent: string, exp: { resource_type: string; resource_target: string }): string {
  const name = fileName(exp.resource_target);
  if (exp.resource_type === 'network') return `${agent} wants to reach ${name}`;
  if (exp.resource_type === 'file_write') return `${agent} wants to write ${name}`;
  if (exp.resource_type === 'peer_agent') return `${agent} wants to talk to ${name}`;
  return `${agent} wants ${name}`;
}

export function needsYouReason(exp: {
  learned_from?: string | null;
  escalated_by_provenance?: boolean;
  prior_untrusted_reads?: ExpansionItem['prior_untrusted_reads'];
}): string {
  const src = learnedFrom(exp);
  if (src) return `learned of it from inside ${fileName(src)}`;
  if (exp.escalated_by_provenance) return 'asked after reading content that did not come from you';
  return 'not part of the request it was given';
}

export function formatCountdown(secondsLeft: number): string {
  if (secondsLeft <= 0) return 'Time is up. It stays blocked.';
  const s = Math.ceil(secondsLeft);
  const mm = Math.floor(s / 60);
  const ss = String(s % 60).padStart(2, '0');
  return `Decide within ${mm}:${ss}, or it stays blocked.`;
}

export function secondsLeft(exp: Pick<ExpansionItem, 'created_at' | 'timeout_seconds'>, now: number): number {
  const created = new Date(exp.created_at).getTime();
  if (Number.isNaN(created)) return 0;
  return (created + (exp.timeout_seconds ?? 120) * 1000 - now) / 1000;
}

export function receiptSentence(r: ReceiptResponse | null | undefined, loaded: boolean): { text: string; tone: 'ok' | 'bad' | 'none' } {
  if (!loaded) return { text: 'Checking the record…', tone: 'none' };
  if (!r || r.available === false || !r.receipt) return { text: 'No record was saved for this run.', tone: 'none' };
  if (r.verified) return { text: 'Record checked: no entries changed', tone: 'ok' };
  return { text: "Record check failed: the entries don't match.", tone: 'bad' };
}

export function fleetHeadline(atWork: number, needYou: number): [string, string] {
  if (atWork === 0 && needYou === 0) return ['All quiet.', 'No agents are running.'];
  const first = `${atWork.toLocaleString('en-US')} ${n(atWork, 'agent', 'agents')} at work.`;
  if (needYou === 0) return [first, 'Nothing needs you.'];
  return [first, `${needYou.toLocaleString('en-US')} ${n(needYou, 'needs', 'need')} you.`];
}

export function outcomeLabel(status: string): { text: string; tone: 'ok' | 'bad' | 'wait' | 'none' } {
  switch (status) {
    case 'COMPLETED':
      return { text: 'Done', tone: 'ok' };
    case 'ACTIVE':
    case 'RUNNING':
      return { text: 'Running', tone: 'wait' };
    case 'TERMINATED':
      return { text: 'Stopped', tone: 'bad' };
    case 'FAILED':
      return { text: 'Failed', tone: 'bad' };
    case 'EXPIRED':
      return { text: 'Timed out', tone: 'bad' };
    case 'PENDING':
      return { text: 'Not started', tone: 'none' };
    default:
      return { text: status.toLowerCase(), tone: 'none' };
  }
}

// "enforced" + "landlock" -> "enforced · kernel (Landlock)"; used only in Details.
const LAYER_LABELS: Record<string, string> = {
  landlock: 'kernel (Landlock)',
  seccomp: 'kernel (seccomp)',
  broker: 'tool broker',
  proxy: 'egress proxy',
  launcher: 'launcher',
  intake: 'intake',
  sensor: 'OS sensor',
  gateway: 'A2A gateway',
};

export function technicalLabel(sourceLabel: string, layer: string): string {
  const l = LAYER_LABELS[(layer || '').toLowerCase()] || layer;
  return l ? `${sourceLabel} · ${l}` : sourceLabel;
}

export function relativeTime(iso: string | undefined | null, now: number): string {
  if (!iso) return '';
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return '';
  const s = Math.max(0, Math.round((now - t) / 1000));
  if (s < 60) return 'just now';
  const m = Math.round(s / 60);
  if (m < 60) return `${m} min ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h} h ago`;
  const d = Math.round(h / 24);
  return `${d} ${n(d, 'day', 'days')} ago`;
}
