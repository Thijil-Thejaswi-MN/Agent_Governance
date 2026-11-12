// Standing rules (Policies page): plain-English wording and draft checks. No I/O.

export type RuleResponse = 'allow' | 'ask' | 'block';
export type RuleAction = 'file_read' | 'file_write' | 'network' | 'peer_agent';

export interface PolicyRule {
  rule_id: string;
  agent_or_profile: string;
  action: string;
  target: string;
  owner: string;
  created_at: string;
  expires_at: string;
  team?: string | null;
  is_active: boolean;
  response?: RuleResponse;
}

export interface RuleDraft {
  agent_or_profile: string;
  action: RuleAction;
  target: string;
  response: RuleResponse;
  expiry_days: number;
}

export const RESPONSES: { value: RuleResponse; label: string; hint: string }[] = [
  { value: 'allow', label: 'Allow and log', hint: 'Let it through and write it in the record.' },
  { value: 'ask', label: 'Ask', hint: 'Always ask a person, even if another rule would allow it.' },
  { value: 'block', label: 'Block', hint: 'Refuse it without asking.' },
];

export const ACTIONS: { value: RuleAction; label: string; verb: string; placeholder: string }[] = [
  { value: 'file_read', label: 'Read a file', verb: 'read', placeholder: 'docs/notes.txt' },
  { value: 'file_write', label: 'Write a file', verb: 'write', placeholder: 'output/summary.md' },
  { value: 'network', label: 'Reach an address', verb: 'reach', placeholder: 'localhost:8080' },
  { value: 'peer_agent', label: 'Message another agent', verb: 'message', placeholder: 'agent_reports' },
];

export function responseLabel(r: string | undefined): string {
  return RESPONSES.find(x => x.value === (r ?? 'allow'))?.label ?? 'Allow and log';
}

export function actionVerb(action: string): string {
  return ACTIONS.find(a => a.value === action)?.verb ?? action.replace(/_/g, ' ');
}

function agentPhrase(agent: string): string {
  const a = agent.trim();
  return !a || a === '*' ? 'any agent' : a;
}

const OUTCOME: Record<RuleResponse, string> = {
  allow: 'allow it and log it',
  ask: 'ask a person',
  block: 'block it',
};

/** "When any agent asks to read docs/notes.txt: allow it and log it." */
export function ruleSentence(rule: { agent_or_profile: string; action: string; target: string; response?: string }): {
  lead: string;
  target: string;
  outcome: string;
} {
  const response = (rule.response ?? 'allow') as RuleResponse;
  return {
    lead: `When ${agentPhrase(rule.agent_or_profile)} asks to ${actionVerb(rule.action)}`,
    target: rule.target.trim() || '…',
    outcome: OUTCOME[response] ?? OUTCOME.allow,
  };
}

export function ruleSentenceText(rule: Parameters<typeof ruleSentence>[0]): string {
  const s = ruleSentence(rule);
  return `${s.lead} ${s.target}: ${s.outcome}.`;
}

/** Problems with a draft, in plain words; empty when it can be saved. Mirrors the server's checks. */
export function draftProblems(d: RuleDraft): string[] {
  const out: string[] = [];
  if (!d.agent_or_profile.trim()) out.push('Name the agent, or use * for every agent.');
  const t = d.target.trim();
  if (!t) out.push('Give the exact file, address or agent.');
  else if (/[*?[\]]/.test(t)) out.push('Use one exact name. Patterns such as * are not allowed.');
  if (!Number.isFinite(d.expiry_days) || d.expiry_days < 1 || d.expiry_days > 90)
    out.push('A rule can last from 1 to 90 days.');
  return out;
}

export type RuleState = 'active' | 'expired' | 'switched_off';

export function ruleState(rule: PolicyRule, now: number = Date.now()): RuleState {
  if (!rule.is_active) return 'switched_off';
  const exp = Date.parse(rule.expires_at);
  if (Number.isFinite(exp) && exp <= now) return 'expired';
  return 'active';
}

/** Active rules first (newest first), then the rest. */
export function sortRules(rules: PolicyRule[], now: number = Date.now()): PolicyRule[] {
  const rank = (r: PolicyRule) => (ruleState(r, now) === 'active' ? 0 : 1);
  return [...rules].sort((a, b) => rank(a) - rank(b) || b.created_at.localeCompare(a.created_at));
}

/** "standing_rule:rule_ab12cd34" -> "rule_ab12cd34"; anything else -> null. */
export function ruleIdFromDecider(decider: string | null | undefined): string | null {
  if (!decider || !decider.startsWith('standing_rule:')) return null;
  return decider.slice('standing_rule:'.length) || null;
}

/** A draft from ?agent=&action=&target=&response= (unknown values keep the defaults). */
export function draftFromParams(p: URLSearchParams, base: RuleDraft): RuleDraft {
  const action = p.get('action');
  const response = p.get('response');
  return {
    ...base,
    agent_or_profile: p.get('agent')?.trim() || base.agent_or_profile,
    action: ACTIONS.some(a => a.value === action) ? (action as RuleAction) : base.action,
    target: p.get('target')?.trim() || base.target,
    response: RESPONSES.some(r => r.value === response) ? (response as RuleResponse) : base.response,
  };
}
