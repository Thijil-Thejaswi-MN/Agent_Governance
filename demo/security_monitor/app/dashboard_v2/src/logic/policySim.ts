// "Check a decision" (Policies page): what the broker would do with one action, layer by
// layer, without running it. Wording and request building only; no I/O.

import type { RuleDraft } from './rules';

export type SimKind = 'tool_call' | 'access_request';
export type SimOutcome = 'allow' | 'deny' | 'ask';

export interface SimStep {
  layer: string;
  result: string;
  reason: string;
}

export interface SimResult {
  kind: SimKind;
  outcome: SimOutcome;
  decided_by: string;
  reason: string;
  trace: SimStep[];
  policy_version: string;
  current_policy_version: string;
  precedence: string;
  draft_rule?: boolean;
  rule_id?: string;
  effective_risk?: string;
  baseline_risk?: string;
}

export interface SimChoice {
  value: string;
  label: string;
  kind: SimKind;
  tool?: string;
  resource_type?: string;
  placeholder: string;
  // The standing-rule action this choice can be tested against (access requests only).
  ruleAction?: RuleDraft['action'];
}

export const SIM_CHOICES: SimChoice[] = [
  { value: 'read_file', label: 'Read a file', kind: 'tool_call', tool: 'read_file', placeholder: 'input/sales.csv' },
  { value: 'write_file', label: 'Write a file', kind: 'tool_call', tool: 'write_file', placeholder: 'output/summary.txt' },
  { value: 'http_get', label: 'Fetch an address', kind: 'tool_call', tool: 'http_get', placeholder: 'https://api.example.com/x' },
  { value: 'call_agent', label: 'Call another agent', kind: 'tool_call', tool: 'call_agent', placeholder: 'agent_bob' },
  { value: 'run_command', label: 'Run a command', kind: 'tool_call', tool: 'run_command', placeholder: 'wc -l input/sales.csv' },
  { value: 'ask_file_read', label: 'Ask to read a file', kind: 'access_request', resource_type: 'file_read', placeholder: 'docs/plan.txt', ruleAction: 'file_read' },
  { value: 'ask_file_write', label: 'Ask to save a file', kind: 'access_request', resource_type: 'file_write', placeholder: 'output/extra.txt', ruleAction: 'file_write' },
  { value: 'ask_network', label: 'Ask to reach an address', kind: 'access_request', resource_type: 'network', placeholder: '127.0.0.1:8080', ruleAction: 'network' },
  { value: 'ask_peer_agent', label: 'Ask to talk to an agent', kind: 'access_request', resource_type: 'peer_agent', placeholder: 'agent_bob', ruleAction: 'peer_agent' },
];

export const LAYER_LABEL: Record<string, string> = {
  identity: 'Task token',
  agent_tool_limit: "Agent's tool limit",
  boundary_tools: 'Tools in the task',
  boundary_resource: 'Task boundary',
  graduated_response: 'Repeated violations',
  workspace: 'Task folder',
  kernel: 'Kernel (Landlock, seccomp)',
  request_shape: 'Exact target',
  risk_tier: 'Risk',
  provenance: 'Untrusted reads',
  risk_policy: 'Risk policy',
  standing_rules: 'Standing rules',
  person: 'A person',
};

export const OUTCOME_LABEL: Record<SimOutcome, string> = {
  allow: 'Would be allowed',
  deny: 'Would be blocked',
  ask: 'Would ask a person',
};

export function layerLabel(id: string): string {
  return LAYER_LABEL[id] || id;
}

export function choiceFor(value: string): SimChoice {
  return SIM_CHOICES.find(c => c.value === value) || SIM_CHOICES[0];
}

/** True when the rule in the form can be tested on this choice. */
export function draftApplies(choice: SimChoice, draft: RuleDraft): boolean {
  return choice.kind === 'access_request' && choice.ruleAction === draft.action && draft.target.trim() !== '';
}

export function buildSimRequest(
  taskId: string,
  choice: SimChoice,
  target: string,
  draft?: RuleDraft | null,
): Record<string, unknown> {
  const body: Record<string, unknown> = { task_id: taskId, kind: choice.kind, target: target.trim() };
  if (choice.kind === 'tool_call') body.tool = choice.tool;
  else body.resource_type = choice.resource_type;
  if (draft && draftApplies(choice, draft)) {
    body.draft_rule = {
      agent_or_profile: draft.agent_or_profile.trim() || '*',
      action: draft.action,
      target: draft.target.trim(),
      response: draft.response,
    };
  }
  return body;
}

/** One line for the result: what would happen and which layer decided it. */
export function simHeadline(r: SimResult): string {
  return `${OUTCOME_LABEL[r.outcome] || r.outcome}: decided by ${layerLabel(r.decided_by).toLowerCase()}`;
}

/** The steps a reader should see: every layer up to and including the deciding one, then the kernel note. */
export function shownSteps(r: SimResult): SimStep[] {
  return r.trace.filter(s => s.result !== 'skip' || s.layer === 'standing_rules');
}

export function stepTone(s: SimStep): 'ok' | 'bad' | 'ask' | 'info' {
  if (s.result === 'deny') return 'bad';
  if (s.result === 'ask') return 'ask';
  if (s.result === 'allow') return 'ok';
  return 'info';
}
