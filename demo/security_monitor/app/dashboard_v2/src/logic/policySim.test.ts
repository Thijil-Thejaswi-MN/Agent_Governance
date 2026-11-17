import { describe, expect, it } from 'vitest';
import {
  SIM_CHOICES,
  buildSimRequest,
  choiceFor,
  draftApplies,
  layerLabel,
  shownSteps,
  simHeadline,
  stepTone,
  type SimResult,
} from './policySim';
import type { RuleDraft } from './rules';

const draft: RuleDraft = { agent_or_profile: ' * ', action: 'file_read', target: ' docs/plan.txt ', response: 'allow', expiry_days: 30 };

describe('policy check requests', () => {
  it('builds a tool call', () => {
    expect(buildSimRequest('task_1', choiceFor('read_file'), ' input/a.csv ')).toEqual({
      task_id: 'task_1',
      kind: 'tool_call',
      target: 'input/a.csv',
      tool: 'read_file',
    });
  });

  it('adds the draft rule only to a matching access request', () => {
    const ask = choiceFor('ask_file_read');
    expect(draftApplies(ask, draft)).toBe(true);
    expect(buildSimRequest('t', ask, 'docs/plan.txt', draft)).toEqual({
      task_id: 't',
      kind: 'access_request',
      target: 'docs/plan.txt',
      resource_type: 'file_read',
      draft_rule: { agent_or_profile: '*', action: 'file_read', target: 'docs/plan.txt', response: 'allow' },
    });
    expect(draftApplies(choiceFor('ask_network'), draft)).toBe(false);
    expect(draftApplies(choiceFor('read_file'), draft)).toBe(false);
    expect('draft_rule' in buildSimRequest('t', choiceFor('read_file'), 'x', draft)).toBe(false);
    expect(draftApplies(ask, { ...draft, target: '  ' })).toBe(false);
  });

  it('has a placeholder and a known kind for every choice', () => {
    for (const c of SIM_CHOICES) {
      expect(c.placeholder.length).toBeGreaterThan(0);
      expect(c.kind === 'tool_call' ? !!c.tool : !!c.resource_type).toBe(true);
    }
    expect(choiceFor('nope').value).toBe('read_file');
  });
});

describe('policy check results', () => {
  const r: SimResult = {
    kind: 'tool_call',
    outcome: 'deny',
    decided_by: 'agent_tool_limit',
    reason: 'run_command is not in the tool limit of notes_bot',
    trace: [
      { layer: 'identity', result: 'pass', reason: 'ok' },
      { layer: 'agent_tool_limit', result: 'deny', reason: 'run_command is not in the tool limit of notes_bot' },
      { layer: 'standing_rules', result: 'skip', reason: 'off' },
      { layer: 'other', result: 'skip', reason: 'hidden' },
    ],
    policy_version: 'pv_1',
    current_policy_version: 'pv_1',
    precedence: 'precedence_v1',
  };

  it('says what would happen and which layer decided it', () => {
    expect(simHeadline(r)).toBe("Would be blocked: decided by agent's tool limit");
    expect(layerLabel('unknown_layer')).toBe('unknown_layer');
  });

  it('keeps the steps worth reading', () => {
    expect(shownSteps(r).map(s => s.layer)).toEqual(['identity', 'agent_tool_limit', 'standing_rules']);
    expect(r.trace.map(stepTone)).toEqual(['info', 'bad', 'info', 'info']);
  });
});
