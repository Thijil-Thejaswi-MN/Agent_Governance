import { describe, expect, it } from 'vitest';
import {
  draftProblems,
  responseLabel,
  ruleIdFromDecider,
  ruleSentenceText,
  ruleState,
  sortRules,
  PolicyRule,
  RuleDraft,
} from './rules';

const base: PolicyRule = {
  rule_id: 'rule_1',
  agent_or_profile: 'agent_docs',
  action: 'file_read',
  target: 'docs/notes.txt',
  owner: 'rev_ana',
  created_at: '2026-11-12T10:00:00+00:00',
  expires_at: '2026-12-12T10:00:00+00:00',
  is_active: true,
  response: 'allow',
};
const NOW = Date.parse('2026-11-12T12:00:00Z');

describe('rule sentences', () => {
  it('reads as plain English for each response', () => {
    expect(ruleSentenceText(base)).toBe('When agent_docs asks to read docs/notes.txt: allow it and log it.');
    expect(ruleSentenceText({ ...base, response: 'ask' })).toBe('When agent_docs asks to read docs/notes.txt: ask a person.');
    expect(ruleSentenceText({ ...base, response: 'block', agent_or_profile: '*', action: 'network', target: 'localhost:9000' }))
      .toBe('When any agent asks to reach localhost:9000: block it.');
  });

  it('treats old rules without a response as allow', () => {
    const { response: _r, ...old } = base;
    expect(ruleSentenceText(old)).toContain('allow it and log it');
    expect(responseLabel(undefined)).toBe('Allow and log');
    expect(responseLabel('block')).toBe('Block');
  });
});

describe('draft checks', () => {
  const ok: RuleDraft = { agent_or_profile: '*', action: 'file_read', target: 'docs/a.txt', response: 'allow', expiry_days: 30 };
  it('accepts an exact rule', () => expect(draftProblems(ok)).toEqual([]));
  it('refuses patterns, blanks and long expiries', () => {
    expect(draftProblems({ ...ok, target: 'docs/*.txt' })).toHaveLength(1);
    expect(draftProblems({ ...ok, target: '  ' })).toHaveLength(1);
    expect(draftProblems({ ...ok, agent_or_profile: '' })).toHaveLength(1);
    expect(draftProblems({ ...ok, expiry_days: 91 })).toHaveLength(1);
    expect(draftProblems({ ...ok, expiry_days: 0 })).toHaveLength(1);
  });
});

describe('rule state and order', () => {
  it('knows active, expired and switched off', () => {
    expect(ruleState(base, NOW)).toBe('active');
    expect(ruleState({ ...base, expires_at: '2026-11-12T11:00:00Z' }, NOW)).toBe('expired');
    expect(ruleState({ ...base, is_active: false }, NOW)).toBe('switched_off');
  });
  it('lists active rules first, newest first', () => {
    const old = { ...base, rule_id: 'old', created_at: '2026-11-01T00:00:00Z' };
    const off = { ...base, rule_id: 'off', is_active: false, created_at: '2026-11-12T11:00:00Z' };
    const fresh = { ...base, rule_id: 'fresh', created_at: '2026-11-12T11:30:00Z' };
    expect(sortRules([off, old, fresh], NOW).map(r => r.rule_id)).toEqual(['fresh', 'old', 'off']);
  });
});

describe('decider names', () => {
  it('extracts the rule id', () => {
    expect(ruleIdFromDecider('standing_rule:rule_ab12')).toBe('rule_ab12');
    expect(ruleIdFromDecider('operator:admin')).toBeNull();
    expect(ruleIdFromDecider(null)).toBeNull();
  });
});
