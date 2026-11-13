import { describe, expect, it } from 'vitest';
import { mentionText, responseTaken, ruleLink, triedLead } from './incidents';

describe('incident wording', () => {
  it('says what it tried', () => {
    expect(triedLead({ agent_id: 'brief_bot', kind: 'file_read', rule_action: 'file_read' })).toBe('brief_bot tried to read');
    expect(triedLead({ agent_id: 'b', kind: 'network_http', rule_action: 'network' })).toBe('b tried to reach');
    expect(triedLead({ agent_id: 'b', kind: 'run_command', rule_action: null })).toBe('b tried to run');
  });

  it('says what the system did', () => {
    expect(responseTaken({ layer: 'comparison_unlocked', followup: null })).toBe(
      'Comparison run: decoy was read (would be blocked by the kernel lock).',
    );
    expect(responseTaken({ layer: 'landlock', followup: null })).toBe(
      'Refused by the operating system (Landlock). It did not ask for it.',
    );
    expect(
      responseTaken({
        layer: 'broker',
        followup: { request_id: 'e', status: 'APPROVED', decided_by: 'operator:ana', decided_by_label: 'ana (operator)', decided_at: null, single_use: false },
      }),
    ).toBe('Refused by the tool broker. Then it asked, and it was allowed for this run by ana (operator).');
    expect(
      responseTaken({
        layer: 'broker',
        followup: { request_id: 'e', status: 'DENIED', decided_by: 'timeout_fail_closed', decided_by_label: 'No one in time (stayed blocked)', decided_at: null, single_use: false },
      }),
    ).toBe('Refused by the tool broker. Then it asked; no one decided in time, so it stayed blocked.');
    expect(
      responseTaken({
        layer: 'broker',
        followup: { request_id: 'e', status: 'DENIED', decided_by: 'operator:ana', decided_by_label: 'ana (operator)', decided_at: null, single_use: false },
      }),
    ).toBe('Refused by the tool broker. Then it asked, and it stayed blocked. Decided by ana (operator).');
  });

  it('never guesses the mention', () => {
    expect(mentionText({ mention: { file: 'input/briefing.txt', line_number: 2, line: 'x' }, files_searched: 1 })).toEqual({
      known: true,
      text: 'input/briefing.txt, line 2',
    });
    expect(mentionText({ mention: null, files_searched: 0 }).text).toBe('Unknown: it had not read any file before this.');
    expect(mentionText({ mention: null, files_searched: 3 }).text).toBe(
      'Unknown: no line in the 3 files it read before this names it.',
    );
  });

  it('builds the Make this a rule link', () => {
    expect(ruleLink({ agent_id: 'b', rule_action: 'file_read', target: 'input/payroll.csv' })).toBe(
      '/standing-rules?agent=b&action=file_read&target=input%2Fpayroll.csv&response=block',
    );
    expect(ruleLink({ agent_id: 'b', rule_action: null, target: 'x' })).toBeNull();
  });
});
