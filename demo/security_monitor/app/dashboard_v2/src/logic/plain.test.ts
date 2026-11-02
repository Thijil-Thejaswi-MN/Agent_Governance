import { describe, expect, it } from 'vitest';
import {
  FIRST_SCREEN_JARGON,
  NEVER_SAY,
  boundaryVersionLabel,
  decisionLead,
  decisionWarning,
  fleetHeadline,
  formatCountdown,
  needsYouReason,
  needsYouTitle,
  receiptSentence,
  secondsLeft,
  statusSentence,
  technicalLabel,
} from './plain';
import { BlockedAttempt, RunState } from './runView';

const blockedTarget: BlockedAttempt = { action: 'open', target: 'input/target_metrics.csv', name: 'target_metrics.csv', stepNumber: 4 };

describe('statusSentence', () => {
  const base = { blocked: [] as BlockedAttempt[] };

  it('preparing', () => {
    expect(statusSentence({ ...base, state: 'preparing' })).toBe('Setting up a fenced space for the agent…');
  });

  it('running', () => {
    expect(statusSentence({ ...base, state: 'running' })).toBe('The agent is working.');
  });

  it('running, just blocked', () => {
    expect(statusSentence({ ...base, state: 'running', justBlocked: blockedTarget })).toBe(
      "The agent tried to open target_metrics.csv. Your request doesn't include it, so it was stopped.",
    );
    expect(
      statusSentence({ ...base, state: 'running', justBlocked: { ...blockedTarget, action: 'write', name: 'notes.txt' } }),
    ).toBe("The agent tried to write to notes.txt. Your request doesn't include it, so it was stopped.");
    expect(
      statusSentence({ ...base, state: 'running', justBlocked: { ...blockedTarget, action: 'run', name: 'cat ~/x' } }),
    ).toBe("The agent tried to run a command. Your request doesn't include it, so it was stopped.");
  });

  it('waiting, by resource type', () => {
    expect(statusSentence({ ...base, state: 'waiting_approval', pending: { resource_type: 'file_read' } })).toBe(
      'The agent wants one more file.',
    );
    expect(statusSentence({ ...base, state: 'waiting_approval', pending: null })).toBe('The agent wants one more file.');
    expect(statusSentence({ ...base, state: 'waiting_approval', pending: { resource_type: 'network' } })).toBe(
      'The agent wants to reach one more website.',
    );
  });

  it('completed, with and without stopped attempts', () => {
    expect(statusSentence({ state: 'completed', blocked: [] })).toBe('Done. The agent stayed inside its fence.');
    expect(statusSentence({ state: 'completed', blocked: [blockedTarget] })).toBe('Done. 1 attempt was stopped.');
    expect(statusSentence({ state: 'completed', blocked: [blockedTarget, { ...blockedTarget, name: 'b' }] })).toBe(
      'Done. 2 attempts were stopped.',
    );
  });

  it('stopped by the operator, before and after the agent started', () => {
    expect(statusSentence({ ...base, state: 'stopped', endReason: 'operator_stop', agentStarted: false })).toBe(
      'Stopped before the agent started. It never ran.',
    );
    expect(statusSentence({ ...base, state: 'stopped', endReason: 'operator_stop', agentStarted: true })).toBe(
      'Stopped. You ended the run and the agent was shut down.',
    );
  });

  it('stopped by the system, failed, timed out', () => {
    expect(statusSentence({ ...base, state: 'stopped', endReason: 'freeze_timeout (task status TERMINATED)' })).toBe(
      'The run was stopped before it finished. "Show what happened" has the reason.',
    );
    expect(statusSentence({ ...base, state: 'failed' })).toBe(
      'The run ended with an error before it finished. "Show what happened" has the reason.',
    );
    expect(statusSentence({ ...base, state: 'timed_out' })).toBe(
      'The run took too long, so it was stopped before it finished.',
    );
    expect(statusSentence({ ...base, state: 'stopping' })).toBe('Stopping the agent…');
    expect(statusSentence({ ...base, state: 'idle' })).toBe('Nothing is running.');
  });

  it('every state has a sentence without jargon or forbidden words', () => {
    const states: RunState[] = ['idle', 'preparing', 'running', 'waiting_approval', 'stopping', 'completed', 'stopped', 'failed', 'timed_out'];
    for (const state of states) {
      for (const extra of [{}, { justBlocked: blockedTarget, blocked: [blockedTarget] }]) {
        const s = statusSentence({ blocked: [], state, ...extra });
        expect(s.length).toBeGreaterThan(5);
        for (const w of [...FIRST_SCREEN_JARGON, ...NEVER_SAY]) {
          expect(new RegExp(`\\b${w}\\b`, 'i').test(s), `${state}: "${s}" contains "${w}"`).toBe(false);
        }
      }
    }
  });
});

describe('decision card copy', () => {
  const exp = { resource_type: 'file_read', resource_target: 'input/target_metrics.csv' };

  it('lead depends on whether the agent tried before asking', () => {
    expect(decisionLead(exp, true)).toBe(
      "It tried to open target_metrics.csv. You didn't ask for that file, so it was stopped. Now it's asking you.",
    );
    expect(decisionLead(exp, false)).toBe("It's asking to open target_metrics.csv. Your request doesn't include it.");
  });

  it('warning names the file it learned from', () => {
    expect(
      decisionWarning({
        ...exp,
        escalated_by_provenance: true,
        prior_untrusted_reads: [
          { task_id: 't', timestamp: '', source_type: 'file_read', source_target: 'input/notes.txt', content_hash: '', content_len: 1, linked: false },
          { task_id: 't', timestamp: '', source_type: 'file_read', source_target: 'input/sales_data.csv', content_hash: '', content_len: 1, linked: true },
        ],
      }),
    ).toBe('It only learned about this file from inside sales_data.csv.');
  });

  it('warning without a linked read, and no warning when not escalated', () => {
    expect(decisionWarning({ ...exp, escalated_by_provenance: true, prior_untrusted_reads: [] })).toBe(
      "It asked for this after reading content that didn't come from you.",
    );
    expect(decisionWarning({ ...exp, escalated_by_provenance: false })).toBeNull();
  });

  it('countdown', () => {
    expect(formatCountdown(94)).toBe('Decide within 1:34, or it stays blocked.');
    expect(formatCountdown(5.2)).toBe('Decide within 0:06, or it stays blocked.');
    expect(formatCountdown(0)).toBe('Time is up. It stays blocked.');
    const created = '2026-10-30T12:00:00Z';
    expect(secondsLeft({ created_at: created, timeout_seconds: 120 }, Date.parse('2026-10-30T12:00:26Z'))).toBe(94);
  });
});

describe('fleet copy', () => {
  it('headline', () => {
    expect(fleetHeadline(0, 0)).toEqual(['All quiet.', 'No agents are running.']);
    expect(fleetHeadline(1, 0)).toEqual(['1 agent at work.', 'Nothing needs you.']);
    expect(fleetHeadline(1284, 3)).toEqual(['1,284 agents at work.', '3 need you.']);
    expect(fleetHeadline(2, 1)).toEqual(['2 agents at work.', '1 needs you.']);
  });

  it('needs-you line', () => {
    const item = { resource_type: 'file_read', resource_target: 'input/targets.csv' };
    expect(needsYouTitle('Finance bot', item)).toBe('Finance bot wants targets.csv');
    expect(needsYouTitle('Support agent', { resource_type: 'network', resource_target: 'https://crm.example.com/x' })).toBe(
      'Support agent wants to reach crm.example.com',
    );
    expect(needsYouReason({ learned_from: 'input/sales_data.csv' })).toBe('learned of it from inside sales_data.csv');
    expect(needsYouReason({ escalated_by_provenance: true })).toBe('asked after reading content that did not come from you');
    expect(needsYouReason({})).toBe('not part of the request it was given');
  });
});

describe('record and labels', () => {
  it('receipt sentence', () => {
    expect(receiptSentence(null, false).text).toBe('Checking the record…');
    expect(receiptSentence(null, true).text).toBe('No record was saved for this run.');
    const r = { task_id: 't', receipt: { task_id: 't' }, verified: true, verification_message: 'ok' };
    expect(receiptSentence(r, true)).toEqual({ text: 'Record checked: no entries changed', tone: 'ok' });
    expect(receiptSentence({ ...r, verified: false }, true).tone).toBe('bad');
    expect(receiptSentence({ ...r, available: false }, true).text).toBe('No record was saved for this run.');
  });

  it('technical label joins the stored source label and layer', () => {
    expect(technicalLabel('enforced', 'landlock')).toBe('enforced · kernel (Landlock)');
    expect(technicalLabel('reported by the in-sandbox shim', 'broker')).toBe('reported by the in-sandbox shim · tool broker');
    expect(technicalLabel('enforced', 'custom_layer')).toBe('enforced · custom_layer');
  });
});

describe('boundary version label', () => {
  it('names the version and counts approvals, never a bare vN', () => {
    expect(boundaryVersionLabel(1, 0)).toBe('Boundary version 1');
    expect(boundaryVersionLabel(undefined, 0)).toBe('Boundary version 1');
    expect(boundaryVersionLabel(2, 1)).toBe('Boundary version 2 (after 1 approval)');
    expect(boundaryVersionLabel(4, 3)).toBe('Boundary version 4 (after 3 approvals)');
    expect(boundaryVersionLabel(2, 1)).not.toMatch(/^v\d/);
  });
});
