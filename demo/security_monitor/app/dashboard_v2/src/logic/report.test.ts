import { describe, expect, it } from 'vitest';
import { addedLater, capRows, decisionLabel, formatWhen, layerLabel, recordLine } from './report';

describe('report wording', () => {
  it('names each decision plainly', () => {
    expect(decisionLabel({ status: 'APPROVED', scope: 'run' })).toBe('Allowed for this run');
    expect(decisionLabel({ status: 'APPROVED', scope: 'once' })).toBe('Allowed once');
    expect(decisionLabel({ status: 'APPROVED', scope: 'rule' })).toBe('Allowed by a rule');
    expect(decisionLabel({ status: 'DENIED', scope: 'timeout' })).toBe('Not decided in time: stayed blocked');
    expect(decisionLabel({ status: 'DENIED', scope: 'blocked' })).toBe('Blocked');
    expect(decisionLabel({ status: 'PENDING', scope: 'waiting' })).toBe('Waiting');
  });
  it('names layers and never guesses an unknown one', () => {
    expect(layerLabel('landlock')).toBe('Operating system (Landlock)');
    expect(layerLabel('broker')).toBe('Tool broker');
    expect(layerLabel('')).toBe('Unknown');
  });
  it('states the record check', () => {
    expect(recordLine({ available: false, verified: false, message: null, final_hash: null, event_count: 0 }).tone).toBe('none');
    expect(recordLine({ available: true, verified: true, message: 'ok', final_hash: 'h', event_count: 2 }).text).toBe(
      'Record checked: no entries changed',
    );
    expect(recordLine({ available: true, verified: false, message: 'entry 1: hash mismatch', final_hash: 'h', event_count: 2 }).text).toBe(
      'Record check failed: entry 1: hash mismatch.',
    );
  });
  it('lists what was added after the start', () => {
    const b = { version: 1, files_read: ['a'], files_write: ['o'], network: [], tools: [] };
    expect(addedLater({ initial: b, final: { ...b, version: 2, files_read: ['a', 'b'] } })).toEqual(['b']);
    expect(addedLater({ initial: null, final: b })).toEqual([]);
  });
  it('caps rows for one page', () => {
    expect(capRows([1, 2, 3], 5)).toEqual({ shown: [1, 2, 3], more: 0 });
    expect(capRows([1, 2, 3], 2)).toEqual({ shown: [1, 2], more: 1 });
  });
  it('formats missing times as a dash', () => {
    expect(formatWhen(null)).toBe('—');
    expect(formatWhen('nope')).toBe('—');
  });
});
