import { describe, expect, it } from 'vitest';
import { getTone, statusToTone } from './tones';

describe('statusToTone mapping', () => {
  it('maps approved / allow / completed to ok tone', () => {
    expect(getTone('ALLOW')).toBe('ok');
    expect(getTone('APPROVED')).toBe('ok');
    expect(getTone('COMPLETED')).toBe('ok');
    expect(statusToTone('allow')).toBe('ok');
    expect(statusToTone('approved')).toBe('ok');
    expect(statusToTone('completed')).toBe('ok');
  });

  it('maps blocked / denied / failed / killed to bad tone', () => {
    expect(getTone('BLOCK_ACTION')).toBe('bad');
    expect(getTone('DENIED')).toBe('bad');
    expect(getTone('FAILED')).toBe('bad');
    expect(getTone('KILLED')).toBe('bad');
    expect(statusToTone('block_action')).toBe('bad');
    expect(statusToTone('denied')).toBe('bad');
    expect(statusToTone('failed')).toBe('bad');
    expect(statusToTone('killed')).toBe('bad');
  });

  it('maps pending and waiting_approval to wait tone', () => {
    expect(getTone('PENDING')).toBe('wait');
    expect(getTone('pending')).toBe('wait');
    expect(getTone('waiting_approval')).toBe('wait');
    expect(statusToTone('WAITING_APPROVAL')).toBe('wait');
  });

  it('maps running and preparing to info tone', () => {
    expect(getTone('running')).toBe('info');
    expect(getTone('preparing')).toBe('info');
    expect(statusToTone('RUNNING')).toBe('info');
    expect(statusToTone('PREPARING')).toBe('info');
  });

  it('maps unrecognized or empty inputs to neutral tone', () => {
    expect(getTone('')).toBe('neutral');
    expect(getTone(null)).toBe('neutral');
    expect(getTone(undefined)).toBe('neutral');
    expect(getTone('unknown_state')).toBe('neutral');
    expect(statusToTone('idle')).toBe('neutral');
  });
});
