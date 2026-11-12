import { describe, expect, it } from 'vitest';
import { alwaysBlockedReason, formatBytes, onceBlockedReason, previewFacts, riskLabel } from './approval';

describe('sizes', () => {
  it('formats bytes in plain units', () => {
    expect(formatBytes(1)).toBe('1 byte');
    expect(formatBytes(512)).toBe('512 bytes');
    expect(formatBytes(1234)).toBe('1.2 KB');
    expect(formatBytes(20 * 1024)).toBe('20 KB');
    expect(formatBytes(3 * 1024 * 1024)).toBe('3.0 MB');
    expect(formatBytes(null)).toBeNull();
    expect(formatBytes(-1)).toBeNull();
  });
});

describe('preview facts', () => {
  const file = { kind: 'file' as const, folder: 'docs', size_bytes: 1234, exists: true, inside_workspace: true };
  it('shows folder and size', () => expect(previewFacts(file)).toEqual(['in docs', '1.2 KB']));
  it('never guesses a size', () => {
    expect(previewFacts({ ...file, inside_workspace: false, size_bytes: null, exists: null })).toEqual([
      'in docs',
      'outside the task folder, size unknown',
    ]);
    expect(previewFacts({ ...file, exists: false, size_bytes: null })).toEqual(['in docs', 'not found in the task folder']);
    expect(previewFacts({ ...file, size_bytes: null })).toEqual(['in docs', 'size unknown']);
    expect(previewFacts({ ...file, folder: null })[0]).toBe('in the task folder');
  });
  it('describes addresses and agents', () => {
    expect(previewFacts({ ...file, kind: 'address' })).toEqual(['a network address']);
    expect(previewFacts({ ...file, kind: 'agent' })).toEqual(['another agent']);
  });
});

describe('risk and rules', () => {
  it('labels tiers', () => {
    expect(riskLabel('MEDIUM').label).toBe('Medium risk');
    expect(riskLabel('low').label).toBe('Low risk');
    expect(riskLabel(undefined).label).toBe('Risk unknown');
  });
  it('explains when Always is unavailable', () => {
    expect(alwaysBlockedReason({ canManageRules: true, rulePossible: true })).toBeNull();
    expect(alwaysBlockedReason({ canManageRules: true, rulePossible: false })).toContain('always go to a person');
    expect(alwaysBlockedReason({ canManageRules: false, rulePossible: true })).toContain('security reviewer or an admin');
    expect(alwaysBlockedReason({ canManageRules: true, rulePossible: null })).toBeNull();
  });
});

describe('allow once', () => {
  it('is available unless another one-time grant is unused', () => {
    expect(onceBlockedReason(null)).toBeNull();
    expect(onceBlockedReason({ once_possible: true })).toBeNull();
    expect(onceBlockedReason({ once_possible: false, once_blocked_by: 'docs/notes.txt' })).toContain('notes.txt');
  });
});
