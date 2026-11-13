import { describe, it, expect } from 'vitest';
import { localClock } from './TechnicalTimeline';

describe('localClock', () => {
  it('converts a UTC timestamp to the local clock, not the raw UTC digits', () => {
    const ts = '2026-11-13T12:13:54.120000+00:00';
    const expected = new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
    expect(localClock(ts)).toBe(expected);
  });
  it('treats a timestamp without a zone as UTC', () => {
    expect(localClock('2026-11-13T12:13:54')).toBe(localClock('2026-11-13T12:13:54Z'));
  });
  it('handles empty and invalid input', () => {
    expect(localClock(null)).toBe('');
    expect(localClock('nope')).toBe('nope');
  });
});
