import { afterEach, describe, expect, it, vi } from 'vitest';
import { onCountsRefresh, requestCountsRefresh } from './countsRefresh';

describe('counts refresh', () => {
  const offs: Array<() => void> = [];
  afterEach(() => offs.splice(0).forEach(off => off()));

  it('calls every subscriber once per request', () => {
    const a = vi.fn();
    const b = vi.fn();
    offs.push(onCountsRefresh(a), onCountsRefresh(b));
    requestCountsRefresh();
    expect(a).toHaveBeenCalledTimes(1);
    expect(b).toHaveBeenCalledTimes(1);
    requestCountsRefresh();
    expect(a).toHaveBeenCalledTimes(2);
  });

  it('stops calling a subscriber after it unsubscribes', () => {
    const a = vi.fn();
    const off = onCountsRefresh(a);
    off();
    requestCountsRefresh();
    expect(a).not.toHaveBeenCalled();
  });

  it('a failing subscriber does not block the others', () => {
    const bad = vi.fn(() => {
      throw new Error('network');
    });
    const good = vi.fn();
    offs.push(onCountsRefresh(bad), onCountsRefresh(good));
    expect(() => requestCountsRefresh()).not.toThrow();
    expect(good).toHaveBeenCalledTimes(1);
  });

  it('does nothing with no subscribers', () => {
    expect(() => requestCountsRefresh()).not.toThrow();
  });
});
