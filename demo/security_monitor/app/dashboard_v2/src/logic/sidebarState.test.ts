import { describe, expect, it } from 'vitest';
import { SIDEBAR_COLLAPSED_KEY, readCollapsed, safeLocalStorage, StorageLike, writeCollapsed } from './sidebarState';

const memory = (): StorageLike & { data: Record<string, string> } => {
  const data: Record<string, string> = {};
  return { data, getItem: k => (k in data ? data[k] : null), setItem: (k, v) => void (data[k] = v) };
};

const broken: StorageLike = {
  getItem: () => {
    throw new Error('SecurityError');
  },
  setItem: () => {
    throw new Error('QuotaExceededError');
  },
};

describe('sidebar collapse state', () => {
  it('starts expanded when nothing is stored', () => {
    expect(readCollapsed(memory())).toBe(false);
  });

  it('remembers collapsed and expanded', () => {
    const s = memory();
    writeCollapsed(s, true);
    expect(s.data[SIDEBAR_COLLAPSED_KEY]).toBe('1');
    expect(readCollapsed(s)).toBe(true);
    writeCollapsed(s, false);
    expect(readCollapsed(s)).toBe(false);
  });

  it('ignores values it did not write', () => {
    const s = memory();
    s.setItem(SIDEBAR_COLLAPSED_KEY, 'yes');
    expect(readCollapsed(s)).toBe(false);
  });

  it('works without storage: reads expanded, writes do nothing and never throw', () => {
    expect(readCollapsed(null)).toBe(false);
    expect(() => writeCollapsed(null, true)).not.toThrow();
    expect(readCollapsed(broken)).toBe(false);
    expect(() => writeCollapsed(broken, true)).not.toThrow();
  });

  it('safeLocalStorage returns null where there is no window', () => {
    expect(safeLocalStorage()).toBeNull();
  });
});
