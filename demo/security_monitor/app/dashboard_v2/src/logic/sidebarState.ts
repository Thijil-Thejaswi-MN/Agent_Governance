// Whether the desktop sidebar is collapsed to icons, remembered per browser. Storage can be
// missing or throw (private mode, blocked site data), so every access is guarded and the
// sidebar simply starts expanded.

export const SIDEBAR_COLLAPSED_KEY = 'ag.sidebar.collapsed';

export type StorageLike = Pick<Storage, 'getItem' | 'setItem'>;

export function safeLocalStorage(): StorageLike | null {
  try {
    return typeof window !== 'undefined' && window.localStorage ? window.localStorage : null;
  } catch {
    return null;
  }
}

export function readCollapsed(storage: StorageLike | null): boolean {
  try {
    return storage?.getItem(SIDEBAR_COLLAPSED_KEY) === '1';
  } catch {
    return false;
  }
}

export function writeCollapsed(storage: StorageLike | null, collapsed: boolean): void {
  try {
    storage?.setItem(SIDEBAR_COLLAPSED_KEY, collapsed ? '1' : '0');
  } catch {
    // not remembered; the toggle still works for this page view
  }
}
