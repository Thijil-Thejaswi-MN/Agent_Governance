// Asks the layout to re-read its counts (the Approvals badge and the "running" chip) now,
// instead of waiting for its 5-second poll. Fired when a run changes state and right after a
// decision (Allow / Don't allow). Plain module-level listeners, so it needs no DOM.

type Listener = () => void;

const listeners = new Set<Listener>();

/** Subscribe; returns the unsubscribe function. */
export function onCountsRefresh(fn: Listener): () => void {
  listeners.add(fn);
  return () => {
    listeners.delete(fn);
  };
}

/** Tell every subscriber to refresh. One failing subscriber does not stop the others. */
export function requestCountsRefresh(): void {
  for (const fn of [...listeners]) {
    try {
      fn();
    } catch {
      // a refresh is best effort; the poll still runs
    }
  }
}
