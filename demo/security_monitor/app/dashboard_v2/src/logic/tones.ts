export type Tone = 'ok' | 'bad' | 'wait' | 'info' | 'neutral';

/**
 * Maps system execution states and verdict actions to semantic design tones.
 * ALLOW / APPROVED / COMPLETED -> ok
 * BLOCK_ACTION / DENIED / FAILED / KILLED -> bad
 * PENDING / waiting_approval -> wait
 * running / preparing -> info
 * other -> neutral
 */
export function getTone(status: string | null | undefined): Tone {
  if (!status) return 'neutral';
  const s = status.trim();
  const upper = s.toUpperCase();
  const lower = s.toLowerCase();

  if (upper === 'ALLOW' || upper === 'APPROVED' || upper === 'COMPLETED') {
    return 'ok';
  }

  if (
    upper === 'BLOCK_ACTION' ||
    upper === 'DENIED' ||
    upper === 'FAILED' ||
    upper === 'KILLED'
  ) {
    return 'bad';
  }

  if (upper === 'PENDING' || lower === 'waiting_approval') {
    return 'wait';
  }

  if (lower === 'running' || lower === 'preparing') {
    return 'info';
  }

  return 'neutral';
}

export const statusToTone = getTone;
export const verdictToTone = getTone;
