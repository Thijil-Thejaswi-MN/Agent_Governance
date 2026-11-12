import { api } from './client';
import { TaskEvent } from '../types';
import { startOfLocalDay } from '../logic/teamStats';

/** Events since local midnight, oldest first (up to 5 pages of 500). */
export async function loadTodayEvents(now: number): Promise<TaskEvent[]> {
  let since = new Date(startOfLocalDay(now)).toISOString();
  const out: TaskEvent[] = [];
  for (let i = 0; i < 5; i++) {
    const res = await api.getEvents(since, 500);
    out.push(...res.events);
    if (res.events.length < 500 || !res.cursor || res.cursor === since) break;
    since = res.cursor;
  }
  return out;
}

/** Events of the last 24 hours (covers both "today" and "last 24 hours" views). */
export async function loadRecentEvents(now: number): Promise<TaskEvent[]> {
  const from = Math.min(startOfLocalDay(now), now - 24 * 3600_000);
  let since = new Date(from).toISOString();
  const out: TaskEvent[] = [];
  for (let i = 0; i < 5; i++) {
    const res = await api.getEvents(since, 500);
    out.push(...res.events);
    if (res.events.length < 500 || !res.cursor || res.cursor === since) break;
    since = res.cursor;
  }
  return out;
}
