// Follows one task: the live stream (it replays stored steps first), a stall watchdog that
// falls back to stored state, the pending decision, and the end-of-run output and record.
// Every run ends visibly in a terminal state; nothing is shown that the server did not report.
import { useCallback, useEffect, useRef, useState } from 'react';
import { api } from '../api/client';
import { ExpansionItem, ReceiptResponse, RunOutputFile, TaskBoundary, TaskRecord, TaskStep } from '../types';
import { RunState, TERMINAL_STATES, isAgentLaunchStep } from '../logic/runView';

// No step for this long (or a stream error) -> stop trusting the stream and read stored state.
const STREAM_STALL_MS = 20000;
const POLL_INTERVAL_MS = 2000;
// Same rule as the fleet summary (fleet.py STALE_STEPS_AFTER_S).
const STALE_STEPS_AFTER_MS = 15 * 60 * 1000;

const TASK_STATUS_TO_STATE: Record<string, RunState> = {
  COMPLETED: 'completed',
  FAILED: 'failed',
  TERMINATED: 'stopped',
  EXPIRED: 'timed_out',
};

export interface RunTracker {
  state: RunState;
  steps: TaskStep[];
  task: TaskRecord | null;
  boundary: TaskBoundary | null;
  notFound: boolean;
  endReason: string | null;
  streamNote: string | null;
  stopNote: string | null;
  pending: ExpansionItem | null;
  expansions: ExpansionItem[];
  outputFiles: RunOutputFile[];
  receipt: ReceiptResponse | null;
  receiptLoaded: boolean;
  actionError: string | null;
  deciding: boolean;
  stop: () => Promise<void>;
  approve: (requestId: string) => Promise<void>;
  deny: (requestId: string, reason: string) => Promise<void>;
}

export function useRunTracker(taskId: string | undefined): RunTracker {
  const [state, setState] = useState<RunState>('preparing');
  const [steps, setSteps] = useState<TaskStep[]>([]);
  const [task, setTask] = useState<TaskRecord | null>(null);
  const [boundary, setBoundary] = useState<TaskBoundary | null>(null);
  const [notFound, setNotFound] = useState(false);
  const [endReason, setEndReason] = useState<string | null>(null);
  const [streamNote, setStreamNote] = useState<string | null>(null);
  const [stopNote, setStopNote] = useState<string | null>(null);
  const [pending, setPending] = useState<ExpansionItem | null>(null);
  const [expansions, setExpansions] = useState<ExpansionItem[]>([]);
  const [outputFiles, setOutputFiles] = useState<RunOutputFile[]>([]);
  const [receipt, setReceipt] = useState<ReceiptResponse | null>(null);
  const [receiptLoaded, setReceiptLoaded] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [deciding, setDeciding] = useState(false);

  const concludedRef = useRef<string | null>(null);
  const stateRef = useRef<RunState>('preparing');
  stateRef.current = state;

  const loadTask = useCallback(async (id: string) => {
    try {
      const detail = await api.getTaskDetail(id);
      setTask(detail.task);
      setBoundary(detail.boundary);
      setNotFound(false);
      return detail.task;
    } catch (err: any) {
      if (err?.status === 404) setNotFound(true);
      return null;
    }
  }, []);

  // The stored expansion list is the source of truth for "is a decision waiting?".
  const loadExpansions = useCallback(async (id: string) => {
    try {
      const all = await api.getExpansions(id);
      setExpansions(all);
      const waiting = all.find(e => e.status === 'PENDING') || null;
      setPending(waiting);
      if (concludedRef.current === id) return;
      setState(s => (waiting ? (TERMINAL_STATES.includes(s) || s === 'stopping' ? s : 'waiting_approval') : s === 'waiting_approval' ? 'running' : s));
    } catch {
      // keep what we have
    }
  }, []);

  const loadConcluded = useCallback(async (id: string) => {
    const [outputResp, receiptResp] = await Promise.all([
      api.getRunOutput(id).catch(() => ({ task_id: id, files: [] as RunOutputFile[] })),
      api.getTaskReceipt(id).catch(() => null),
    ]);
    setOutputFiles(outputResp.files || []);
    setReceipt(receiptResp);
    setReceiptLoaded(true);
  }, []);

  // Ends the run in the UI exactly once, with the server-reported terminal state.
  const conclude = useCallback(
    (id: string, terminal: string, reason: string) => {
      if (concludedRef.current === id) return;
      concludedRef.current = id;
      setState(TERMINAL_STATES.includes(terminal as RunState) ? (terminal as RunState) : 'failed');
      setEndReason(reason || null);
      setPending(null);
      loadTask(id);
      loadExpansions(id);
      loadConcluded(id);
    },
    [loadTask, loadExpansions, loadConcluded],
  );

  const onStep = useCallback(
    (id: string, step: TaskStep) => {
      if (isAgentLaunchStep(step)) setState(s => (s === 'preparing' ? 'running' : s));
      if (step.kind === 'expansion') {
        loadExpansions(id);
        loadTask(id); // an approval widens the fence
      }
    },
    [loadExpansions, loadTask],
  );

  // Reads stored steps + task status and shows the real state. Returns true once terminal.
  const reconcile = useCallback(
    async (id: string): Promise<boolean> => {
      try {
        const polled = await api.getRunSteps(id, 0);
        setSteps(polled);
        const finished = polled.find(s => s.kind === 'finished');
        if (finished) {
          conclude(id, finished.verdict.toLowerCase(), finished.detail);
          return true;
        }
        if (polled.some(isAgentLaunchStep)) setState(s => (s === 'preparing' ? 'running' : s));
        await loadExpansions(id);

        const active = await api.getActiveRun();
        if (active.active && active.task_id === id) return false;
        const t = await loadTask(id);
        if (t) {
          const terminal = TASK_STATUS_TO_STATE[t.status];
          if (terminal) {
            conclude(id, terminal, `task status ${t.status}`);
            return true;
          }
          // Not run from this console (e.g. a CLI launch) but still going: keep following it.
          // The launcher keeps a task PENDING until it ends, so recent non-terminal steps count.
          const lastStepAt = Math.max(0, ...polled.map(s => Date.parse(s.timestamp) || 0));
          const stillGoing =
            t.status === 'ACTIVE' ||
            (t.status === 'PENDING' &&
              polled.length > 0 &&
              !polled.some(s => ['finished', 'termination', 'receipt'].includes(s.kind)) &&
              Date.now() - lastStepAt < STALE_STEPS_AFTER_MS);
          if (stillGoing) {
            setState(s => (s === 'preparing' ? 'running' : s));
            return false;
          }
        }
        conclude(id, 'failed', 'The run is no longer active and ended without a terminal event.');
        return true;
      } catch (err: any) {
        setStreamNote(`Could not read run state: ${err.message || err}`);
        return err?.status === 401;
      }
    },
    [conclude, loadExpansions, loadTask],
  );

  useEffect(() => {
    if (!taskId) return;
    const id = taskId;
    concludedRef.current = null;
    setState('preparing');
    setSteps([]);
    setEndReason(null);
    setStreamNote(null);
    setStopNote(null);
    setPending(null);
    setOutputFiles([]);
    setReceipt(null);
    setReceiptLoaded(false);
    setActionError(null);
    loadTask(id);
    loadExpansions(id);

    let ended = false;
    let watchdog: ReturnType<typeof setTimeout> | null = null;
    let pollTimer: ReturnType<typeof setInterval> | null = null;
    const es = new EventSource(api.getRunStreamUrl(id), { withCredentials: true });

    const startFallback = (note: string) => {
      if (ended || pollTimer) return;
      es.close();
      if (watchdog) clearTimeout(watchdog);
      setStreamNote(note);
      const tick = async () => {
        if (ended) return;
        if (await reconcile(id)) {
          ended = true;
          if (pollTimer) clearInterval(pollTimer);
        }
      };
      pollTimer = setInterval(tick, POLL_INTERVAL_MS);
      tick();
    };

    const armWatchdog = () => {
      if (watchdog) clearTimeout(watchdog);
      watchdog = setTimeout(
        () => startFallback(`No update from the live stream for ${STREAM_STALL_MS / 1000} s; showing stored state.`),
        STREAM_STALL_MS,
      );
    };

    es.onmessage = event => {
      armWatchdog();
      let step: TaskStep;
      try {
        step = JSON.parse(event.data);
      } catch {
        return;
      }
      setSteps(prev =>
        prev.some(s => s.step_number === step.step_number) ? prev : [...prev, step].sort((a, b) => a.step_number - b.step_number),
      );
      onStep(id, step);
    };

    es.addEventListener('end', event => {
      ended = true;
      es.close();
      if (watchdog) clearTimeout(watchdog);
      try {
        const data = JSON.parse((event as MessageEvent).data);
        conclude(id, data.state, data.reason);
      } catch {
        conclude(id, 'failed', 'Malformed end event');
      }
    });

    es.onerror = () => startFallback('Live stream interrupted; showing stored state.');
    armWatchdog();

    return () => {
      ended = true;
      es.close();
      if (watchdog) clearTimeout(watchdog);
      if (pollTimer) clearInterval(pollTimer);
    };
  }, [taskId, conclude, loadExpansions, loadTask, onStep, reconcile]);

  // Stop: the stream's end event (or the stored state) reports when it has really stopped.
  const stop = useCallback(async () => {
    if (!taskId) return;
    setActionError(null);
    try {
      const res = await api.stopRun(taskId);
      setState(s => (TERMINAL_STATES.includes(s) ? s : 'stopping'));
      setStopNote(res.killed ? 'Task cgroup killed.' : 'Cancelled before the agent started.');
    } catch (err: any) {
      setActionError(err.message || 'Could not stop the run.');
    }
  }, [taskId]);

  const approve = useCallback(
    async (requestId: string) => {
      setDeciding(true);
      setActionError(null);
      try {
        await api.approveExpansion(requestId, { decided_by: 'operator', reason: 'Allowed for this run in the console' });
        setPending(null);
        setState(s => (s === 'waiting_approval' ? 'running' : s));
        if (taskId) {
          loadTask(taskId);
          loadExpansions(taskId);
        }
      } catch (err: any) {
        setActionError(err.message || 'Could not record the decision.');
      } finally {
        setDeciding(false);
      }
    },
    [taskId, loadTask, loadExpansions],
  );

  const deny = useCallback(
    async (requestId: string, reason: string) => {
      if (!reason.trim()) {
        setActionError('Please give a short reason.');
        return;
      }
      setDeciding(true);
      setActionError(null);
      try {
        await api.denyExpansion(requestId, { decided_by: 'operator', reason: reason.trim() });
        setPending(null);
        setState(s => (s === 'waiting_approval' ? 'running' : s));
        if (taskId) loadExpansions(taskId);
      } catch (err: any) {
        setActionError(err.message || 'Could not record the decision.');
      } finally {
        setDeciding(false);
      }
    },
    [taskId, loadExpansions],
  );

  return {
    state,
    steps,
    task,
    boundary,
    notFound,
    endReason,
    streamNote,
    stopNote,
    pending,
    expansions,
    outputFiles,
    receipt,
    receiptLoaded,
    actionError,
    deciding,
    stop,
    approve,
    deny,
  };
}
