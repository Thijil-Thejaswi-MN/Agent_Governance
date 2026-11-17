// The run's progress pill (Watch page): which phase a run is in, from its real state only.
// Nothing here advances on a timer: a phase changes when the server says the run moved on.

import type { RunState } from './runView';
import { isTerminal } from './runView';

export type PhaseId = 'setup' | 'working' | 'waiting' | 'record' | 'end';

export interface Phase {
  id: PhaseId;
  label: string;
}

export interface RunPhaseView {
  phases: Phase[];
  current: number; // index into phases
  label: string; // what the pill says now
  tone: 'busy' | 'ask' | 'ok' | 'bad';
  finished: boolean;
}

const END_LABEL: Record<string, string> = {
  completed: 'Done',
  stopped: 'Stopped',
  failed: 'Failed',
  timed_out: 'Timed out',
};

export function runPhase(state: RunState, agentStarted: boolean, waiting: boolean, receiptLoaded: boolean): RunPhaseView {
  const terminal = isTerminal(state);
  const endLabel = END_LABEL[state] || 'Done';
  const phases: Phase[] = [
    { id: 'setup', label: 'Setting up the task' },
    { id: 'working', label: 'Agent working' },
    { id: 'waiting', label: 'Waiting for you' },
    { id: 'record', label: 'Writing the record' },
    { id: 'end', label: terminal ? endLabel : 'Done' },
  ];
  const at = (id: PhaseId) => phases.findIndex(p => p.id === id);
  let current: number;
  if (terminal) current = receiptLoaded ? at('end') : at('record');
  else if (state === 'stopping') current = at('record');
  else if (state === 'waiting_approval' || waiting) current = at('waiting');
  else if (state === 'running' && agentStarted) current = at('working');
  else current = at('setup');

  const finished = terminal && receiptLoaded;
  const tone: RunPhaseView['tone'] = finished
    ? state === 'completed'
      ? 'ok'
      : 'bad'
    : phases[current].id === 'waiting'
      ? 'ask'
      : 'busy';
  const label = state === 'stopping' ? 'Stopping, writing the record' : phases[current].label;
  return { phases, current, label, tone, finished };
}
