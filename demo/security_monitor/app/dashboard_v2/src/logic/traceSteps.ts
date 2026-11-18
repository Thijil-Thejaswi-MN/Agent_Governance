// Transforms raw TaskStep[] from the server into trace rows for AgentTrace.
// Pure module; see traceSteps.test.ts.
import { TaskStep } from '../types';
import { Tone } from './tones';

export interface TraceRow {
  id: string;
  icon: string;        // lucide-react icon name
  title: string;
  description?: string;
  tone: Tone;
  detail?: string;
  live: boolean;
}

// Tool name -> lucide icon name
const TOOL_ICONS: Record<string, string> = {
  read_file: 'FileText',
  write_file: 'Pencil',
  http_get: 'Globe',
  call_agent: 'Bot',
  run_command: 'Terminal',
};

// Extract tool name from summary
function toolFromSummary(summary: string): string | null {
  if (summary.startsWith('run_command') || summary.startsWith('Command output reported')) {
    return 'run_command';
  }
  for (const tool of Object.keys(TOOL_ICONS)) {
    if (summary.startsWith(tool)) {
      return tool;
    }
  }
  return null;
}

// Extract the target from tool summary
function targetFromSummary(summary: string): string {
  if (summary.startsWith('Command output reported:')) {
    return summary.slice('Command output reported:'.length).trim();
  }
  const m = summary.match(/^(?:\w+(?:\s+\w+)?):\s*(.+)$/);
  if (m) return m[1].trim();
  const m2 = summary.match(/:\s*(.+)$/);
  return m2 ? m2[1].trim() : '';
}

// Plain past-tense title for a tool step
function toolTitle(summary: string, verdict: string): string {
  const tool = toolFromSummary(summary);
  const target = targetFromSummary(summary);
  const blocked = verdict === 'BLOCK_ACTION' || verdict === 'DENY' || verdict === 'BLOCKED';

  if (blocked) {
    switch (tool) {
      case 'read_file': return `Tried to read ${target || 'a file'}`;
      case 'write_file': return `Tried to write ${target || 'a file'}`;
      case 'http_get': return `Tried to reach ${target || 'a website'}`;
      case 'call_agent': return `Tried to call ${target || 'an agent'}`;
      case 'run_command': return `Tried to run a command`;
      default: return summary;
    }
  }

  switch (tool) {
    case 'read_file': return `Read ${target || 'a file'}`;
    case 'write_file': return `Wrote ${target || 'a file'}`;
    case 'http_get': return `Fetched ${target || 'a URL'}`;
    case 'call_agent': return `Called ${target || 'an agent'}`;
    case 'run_command': return target ? `Ran a command` : `Ran a command`;
    default: return summary;
  }
}

// Present-tense title for the live (current) tool step
function toolTitleLive(summary: string): string {
  const tool = toolFromSummary(summary);
  const target = targetFromSummary(summary);

  switch (tool) {
    case 'read_file': return `Reading ${target || 'a file'}`;
    case 'write_file': return `Writing ${target || 'a file'}`;
    case 'http_get': return `Reaching ${target || 'a URL'}`;
    case 'call_agent': return `Calling ${target || 'an agent'}`;
    case 'run_command': return `Running a command`;
    default: return summary;
  }
}

// Compute the duration in whole seconds between two ISO timestamps. Returns null if either is missing.
function durationSeconds(from: string | undefined, to: string | undefined): number | null {
  if (!from || !to) return null;
  const a = new Date(from).getTime();
  const b = new Date(to).getTime();
  if (Number.isNaN(a) || Number.isNaN(b)) return null;
  const diff = Math.round((b - a) / 1000);
  return diff >= 0 ? diff : null;
}

function durationLabel(seconds: number | null): string {
  if (seconds === null) return '';
  if (seconds === 0) return '';
  return `took ${seconds} s`;
}

function iconForTool(summary: string): string {
  const tool = toolFromSummary(summary);
  return (tool && TOOL_ICONS[tool]) || 'Circle';
}

function toneFromVerdict(verdict: string): Tone {
  const v = verdict.toUpperCase();
  if (v === 'BLOCK_ACTION' || v === 'DENY' || v === 'BLOCKED' || v === 'DENIED' || v === 'FAILED') return 'bad';
  if (v === 'PENDING') return 'wait';
  if (v === 'ALLOW' || v === 'APPROVED') return 'ok';
  return 'neutral';
}

// Group consecutive sensor steps with the same summary pattern into one row.
function groupSensors(steps: TaskStep[]): Array<{ steps: TaskStep[]; count: number }> {
  const groups: Array<{ steps: TaskStep[]; count: number }> = [];
  for (const step of steps) {
    if (step.kind !== 'sensor') {
      groups.push({ steps: [step], count: 1 });
      continue;
    }
    // Sensor grouping: group by layer + a simplified summary (drop the target path).
    const key = step.layer + ':' + (step.summary.replace(/on\s+\S+$/, '').trim());
    const last = groups[groups.length - 1];
    if (last && last.steps[0].kind === 'sensor') {
      const lastKey = last.steps[0].layer + ':' + last.steps[0].summary.replace(/on\s+\S+$/, '').trim();
      if (lastKey === key) {
        last.steps.push(step);
        last.count++;
        continue;
      }
    }
    groups.push({ steps: [step], count: 1 });
  }
  return groups;
}

function sensorTitle(summary: string, count: number): string {
  // "Landlock blocked file_read on /path" -> "The kernel saw a blocked file read"
  const m = summary.match(/blocked\s+(\S+)/i);
  const what = m ? m[1].replace(/_/g, ' ') : 'an action';
  if (count > 1) return `The kernel saw ${count} blocked ${what}s`;
  return `The kernel saw a blocked ${what}`;
}

export function buildTraceRows(
  steps: TaskStep[],
  runState: string,
): TraceRow[] {
  const isRunning = runState === 'running' || runState === 'preparing';
  const isWaiting = runState === 'waiting_approval';
  const grouped = groupSensors(steps);
  const rows: TraceRow[] = [];

  for (let gi = 0; gi < grouped.length; gi++) {
    const g = grouped[gi];
    const step = g.steps[0]; // representative step
    const isLast = gi === grouped.length - 1;
    const nextStep = gi + 1 < grouped.length ? grouped[gi + 1].steps[0] : undefined;

    switch (step.kind) {
      case 'model': {
        const dur = durationSeconds(step.timestamp, nextStep?.timestamp);
        const durStr = durationLabel(dur);
        const isLive = isLast && isRunning;
        rows.push({
          id: `trace-${step.step_number}`,
          icon: 'Brain',
          title: isLive ? 'Asking the model' : 'Asked the model',
          description: durStr || undefined,
          tone: 'neutral',
          detail: step.detail || undefined,
          live: isLive,
        });
        break;
      }

      case 'tool': {
        const isBlocked = step.verdict === 'BLOCK_ACTION' || step.verdict === 'DENY' || step.verdict === 'BLOCKED';
        const isLive = isLast && isRunning;
        const icon = iconForTool(step.summary);
        const title = isLive ? toolTitleLive(step.summary) : toolTitle(step.summary, step.verdict);
        const tone: Tone = isBlocked ? 'bad' : 'neutral';
        const desc = isBlocked ? 'stopped' : undefined;
        rows.push({
          id: `trace-${step.step_number}`,
          icon,
          title,
          description: desc,
          tone,
          detail: step.detail || undefined,
          live: isLive,
        });
        break;
      }

      case 'sensor': {
        const title = sensorTitle(step.summary, g.count);
        rows.push({
          id: `trace-${step.step_number}`,
          icon: 'Cpu',
          title,
          description: g.count > 1 ? `${g.count} times` : (step.summary.match(/on\s+(\S+)$/)?.[1] || undefined),
          tone: toneFromVerdict(step.verdict),
          detail: g.steps.map(s => s.detail || s.summary).join('\n'),
          live: false,
        });
        break;
      }

      case 'expansion': {
        const isBlocked = step.verdict === 'BLOCK_ACTION' || step.verdict === 'DENIED';
        const isApproved = step.verdict === 'APPROVED' || step.verdict === 'ALLOW';
        const isPending = step.verdict === 'PENDING';
        const isLive = isLast && (isWaiting || isRunning);
        const target = targetFromSummary(step.summary) || step.summary.match(/(?:for|requested for)\s+(.+?)(?:\s+\(|$)/)?.[1] || '';

        let title: string;
        let tone: Tone;
        let desc: string | undefined;

        if (isPending || (isLive && isWaiting)) {
          title = `Asked for ${target || 'more access'}`;
          tone = 'wait';
          desc = 'waiting for you';
        } else if (isApproved) {
          const by = step.summary.match(/by\s+(.+)$/)?.[1];
          title = `Asked for ${target || 'more access'}`;
          tone = 'ok';
          desc = `allowed${by ? ` by ${by}` : ''}`;
        } else if (isBlocked) {
          title = `Asked for ${target || 'more access'}`;
          tone = 'bad';
          desc = 'blocked';
        } else {
          title = `Asked for ${target || 'more access'}`;
          tone = 'neutral';
        }

        rows.push({
          id: `trace-${step.step_number}`,
          icon: 'Hand',
          title,
          description: desc,
          tone,
          detail: step.detail || undefined,
          live: isLive && isWaiting,
        });
        break;
      }

      case 'request_access': {
        // The expansion.py also records steps under 'expansion' kind; request_access from
        // broker_rpc is an event, not commonly a step. Map similarly to expansion.
        const target = step.summary.match(/(?:for|requested)\s+(.+?)(?:\s+\(|$)/)?.[1] || '';
        rows.push({
          id: `trace-${step.step_number}`,
          icon: 'Hand',
          title: `Asked for ${target || 'more access'}`,
          tone: toneFromVerdict(step.verdict),
          detail: step.detail || undefined,
          live: false,
        });
        break;
      }

      case 'staged_write': {
        const target = step.summary.match(/Staged\s+(.+?)\s+for/)?.[1] || '';
        rows.push({
          id: `trace-${step.step_number}`,
          icon: 'FilePen',
          title: `Staged ${target || 'a file'} for review`,
          tone: 'neutral',
          detail: step.detail || undefined,
          live: false,
        });
        break;
      }

      case 'phase': {
        // Phase steps: "Agent process launched", "Boundary derived", "Compiled Landlock", "Task execution finished"
        const isLive = isLast && isRunning;
        if (step.summary.startsWith('Agent process launched')) {
          rows.push({
            id: `trace-${step.step_number}`,
            icon: 'Play',
            title: isLive ? 'Starting in its own sandbox' : 'Started in its own sandbox',
            tone: 'neutral',
            detail: step.detail || undefined,
            live: isLive,
          });
        } else if (step.summary.toLowerCase().includes('finished')) {
          const lastRow = rows[rows.length - 1];
          if (!lastRow || lastRow.title !== 'Finished') {
            rows.push({
              id: `trace-${step.step_number}`,
              icon: 'CheckCircle2',
              title: 'Finished',
              tone: 'neutral',
              detail: step.detail || undefined,
              live: false,
            });
          }
        }
        break;
      }

      case 'output': {
        const m = step.summary.match(/Output file written:\s*(.+)/);
        const name = m ? m[1] : '';
        rows.push({
          id: `trace-${step.step_number}`,
          icon: 'FileOutput',
          title: name ? `Wrote ${name}` : 'Wrote output',
          tone: 'neutral',
          detail: step.detail || undefined,
          live: false,
        });
        break;
      }

      case 'receipt': {
        rows.push({
          id: `trace-${step.step_number}`,
          icon: 'FileCheck',
          title: 'Record saved and checked',
          tone: 'neutral',
          detail: step.detail || undefined,
          live: false,
        });
        break;
      }

      case 'termination': {
        // "Task execution halted (operator_stop)" or "Task lifecycle termination: agent_exited"
        const isStopped = step.summary.includes('operator_stop') || step.summary.includes('halted');
        const icon = isStopped ? 'StopCircle' : 'CircleStop';
        const title = isStopped ? 'Run was stopped' : 'Agent exited';
        rows.push({
          id: `trace-${step.step_number}`,
          icon,
          title,
          tone: isStopped ? 'bad' : 'neutral',
          detail: step.detail || undefined,
          live: false,
        });
        break;
      }

      case 'finished': {
        const lastRow = rows[rows.length - 1];
        if (!lastRow || lastRow.title !== 'Finished') {
          rows.push({
            id: `trace-${step.step_number}`,
            icon: 'CheckCircle2',
            title: 'Finished',
            tone: 'neutral',
            detail: step.detail || undefined,
            live: false,
          });
        }
        break;
      }

      default: {
        // Unknown kind: show summary as-is
        rows.push({
          id: `trace-${step.step_number}`,
          icon: 'Circle',
          title: step.summary || step.kind,
          tone: 'neutral',
          detail: step.detail || undefined,
          live: isLast && isRunning,
        });
        break;
      }
    }
  }

  return rows;
}
