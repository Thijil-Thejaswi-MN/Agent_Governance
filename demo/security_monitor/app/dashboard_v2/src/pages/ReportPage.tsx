import React, { useCallback, useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { Download, FileJson, Printer } from 'lucide-react';
import { api } from '../api/client';
import { ErrorState, LoadingState } from '../components/common/States';
import { outcomeLabel } from '../logic/plain';
import { getTone } from '../logic/tones';
import { PageHeader } from '../components/ui/PageHeader';
import { StatusPill } from '../components/ui/StatusPill';
import { Button } from '../components/ui/Button';
import {
  ReportApproval,
  ReportBlocked,
  TaskReport,
  addedLater,
  capRows,
  decisionLabel,
  formatWhen,
  layerLabel,
  recordLine,
} from '../logic/report';

const MAX_ROWS = 10;

/** The printable sheet. No effects, so tests can render it. */
export const ReportSheet: React.FC<{ report: TaskReport }> = ({ report }) => {
  const t = report.task;
  const approvals = capRows<ReportApproval>(report.approvals, MAX_ROWS);
  const blocked = capRows<ReportBlocked>(report.blocked, MAX_ROWS);
  const added = addedLater(report.boundary);
  const rec = recordLine(report.record);
  const initial = report.boundary.initial;
  // Comparison run (kernel lock off): attempts outside the boundary were not stopped.
  const isComparison = !!(report.task.comparison_mode || report.task.condition === 'B');
  const gotThrough = report.blocked.filter(b => b.layer === 'comparison_unlocked').length;
  const stopped = report.blocked.length - gotThrough;

  return (
    <article id="report-sheet" className="report-sheet flex flex-col gap-6 text-[14px] leading-relaxed">
      {(report.task.comparison_mode || report.task.condition === 'B') && (
        <div
          id="comparison-report-banner"
          role="status"
          className="px-4 py-3 rounded-xl border border-wait/40 bg-wait-tint text-wait-kpi text-[15px] font-medium flex items-center gap-2.5"
        >
          <span className="font-bold">Notice:</span>
          <span>Comparison run: kernel lock off, for demonstration</span>
        </div>
      )}

      <div className="p-6 sm:p-8 rounded-xl bg-surface-1 border border-line flex flex-col gap-6">
        <PageHeader
          title={t.request_text}
          subtitle={
            <span>
              <span className="font-mono">{t.task_id}</span> · generated {formatWhen(report.generated_at)}
            </span>
          }
          className="border-b border-line pb-4"
        />

        <section aria-label="Run" className="grid grid-cols-2 sm:grid-cols-4 gap-x-6 gap-y-3">
          <Fact k="Requested by" v={t.requester || '—'} id="report-requester" />
          <Fact k="Agent" v={t.agent_name || t.agent_id} id="report-agent" />
          <Fact k="Model" v={t.model || '—'} mono id="report-model" />
          <Fact
            k="Outcome"
            v={outcomeLabel(t.status).text}
            id="report-outcome"
            pill={<StatusPill tone={getTone(t.status)} label={outcomeLabel(t.status).text} />}
          />
          <Fact k="Agent owner" v={t.agent_owner ? `${t.agent_owner}${t.team ? ` (${t.team})` : ''}` : t.team || '—'} id="report-agent-owner" />
          <Fact k="Started" v={formatWhen(t.started_at || t.created_at)} nowrap />
          <Fact k="Ended" v={formatWhen(t.completed_at)} nowrap />
          <Fact k="Approvals" v={String(report.approvals.length)} />
          {isComparison ? (
            <Fact k="Got through (lock off)" v={String(gotThrough)} />
          ) : (
            <Fact k="Blocked actions" v={String(report.blocked.length)} />
          )}
        </section>
      </div>

      <Section title="Boundary" id="report-boundary">
        {initial ? (
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <ListFact k="Could read" items={initial.files_read} />
            <ListFact k="Could write" items={initial.files_write} />
            <ListFact k="Added after a decision" items={added} empty="nothing" />
          </div>
        ) : (
          <p className="m-0 text-fg-2">No boundary was stored for this run.</p>
        )}
      </Section>

      <Section title={`Approvals (${report.approvals.length})`} id="report-approvals">
        {report.approvals.length === 0 ? (
          <p className="m-0 text-fg-2">The agent asked for nothing beyond its boundary.</p>
        ) : (
          <Table
            head={['Asked for', 'Decision', 'Who', 'When']}
            rows={approvals.shown.map(a => [
              <span key="target" className="font-mono [overflow-wrap:anywhere] text-fg">{a.target}</span>,
              <span key="decision" className="inline-flex items-center gap-1.5 flex-wrap">
                <StatusPill tone={a.status === 'APPROVED' ? 'ok' : a.status === 'DENIED' ? 'bad' : 'wait'} label={decisionLabel(a)} />
                {a.prompted_by_file && <span className="text-fg-3 text-[12px]">· prompted by a file it read</span>}
              </span>,
              <span key="who" className="text-fg-2">{a.decided_by_label}</span>,
              <span key="when" className="text-fg-3 whitespace-nowrap">{formatWhen(a.decided_at)}</span>,
            ])}
            more={approvals.more}
          />
        )}
      </Section>

      <Section
        title={
          isComparison
            ? `Outside the boundary (${report.blocked.length}): ${gotThrough} got through with the kernel lock off${stopped ? `, ${stopped} stopped` : ''}`
            : `Blocked actions (${report.blocked.length})`
        }
        id="report-blocked"
      >
        {report.blocked.length === 0 ? (
          <p className="m-0 text-fg-2">Nothing was blocked.</p>
        ) : (
          <Table
            head={['Tried', isComparison ? 'Layer' : 'Stopped by', 'Result', 'When']}
            rows={blocked.shown.map(b => [
              <span key="tried" className="font-mono [overflow-wrap:anywhere] text-fg">{b.target || '—'}</span>,
              <span key="layer" className="text-fg-2">{b.layer === 'comparison_unlocked' ? 'None: kernel lock off (comparison mode)' : layerLabel(b.layer)}</span>,
              <span key="result" className="text-fg-2">{b.layer === 'comparison_unlocked' ? 'Got through: the private file was read (the kernel lock blocks this in a normal run)' : 'Attempted, not successful'}</span>,
              <span key="when" className="text-fg-3 whitespace-nowrap">{formatWhen(b.timestamp)}</span>,
            ])}
            more={blocked.more}
          />
        )}
      </Section>

      <Section title="Record" id="report-record">
        <div id="report-record-line" data-tone={rec.tone}>
          <StatusPill
            tone={rec.tone === 'ok' ? 'ok' : rec.tone === 'bad' ? 'bad' : 'neutral'}
            label={rec.text}
          />
        </div>
        {report.record.available && (
          <p className="m-0 text-[12px] [overflow-wrap:anywhere] text-fg-3">
            {report.record.event_count} hash-chained entries (SHA-256) · last link of the chain{' '}
            <span className="font-mono text-fg">{report.record.final_hash || '—'}</span>
          </p>
        )}
      </Section>
    </article>
  );
};

export const ReportPage: React.FC = () => {
  const { taskId } = useParams<{ taskId: string }>();
  const [report, setReport] = useState<TaskReport | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    if (!taskId) return;
    setError(null);
    api
      .getTaskReport(taskId)
      .then(setReport)
      .catch(err => setError(err?.message || 'Could not load the report.'));
  }, [taskId]);

  useEffect(load, [load]);

  const downloadJson = () => {
    if (!report) return;
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `task_report_${report.task.task_id}.json`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };

  return (
    <div className="max-w-[880px] pb-12 flex flex-col gap-5 font-sans">
      <div data-print-hide className="flex flex-wrap items-center gap-3">
        <Link to={taskId ? `/history/${taskId}` : '/history'} className="text-[14px] text-fg-2 hover:text-fg inline-flex items-center min-h-[44px]">
          ← Back to the run
        </Link>
        <span className="flex-1" />
        <Button id="report-print-btn" variant="primary" size="md" onClick={() => window.print()} disabled={!report} className="inline-flex items-center gap-2">
          <Printer className="w-4 h-4" aria-hidden="true" /> Print / Save as PDF
        </Button>
        <Button id="report-json-btn" variant="ghost" size="md" onClick={downloadJson} disabled={!report} className="inline-flex items-center gap-2">
          <FileJson className="w-4 h-4" aria-hidden="true" /> JSON
        </Button>
        {taskId && (
          <a id="report-csv-link" href={api.getTaskReportCsvUrl(taskId)} download className="no-underline inline-flex">
            <Button variant="ghost" size="md" className="inline-flex items-center gap-2">
              <Download className="w-4 h-4" aria-hidden="true" /> CSV
            </Button>
          </a>
        )}
      </div>
      {error ? (
        <ErrorState message={error} onRetry={load} id="report-error" />
      ) : !report ? (
        <LoadingState label="Building the report…" id="report-loading" />
      ) : (
        <ReportSheet report={report} />
      )}
    </div>
  );
};

const Fact: React.FC<{ k: string; v: string; mono?: boolean; id?: string; nowrap?: boolean; pill?: React.ReactNode }> = ({
  k,
  v,
  mono,
  id,
  nowrap,
  pill,
}) => (
  <div className="flex flex-col min-w-0">
    <span className="text-[12px] uppercase tracking-wider text-fg-3 font-semibold">
      {k}
    </span>
    <span id={id} className={`text-fg ${nowrap ? 'whitespace-nowrap' : '[overflow-wrap:anywhere]'} ${mono ? 'font-mono text-[13px]' : ''}`}>
      {pill || v}
    </span>
  </div>
);

const ListFact: React.FC<{ k: string; items: string[]; empty?: string }> = ({ k, items, empty = 'nothing' }) => (
  <div className="flex flex-col min-w-0">
    <span className="text-[12px] uppercase tracking-wider text-fg-3 font-semibold">
      {k}
    </span>
    <span className="font-mono text-[13px] text-fg [overflow-wrap:anywhere]">{items.length ? items.join(', ') : empty}</span>
  </div>
);

const Section: React.FC<{ title: string; id: string; children: React.ReactNode }> = ({ title, id, children }) => (
  <section id={id} className="p-6 sm:p-8 rounded-xl bg-surface-1 border border-line flex flex-col gap-3 break-inside-avoid">
    <h2 className="m-0 text-[12px] uppercase tracking-wider text-fg-3 font-semibold">{title}</h2>
    {children}
  </section>
);

const Table: React.FC<{ head: string[]; rows: React.ReactNode[][]; more: number }> = ({ head, rows, more }) => (
  <div className="overflow-x-auto rounded-xl border border-line bg-surface-1">
    <table className="w-full text-left text-[13px] border-collapse">
      <thead>
        <tr className="bg-surface-2 text-[12px] uppercase tracking-wider text-fg-3 font-semibold border-b border-line">
          {head.map(h => (
            <th key={h} className="px-4 py-2.5 font-medium">
              {h}
            </th>
          ))}
        </tr>
      </thead>
      <tbody className="divide-y divide-line">
        {rows.map((r, i) => (
          <tr key={i} className="h-11 min-h-[44px] hover:bg-surface-2/50 transition-colors">
            {r.map((c, j) => (
              <td key={j} className="px-4 py-2.5 text-fg align-middle">
                {c}
              </td>
            ))}
          </tr>
        ))}
      </tbody>
    </table>
    {more > 0 && (
      <p className="m-0 p-3 text-[12px] text-fg-3 border-t border-line">
        and {more} more in the CSV and JSON downloads
      </p>
    )}
  </div>
);
