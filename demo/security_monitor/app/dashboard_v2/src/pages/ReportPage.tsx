import React, { useCallback, useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { Download, FileJson, Printer } from 'lucide-react';
import { api } from '../api/client';
import { ErrorState, LoadingState } from '../components/common/States';
import { outcomeLabel } from '../logic/plain';
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

const TONE = { ok: '#16A34A', bad: '#DC2626', none: 'var(--text-2)' } as const;

/** The printable sheet. No effects, so tests can render it. */
export const ReportSheet: React.FC<{ report: TaskReport }> = ({ report }) => {
  const t = report.task;
  const approvals = capRows<ReportApproval>(report.approvals, MAX_ROWS);
  const blocked = capRows<ReportBlocked>(report.blocked, MAX_ROWS);
  const added = addedLater(report.boundary);
  const rec = recordLine(report.record);
  const initial = report.boundary.initial;

  return (
    <article id="report-sheet" className="report-sheet card p-6 sm:p-8 flex flex-col gap-6 text-[14px] leading-relaxed">
      <header className="flex flex-col gap-1 border-b border-[#1F2633] pb-4">
        <p className="m-0 text-[12px] uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>
          Task report
        </p>
        <h1 className="m-0 font-display font-bold text-[22px] sm:text-[26px] leading-tight text-[#E6E9EF] [overflow-wrap:anywhere]">
          {t.request_text}
        </h1>
        <p className="m-0 text-[13px]" style={{ color: 'var(--text-2)' }}>
          <span className="font-mono">{t.task_id}</span> · generated {formatWhen(report.generated_at)}
        </p>
      </header>

      <section aria-label="Run" className="grid grid-cols-2 sm:grid-cols-4 gap-x-6 gap-y-3">
        <Fact k="Requested by" v={t.requester || '—'} id="report-requester" />
        <Fact k="Agent" v={t.agent_id} mono />
        <Fact k="Outcome" v={outcomeLabel(t.status).text} id="report-outcome" />
        <Fact k="Team" v={t.team || '—'} />
        <Fact k="Started" v={formatWhen(t.started_at || t.created_at)} />
        <Fact k="Ended" v={formatWhen(t.completed_at)} />
        <Fact k="Approvals" v={String(report.approvals.length)} />
        <Fact k="Blocked actions" v={String(report.blocked.length)} />
      </section>

      <Section title="Boundary" id="report-boundary">
        {initial ? (
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <ListFact k="Could read" items={initial.files_read} />
            <ListFact k="Could write" items={initial.files_write} />
            <ListFact k="Added after a decision" items={added} empty="nothing" />
          </div>
        ) : (
          <p className="m-0" style={{ color: 'var(--text-2)' }}>No boundary was stored for this run.</p>
        )}
      </Section>

      <Section title={`Approvals (${report.approvals.length})`} id="report-approvals">
        {report.approvals.length === 0 ? (
          <p className="m-0" style={{ color: 'var(--text-2)' }}>The agent asked for nothing beyond its boundary.</p>
        ) : (
          <Table
            head={['Asked for', 'Decision', 'Who', 'When']}
            rows={approvals.shown.map(a => [
              <span className="font-mono [overflow-wrap:anywhere]">{a.target}</span>,
              <span>
                {decisionLabel(a)}
                {a.prompted_by_file && <span style={{ color: 'var(--text-3)' }}> · prompted by a file it read</span>}
              </span>,
              a.decided_by_label,
              formatWhen(a.decided_at),
            ])}
            more={approvals.more}
          />
        )}
      </Section>

      <Section title={`Blocked actions (${report.blocked.length})`} id="report-blocked">
        {report.blocked.length === 0 ? (
          <p className="m-0" style={{ color: 'var(--text-2)' }}>Nothing was blocked.</p>
        ) : (
          <Table
            head={['Tried', 'Stopped by', 'Result', 'When']}
            rows={blocked.shown.map(b => [
              <span className="font-mono [overflow-wrap:anywhere]">{b.target || '—'}</span>,
              layerLabel(b.layer),
              'Attempted, not successful',
              formatWhen(b.timestamp),
            ])}
            more={blocked.more}
          />
        )}
      </Section>

      <Section title="Record" id="report-record">
        <p className="m-0 font-semibold" style={{ color: TONE[rec.tone] }} id="report-record-line" data-tone={rec.tone}>
          {rec.text}
        </p>
        {report.record.available && (
          <p className="m-0 text-[12px] [overflow-wrap:anywhere]" style={{ color: 'var(--text-3)' }}>
            {report.record.event_count} hash-chained entries (SHA-256) · final hash{' '}
            <span className="font-mono">{report.record.final_hash || '—'}</span>
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
    <div className="max-w-[880px] pb-12 flex flex-col gap-5">
      <div data-print-hide className="flex flex-wrap items-center gap-3">
        <Link to={taskId ? `/history/${taskId}` : '/history'} className="text-[15px] inline-flex items-center min-h-[44px]">
          ← Back to the run
        </Link>
        <span className="flex-1" />
        <button id="report-print-btn" type="button" className="btn-primary min-h-[44px] px-5 inline-flex items-center gap-2" onClick={() => window.print()} disabled={!report}>
          <Printer className="w-4 h-4" aria-hidden="true" /> Print / Save as PDF
        </button>
        <button id="report-json-btn" type="button" className="btn-ghost min-h-[44px] px-4 inline-flex items-center gap-2" onClick={downloadJson} disabled={!report}>
          <FileJson className="w-4 h-4" aria-hidden="true" /> JSON
        </button>
        {taskId && (
          <a id="report-csv-link" href={api.getTaskReportCsvUrl(taskId)} download className="btn-ghost min-h-[44px] px-4 inline-flex items-center gap-2 no-underline">
            <Download className="w-4 h-4" aria-hidden="true" /> CSV
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

const Fact: React.FC<{ k: string; v: string; mono?: boolean; id?: string }> = ({ k, v, mono, id }) => (
  <div className="flex flex-col min-w-0">
    <span className="text-[12px]" style={{ color: 'var(--text-3)' }}>
      {k}
    </span>
    <span id={id} className={`text-[#E6E9EF] [overflow-wrap:anywhere] ${mono ? 'font-mono text-[13px]' : ''}`}>
      {v}
    </span>
  </div>
);

const ListFact: React.FC<{ k: string; items: string[]; empty?: string }> = ({ k, items, empty = 'nothing' }) => (
  <div className="flex flex-col min-w-0">
    <span className="text-[12px]" style={{ color: 'var(--text-3)' }}>
      {k}
    </span>
    <span className="font-mono text-[13px] text-[#E6E9EF] [overflow-wrap:anywhere]">{items.length ? items.join(', ') : empty}</span>
  </div>
);

const Section: React.FC<{ title: string; id: string; children: React.ReactNode }> = ({ title, id, children }) => (
  <section id={id} className="flex flex-col gap-2 break-inside-avoid">
    <h2 className="m-0 text-[15px] font-semibold text-[#E6E9EF]">{title}</h2>
    {children}
  </section>
);

const Table: React.FC<{ head: string[]; rows: React.ReactNode[][]; more: number }> = ({ head, rows, more }) => (
  <div className="overflow-x-auto">
    <table className="w-full text-left text-[13px] border-collapse">
      <thead>
        <tr className="border-b border-[#1F2633]" style={{ color: 'var(--text-3)' }}>
          {head.map(h => (
            <th key={h} className="py-1.5 pr-3 font-normal text-[12px]">
              {h}
            </th>
          ))}
        </tr>
      </thead>
      <tbody>
        {rows.map((r, i) => (
          <tr key={i} className="border-b border-[#1F2633] align-top">
            {r.map((c, j) => (
              <td key={j} className="py-1.5 pr-3 text-[#E6E9EF]">
                {c}
              </td>
            ))}
          </tr>
        ))}
      </tbody>
    </table>
    {more > 0 && (
      <p className="m-0 mt-1.5 text-[12px]" style={{ color: 'var(--text-3)' }}>
        and {more} more in the CSV and JSON downloads
      </p>
    )}
  </div>
);
