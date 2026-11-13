import React, { useEffect, useMemo, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { CheckCircle2, Download, FileText, AlertTriangle, Square } from 'lucide-react';
import { api } from '../api/client';
import { useAuth } from '../context/AuthContext';
import { useRunTracker } from '../hooks/useRunTracker';
import { TaskEvent } from '../types';
import { Fence } from '../components/v3/Fence';
import { DecisionCard } from '../components/v3/DecisionCard';
import { DetailsDrawer, DetailsSection, KV } from '../components/v3/DetailsDrawer';
import { EventTable, TechnicalTimeline } from '../components/v3/TechnicalTimeline';
import { boundaryVersionLabel, receiptSentence, statusSentence } from '../logic/plain';
import { agentStarted, blockedAttempts, fileName, isTerminal, justBlocked, outputsFromSteps, OutputPreview } from '../logic/runView';

const STATUS_LABELS: Record<string, string> = {
  idle: 'Idle',
  preparing: 'Preparing sandbox',
  running: 'Running',
  waiting_approval: 'Waiting for Approval',
  stopping: 'Stopping',
  completed: 'Completed',
  stopped: 'Stopped',
  failed: 'Failed',
  timed_out: 'Timed out',
};

const uniq = (xs: string[]) => [...new Set(xs.filter(Boolean))];

export const WatchPage: React.FC<{ readOnly?: boolean }> = ({ readOnly = false }) => {
  const { taskId } = useParams<{ taskId: string }>();
  const { hasToken, openAuthModal, role } = useAuth();
  const run = useRunTracker(taskId);
  const [detailsOpen, setDetailsOpen] = useState(false);
  const [outputOpen, setOutputOpen] = useState(false);
  const [events, setEvents] = useState<TaskEvent[]>([]);

  const terminal = isTerminal(run.state);
  const live = !terminal;

  useEffect(() => {
    if (!readOnly || !taskId || !detailsOpen) return;
    api.getTaskEvents(taskId).then(setEvents).catch(() => setEvents([]));
  }, [readOnly, taskId, detailsOpen]);

  const attempts = useMemo(() => blockedAttempts(run.steps), [run.steps]);
  const lastBlock = useMemo(() => justBlocked(run.steps), [run.steps]);
  const started = agentStarted(run.steps);

  const insideNames = uniq([...(run.boundary?.files_read || []), ...(run.boundary?.files_write || [])].map(fileName));
  const requestedNames = run.pending ? [fileName(run.pending.resource_target)] : [];
  const deniedNames = run.expansions.filter(e => e.status === 'DENIED').map(e => fileName(e.resource_target));
  const blockedNames = uniq([...attempts.map(a => (a.action === 'run' ? 'a command' : a.name)), ...deniedNames]).filter(
    n => !insideNames.includes(n) && !requestedNames.includes(n),
  );

  const sentence = statusSentence({
    state: run.state,
    blocked: attempts,
    justBlocked: lastBlock,
    pending: run.pending,
    agentStarted: started,
    endReason: run.endReason,
  });

  const outputs: OutputPreview[] = run.outputFiles.length
    ? run.outputFiles.map(f => ({ path: f.path, name: f.name || fileName(f.path), content: f.content, size: f.size, truncated: f.truncated }))
    : outputsFromSteps(run.steps);
  const record = receiptSentence(run.receipt, run.receiptLoaded);

  const requireToken = (fn: () => void) => () => (hasToken ? fn() : openAuthModal());

  if (run.notFound) {
    return (
      <div className="max-w-xl mx-auto py-20 text-center space-y-4">
        <h1 className="font-display text-[28px] sm:text-[32px] font-bold m-0">We couldn't find that run.</h1>
        <Link to="/history" className="btn-ghost">
          Go to History
        </Link>
      </div>
    );
  }

  const stepColor = (k: 'ask' | 'work' | 'done') => {
    if (k === 'ask') return '#4ADE80';
    if (k === 'work') return terminal ? '#4ADE80' : run.state === 'waiting_approval' ? '#FBBF24' : '#60A5FA';
    return terminal ? (run.state === 'completed' ? '#4ADE80' : '#F87171') : 'var(--text-3)';
  };

  return (
    <div className="max-w-[1280px]">
      <div className="flex flex-wrap items-center justify-between gap-3 pb-5 border-b border-[#1F2633]">
        <ol aria-label="Progress" className="flex flex-wrap items-center gap-2.5 text-[14px] list-none p-0 m-0 min-h-[44px]" style={{ color: 'var(--text-3)' }}>
          {readOnly ? (
            <li>
              <Link to="/history">History</Link> <span aria-hidden="true">/</span> <span style={{ color: 'var(--text-2)' }}>One run</span>
            </li>
          ) : (
            <>
              <li style={{ color: stepColor('ask') }}>Ask</li>
              <li aria-hidden="true">—</li>
              <li style={{ color: stepColor('work'), fontWeight: terminal ? 400 : 600 }} aria-current={terminal ? undefined : 'step'}>
                {run.state === 'waiting_approval' ? 'Waiting for you' : 'Working'}
              </li>
              <li aria-hidden="true">—</li>
              <li style={{ color: stepColor('done'), fontWeight: terminal ? 600 : 400 }} aria-current={terminal ? 'step' : undefined}>
                Done
              </li>
            </>
          )}
        </ol>
        {!readOnly && !terminal && (
          <button
            id="stop-run-btn"
            onClick={requireToken(run.stop)}
            disabled={run.state === 'stopping'}
            className="btn-ghost min-h-[44px] sm:min-h-[40px]"
            style={{ borderColor: 'rgba(239,68,68,0.5)', color: '#FCA5A5' }}
          >
            <Square className="w-4 h-4" />
            {run.state === 'stopping' ? 'Stopping…' : 'Stop'}
          </button>
        )}
      </div>

      {(run.task?.comparison_mode || run.task?.condition === 'B') && (
        <div
          id="comparison-run-banner"
          role="status"
          className="mt-4 px-4 py-3 rounded-xl border border-[#F59E0B]/40 bg-[rgba(245,158,11,0.10)] text-[#FBBF24] text-[15px] font-medium flex items-center gap-2.5"
        >
          <AlertTriangle className="w-5 h-5 shrink-0 text-[#F59E0B]" />
          <span>Comparison run: kernel lock off, for demonstration</span>
        </div>
      )}

      <div className="pt-6 pb-10 flex flex-wrap items-center gap-8 lg:gap-12">
        <div className="flex-[1_1_420px] min-w-0 flex justify-center">
          <Fence inside={insideNames} blocked={blockedNames} requested={requestedNames} live={live} />
        </div>

        <section aria-label={run.pending ? 'Your decision' : 'What is happening'} className="flex-[1_1_380px] max-w-[540px] min-w-0 flex flex-col gap-5">
          <h1
            id="run-status"
            data-state={run.state}
            aria-live="polite"
            className="m-0 font-display font-bold text-[28px] sm:text-[36px] leading-[1.15] text-[#E6E9EF]"
          >
            {sentence}
          </h1>

          {run.pending && (
            <DecisionCard
              key={run.pending.request_id}
              exp={run.pending}
              triedBefore={attempts.some(a => a.name === fileName(run.pending!.resource_target))}
              deciding={run.deciding}
              readOnly={readOnly}
              canManageRules={role === 'admin' || role === 'security_reviewer'}
              onAllow={scope => (hasToken ? run.approve(run.pending!.request_id, scope) : openAuthModal())}
              onDeny={reason => (hasToken ? run.deny(run.pending!.request_id, reason) : openAuthModal())}
            />
          )}

          {!run.pending && !terminal && (
            <p className="m-0 text-[17px] leading-relaxed" style={{ color: 'var(--text-2)' }}>
              It can only touch what is inside the fence. If it needs anything more, it will ask you here.
            </p>
          )}

          {terminal && outputs.length > 0 && (
            <div
              className="card p-5 cursor-pointer hover:brightness-110 focus:outline-none focus-visible:ring-2 focus-visible:ring-[#2563EB]"
              id="output-preview"
              role="button"
              tabIndex={0}
              aria-label={`Open ${outputs[0].name}`}
              onClick={() => setOutputOpen(true)}
              onKeyDown={e => {
                if (e.key === 'Enter' || e.key === ' ') {
                  e.preventDefault();
                  setOutputOpen(true);
                }
              }}
            >
              <div className="flex items-center gap-2 text-[15px] font-semibold">
                <FileText className="w-4 h-4" style={{ color: 'var(--allowed)' }} />
                <span className="mono text-[14px]">{outputs[0].name}</span>
                {outputs.length > 1 && (
                  <span className="font-normal" style={{ color: 'var(--text-3)' }}>
                    and {outputs.length - 1} more
                  </span>
                )}
                <span className="ml-auto text-[13px] font-normal" style={{ color: 'var(--text-3)' }}>
                  Open
                </span>
              </div>
              <pre className="mt-3 mb-0 whitespace-pre-wrap text-[15px] leading-relaxed max-h-48 overflow-y-auto" style={{ fontFamily: 'Inter, sans-serif', color: 'var(--text)' }}>
                {outputs[0].content || '(empty file)'}
              </pre>
            </div>
          )}
          {terminal && outputs.length === 0 && run.receiptLoaded && (
            <p className="m-0 text-[16px]" style={{ color: 'var(--text-2)' }}>
              The agent did not write any output.
            </p>
          )}

          {terminal && (
            <div className="flex flex-wrap items-center gap-3">
              <span
                id="record-status"
                data-tone={record.tone}
                className="inline-flex items-center gap-2 min-h-[44px] px-4 rounded-lg text-[14px] font-semibold"
                style={
                  record.tone === 'ok'
                    ? { background: 'rgba(34,197,94,0.12)', border: '1px solid rgba(34,197,94,0.45)', color: '#86EFAC' }
                    : record.tone === 'bad'
                    ? { background: 'rgba(239,68,68,0.10)', border: '1px solid rgba(239,68,68,0.5)', color: '#FECACA' }
                    : { border: '1px solid var(--border-strong)', color: 'var(--text-2)' }
                }
              >
                {record.tone === 'ok' ? <CheckCircle2 className="w-4 h-4" /> : record.tone === 'bad' ? <AlertTriangle className="w-4 h-4" /> : null}
                {record.text}
              </span>
              {run.receipt?.receipt && run.receipt.available !== false && (
                <a id="download-record" href={api.getRawReceiptUrl(run.receipt.task_id)} download={`${run.receipt.task_id}_receipt.json`} className="btn-ghost min-h-[44px]">
                  <Download className="w-4 h-4" />
                  Download record
                </a>
              )}
            </div>
          )}

          {run.decisionNote && !run.pending && (
            <p id="decision-note" role="status" className="m-0 text-[15px] leading-relaxed" style={{ color: '#BBF7D0' }}>
              {run.decisionNote}
            </p>
          )}

          {run.actionError && (
            <div id="action-error" role="alert" className="px-4 py-3 rounded-xl text-[15px]" style={{ background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.45)', color: '#FECACA' }}>
              {run.actionError}
            </div>
          )}

          <div className="flex flex-wrap items-center gap-x-6 gap-y-1">
            <button id="show-what-happened" className="link-btn" onClick={() => setDetailsOpen(true)}>
              Show what happened ({run.steps.length} {run.steps.length === 1 ? 'step' : 'steps'})
            </button>
            {terminal && taskId && (
              <Link id="task-report-link" to={`/report/${taskId}`} className="text-[15px] inline-flex items-center min-h-[44px]">
                Task report
              </Link>
            )}
            {terminal && !readOnly && (
              <Link to="/run" className="text-[15px] inline-flex items-center min-h-[44px]">
                Start another
              </Link>
            )}
          </div>
        </section>
      </div>

      <DetailsDrawer open={outputOpen} title="Output files" onClose={() => setOutputOpen(false)} id="output-drawer">
        {outputs.map(f => (
          <DetailsSection key={f.path} title={f.path}>
            <div className="flex items-center gap-3 mb-2 text-[13px]" style={{ color: 'var(--text-3)' }}>
              {typeof f.size === 'number' && <span>{f.size} bytes</span>}
              {f.truncated && <span>Showing the first 20,000 bytes</span>}
              <button
                type="button"
                className="ml-auto inline-flex items-center gap-1.5 underline"
                style={{ color: 'var(--text-2)' }}
                onClick={() => {
                  const url = URL.createObjectURL(new Blob([f.content || ''], { type: 'text/plain;charset=utf-8' }));
                  const a = document.createElement('a');
                  a.href = url;
                  a.download = f.name;
                  a.click();
                  setTimeout(() => URL.revokeObjectURL(url), 1000);
                }}
              >
                <Download className="w-3.5 h-3.5" /> Download
              </button>
            </div>
            <pre className="m-0 whitespace-pre-wrap text-[14px] leading-relaxed mono" style={{ color: 'var(--text)' }}>
              {f.content || '(empty file)'}
            </pre>
          </DetailsSection>
        ))}
      </DetailsDrawer>

      <DetailsDrawer open={detailsOpen} title="What happened" onClose={() => setDetailsOpen(false)}>
        <DetailsSection title="Run">
          <KV k="Task" v={taskId} />
          <KV k="Status" v={STATUS_LABELS[run.state] || run.state} id="run-status-label" />
          {(run.endReason || run.stopNote) && <KV k="End reason" v={run.endReason || run.stopNote} id="run-end-reason" />}
          {run.stopNote && run.endReason && <KV k="Stop" v={run.stopNote} />}
          {run.streamNote && <KV k="Live updates" v={run.streamNote} id="stream-note" />}
          {run.task && <KV k="Agent" v={run.task.agent_id} />}
          {run.task && <KV k="Request" v={run.task.request_text} />}
          {run.task?.llm_provider && <KV k="Model provider" v={run.task.llm_provider} />}
        </DetailsSection>

        <DetailsSection title="Boundary (what the request allows)">
          {run.boundary ? (
            <>
              <KV
                k="Version"
                id="boundary-version"
                v={boundaryVersionLabel(run.boundary.version, run.expansions.filter(e => e.status === 'APPROVED').length)}
              />
              <KV k="Files read" v={(run.boundary.files_read || []).join(', ') || 'none'} />
              <KV k="Files write" v={(run.boundary.files_write || []).join(', ') || 'none'} />
              <KV k="Tools" v={(run.boundary.tools || []).join(', ') || 'none'} />
              <KV
                k="Network"
                v={(run.boundary.network || run.boundary.network_hosts || []).length ? (run.boundary.network || run.boundary.network_hosts || []).join(', ') : 'network: none'}
                id="network-marker"
              />
            </>
          ) : (
            <p style={{ color: 'var(--text-2)' }}>Not derived yet.</p>
          )}
          <p className="m-0 text-[13px] leading-relaxed" style={{ color: 'var(--text-2)' }}>
            Approved files are given to the agent as a read-only copy in granted/. The original path stays blocked.
          </p>
        </DetailsSection>

        {run.expansions.length > 0 && (
          <DetailsSection title="Expansion requests">
            {run.expansions.map(e => (
              <div key={e.request_id} className="p-3 rounded-[14px] space-y-0.5" style={{ background: 'var(--card-2)', border: '1px solid var(--line)' }}>
                <KV k="Request" v={e.request_id} />
                <KV k="Resource" v={`${e.resource_type}: ${e.resource_target}`} />
                <KV k="Status" v={e.status} />
                <KV k="Risk tier" v={`${e.baseline_risk_tier} → ${e.effective_risk_tier}`} />
                <KV k="Escalated by provenance" v={e.escalated_by_provenance || e.provenance_escalation ? 'yes: requested after reading untrusted content' : 'no'} />
                {(e.prior_untrusted_reads || []).map((pr, i) => (
                  <KV key={i} k="Untrusted read" v={`${pr.source_target}${pr.linked ? '  ★ mentions the requested resource' : ''}`} />
                ))}
                <KV k="Agent justification (untrusted)" v={`"${e.justification}"`} />
                {(e.resolved_by || e.decided_by) && <KV k="Decided by" v={e.resolved_by || e.decided_by} />}
                {(e.reason || e.denial_reason) && <KV k="Reason" v={e.reason || e.denial_reason} />}
                <KV k="Fail-closed timeout" v={`${e.timeout_seconds ?? 120} s`} />
              </div>
            ))}
          </DetailsSection>
        )}

        {terminal && (
          <DetailsSection title="Task Receipt">
            {run.receipt?.receipt && run.receipt.available !== false ? (
              <>
                <KV k="Hash chain" v={run.receipt.verified ? 'Verified (SHA-256 hash chain intact)' : `Does not verify: ${run.receipt.verification_message || 'mismatch'}`} id="receipt-verification" />
                <KV k="Final hash" v={run.receipt.final_hash || run.receipt.receipt?.hash_chain?.final_hash || 'n/a'} />
                <KV k="Chained events" v={run.receipt.receipt?.hash_chain?.count ?? run.receipt.receipt?.events?.length ?? 0} />
                {run.receipt.file_sha256 && <KV k="File SHA-256" v={run.receipt.file_sha256} />}
                <p className="m-0 text-[13px] leading-relaxed" style={{ color: 'var(--text-2)' }}>
                  Verification recomputes the SHA-256 chain. This detects edits to individual entries, but the receipt is not
                  signed: someone able to rewrite the whole file can recompute the chain. Check a download with{' '}
                  <code className="mono">scripts/verify_receipt.py</code>.
                </p>
              </>
            ) : (
              <p style={{ color: 'var(--text-2)' }}>{run.receiptLoaded ? 'No stored receipt found.' : 'Loading…'}</p>
            )}
          </DetailsSection>
        )}

        <DetailsSection title={`Timeline (${run.steps.length} steps)`}>
          <TechnicalTimeline steps={run.steps} />
        </DetailsSection>

        {readOnly && (
          <DetailsSection title={`Governance events (${events.length})`}>
            <EventTable events={events} />
          </DetailsSection>
        )}
      </DetailsDrawer>
    </div>
  );
};
