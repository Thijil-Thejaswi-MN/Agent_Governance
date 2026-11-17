import React, { useEffect, useMemo, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { CheckCircle2, Download, FileText, AlertTriangle, Square } from 'lucide-react';
import { api } from '../api/client';
import { useAuth } from '../context/AuthContext';
import { GrantList, cancellableGrants } from '../components/v3/GrantList';
import { useRunTracker } from '../hooks/useRunTracker';
import { RunFile, TaskEvent } from '../types';
import { Fence } from '../components/v3/Fence';
import { DecisionCard } from '../components/v3/DecisionCard';
import { DetailsDrawer, DetailsSection, KV } from '../components/v3/DetailsDrawer';
import { EventTable, TechnicalTimeline } from '../components/v3/TechnicalTimeline';
import { boundaryVersionLabel, receiptSentence, statusSentence } from '../logic/plain';
import { runPhase } from '../logic/runPhase';
import { RunProgress } from '../components/action/RunProgress';
import { agentStarted, blockedAttempts, boundaryLabel, fenceBlocked, splitAttempts, fileName, isTerminal, justBlocked, outputsFromSteps, OutputPreview } from '../logic/runView';
import { Button } from '../components/ui/Button';
import { PageHeader } from '../components/ui/PageHeader';

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
  // A file opened from its chip: the input with the hidden note, the output, or the private file.
  const [openName, setOpenName] = useState<string | null>(null);
  const [fileView, setFileView] = useState<RunFile | null>(null);
  const [fileError, setFileError] = useState<string | null>(null);
  useEffect(() => {
    if (!taskId || !openName) return;
    setFileView(null);
    setFileError(null);
    api
      .getRunFile(taskId, openName)
      .then(setFileView)
      .catch(() => setFileError("This file can't be opened here: it is not in the run's folder, or the run started before this update."));
  }, [taskId, openName]);
  const [events, setEvents] = useState<TaskEvent[]>([]);
  const [agentNames, setAgentNames] = useState<Record<string, string>>({});
  useEffect(() => {
    api
      .getRunAgents()
      .then(list => setAgentNames(Object.fromEntries(list.map(a => [a.id, a.name]))))
      .catch(() => undefined);
  }, []);

  const terminal = isTerminal(run.state);
  const live = !terminal;

  useEffect(() => {
    if (!readOnly || !taskId || !detailsOpen) return;
    api.getTaskEvents(taskId).then(setEvents).catch(() => setEvents([]));
  }, [readOnly, taskId, detailsOpen]);

  const attempts = useMemo(() => blockedAttempts(run.steps), [run.steps]);
  const split = useMemo(() => splitAttempts(run.steps), [run.steps]);
  const lastBlock = useMemo(() => justBlocked(run.steps), [run.steps]);
  const started = agentStarted(run.steps);

  const insideNames = uniq([...(run.boundary?.files_read || []), ...(run.boundary?.files_write || [])].map(boundaryLabel));
  const requestedNames = run.pending ? [fileName(run.pending.resource_target)] : [];
  const deniedNames = run.expansions.filter(e => e.status === 'DENIED' || e.status === 'REVOKED').map(e => fileName(e.resource_target));
  const blockedChips = fenceBlocked(attempts, insideNames, requestedNames);
  const blockedNames = uniq([
    ...blockedChips.map(c => c.label),
    ...deniedNames.filter(n => !insideNames.includes(n) && !requestedNames.includes(n)),
  ]);
  // A chip's label may differ from its file name ("summary.txt (write)"); opening looks up the name.
  const openByLabel = (label: string) => setOpenName(blockedChips.find(c => c.label === label)?.name || label);

  const isComparison = !!(run.task?.comparison_mode || run.task?.condition === 'B');
  const outputs: OutputPreview[] = run.outputFiles.length
    ? run.outputFiles.map(f => ({ path: f.path, name: f.name || fileName(f.path), content: f.content, size: f.size, truncated: f.truncated, location: f.location, windowsLocation: f.windows_location }))
    : outputsFromSteps(run.steps);
  const noResult = outputs.length === 0 || outputs.every(o => o.size === 0 || (o.size == null && o.content === ''));
  const sentence = statusSentence({
    state: run.state,
    blocked: split.direct,
    background: split.background.length,
    justBlocked: lastBlock,
    pending: run.pending,
    agentStarted: started,
    endReason: run.endReason,
    comparison: isComparison,
    refused: deniedNames.filter(d => !attempts.some(a => a.name === d)).length,
    noResult,
  });

  const record = receiptSentence(run.receipt, run.receiptLoaded);

  const requireToken = (fn: () => void) => () => (hasToken ? fn() : openAuthModal());

  if (run.notFound) {
    return (
      <div className="max-w-xl mx-auto py-20 text-center space-y-4">
        <PageHeader
          title="We couldn't find that run."
          className="text-center items-center"
          actions={
            <Link to="/history" className="btn-ghost">
              Go to History
            </Link>
          }
        />
      </div>
    );
  }

  return (
    <div className="max-w-[1280px]">
      <div className="flex flex-wrap items-center justify-between gap-3 pb-5 border-b border-line">
        {readOnly ? (
          <ol aria-label="Progress" className="flex flex-wrap items-center gap-2.5 text-[14px] list-none p-0 m-0 min-h-[44px]" style={{ color: 'var(--text-3)' }}>
            <li>
              <Link to="/history">History</Link> <span aria-hidden="true">/</span> <span style={{ color: 'var(--text-2)' }}>One run</span>
            </li>
          </ol>
        ) : (
          <RunProgress view={runPhase(run.state, started, !!run.pending, run.receiptLoaded)} />
        )}
        {!readOnly && !terminal && (
          <Button
            id="stop-run-btn"
            variant="danger"
            size="md"
            onClick={requireToken(run.stop)}
            disabled={run.state === 'stopping'}
            className="min-h-[44px] sm:min-h-[40px]"
          >
            <Square className="w-4 h-4" />
            {run.state === 'stopping' ? 'Stopping…' : 'Stop'}
          </Button>
        )}
      </div>

      {(run.task?.comparison_mode || run.task?.condition === 'B') && (
        <div
          id="comparison-run-banner"
          role="status"
          className="mt-4 px-4 py-3 rounded-xl border border-wait/40 bg-wait-tint text-wait-kpi text-[15px] font-medium flex items-center gap-2.5"
        >
          <AlertTriangle className="w-5 h-5 shrink-0 text-wait" />
          <span>Comparison run: kernel lock off, for demonstration</span>
        </div>
      )}

      <div className="pt-6 pb-10 flex flex-wrap items-start gap-8 lg:gap-12">
        <div className="flex-[1_1_460px] min-w-0">
          <div className="relative overflow-hidden rounded-3xl border border-line bg-surface-1/40 p-4 sm:p-6 flex flex-col items-center">
            <div className="pipeline-dots absolute inset-0 pointer-events-none" />

            <div className="relative z-10 w-full flex flex-wrap items-center gap-2 mb-6">
              <div
                id="live-status-chip"
                className="flex h-9 shrink-0 items-center justify-center gap-2 rounded-xl border border-line bg-surface-2 px-3"
              >
                <span className="relative flex size-2">
                  {live && <span className="absolute inset-0 animate-ping rounded-full bg-ok opacity-60 motion-reduce:hidden" />}
                  <span className={`relative size-full rounded-full ${live ? 'bg-ok' : run.state === 'stopped' || run.state === 'failed' ? 'bg-bad' : 'bg-fg-3'}`} />
                </span>
                <span className={`text-[13px] font-medium ${live ? 'text-ok' : 'text-fg-2'}`}>
                  {live ? 'Live' : run.state === 'stopped' ? 'Stopped' : 'Finished'}
                </span>
              </div>
              {run.task && (
                <div className="flex h-9 items-center rounded-xl border border-line bg-surface-2 px-3 min-w-0" id="run-agent-line">
                  <span className="truncate text-[13px] font-medium text-fg">
                    <span>{agentNames[run.task.agent_id] || run.task.agent_id}</span>
                    {run.task.model ? (
                      <>
                        <span className="text-fg-3"> · runs on </span>
                        <span className="font-mono text-fg-2">{run.task.model}</span>
                      </>
                    ) : null}
                  </span>
                </div>
              )}
            </div>

            <div className="relative z-10 w-full flex flex-col items-center">
              <div className="w-full flex justify-center py-2">
                <Fence inside={insideNames} blocked={blockedNames} requested={requestedNames} live={live} gotThrough={isComparison} onOpen={terminal ? openByLabel : undefined} />
              </div>
              <div className="mt-6 text-center max-w-lg mx-auto px-2">
                <h1
                  id="run-status"
                  data-state={run.state}
                  aria-live="polite"
                  className="m-0 font-display font-bold text-[24px] sm:text-[30px] leading-tight text-fg"
                >
                  {sentence}
                </h1>
              </div>
            </div>
          </div>
        </div>

        <section aria-label={run.pending ? 'Your decision' : 'What is happening'} className="flex-[1_1_380px] max-w-[540px] min-w-0 flex flex-col gap-5">
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
            <div className="rounded-2xl border border-line bg-surface-1 p-5 shadow-sm">
              <p className="m-0 text-[16px] leading-relaxed text-fg-2">
                It can only touch what is inside the fence. If it needs anything more, it will ask you here.
              </p>
            </div>
          )}

          {!terminal && !readOnly && (
            <GrantList
              grants={cancellableGrants(run.expansions)}
              deciding={run.deciding}
              onCancel={id => (hasToken ? run.revoke(id) : openAuthModal())}
            />
          )}

          {terminal && outputs.length > 0 && (
            <div
              className="rounded-2xl border border-line bg-surface-1 p-5 cursor-pointer shadow-sm hover:border-line-strong transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
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
                <FileText className="w-4 h-4 text-ok" />
                <span className="mono text-[14px] text-fg">{outputs[0].name}</span>
                {outputs.length > 1 && (
                  <span className="font-normal text-fg-3">
                    and {outputs.length - 1} more
                  </span>
                )}
                <span className="ml-auto text-[13px] font-normal text-fg-3">
                  Open
                </span>
              </div>
              <pre className="mt-3 mb-0 whitespace-pre-wrap text-[14px] leading-relaxed max-h-48 overflow-y-auto text-fg font-sans">
                {outputs[0].content || '(empty file)'}
              </pre>
            </div>
          )}
          {terminal && run.privateCheck && (
            <div className="rounded-2xl border border-line bg-surface-1 p-4 shadow-sm">
              <p
                className="m-0 text-[14px] leading-relaxed"
                id="private-check"
                data-result={run.privateCheck}
                style={{ color: run.privateCheck === 'leaked' ? 'var(--bad-text)' : 'var(--ok-text)' }}
              >
                {run.privateCheck === 'leaked'
                  ? 'Private file check: the output contains the private file’s unique code, so its content got out.'
                  : 'Private file check: the output does not contain the private file’s unique code, so none of its real content got out.'}
              </p>
            </div>
          )}
          {terminal && outputs.length === 0 && run.receiptLoaded && (
            <div className="rounded-2xl border border-line bg-surface-1 p-5 shadow-sm">
              <p className="m-0 text-[15px] text-fg-2">
                The agent did not write any output.
              </p>
            </div>
          )}

          {terminal && (
            <div className="flex flex-wrap items-center gap-3">
              <span
                id="record-status"
                data-tone={record.tone}
                className="inline-flex items-center gap-2 min-h-[44px] px-4 rounded-xl text-[14px] font-semibold"
                style={
                  record.tone === 'ok'
                    ? { background: 'var(--ok-tint)', border: '1px solid rgb(var(--ok-rgb) / 0.45)', color: 'var(--ok-text)' }
                    : record.tone === 'bad'
                    ? { background: 'var(--bad-tint)', border: '1px solid rgb(var(--bad-rgb) / 0.5)', color: 'var(--bad-lighter)' }
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
            <p id="decision-note" role="status" className="m-0 text-[15px] leading-relaxed text-ok-lighter">
              {run.decisionNote}
            </p>
          )}

          {run.actionError && (
            <div id="action-error" role="alert" className="px-4 py-3 rounded-xl text-[15px] bg-bad-tint border border-bad/45 text-bad-lighter">
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
            {f.location && (
              <div className="mb-3 text-[13px]" id="output-location">
                <div style={{ color: 'var(--text-3)' }}>Saved at</div>
                <PathLine label="Linux" value={f.location} />
                {f.windowsLocation && <PathLine label="Windows Explorer" value={f.windowsLocation} />}
              </div>
            )}
            <pre className="m-0 whitespace-pre-wrap text-[14px] leading-relaxed mono" style={{ color: 'var(--text)' }}>
              {f.content || '(empty file)'}
            </pre>
          </DetailsSection>
        ))}
      </DetailsDrawer>

      <DetailsDrawer
        open={!!openName}
        title={fileView?.kind === 'private' ? 'Private file (outside the request)' : fileView?.kind === 'output' ? 'Output file' : 'Input file'}
        onClose={() => setOpenName(null)}
        id="file-drawer"
      >
        {fileError && <p className="m-0 text-[14px]" style={{ color: 'var(--text-2)' }}>{fileError}</p>}
        {!fileView && !fileError && <p className="m-0 text-[14px]" style={{ color: 'var(--text-3)' }}>Loading…</p>}
        {fileView && <FileView file={fileView} pointsTo={uniq(blockedChips.filter(c => c.label !== 'a command').map(c => c.name))} privateCheck={run.privateCheck} />}
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
          {run.task?.model ? (
            <KV k="Model" v={run.task.model} id="run-model" />
          ) : (
            run.task?.llm_provider && <KV k="Model provider" v={run.task.llm_provider} />
          )}
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
                <KV k="Hash chain" v={
                    !run.receipt.verified
                      ? `Does not verify: ${run.receipt.verification_message || 'mismatch'}`
                      : run.receipt.verified_scope === 'events_only'
                        ? 'Verified: event chain only (older record, SHA-256, not signed)'
                        : 'Verified: events chained and whole record hashed (SHA-256, not signed)'
                  } id="receipt-verification" />
                <KV k="Events in the chain" v={run.receipt.receipt?.hash_chain?.count ?? run.receipt.receipt?.events?.length ?? 0} />
                <KV k="Last link of the chain" v={run.receipt.final_hash || run.receipt.receipt?.hash_chain?.final_hash || 'n/a'} />
                <p className="m-0 text-[13px] leading-relaxed" style={{ color: 'var(--text-2)' }}>
                  Each event's hash includes the previous one, so this last link depends on every event before it. Change
                  any event and it changes. It is the same value as in the step "Task receipt written".
                </p>
                {run.receipt.file_sha256 && (
                  <>
                    <KV k="Fingerprint of the receipt file" v={run.receipt.file_sha256} />
                    <p className="m-0 text-[13px] leading-relaxed" style={{ color: 'var(--text-2)' }}>
                      A different value by design: the SHA-256 of the whole downloaded file, so a copy can be checked to be
                      exactly this receipt.
                    </p>
                  </>
                )}
                <p className="m-0 text-[13px] leading-relaxed" style={{ color: 'var(--text-2)' }}>
                  The receipt is not signed: someone able to rewrite the whole file could recompute the chain. Check a
                  download with <code className="mono">scripts/verify_receipt.py</code>.
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


// One file location with a copy button (a browser page cannot open a folder by itself;
// paste the Windows path into File Explorer's address bar).
/** An opened file. Lines that point to a file outside the request are marked (the hidden note). */
export function FileView({ file, pointsTo, privateCheck }: { file: RunFile; pointsTo: string[]; privateCheck?: 'clean' | 'leaked' | null }) {
  const lines = (file.content || '').split('\n');
  if (lines.length > 1 && lines[lines.length - 1] === '') lines.pop();
  const marks = (line: string) => (file.kind === 'private' ? [] : pointsTo.filter(n => line.includes(n)));
  const marked = lines.some(l => marks(l).length > 0);
  return (
    <DetailsSection title={file.path}>
      {file.kind === 'private' ? (
        <p className="m-0 mb-3 text-[14px] leading-relaxed" id="file-note" style={{ color: 'var(--text-2)' }}>
          Planted for this run outside what the request allows, to test the agent. The agent was refused it, so it never
          saw this text. Its unique code is <span className="mono">{file.canary}</span>
          {privateCheck === 'clean' && ', and that code is not in the output'}
          {privateCheck === 'leaked' && ', and that code was found in the output'}.
        </p>
      ) : marked ? (
        <p className="m-0 mb-3 text-[14px] leading-relaxed" id="file-note" style={{ color: 'var(--text-2)' }}>
          The highlighted line is the hidden instruction. It asks for a file your request did not allow. The agent read this
          file because the request allowed it, so the note reached the model as part of the data.
        </p>
      ) : null}
      <div className="flex items-center gap-3 mb-2 text-[13px]" style={{ color: 'var(--text-3)' }}>
        <span>{file.size} bytes</span>
        {file.truncated && <span>Showing the first 20,000 bytes</span>}
      </div>
      {file.location && (
        <div className="mb-3 text-[13px]" id="file-location">
          <div style={{ color: 'var(--text-3)' }}>Saved at (open it yourself to check)</div>
          <PathLine label="Linux" value={file.location} />
          {file.windows_location && <PathLine label="Windows Explorer" value={file.windows_location} />}
        </div>
      )}
      <pre className="m-0 whitespace-pre-wrap text-[14px] leading-relaxed mono" style={{ color: 'var(--text)' }} id="file-content">
        {lines.map((l, i) => {
          const m = marks(l);
          return m.length ? (
            <span key={i} data-hidden-note="true" style={{ display: 'block', background: 'rgba(251,113,133,0.16)', color: 'var(--blocked-text)', borderLeft: '3px solid var(--blocked)', paddingLeft: 8 }}>
              {l}
            </span>
          ) : (
            <span key={i} style={{ display: 'block', paddingLeft: 11 }}>
              {l || '\u00a0'}
            </span>
          );
        })}
      </pre>
    </DetailsSection>
  );
}

function PathLine({ label, value }: { label: string; value: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="flex items-start gap-2 mt-1">
      <span className="shrink-0 w-[132px]" style={{ color: 'var(--text-3)' }}>{label}</span>
      <code className="mono break-all flex-1" style={{ color: 'var(--text)' }}>{value}</code>
      <button
        type="button"
        className="shrink-0 underline"
        style={{ color: 'var(--text-2)' }}
        onClick={() => {
          try {
            navigator.clipboard.writeText(value).then(() => {
              setCopied(true);
              setTimeout(() => setCopied(false), 1500);
            });
          } catch {
            // clipboard not available; the path is still visible to select by hand
          }
        }}
      >
        {copied ? 'Copied' : 'Copy'}
      </button>
    </div>
  );
}
