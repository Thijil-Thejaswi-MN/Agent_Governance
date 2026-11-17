import React, { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { ChevronDown, ChevronRight, ShieldX } from 'lucide-react';
import { api } from '../api/client';
import { EmptyState, ErrorState, LoadingState } from '../components/common/States';
import { Incident, IncidentDetail, mentionText, responseTaken, ruleLink, stoppedBy, triedLead } from '../logic/incidents';
import { formatWhen } from '../logic/report';
import { PageHeader } from '../components/ui/PageHeader';
import { StatusPill } from '../components/ui/StatusPill';
import { Button } from '../components/ui/Button';

/** The expanded part of one incident. No effects, so tests can render it. */
export const IncidentDetailView: React.FC<{ d: IncidentDetail }> = ({ d }) => {
  const m = mentionText(d);
  const link = ruleLink(d);
  return (
    <div className="flex flex-col gap-3 pt-3 border-t border-line" data-incident-detail={d.incident_id}>
      <Row k="What happened">
        <span id={`incident-response-${d.incident_id}`}>{responseTaken(d)}</span>
      </Row>
      <Row k="Where it learned of it">
        <span id={`incident-mention-${d.incident_id}`} data-known={m.known ? 'true' : 'false'}>
          {m.known ? <span className="font-mono">{m.text}</span> : <span className="text-fg-2">{m.text}</span>}
        </span>
        {d.mention && (
          <blockquote className="m-0 mt-1.5 px-3 py-2 rounded-lg bg-surface-2 border-l-2 border-wait font-mono text-[13px] text-fg [overflow-wrap:anywhere]">
            {d.mention.line}
          </blockquote>
        )}
      </Row>
      <Row k="The request">
        <span className="[overflow-wrap:anywhere]">{d.request_text}</span>
      </Row>
      <div className="flex flex-wrap items-center gap-3 pt-1">
        {d.can_make_rule && link ? (
          <Link
            id={`make-rule-${d.incident_id}`}
            to={link}
            className="inline-flex items-center justify-center min-h-[36px] h-9 px-3 rounded-lg text-[13px] font-medium text-white bg-[image:var(--accent-grad)] hover:brightness-110 active:brightness-95 transition-all no-underline"
          >
            Make this a rule
          </Link>
        ) : (
          <span className="flex flex-col gap-1">
            <Button
              variant="ghost"
              size="sm"
              disabled
              aria-describedby={`rule-why-${d.incident_id}`}
            >
              Make this a rule
            </Button>
            <span id={`rule-why-${d.incident_id}`} className="text-[12px] text-fg-3">
              {d.rule_unavailable_reason}
            </span>
          </span>
        )}
        <Link
          to={`/history/${d.task_id}`}
          className="inline-flex items-center justify-center min-h-[36px] h-9 px-3 rounded-lg text-[13px] font-medium text-fg-2 hover:text-fg hover:bg-surface-2 transition-colors no-underline"
        >
          Open the run
        </Link>
        <Link
          to={`/report/${d.task_id}`}
          className="inline-flex items-center justify-center min-h-[36px] h-9 px-3 rounded-lg text-[13px] font-medium text-fg-2 hover:text-fg hover:bg-surface-2 transition-colors no-underline"
        >
          Task report
        </Link>
      </div>
    </div>
  );
};

export const IncidentsPage: React.FC = () => {
  const [items, setItems] = useState<Incident[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState<string | null>(null);
  const [details, setDetails] = useState<Record<string, IncidentDetail | 'error'>>({});

  const load = useCallback(() => {
    setError(null);
    api
      .getIncidents()
      .then(r => setItems(r.incidents))
      .catch(err => setError(err?.message || 'Could not load the incidents.'));
  }, []);
  useEffect(load, [load]);

  const toggle = (i: Incident) => {
    const key = `${i.task_id}/${i.incident_id}`;
    if (open === key) return setOpen(null);
    setOpen(key);
    if (!details[key]) {
      api
        .getIncident(i.task_id, i.incident_id)
        .then(d => setDetails(x => ({ ...x, [key]: d })))
        .catch(() => setDetails(x => ({ ...x, [key]: 'error' })));
    }
  };

  return (
    <div className="max-w-[960px] pb-12 flex flex-col gap-5">
      <PageHeader
        title={items == null ? 'Incidents' : items.length === 0 ? 'No incidents.' : `${items.length} blocked ${items.length === 1 ? 'action' : 'actions'}.`}
        subtitle="Every time an agent tried something outside its boundary. Each one was attempted, not successful."
      />

      {error ? (
        <ErrorState message={error} onRetry={load} id="incidents-error" />
      ) : items == null ? (
        <LoadingState label="Loading incidents…" id="incidents-loading" />
      ) : items.length === 0 ? (
        <EmptyState id="incidents-empty" title="Nothing has been blocked." body="Blocked actions from every run you can see appear here." />
      ) : (
        <div className="rounded-xl border border-line bg-surface-1 overflow-hidden">
          <div className="hidden sm:grid sm:grid-cols-[1fr_auto_32px] items-center gap-4 bg-surface-2 px-4 py-2.5 text-[12px] uppercase tracking-wider text-fg-3 font-semibold border-b border-line">
            <span>Incident / Target</span>
            <span>Layer / Verdict</span>
            <span className="sr-only">Toggle</span>
          </div>
          <ul id="incidents-list" className="list-none m-0 p-0 divide-y divide-line">
            {items.map(i => {
              const key = `${i.task_id}/${i.incident_id}`;
              const isOpen = open === key;
              const d = details[key];
              return (
                <li key={key} className="transition-colors" data-incident={i.incident_id}>
                  <button
                    type="button"
                    onClick={() => toggle(i)}
                    aria-expanded={isOpen}
                    aria-controls={`incident-body-${i.incident_id}`}
                    className="w-full text-left bg-transparent border-0 px-4 py-3 sm:py-2.5 min-h-[44px] cursor-pointer flex flex-col sm:flex-row sm:items-center justify-between gap-3 hover:bg-surface-2/50 transition-colors text-[14px]"
                  >
                    <div className="flex items-center gap-3 min-w-0 flex-1">
                      <ShieldX aria-hidden="true" className="w-4 h-4 shrink-0 text-bad" />
                      <div className="min-w-0 flex-1">
                        <span className="text-[14px] text-fg [overflow-wrap:anywhere]">
                          {triedLead(i)} <code className="font-mono text-[13px] text-accent font-medium">{i.target || '—'}</code>
                        </span>
                      </div>
                    </div>

                    <div className="flex flex-wrap items-center gap-3 shrink-0">
                      <span className="text-[12px] text-fg-3">{formatWhen(i.timestamp)}</span>
                      {i.comparison_mode || i.layer === 'comparison_unlocked' ? (
                        <span
                          data-incident-label="comparison"
                          className="inline-flex items-center px-2 py-0.5 rounded text-[12px] font-semibold text-wait-kpi bg-wait-tint border border-wait/25"
                        >
                          Comparison run: decoy was read (would be blocked by the kernel lock)
                        </span>
                      ) : (
                        <>
                          <span className="text-[12px] text-fg-3">Stopped by: {stoppedBy(i.layer)}</span>
                          <StatusPill tone="bad" label="Attempted, not successful" />
                        </>
                      )}
                      <span className="w-5 flex items-center justify-center text-fg-3">
                        {isOpen ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
                      </span>
                    </div>
                  </button>
                  {isOpen && (
                    <div id={`incident-body-${i.incident_id}`} className="px-4 pb-4 pt-1 bg-surface-1 border-t border-line">
                      {d === 'error' ? (
                        <ErrorState message="Could not load this incident." />
                      ) : !d ? (
                        <p className="m-0 text-[14px] text-fg-2">
                          Looking it up…
                        </p>
                      ) : (
                        <IncidentDetailView d={d} />
                      )}
                    </div>
                  )}
                </li>
              );
            })}
          </ul>
        </div>
      )}
    </div>
  );
};

const Row: React.FC<{ k: string; children: React.ReactNode }> = ({ k, children }) => (
  <div className="grid grid-cols-1 sm:grid-cols-[200px_1fr] gap-x-4 gap-y-1 text-[14px]">
    <span className="text-[13px] text-fg-3">{k}</span>
    <div className="min-w-0 text-fg">{children}</div>
  </div>
);
