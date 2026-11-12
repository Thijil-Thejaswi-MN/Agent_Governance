import React, { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { ChevronDown, ChevronRight, ShieldX } from 'lucide-react';
import { api } from '../api/client';
import { EmptyState, ErrorState, LoadingState } from '../components/common/States';
import { Incident, IncidentDetail, mentionText, responseTaken, ruleLink, stoppedBy, triedLead } from '../logic/incidents';
import { formatWhen } from '../logic/report';

/** The expanded part of one incident. No effects, so tests can render it. */
export const IncidentDetailView: React.FC<{ d: IncidentDetail }> = ({ d }) => {
  const m = mentionText(d);
  const link = ruleLink(d);
  return (
    <div className="flex flex-col gap-3 pt-3 border-t border-[#1F2633]" data-incident-detail={d.incident_id}>
      <Row k="What happened">
        <span id={`incident-response-${d.incident_id}`}>{responseTaken(d)}</span>
      </Row>
      <Row k="Where it learned of it">
        <span id={`incident-mention-${d.incident_id}`} data-known={m.known ? 'true' : 'false'}>
          {m.known ? <span className="font-mono">{m.text}</span> : <span style={{ color: 'var(--text-2)' }}>{m.text}</span>}
        </span>
        {d.mention && (
          <blockquote className="m-0 mt-1.5 px-3 py-2 rounded-lg bg-[#0E121A] border-l-2 border-[#F59E0B] font-mono text-[13px] text-[#E6E9EF] [overflow-wrap:anywhere]">
            {d.mention.line}
          </blockquote>
        )}
      </Row>
      <Row k="The request">
        <span className="[overflow-wrap:anywhere]">{d.request_text}</span>
      </Row>
      <div className="flex flex-wrap items-center gap-3 pt-1">
        {d.can_make_rule && link ? (
          <Link id={`make-rule-${d.incident_id}`} to={link} className="btn-primary min-h-[44px] px-4 inline-flex items-center no-underline">
            Make this a rule
          </Link>
        ) : (
          <span className="flex flex-col gap-1">
            <button type="button" className="btn-ghost min-h-[44px] px-4 opacity-50 cursor-not-allowed" disabled aria-describedby={`rule-why-${d.incident_id}`}>
              Make this a rule
            </button>
            <span id={`rule-why-${d.incident_id}`} className="text-[13px]" style={{ color: 'var(--text-3)' }}>
              {d.rule_unavailable_reason}
            </span>
          </span>
        )}
        <Link to={`/history/${d.task_id}`} className="text-[15px] inline-flex items-center min-h-[44px]">
          Open the run
        </Link>
        <Link to={`/report/${d.task_id}`} className="text-[15px] inline-flex items-center min-h-[44px]">
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
      <header className="flex flex-col gap-2">
        <h1 className="m-0 font-display font-bold text-[28px] sm:text-[32px] leading-[1.15] text-[#E6E9EF]">
          {items == null ? 'Incidents' : items.length === 0 ? 'No incidents.' : `${items.length} blocked ${items.length === 1 ? 'action' : 'actions'}.`}
        </h1>
        <p className="m-0 text-[16px] leading-relaxed" style={{ color: 'var(--text-2)' }}>
          Every time an agent tried something outside its boundary. Each one was attempted, not successful.
        </p>
      </header>

      {error ? (
        <ErrorState message={error} onRetry={load} id="incidents-error" />
      ) : items == null ? (
        <LoadingState label="Loading incidents…" id="incidents-loading" />
      ) : items.length === 0 ? (
        <EmptyState id="incidents-empty" title="Nothing has been blocked." body="Blocked actions from every run you can see appear here." />
      ) : (
        <ul id="incidents-list" className="list-none m-0 p-0 flex flex-col gap-3">
          {items.map(i => {
            const key = `${i.task_id}/${i.incident_id}`;
            const isOpen = open === key;
            const d = details[key];
            return (
              <li key={key} className="card p-4 sm:p-5 flex flex-col gap-3" data-incident={i.incident_id}>
                <button
                  type="button"
                  onClick={() => toggle(i)}
                  aria-expanded={isOpen}
                  aria-controls={`incident-body-${i.incident_id}`}
                  className="w-full text-left bg-transparent border-0 p-0 cursor-pointer flex items-start gap-3 min-h-[44px]"
                >
                  <ShieldX aria-hidden="true" className="w-5 h-5 mt-0.5 shrink-0" style={{ color: '#F87171' }} />
                  <span className="flex-1 min-w-0 flex flex-col gap-1">
                    <span className="text-[16px] text-[#E6E9EF] [overflow-wrap:anywhere]">
                      {triedLead(i)} <code className="font-mono text-[15px] text-[#BFDBFE]">{i.target || '—'}</code>
                    </span>
                    <span className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[13px]" style={{ color: 'var(--text-2)' }}>
                      <span>{formatWhen(i.timestamp)}</span>
                      <span>Stopped by: {stoppedBy(i.layer)}</span>
                      <span
                        className="inline-flex items-center px-2 py-0.5 rounded-full text-[12px] font-semibold"
                        style={{ color: '#FCA5A5', background: 'rgba(239,68,68,0.12)' }}
                      >
                        Attempted, not successful
                      </span>
                    </span>
                  </span>
                  {isOpen ? (
                    <ChevronDown aria-hidden="true" className="w-5 h-5 shrink-0" style={{ color: 'var(--text-3)' }} />
                  ) : (
                    <ChevronRight aria-hidden="true" className="w-5 h-5 shrink-0" style={{ color: 'var(--text-3)' }} />
                  )}
                </button>
                {isOpen && (
                  <div id={`incident-body-${i.incident_id}`}>
                    {d === 'error' ? (
                      <ErrorState message="Could not load this incident." />
                    ) : !d ? (
                      <p className="m-0 text-[14px]" style={{ color: 'var(--text-2)' }}>
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
      )}
    </div>
  );
};

const Row: React.FC<{ k: string; children: React.ReactNode }> = ({ k, children }) => (
  <div className="grid grid-cols-1 sm:grid-cols-[200px_1fr] gap-x-4 gap-y-1 text-[15px]">
    <span className="text-[13px] sm:text-[14px]" style={{ color: 'var(--text-3)' }}>
      {k}
    </span>
    <div className="min-w-0 text-[#E6E9EF]">{children}</div>
  </div>
);
