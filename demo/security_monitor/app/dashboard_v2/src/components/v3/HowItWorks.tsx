import React, { useState } from 'react';
import { DetailsDrawer, DetailsSection, KV } from './DetailsDrawer';

const box: React.CSSProperties = {
  background: 'var(--card-2)',
  border: '1px solid var(--line)',
  borderRadius: 18,
};

const Arrow: React.FC = () => (
  <div aria-hidden="true" className="flex justify-center py-1.5" style={{ color: 'var(--text-3)' }}>
    <svg width="18" height="22" viewBox="0 0 18 22" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M9 2v16M3 12l6 6 6-6" />
    </svg>
  </div>
);

const Step: React.FC<{ title: string; body: string; accent?: string }> = ({ title, body, accent = 'var(--cyan)' }) => (
  <div className="px-5 py-4 text-center" style={box}>
    <div className="font-display text-[18px] font-bold" style={{ color: accent }}>
      {title}
    </div>
    <p className="mt-1 mb-0 text-[15px]" style={{ color: 'var(--text-2)' }}>
      {body}
    </p>
  </div>
);

const SETUPS = [
  { id: 'A', name: 'No fence', body: 'The agent can touch anything the computer lets it.' },
  { id: 'B', name: 'Tool fence only', body: 'Its tools check each action; the computer does not.' },
  { id: 'C', name: 'Both fences', body: 'Its tools check each action, and the computer refuses files outside the fence.' },
  { id: 'D', name: 'Computer fence only', body: 'The computer refuses files outside the fence; the agent cannot ask for more.' },
];

// The tool-layer / kernel-layer picture from the old Architecture page, in plain words;
// the precise components are in the drawer.
export const HowItWorks: React.FC = () => {
  const [open, setOpen] = useState(false);
  return (
    <section id="how-it-works" aria-labelledby="how-it-works-title" className="card p-6 space-y-6">
      <div>
        <h2 id="how-it-works-title" className="m-0 font-display text-[24px] font-bold">
          How it works
        </h2>
        <p className="mt-1 mb-0 text-[15px]" style={{ color: 'var(--text-2)' }}>
          Every request gets its own fence, and two separate layers keep the agent inside it.
        </p>
      </div>

      <div className="max-w-[760px] mx-auto">
        <Step title="You ask" body="Your request decides what the agent may touch." />
        <Arrow />
        <Step title="We draw the fence" body="The files it may read and write and the tools it may use. No network unless the request needs it." />
        <Arrow />
        <div className="p-4 rounded-[22px] space-y-3" style={{ border: '2px dashed rgba(34,211,238,0.6)' }} aria-label="The agent works inside two layers">
          <div className="text-center text-[14px] font-semibold" style={{ color: '#A5F3FC' }}>
            The agent works inside the fence
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div className="px-5 py-4" style={box} id="layer-tools">
              <div className="font-display text-[17px] font-bold">Layer 1: its tools</div>
              <p className="mt-1 mb-0 text-[15px]" style={{ color: 'var(--text-2)' }}>
                Reading, writing, web and command tools check every action against the fence. Anything outside is refused, or the agent can ask you.
              </p>
            </div>
            <div className="px-5 py-4" style={box} id="layer-os">
              <div className="font-display text-[17px] font-bold">Layer 2: the operating system</div>
              <p className="mt-1 mb-0 text-[15px]" style={{ color: 'var(--text-2)' }}>
                Even when the agent runs a command directly, the computer itself refuses files outside the fence.
              </p>
            </div>
          </div>
        </div>
        <Arrow />
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <Step title="You decide extras" body="A request for anything more waits for you. If nobody answers in time, it stays blocked." accent="#FDE68A" />
          <Step title="A record of every run" body="Checking the record shows whether any entry was changed afterwards." accent="#6EE7B7" />
        </div>
      </div>

      <div className="space-y-3">
        <h3 className="m-0 text-[16px] font-semibold">The four setups compared in the tests</h3>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          {SETUPS.map(s => (
            <div key={s.id} className="px-4 py-3" style={{ ...box, ...(s.id === 'C' ? { borderColor: 'rgba(34,211,238,0.55)' } : {}) }}>
              <div className="text-[13px]" style={{ color: 'var(--text-3)' }}>
                {s.id}
              </div>
              <div className="font-semibold">{s.name}</div>
              <p className="mt-1 mb-0 text-[14px]" style={{ color: 'var(--text-2)' }}>
                {s.body}
              </p>
            </div>
          ))}
        </div>
      </div>

      <button id="how-it-works-details-btn" className="link-btn" onClick={() => setOpen(true)}>
        Technical details
      </button>

      <DetailsDrawer open={open} title="How it works: technical details" onClose={() => setOpen(false)} id="how-it-works-drawer">
        <DetailsSection title="Request to boundary">
          <KV k="Intake" v="intake.py derives a per-task boundary: files read and write, tools, network hosts, peer agents" />
          <KV k="Derivation" v="v1 templates (catalog.BoundaryDerivationV1) in the launcher; v2 LLM derivation (derivation_v2.py) evaluated in M5, not wired into the launcher" />
          <KV k="Identity" v="one cgroup v2 scope per task (systemd-run --user --scope), created before the agent acts" />
        </DetailsSection>
        <DetailsSection title="Layer 1: tool layer">
          <KV k="Broker" v="Unix-socket RPC with 7 agent-facing endpoints: read_file, write_file, http_get, call_agent, request_access, run_command_check, llm_complete; no approve, deny or grant endpoint" />
          <KV k="Egress proxy" v="the only TCP port the sandbox may connect to" />
          <KV k="Expansion" v="request_access gets a risk tier, raised when the agent read untrusted input before asking (provenance); grants are exact resources, wildcards are rejected; an approved file is copied into the read-only granted/ directory" />
          <KV k="Fail closed" v="a request nobody decides before its timeout is denied" />
        </DetailsSection>
        <DetailsSection title="Layer 2: kernel layer (Linux/WSL2)">
          <KV k="Landlock" v="rules compiled from the boundary (os_layer/sandbox_spec.py); enforced by the kernel for file access, including shell commands" />
          <KV k="seccomp" v="io_uring is refused (it would bypass observation); file opens, program starts and network connects are routed to the sensor" />
          <KV k="Namespaces" v="user, mount and network namespaces; tmpfs over /run/user/<uid>; in the evaluation world (used by the console) a tmpfs fake home with decoy files" />
          <KV k="Sensor" v="ptrace + seccomp RET_TRACE; observation only, it does not block. bind() is not observable on WSL2" />
          <KV k="Correlator" v="attributes each OS event to a task by cgroup: INSIDE / OUTSIDE / AMBIGUOUS / UNATTRIBUTED" />
          <KV k="Graduated response" v="deny → freeze (cgroup.freeze) → kill (cgroup.kill)" />
        </DetailsSection>
        <DetailsSection title="Record">
          <KV k="Task Receipt v0" v="a SHA-256 hash-chained JSON log per task; it detects edits to individual entries, but it is not signed, so someone able to rewrite the whole file can recompute the chain (scripts/verify_receipt.py)" />
        </DetailsSection>
        <DetailsSection title="Conditions (M6 evaluation)">
          <KV k="A" v="no governance" />
          <KV k="B" v="tool layer only; the OS sensor observes only" />
          <KV k="C" v="tool layer + OS layer (the console's runs use C)" />
          <KV k="D" v="per-task container baseline: Landlock from the boundary, no broker, no expansion" />
        </DetailsSection>
        <DetailsSection title="Who decides expansions">
          <KV k="Evaluation" v="an idealised ORACLE approves exactly the legitimate resources; real human approvals were not tested" />
          <KV k="Console" v="requests stay PENDING until a signed-in operator decides; the approver is recorded as operator:<GOVERNANCE_OPERATOR_NAME>" />
        </DetailsSection>
      </DetailsDrawer>
    </section>
  );
};
