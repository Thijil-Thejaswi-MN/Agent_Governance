import React from 'react';

// Layout (index.css .fence*): the ring fills a square on the left; outside chips sit in a lane
// that starts 28 px past the ring's rightmost point (more than the knock animation's 22 px), or
// in a row under the ring on narrow screens, so they never touch the ring.

// Inside chips stack centred above and below the agent (the agent spans 41–59 %).
const INSIDE_TOPS = ['11%', '25%', '62%', '76%'];
const OUTSIDE_TOPS = ['22%', '40%', '58%', '76%'];

const insideChip: React.CSSProperties = {
  left: '50%',
  transform: 'translateX(-50%)',
  maxWidth: '62%',
  background: 'rgba(52,211,153,0.14)',
  border: '1px solid rgba(52,211,153,0.55)',
  color: '#A7F3D0',
};

const outsideStyle = (kind: 'blocked' | 'requested'): React.CSSProperties =>
  kind === 'blocked'
    ? { background: 'rgba(251,113,133,0.14)', border: '1px solid rgba(251,113,133,0.7)', color: '#FECDD3' }
    : { background: 'rgba(251,191,36,0.14)', border: '1px solid rgba(251,191,36,0.7)', color: '#FDE68A' };

export interface FenceProps {
  inside: string[];
  blocked: string[];
  requested: string[];
  live: boolean;
}

// The agent in the centre, the files its request allows inside the fence, and what it
// tried or asked for outside. Names only; full paths are in Details.
export const Fence: React.FC<FenceProps> = ({ inside, blocked, requested, live }) => {
  // At most four chips each side; the fourth becomes "+N more" when there are more.
  const shownInside = inside.length > 4 ? inside.slice(0, 3) : inside;
  const moreInside = inside.length - shownInside.length;
  const outside = [
    ...requested.map(name => ({ name, kind: 'requested' as const })),
    ...blocked.map(name => ({ name, kind: 'blocked' as const })),
  ];
  const shownOutside = outside.length > 4 ? outside.slice(0, 3) : outside;
  const moreOutside = outside.length - shownOutside.length;

  const description = [
    inside.length ? `Inside the fence: ${inside.join(', ')}.` : 'Nothing is inside the fence yet.',
    requested.length ? `Asking for: ${requested.join(', ')}.` : '',
    blocked.length ? `Stopped outside the fence: ${blocked.join(', ')}.` : '',
  ]
    .filter(Boolean)
    .join(' ');

  return (
    <section aria-label="What the agent can touch" className="flex flex-col items-center gap-4 w-full">
      <div className="fence" id="fence">
        <p className="sr-only">{description}</p>
        {/* The ring's square: static, so its box is the circle's box (the dashed child turns). */}
        <div id="fence-ring" className="fence-ring">
          <div
            aria-hidden="true"
            className="absolute inset-0 rounded-full"
            style={{
              background: 'radial-gradient(circle, rgba(34,211,238,0.12), transparent 70%)',
              animation: live ? 'halo 4s ease-in-out infinite' : undefined,
            }}
          />
          <div
            aria-hidden="true"
            className="absolute inset-0 rounded-full"
            style={{ border: '3px dashed rgba(34,211,238,0.85)', animation: live ? 'spin 40s linear infinite' : undefined }}
          />
          <div
            aria-hidden="true"
            className="absolute flex items-center justify-center rounded-full"
            style={{
              left: '50%',
              top: '50%',
              transform: 'translate(-50%,-50%)',
              width: '18%',
              height: '18%',
              background: 'linear-gradient(135deg, #22D3EE, #A78BFA)',
              boxShadow: '0 0 60px rgba(34,211,238,0.45)',
              animation: live ? 'bob 3s ease-in-out infinite' : undefined,
            }}
          >
            <svg width="44%" height="44%" viewBox="0 0 24 24" fill="none" stroke="#070B14" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <rect x="4" y="8" width="16" height="11" rx="3" />
              <path d="M12 8V4M9 13h.01M15 13h.01M9 17h6" />
            </svg>
          </div>

          {shownInside.map((name, i) => (
            <div key={`in-${name}`} className="fence-chip" style={{ ...insideChip, top: INSIDE_TOPS[i] }} title={name} data-chip="inside" aria-hidden="true">
              {name}
            </div>
          ))}
          {moreInside > 0 && (
            <div className="fence-chip" style={{ ...insideChip, top: INSIDE_TOPS[3] }} data-chip="inside-more" aria-hidden="true">
              +{moreInside} more
            </div>
          )}
        </div>

        <div className="fence-lane">
          {shownOutside.map((o, i) => (
            <div
              key={`out-${o.kind}-${o.name}`}
              className={`fence-chip ${live ? (o.kind === 'blocked' ? 'chip-blocked' : 'chip-waiting') : ''}`}
              title={o.name}
              data-chip={o.kind}
              aria-hidden="true"
              style={{ top: OUTSIDE_TOPS[i], ...outsideStyle(o.kind) }}
            >
              {o.name}
              {o.kind === 'requested' ? ' ?' : ''}
            </div>
          ))}
          {moreOutside > 0 && (
            <div aria-hidden="true" className="fence-chip" data-chip="outside-more" style={{ top: OUTSIDE_TOPS[3], ...outsideStyle('blocked') }}>
              +{moreOutside} more stopped
            </div>
          )}
        </div>
      </div>
      <div className="flex flex-wrap justify-center gap-x-5 gap-y-2 text-[14px]" style={{ color: 'var(--text-2)' }}>
        <span>
          <span className="inline-block w-2.5 h-2.5 rounded-[3px] mr-1.5" style={{ background: 'var(--allowed)' }} />
          Your request allows it
        </span>
        <span>
          <span className="inline-block w-2.5 h-2.5 rounded-full mr-1.5" style={{ border: '2px dashed var(--cyan)' }} />
          Everything else is blocked
        </span>
        {requested.length > 0 && (
          <span>
            <span className="inline-block w-2.5 h-2.5 rounded-full mr-1.5" style={{ background: 'var(--waiting)' }} />
            Asking you
          </span>
        )}
        {blocked.length > 0 && (
          <span>
            <span className="inline-block w-2.5 h-2.5 rounded-full mr-1.5" style={{ background: 'var(--blocked)' }} />
            Stopped
          </span>
        )}
      </div>
    </section>
  );
};
