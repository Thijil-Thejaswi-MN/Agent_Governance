import React from 'react';

// Positions in % of the fence box; the agent sits at 40–60 % on both axes.
const INSIDE_SLOTS: React.CSSProperties[] = [
  { left: '14%', top: '24%' },
  { left: '52%', top: '22%' },
  { left: '16%', top: '68%' },
  { left: '50%', top: '70%' },
];
// Outside chips straddle the fence on the right and knock against it.
const OUTSIDE_SLOTS: React.CSSProperties[] = [
  { right: '-18%', top: '42%' },
  { right: '-18%', top: '57%' },
  { right: '-18%', top: '27%' },
  { right: '-18%', top: '72%' },
];

const insideChip: React.CSSProperties = {
  background: 'rgba(52,211,153,0.14)',
  border: '1px solid rgba(52,211,153,0.55)',
  color: '#A7F3D0',
};

export interface FenceProps {
  inside: string[];
  blocked: string[];
  requested: string[];
  live: boolean;
}

// The agent in the centre, the files its request allows inside the fence, and what it
// tried or asked for outside. Names only; full paths are in Details.
export const Fence: React.FC<FenceProps> = ({ inside, blocked, requested, live }) => {
  const shownInside = inside.slice(0, 4);
  const moreInside = inside.length - shownInside.length;
  const outside = [
    ...requested.map(name => ({ name, kind: 'requested' as const })),
    ...blocked.map(name => ({ name, kind: 'blocked' as const })),
  ];
  const shownOutside = outside.slice(0, 4);
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
      <div className="relative w-[80%] sm:w-[84%] max-w-[520px] aspect-square mr-auto sm:mx-auto" id="fence">
        <p className="sr-only">{description}</p>
        <div
          aria-hidden="true"
          className="absolute rounded-full"
          style={{
            inset: '8%',
            background: 'radial-gradient(circle, rgba(34,211,238,0.12), transparent 70%)',
            animation: live ? 'halo 4s ease-in-out infinite' : undefined,
          }}
        />
        <div
          aria-hidden="true"
          className="absolute rounded-full"
          style={{
            inset: '8%',
            border: '3px dashed rgba(34,211,238,0.85)',
            animation: live ? 'spin 40s linear infinite' : undefined,
          }}
        />
        <div
          aria-hidden="true"
          className="absolute flex items-center justify-center rounded-full"
          style={{
            left: '50%',
            top: '50%',
            transform: 'translate(-50%,-50%)',
            width: '20%',
            height: '20%',
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
          <div key={`in-${name}`} className="fence-chip" style={{ ...insideChip, ...INSIDE_SLOTS[i] }} title={name} data-chip="inside" aria-hidden="true">
            {name}
          </div>
        ))}
        {moreInside > 0 && (
          <div className="fence-chip" style={{ ...insideChip, left: '50%', top: '83%', transform: 'translateX(-50%)' }} data-chip="inside-more" aria-hidden="true">
            +{moreInside} more
          </div>
        )}

        {shownOutside.map((o, i) => (
          <div
            key={`out-${o.kind}-${o.name}`}
            className={`fence-chip ${live ? (o.kind === 'blocked' ? 'chip-blocked' : 'chip-waiting') : ''}`}
            title={o.name}
            data-chip={o.kind}
            aria-hidden="true"
            style={{
              ...OUTSIDE_SLOTS[i],
              ...(o.kind === 'blocked'
                ? { background: 'rgba(251,113,133,0.14)', border: '1px solid rgba(251,113,133,0.7)', color: '#FECDD3' }
                : { background: 'rgba(251,191,36,0.14)', border: '1px solid rgba(251,191,36,0.7)', color: '#FDE68A' }),
            }}
          >
            {o.name}
            {o.kind === 'requested' ? ' ?' : ''}
          </div>
        ))}
        {moreOutside > 0 && (
          <div
            aria-hidden="true"
            className="fence-chip"
            style={{ right: '-18%', top: '87%', background: 'rgba(251,113,133,0.1)', border: '1px solid rgba(251,113,133,0.5)', color: '#FECDD3' }}
          >
            +{moreOutside} more stopped
          </div>
        )}
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
