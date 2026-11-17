import React from 'react';
import Radar from './Radar';

const MAX_BLIPS = 16;

/**
 * A radar for the agent pages. While the list loads it sweeps with no blips ("Finding
 * agents…"); once loaded it shows one blip per agent we know about (up to 16), so the
 * picture never shows agents that do not exist. Blip positions are decoration.
 */
export const AgentScan: React.FC<{ count: number | null; id?: string; size?: number; label?: string }> = ({
  count,
  id,
  size = 168,
  label,
}) => {
  const loading = count == null;
  const text = label ?? (loading ? 'Finding agents…' : `${count} ${count === 1 ? 'agent' : 'agents'} found`);
  return (
    <div id={id} role={loading ? 'status' : undefined} aria-live={loading ? 'polite' : undefined} className="flex flex-col items-center gap-2 shrink-0">
      <div
        className="relative rounded-full overflow-hidden"
        style={{ width: size, height: size, background: 'radial-gradient(circle, rgba(59,130,246,0.10), rgba(14,18,26,0) 70%)' }}
        data-blips={loading ? 0 : Math.min(count ?? 0, MAX_BLIPS)}
        aria-hidden="true"
      >
        <Radar
          color="#60A5FA"
          targets={loading ? 0 : Math.min(count ?? 0, MAX_BLIPS)}
          clutter={0}
          ringCount={4}
          spokeCount={8}
          scale={0.92}
          speed={loading ? 1.6 : 0.8}
          glow={0.8}
          grain={0}
          mouseInteraction={false}
          intro
        />
      </div>
      <span className="text-[13px]" style={{ color: 'var(--text-3)' }}>
        {text}
      </span>
    </div>
  );
};
