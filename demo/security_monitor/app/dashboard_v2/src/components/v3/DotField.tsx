import React, { useEffect, useRef } from 'react';
import { DotState, FleetDot } from '../../types';

// Above this many dots, draw on a canvas instead of one DOM node per dot.
export const CANVAS_THRESHOLD = 1500;

export const DOT_COLORS: Record<DotState, string> = {
  working: '#22D3EE',
  waiting: '#FBBF24',
  blocked: '#FB7185',
  idle: '#64748B',
  no_task: '#A78BFA',
};

export const DOT_LEGEND: Record<DotState, string> = {
  working: 'working inside its fence',
  waiting: 'waiting for your decision',
  blocked: 'blocked in the last hour',
  idle: 'not running now',
  no_task: 'seen acting without a task',
};

const dotStyle = (d: FleetDot, i: number): React.CSSProperties => {
  const base: React.CSSProperties = { display: 'block', aspectRatio: '1', borderRadius: '50%', background: DOT_COLORS[d.state] };
  switch (d.state) {
    case 'working':
      return { ...base, opacity: 0.45, animation: `twinkle 5s ease-in-out ${(i % 3) * 1.7}s infinite` };
    case 'waiting':
      return { ...base, transform: 'scale(1.6)', animation: 'ping 1.6s ease-out infinite' };
    case 'blocked':
      return { ...base, transform: 'scale(1.3)', animation: 'pingRed 2.2s ease-out infinite' };
    case 'no_task':
      return { ...base, background: 'transparent', border: `2px solid ${DOT_COLORS.no_task}` };
    default:
      return { ...base, opacity: 0.5 };
  }
};

const isException = (d: FleetDot) => d.state === 'waiting' || d.state === 'blocked';

export const DotField: React.FC<{ dots: FleetDot[]; onOpen: (d: FleetDot) => void; label: string }> = ({ dots, onOpen, label }) => {
  if (dots.length > CANVAS_THRESHOLD) return <CanvasDots dots={dots} onOpen={onOpen} label={label} />;
  return (
    <div
      id="dot-field"
      data-render="dom"
      role="group"
      aria-label={label}
      className="grid gap-[7px] p-6 rounded-3xl"
      style={{ gridTemplateColumns: 'repeat(auto-fill, minmax(12px, 1fr))', background: 'var(--field)', border: '1px solid rgba(148,163,184,0.14)' }}
    >
      {dots.map((d, i) => (
        <button
          key={d.id}
          type="button"
          data-dot-state={d.state}
          onClick={() => d.view && onOpen(d)}
          disabled={!d.view}
          tabIndex={isException(d) ? 0 : -1}
          aria-label={`${d.label}: ${DOT_LEGEND[d.state]}`}
          title={`${d.label}: ${DOT_LEGEND[d.state]}`}
          className="p-0 border-0 bg-transparent"
          style={{ cursor: d.view ? 'pointer' : 'default', maxWidth: 16 }}
        >
          <span style={dotStyle(d, i)} />
        </button>
      ))}
    </div>
  );
};

const CanvasDots: React.FC<{ dots: FleetDot[]; onOpen: (d: FleetDot) => void; label: string }> = ({ dots, onOpen, label }) => {
  const ref = useRef<HTMLCanvasElement>(null);
  const layout = useRef({ cols: 1, cell: 10 });

  useEffect(() => {
    const canvas = ref.current;
    if (!canvas) return;
    const draw = () => {
      const width = canvas.clientWidth;
      const cell = 10;
      const cols = Math.max(1, Math.floor(width / cell));
      const rows = Math.ceil(dots.length / cols);
      const dpr = window.devicePixelRatio || 1;
      canvas.width = width * dpr;
      canvas.height = rows * cell * dpr;
      canvas.style.height = `${rows * cell}px`;
      layout.current = { cols, cell };
      const ctx = canvas.getContext('2d');
      if (!ctx) return;
      ctx.scale(dpr, dpr);
      dots.forEach((d, i) => {
        const x = (i % cols) * cell + cell / 2;
        const y = Math.floor(i / cols) * cell + cell / 2;
        const r = d.state === 'waiting' ? 4.5 : d.state === 'blocked' ? 4 : 3;
        ctx.beginPath();
        ctx.arc(x, y, r, 0, Math.PI * 2);
        ctx.globalAlpha = d.state === 'working' ? 0.45 : d.state === 'idle' ? 0.5 : 1;
        if (d.state === 'no_task') {
          ctx.strokeStyle = DOT_COLORS.no_task;
          ctx.stroke();
        } else {
          ctx.fillStyle = DOT_COLORS[d.state];
          ctx.fill();
        }
      });
      ctx.globalAlpha = 1;
    };
    draw();
    window.addEventListener('resize', draw);
    return () => window.removeEventListener('resize', draw);
  }, [dots]);

  const onClick = (e: React.MouseEvent<HTMLCanvasElement>) => {
    const rect = e.currentTarget.getBoundingClientRect();
    const { cols, cell } = layout.current;
    const i = Math.floor((e.clientY - rect.top) / cell) * cols + Math.floor((e.clientX - rect.left) / cell);
    const d = dots[i];
    if (d && d.view) onOpen(d);
  };

  return (
    <div className="p-6 rounded-3xl" style={{ background: 'var(--field)', border: '1px solid rgba(148,163,184,0.14)' }}>
      <canvas id="dot-field" data-render="canvas" ref={ref} onClick={onClick} role="img" aria-label={label} className="block w-full cursor-pointer" />
    </div>
  );
};
