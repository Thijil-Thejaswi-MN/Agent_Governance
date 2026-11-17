import { useEffect, useRef, useState } from 'react';

const easeOutCubic = (t: number) => 1 - Math.pow(1 - t, 3);

/**
 * Counts from 0 up to `target` once, when the element first scrolls into view.
 * With reduced motion (or no IntersectionObserver) it shows the final value at once.
 * The number shown always ends at the real value; nothing is invented on the way.
 */
export function useCountUp<T extends HTMLElement>(target: number, durationMs = 1500, delayMs = 0) {
  const ref = useRef<T | null>(null);
  const reduce =
    typeof window !== 'undefined' && !!window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const [value, setValue] = useState(() => (reduce || typeof IntersectionObserver === 'undefined' ? target : 0));
  const started = useRef(false);

  useEffect(() => {
    if (reduce || typeof IntersectionObserver === 'undefined' || !ref.current) {
      setValue(target);
      return;
    }
    if (started.current) {
      setValue(target); // the real value changed after the first count: show it as it is
      return;
    }
    let raf = 0;
    let timer = 0;
    const el = ref.current;
    const obs = new IntersectionObserver(
      entries => {
        if (!entries.some(e => e.isIntersecting) || started.current) return;
        started.current = true;
        obs.disconnect();
        timer = window.setTimeout(() => {
          const t0 = performance.now();
          const tick = (now: number) => {
            const p = Math.min(1, (now - t0) / durationMs);
            setValue(p >= 1 ? target : target * easeOutCubic(p));
            if (p < 1) raf = requestAnimationFrame(tick);
          };
          raf = requestAnimationFrame(tick);
        }, delayMs);
      },
      { threshold: 0.25 },
    );
    obs.observe(el);
    return () => {
      obs.disconnect();
      window.clearTimeout(timer);
      cancelAnimationFrame(raf);
    };
  }, [target, durationMs, delayMs, reduce]);

  return { ref, value };
}

export function formatCount(value: number, decimals = 0): string {
  return value.toLocaleString(undefined, { minimumFractionDigits: decimals, maximumFractionDigits: decimals });
}
