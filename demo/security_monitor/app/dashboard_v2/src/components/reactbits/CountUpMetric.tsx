// Inspired by React Bits (https://reactbits.dev) CountUp - MIT + Commons Clause License
import React, { useEffect, useState, useRef } from 'react';

interface CountUpProps {
  to: number;
  from?: number;
  duration?: number;
  decimals?: number;
  className?: string;
  suffix?: string;
  prefix?: string;
}

export const CountUpMetric: React.FC<CountUpProps> = ({
  to,
  from,
  duration = 1.0,
  decimals = 0,
  className = '',
  suffix = '',
  prefix = '',
}) => {
  const [value, setValue] = useState<number>(from !== undefined ? from : to);
  const prevValueRef = useRef<number>(from !== undefined ? from : to);
  const isFirstRender = useRef(true);

  useEffect(() => {
    // Respect prefers-reduced-motion
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
      setValue(to);
      prevValueRef.current = to;
      return;
    }

    if (isFirstRender.current) {
      isFirstRender.current = false;
      if (from === undefined || from === to) {
        setValue(to);
        prevValueRef.current = to;
        return;
      }
    }

    // Only animate if value actually changed
    if (to === prevValueRef.current) {
      return;
    }

    const startVal = prevValueRef.current;
    const endVal = to;
    let startTime: number | null = null;
    let animationFrameId: number;

    const step = (timestamp: number) => {
      if (!startTime) startTime = timestamp;
      const progress = Math.min((timestamp - startTime) / (duration * 1000), 1);
      // Ease out cubic
      const easedProgress = 1 - Math.pow(1 - progress, 3);
      const current = startVal + (endVal - startVal) * easedProgress;
      setValue(current);

      if (progress < 1) {
        animationFrameId = requestAnimationFrame(step);
      } else {
        setValue(endVal);
        prevValueRef.current = endVal;
      }
    };

    animationFrameId = requestAnimationFrame(step);
    return () => cancelAnimationFrame(animationFrameId);
  }, [to, from, duration]);

  const formatted = decimals > 0 ? value.toFixed(decimals) : Math.round(value).toLocaleString();

  return (
    <span className={className}>
      {prefix}
      {formatted}
      {suffix}
    </span>
  );
};

export default CountUpMetric;
