import React from 'react';

/** A label whose letters settle in one after another when it changes. Screen readers get the plain text. */
export const AnimatedLabel: React.FC<{ text: string; className?: string }> = ({ text, className }) => (
  <span className={className}>
    <span className="sr-only">{text}</span>
    <span key={text} aria-hidden="true">
      {Array.from(text).map((ch, i) => (
        <span key={i} className="letter-in" style={{ animationDelay: `${Math.min(i, 30) * 14}ms` }}>
          {ch}
        </span>
      ))}
    </span>
  </span>
);
