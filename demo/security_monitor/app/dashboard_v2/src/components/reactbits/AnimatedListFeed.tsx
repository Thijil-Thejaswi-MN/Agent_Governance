// Inspired by React Bits (https://reactbits.dev) AnimatedList - MIT + Commons Clause License
import React from 'react';
import { motion } from 'framer-motion';

interface AnimatedListProps {
  children: React.ReactNode[];
  className?: string;
  delay?: number;
}

export const AnimatedListFeed: React.FC<AnimatedListProps> = ({
  children,
  className = '',
  delay = 0.05,
}) => {
  const isReduced = typeof window !== 'undefined' && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  return (
    <div className={className}>
      {children.map((child, index) => (
        <motion.div
          key={index}
          initial={isReduced ? false : { opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.35, delay: index * delay, ease: 'easeOut' }}
        >
          {child}
        </motion.div>
      ))}
    </div>
  );
};
