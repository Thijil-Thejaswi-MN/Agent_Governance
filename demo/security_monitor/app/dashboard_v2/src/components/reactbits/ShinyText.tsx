import React from 'react';

interface ShinyTextProps {
  text: string;
  className?: string;
  speed?: number;
}

export const ShinyText: React.FC<ShinyTextProps> = ({
  text,
  className = '',
  speed = 4,
}) => {
  return (
    <span
      className={`inline-block bg-[linear-gradient(110deg,#93c5fd,45%,#ffffff,55%,#93c5fd)] dark:bg-[linear-gradient(110deg,#38bdf8,45%,#ffffff,55%,#38bdf8)] bg-[length:200%_100%] bg-clip-text text-transparent animate-shimmer font-semibold ${className}`}
      style={{ animationDuration: `${speed}s` }}
    >
      {text}
    </span>
  );
};
