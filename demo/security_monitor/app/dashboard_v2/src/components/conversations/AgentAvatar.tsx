import React from 'react';
import { getAgentColorStyle, getAgentInitials } from '../../logic/agentColors';

export const AgentRingAvatar: React.FC<{
  agentId: string;
  name?: string;
  colourIndex?: number;
  size?: 'sm' | 'md' | 'lg';
  className?: string;
}> = ({ agentId, name, colourIndex, size = 'md', className = '' }) => {
  const style = getAgentColorStyle(agentId, colourIndex);
  const initials = getAgentInitials(name || agentId);

  const sizeClasses = {
    sm: 'w-6 h-6 text-[10px]',
    md: 'w-8 h-8 text-[12px]',
    lg: 'w-10 h-10 text-[14px]',
  }[size];

  return (
    <div
      className={`relative inline-flex items-center justify-center rounded-full bg-surface-1 font-mono font-semibold shrink-0 select-none border-[1.5px] ${style.border} ${style.text} ${sizeClasses} ${className}`}
      title={name || agentId}
      aria-label={name || agentId}
    >
      {initials}
    </div>
  );
};
