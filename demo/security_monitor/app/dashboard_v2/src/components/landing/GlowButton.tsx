import React from 'react';

export interface GlowButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'solid' | 'outline';
  href?: string;
  children: React.ReactNode;
  className?: string;
}

export const GlowButton: React.FC<GlowButtonProps> = ({
  variant = 'solid',
  href,
  children,
  className = '',
  disabled,
  type = 'button',
  onClick,
  ...rest
}) => {
  const handleAnchorClick = (e: React.MouseEvent<HTMLAnchorElement>) => {
    if (href?.startsWith('#')) {
      e.preventDefault();
      const target = document.querySelector(href);
      if (target) {
        const prefersReduced =
          typeof window !== 'undefined' &&
          window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;
        target.scrollIntoView({ behavior: prefersReduced ? 'auto' : 'smooth' });
        if (typeof window !== 'undefined' && window.history?.pushState) {
          window.history.pushState(null, '', href);
        }
      }
    }
    if (onClick) {
      onClick(e as any);
    }
  };

  if (variant === 'outline' || href) {
    return (
      <a
        href={href || '#'}
        onClick={handleAnchorClick}
        className={`group relative inline-flex items-center justify-center rounded-full p-[1px] select-none transition-all duration-200 outline-none focus-visible:ring-2 focus-visible:ring-[#3B82F6] focus-visible:ring-offset-2 focus-visible:ring-offset-black bg-gradient-to-r from-[#4F46E5] via-[#BE185D] to-[#D97706] hover:shadow-[0_0_20px_rgba(99,102,241,0.35)] ${className}`}
        {...(rest as any)}
      >
        <span className="flex min-h-[44px] w-full items-center justify-center rounded-full bg-[#0E121A] px-6 py-2.5 text-[14px] font-medium text-white transition-colors duration-200 group-hover:bg-[#161B26]">
          {children}
        </span>
      </a>
    );
  }

  return (
    <button
      type={type}
      disabled={disabled}
      onClick={onClick}
      className={`relative inline-flex items-center justify-center min-h-[44px] px-6 py-2.5 rounded-full font-semibold text-[14px] text-white select-none transition-all duration-200 bg-gradient-to-r from-[#4338CA] via-[#BE185D] to-[#D97706] hover:brightness-110 hover:-translate-y-0.5 hover:shadow-[0_0_24px_rgba(245,158,11,0.35)] focus:outline-none focus:ring-2 focus:ring-[#3B82F6] focus:ring-offset-2 focus:ring-offset-black disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:translate-y-0 disabled:hover:brightness-100 disabled:hover:shadow-none ${className}`}
      {...rest}
    >
      {children}
    </button>
  );
};