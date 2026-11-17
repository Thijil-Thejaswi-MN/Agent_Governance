+import React, { forwardRef } from 'react';

export type ButtonVariant = 'primary' | 'secondary' | 'ghost' | 'danger';
export type ButtonSize = 'sm' | 'md' | 'lg' | 'icon' | 'icon-sm';

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  children?: React.ReactNode;
}

const variantStyles: Record<ButtonVariant, string> = {
  primary:
    'bg-[image:var(--accent-grad)] text-white font-medium shadow-sm hover:brightness-110 active:brightness-95 focus-visible:ring-accent disabled:opacity-50 disabled:pointer-events-none',
  secondary:
    'bg-surface-2 text-fg border border-line font-medium hover:bg-surface-3 hover:border-line-strong active:bg-surface-1 focus-visible:ring-accent disabled:opacity-50 disabled:pointer-events-none',
  ghost:
    'bg-transparent text-fg-2 hover:bg-surface-2 hover:text-fg active:bg-surface-3 focus-visible:ring-accent disabled:opacity-50 disabled:pointer-events-none',
  danger:
    'bg-bad-tint text-bad border border-bad/30 hover:bg-bad/20 active:bg-bad/30 focus-visible:ring-bad disabled:opacity-50 disabled:pointer-events-none',
};

const sizeStyles: Record<ButtonSize, string> = {
  sm: 'h-8 px-2.5 text-[12px] gap-1.5 rounded-lg',
  md: 'h-10 px-3.5 text-[14px] gap-2 rounded-lg',
  lg: 'h-11 px-4 text-[15px] gap-2.5 rounded-lg',
  icon: 'h-9 w-9 p-0 justify-center rounded-lg',
  'icon-sm': 'h-8 w-8 p-0 justify-center rounded-lg',
};

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ variant = 'secondary', size = 'md', className = '', type = 'button', id, disabled, children, ...rest }, ref) => {
    return (
      <button
        ref={ref}
        id={id}
        type={type}
        disabled={disabled}
        className={`inline-flex items-center justify-center transition-colors cursor-pointer select-none focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-offset-2 focus-visible:ring-offset-bg ${variantStyles[variant]} ${sizeStyles[size]} ${className}`}
        {...rest}
      >
        {children}
      </button>
    );
  }
);

Button.displayName = 'Button';
