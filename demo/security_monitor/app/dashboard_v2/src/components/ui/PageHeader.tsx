import React from 'react';

export interface PageHeaderProps extends Omit<React.HTMLAttributes<HTMLElement>, 'title'> {
  title: React.ReactNode;
  subtitle?: React.ReactNode;
  actions?: React.ReactNode;
  titleId?: string;
  titleProps?: React.HTMLAttributes<HTMLHeadingElement>;
  titleClassName?: string;
}

export const PageHeader: React.FC<PageHeaderProps> = ({
  title,
  subtitle,
  actions,
  titleId,
  titleProps,
  titleClassName,
  className = '',
  ...rest
}) => {
  return (
    <header
      className={`flex flex-col sm:flex-row sm:items-start sm:justify-between gap-4 mb-6 ${className}`}
      {...rest}
    >
      <div className="min-w-0 flex-1">
        <h1
          id={titleId}
          className={`font-serif text-[34px] leading-tight text-fg font-normal m-0 tracking-tight ${titleClassName || ''}`}
          {...titleProps}
        >
          {title}
        </h1>
        {subtitle && (
          <div className="mt-1.5 text-[15px] text-fg-2 leading-normal">
            {subtitle}
          </div>
        )}
      </div>
      {actions && (
        <div className="flex flex-wrap items-center gap-3 shrink-0 sm:self-start">
          {actions}
        </div>
      )}
    </header>
  );
};
