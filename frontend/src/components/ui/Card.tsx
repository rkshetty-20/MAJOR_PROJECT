import React from 'react';

export interface CardProps {
  title?: string;
  icon?: React.ReactNode;
  right?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
  bodyClassName?: string;
}

/**
 * Canonical surface container. Generalized from ids/primitives so the whole
 * app shares one card shell. Retains the exact prop shape the IDS panels use.
 */
export const Card: React.FC<CardProps> = ({
  title,
  icon,
  right,
  children,
  className = '',
  bodyClassName = '',
}) => (
  <div className={`bg-panel/90 border border-line rounded-panel overflow-hidden shadow-panel ${className}`}>
    {title && (
      <div className="px-5 py-3.5 border-b border-line bg-app/40 flex items-center justify-between gap-3">
        <div className="flex items-center gap-2 min-w-0">
          {icon && <span className="text-accent-soft shrink-0">{icon}</span>}
          <h3 className="text-sm font-bold text-ink tracking-wide uppercase truncate">{title}</h3>
        </div>
        {right && <div className="shrink-0">{right}</div>}
      </div>
    )}
    <div className={`p-5 ${bodyClassName}`}>{children}</div>
  </div>
);

export interface SectionHeaderProps {
  title: string;
  description?: string;
  right?: React.ReactNode;
  className?: string;
}

export const SectionHeader: React.FC<SectionHeaderProps> = ({ title, description, right, className = '' }) => (
  <div className={`flex items-start justify-between gap-3 ${className}`}>
    <div className="min-w-0">
      <h2 className="text-sm font-semibold text-ink tracking-wide">{title}</h2>
      {description && <p className="text-xs text-ink-muted mt-0.5">{description}</p>}
    </div>
    {right && <div className="shrink-0">{right}</div>}
  </div>
);
