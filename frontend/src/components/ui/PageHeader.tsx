import React from 'react';

export interface PageHeaderProps {
  title: string;
  description?: string;
  icon?: React.ReactNode;
  actions?: React.ReactNode;
  breadcrumb?: string[];
  className?: string;
}

/**
 * Consistent page-level header (Phase 3.2). Every page aligns to the same
 * grid: breadcrumb (optional) -> title + description -> right-aligned actions.
 */
export const PageHeader: React.FC<PageHeaderProps> = ({
  title,
  description,
  icon,
  actions,
  breadcrumb,
  className = '',
}) => (
  <header className={`mb-6 ${className}`}>
    {breadcrumb && breadcrumb.length > 0 && (
      <nav aria-label="Breadcrumb" className="mb-1.5 flex items-center gap-1.5 text-[11px] text-ink-faint">
        {breadcrumb.map((crumb, i) => (
          <React.Fragment key={i}>
            {i > 0 && <span aria-hidden className="text-ink-faint/70">/</span>}
            <span className={i === breadcrumb.length - 1 ? 'text-ink-muted' : undefined}>{crumb}</span>
          </React.Fragment>
        ))}
      </nav>
    )}
    <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
      <div className="flex items-start gap-3 min-w-0">
        {icon && (
          <span className="mt-0.5 p-2 rounded-lg bg-accent/10 border border-accent/20 text-accent-soft shrink-0">
            {icon}
          </span>
        )}
        <div className="min-w-0">
          <h1 className="text-lg font-bold text-ink tracking-tight">{title}</h1>
          {description && <p className="text-sm text-ink-muted mt-0.5 max-w-3xl">{description}</p>}
        </div>
      </div>
      {actions && <div className="flex items-center gap-2 shrink-0">{actions}</div>}
    </div>
  </header>
);
