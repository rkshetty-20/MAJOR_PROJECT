import React from 'react';
import { AlertTriangle, Inbox, RotateCw } from 'lucide-react';
import { Button } from './Button';

// ---------------------------------------------------------------------------
// Skeleton loaders (layout-stable, generalized from ids/primitives)
// ---------------------------------------------------------------------------
export const Skeleton: React.FC<{ className?: string }> = ({ className = '' }) => (
  <div className={`animate-pulse rounded-lg bg-elevated/70 ${className}`} aria-hidden />
);

export const SkeletonPanel: React.FC<{ lines?: number }> = ({ lines = 4 }) => (
  <div className="space-y-2.5" role="status" aria-label="Loading">
    {Array.from({ length: lines }).map((_, i) => (
      <Skeleton key={i} className={i === 0 ? 'h-6 w-2/3' : 'h-4 w-full'} />
    ))}
  </div>
);

// ---------------------------------------------------------------------------
// Empty state — explains why there is no data + a next action (Phase 14)
// ---------------------------------------------------------------------------
export interface EmptyStateProps {
  title: string;
  description?: string;
  action?: React.ReactNode;
  icon?: React.ReactNode;
  className?: string;
}

export const EmptyState: React.FC<EmptyStateProps> = ({ title, description, action, icon, className = '' }) => (
  <div className={`flex flex-col items-center justify-center text-center py-10 px-4 ${className}`}>
    <span className="p-3 rounded-full bg-elevated/60 border border-line text-ink-faint mb-3">
      {icon ?? <Inbox className="w-6 h-6" />}
    </span>
    <p className="text-sm font-semibold text-ink-soft">{title}</p>
    {description && <p className="text-xs text-ink-muted mt-1 max-w-md">{description}</p>}
    {action && <div className="mt-4">{action}</div>}
  </div>
);

// ---------------------------------------------------------------------------
// Error state — concise explanation + retry when safe (Phase 14)
// ---------------------------------------------------------------------------
export interface ErrorStateProps {
  title?: string;
  message: string;
  onRetry?: () => void;
  retryLabel?: string;
  icon?: React.ReactNode;
  className?: string;
}

export const ErrorState: React.FC<ErrorStateProps> = ({
  title = 'Something went wrong',
  message,
  onRetry,
  retryLabel = 'Retry',
  icon,
  className = '',
}) => (
  <div
    role="alert"
    className={`flex flex-col items-center justify-center text-center py-10 px-4 rounded-panel border border-danger/30 bg-danger/5 ${className}`}
  >
    <span className="p-3 rounded-full bg-danger/15 border border-danger/30 text-danger mb-3">
      {icon ?? <AlertTriangle className="w-6 h-6" />}
    </span>
    <p className="text-sm font-semibold text-ink">{title}</p>
    <p className="text-xs text-ink-muted mt-1 max-w-md">{message}</p>
    {onRetry && (
      <Button variant="secondary" size="sm" className="mt-4" onClick={onRetry} leftIcon={<RotateCw className="w-3.5 h-3.5" />}>
        {retryLabel}
      </Button>
    )}
  </div>
);
