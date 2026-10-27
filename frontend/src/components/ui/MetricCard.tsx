import React from 'react';

export interface MetricCardProps {
  label: string;
  /** Rendered as-is. Pass null/undefined (or set `unavailable`) to show an explicit unavailable state. */
  value?: React.ReactNode;
  unit?: string;
  hint?: string;
  tone?: 'default' | 'success' | 'warning' | 'danger' | 'info';
  unavailable?: boolean;
  /** Label shown when a metric cannot be retrieved. Defaults to "Unavailable". Never faked as 0. */
  unavailableLabel?: string;
  icon?: React.ReactNode;
  className?: string;
}

const VALUE_TONE: Record<NonNullable<MetricCardProps['tone']>, string> = {
  default: 'text-ink',
  success: 'text-success',
  warning: 'text-warning',
  danger: 'text-danger',
  info: 'text-info',
};

/**
 * A single persisted metric. Phase 4A / Phase 14: an unavailable metric is shown
 * as "Unavailable", never substituted with a zero or mock value.
 */
export const MetricCard: React.FC<MetricCardProps> = ({
  label,
  value,
  unit,
  hint,
  tone = 'default',
  unavailable = false,
  unavailableLabel = 'Unavailable',
  icon,
  className = '',
}) => {
  const isUnavailable = unavailable || value === null || value === undefined || value === '';
  return (
    <div className={`bg-panel/90 border border-line rounded-panel p-4 shadow-panel ${className}`}>
      <div className="flex items-center justify-between gap-2">
        <span className="text-[11px] font-semibold uppercase tracking-wider text-ink-faint">{label}</span>
        {icon && <span className="text-ink-faint shrink-0">{icon}</span>}
      </div>
      <div className="mt-2 flex items-baseline gap-1.5">
        {isUnavailable ? (
          <span className="text-lg font-bold text-ink-faint italic" title="This metric is not available from the backend.">
            {unavailableLabel}
          </span>
        ) : (
          <>
            <span className={`text-2xl font-black tracking-tight font-mono ${VALUE_TONE[tone]}`}>{value}</span>
            {unit && <span className="text-sm text-ink-muted font-medium">{unit}</span>}
          </>
        )}
      </div>
      {hint && <p className="mt-1 text-[11px] text-ink-muted leading-snug">{hint}</p>}
    </div>
  );
};
