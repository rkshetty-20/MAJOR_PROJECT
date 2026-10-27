import React from 'react';

export type BadgeTone = 'neutral' | 'accent' | 'success' | 'warning' | 'danger' | 'info';

const TONE: Record<BadgeTone, string> = {
  neutral: 'bg-elevated/60 text-ink-soft border-line-strong',
  accent: 'bg-accent/15 text-accent-soft border-accent/30',
  success: 'bg-success/15 text-success border-success/30',
  warning: 'bg-warning/15 text-warning border-warning/30',
  danger: 'bg-danger/15 text-danger border-danger/30',
  info: 'bg-info/15 text-info border-info/30',
};

export interface StatusBadgeProps {
  tone?: BadgeTone;
  children: React.ReactNode;
  className?: string;
  /** Optional non-color glyph so severity is not conveyed by color alone (Phase 16). */
  glyph?: React.ReactNode;
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({ tone = 'neutral', children, className = '', glyph }) => (
  <span
    className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md text-[11px] font-semibold uppercase tracking-wider border ${TONE[tone]} ${className}`}
  >
    {glyph && <span aria-hidden>{glyph}</span>}
    {children}
  </span>
);

export type RiskLevel = 'none' | 'low' | 'medium' | 'high' | 'critical';

const RISK: Record<RiskLevel, { tone: BadgeTone; label: string }> = {
  none: { tone: 'neutral', label: 'None' },
  low: { tone: 'info', label: 'Low' },
  medium: { tone: 'warning', label: 'Medium' },
  high: { tone: 'danger', label: 'High' },
  critical: { tone: 'danger', label: 'Critical' },
};

export interface RiskIndicatorProps {
  level: RiskLevel;
  label?: string;
  className?: string;
}

export const RiskIndicator: React.FC<RiskIndicatorProps> = ({ level, label, className = '' }) => {
  const cfg = RISK[level];
  return <StatusBadge tone={cfg.tone} className={className}>{label ?? cfg.label}</StatusBadge>;
};
