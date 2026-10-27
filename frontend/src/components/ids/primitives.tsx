// IDS presentational primitives.
// Generic pieces (Card, Tooltip, Skeleton, SkeletonPanel) are now centralized in
// ../ui and re-exported here so existing IDS import sites keep working unchanged.
// The IDS-specific, type-bound pieces (severity/verdict styling, gauges) remain here.
import React from 'react';
import type { Severity, VerdictLabel } from './types';

// Re-export the generalized, token-based primitives from the shared UI kit.
export { Card, Tooltip, Skeleton, SkeletonPanel } from '../ui';
export type { CardProps, TooltipProps } from '../ui';

// ---------------------------------------------------------------------------
// Color helpers (IDS domain)
// ---------------------------------------------------------------------------
export const SEVERITY_STYLES: Record<Severity, string> = {
  info: 'bg-slate-500/15 text-slate-300 border-slate-500/30',
  low: 'bg-sky-500/15 text-sky-300 border-sky-500/30',
  medium: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
  high: 'bg-orange-500/15 text-orange-300 border-orange-500/30',
  critical: 'bg-rose-500/15 text-rose-300 border-rose-500/30',
};

export const VERDICT_STYLES: Record<VerdictLabel, { chip: string; ring: string; hex: string }> = {
  Clean: { chip: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30', ring: '#34d399', hex: '#34d399' },
  Suspicious: { chip: 'bg-amber-500/15 text-amber-300 border-amber-500/30', ring: '#fbbf24', hex: '#fbbf24' },
  Malicious: { chip: 'bg-rose-500/15 text-rose-300 border-rose-500/30', ring: '#fb7185', hex: '#fb7185' },
};

// ---------------------------------------------------------------------------
// Badges (IDS domain)
// ---------------------------------------------------------------------------
export const SeverityBadge: React.FC<{ severity: Severity; className?: string }> = ({ severity, className = '' }) => (
  <span
    className={`inline-flex items-center px-2 py-0.5 rounded-md text-[10px] font-bold uppercase tracking-wider border ${SEVERITY_STYLES[severity]} ${className}`}
  >
    {severity}
  </span>
);

export const VerdictBadge: React.FC<{ label: VerdictLabel; score?: number }> = ({ label, score }) => {
  const style = VERDICT_STYLES[label];
  return (
    <span className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider border ${style.chip}`}>
      {label}
      {typeof score === 'number' && <span className="font-mono normal-case">{score.toFixed(1)}</span>}
    </span>
  );
};

// ---------------------------------------------------------------------------
// Animated SVG threat gauge (0-100)
// ---------------------------------------------------------------------------
export const ThreatGauge: React.FC<{ score: number; size?: number; label?: string }> = ({
  score,
  size = 160,
  label = 'Threat',
}) => {
  const clamped = Math.max(0, Math.min(100, score));
  const stroke = 12;
  const radius = (size - stroke) / 2;
  const circumference = 2 * Math.PI * radius;
  // 270-degree arc gauge
  const arcFraction = 0.75;
  const dash = circumference * arcFraction;
  const progress = (clamped / 100) * dash;
  const color = clamped <= 34 ? '#34d399' : clamped <= 62 ? '#fbbf24' : '#fb7185';

  return (
    <div className="relative inline-flex flex-col items-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-[135deg]">
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke="#1e293b"
          strokeWidth={stroke}
          strokeDasharray={`${dash} ${circumference}`}
          strokeLinecap="round"
        />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth={stroke}
          strokeDasharray={`${progress} ${circumference}`}
          strokeLinecap="round"
          style={{ transition: 'stroke-dasharray 700ms cubic-bezier(0.22,1,0.36,1), stroke 500ms' }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-3xl font-black text-ink font-mono" style={{ color }}>
          {clamped.toFixed(1)}
        </span>
        <span className="text-[10px] uppercase tracking-widest text-ink-muted font-semibold mt-0.5">{label}</span>
      </div>
    </div>
  );
};

// ---------------------------------------------------------------------------
// Horizontal meter bar (for sub-scores / feature contributions)
// ---------------------------------------------------------------------------
export const MeterBar: React.FC<{
  value: number; // 0..1
  color?: string;
  label?: string;
  rightText?: string;
  className?: string;
}> = ({ value, color = '#6366f1', label, rightText, className = '' }) => {
  const pct = Math.max(0, Math.min(1, value)) * 100;
  return (
    <div className={className}>
      {(label || rightText) && (
        <div className="flex items-center justify-between mb-1">
          {label && <span className="text-[11px] text-ink-muted font-medium truncate">{label}</span>}
          {rightText && <span className="text-[11px] font-mono text-ink-soft">{rightText}</span>}
        </div>
      )}
      <div className="w-full h-2 bg-elevated rounded-full overflow-hidden">
        <div
          className="h-full rounded-full"
          style={{ width: `${pct}%`, backgroundColor: color, transition: 'width 600ms cubic-bezier(0.22,1,0.36,1)' }}
        />
      </div>
    </div>
  );
};
