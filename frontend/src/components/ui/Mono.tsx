import React from 'react';

export interface MonoProps {
  children: React.ReactNode;
  /** Optional full value for the title tooltip when text is truncated. */
  title?: string;
  className?: string;
}

/**
 * Monospaced rendering for technical values (event IDs, IPs, hashes,
 * dataset/eval run identifiers) — Phase 2.3.
 */
export const Mono: React.FC<MonoProps> = ({ children, title, className = '' }) => (
  <span
    title={title}
    className={`font-mono text-[11px] text-ink-soft bg-app/60 border border-line rounded px-1.5 py-0.5 ${className}`}
  >
    {children}
  </span>
);
