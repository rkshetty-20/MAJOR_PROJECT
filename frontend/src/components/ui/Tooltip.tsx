import React from 'react';
import { Info } from 'lucide-react';

export interface TooltipProps {
  label: string;
  children?: React.ReactNode;
}

/**
 * Lightweight hover/focus tooltip (pure CSS positioning via group).
 * Same prop shape as ids/primitives Tooltip so it can be re-exported directly.
 */
export const Tooltip: React.FC<TooltipProps> = ({ label, children }) => (
  <span className="relative inline-flex items-center group align-middle">
    {children ?? <Info className="w-3.5 h-3.5 text-ink-faint cursor-help" aria-hidden />}
    <span
      role="tooltip"
      className="pointer-events-none absolute left-1/2 bottom-full z-50 mb-1.5 hidden -translate-x-1/2 whitespace-normal rounded-lg border border-line-strong bg-app px-2.5 py-1.5 text-[11px] text-ink-soft shadow-raised max-w-xs text-center leading-snug group-hover:block group-focus-within:block"
    >
      {label}
    </span>
  </span>
);
