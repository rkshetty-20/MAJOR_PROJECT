// Preset unfolding: plays a multi-stage attack narrative step-by-step and lets
// the analyst expand any stage to see the full detection breakdown.
import React, { useEffect, useState } from 'react';
import { ChevronDown, ChevronUp, Play, Film, Flag } from 'lucide-react';
import type { PresetRunResult } from './types';
import { DetectionResultsPanel } from './DetectionResultsPanel';
import { ThreatGauge, VerdictBadge } from './primitives';
import { Button } from '../ui';

export const PresetRunView: React.FC<{ run: PresetRunResult }> = ({ run }) => {
  const [revealed, setRevealed] = useState(1);
  const [expanded, setExpanded] = useState<Record<number, boolean>>({});

  // Reveal stages one at a time to tell the story.
  useEffect(() => {
    setRevealed(0);
    let step = 0;
    const timer = setInterval(() => {
      step += 1;
      setRevealed(step);
      if (step >= run.steps.length) clearInterval(timer);
    }, 550);
    return () => clearInterval(timer);
  }, [run]);

  const done = revealed >= run.steps.length;

  return (
    <div className="space-y-6">
      {/* Narrative header */}
      <div className="bg-panel/90 border border-purple-500/25 rounded-panel overflow-hidden">
        <div className="p-6 flex flex-col md:flex-row gap-6 items-center">
          <div className="flex-1">
            <div className="flex items-center gap-2 mb-1">
              <Film className="w-4 h-4 text-purple-400" />
              <span className="text-xs font-bold uppercase tracking-widest text-purple-300">Attack Simulation Preset</span>
            </div>
            <h3 className="text-xl font-bold text-ink">{run.name}</h3>
            <p className="text-sm text-ink-muted mt-0.5">{run.tagline}</p>
            <p className="text-xs text-ink-faint mt-2 leading-relaxed italic">{run.narrative}</p>
          </div>
          <div className="flex flex-col items-center gap-2">
            <ThreatGauge score={run.overall_threat_score} size={130} label="Peak Threat" />
            <span className="text-[11px] text-ink-faint">
              {done ? `${run.steps.length} stages complete` : `Unfolding ${Math.min(revealed, run.steps.length)}/${run.steps.length}...`}
            </span>
          </div>
        </div>
      </div>

      {/* Stage timeline */}
      <div className="space-y-3">
        {run.steps.slice(0, Math.max(revealed, 1)).map((step, i) => {
          const isOpen = expanded[i];
          const last = i === run.steps.length - 1;
          const detailsId = `preset-stage-${i}-details`;
          return (
            <div key={i} className="rounded-panel border border-line bg-panel/70 overflow-hidden">
              <div className="flex items-center gap-3 px-5 py-4">
                <div className="flex items-center justify-center w-8 h-8 rounded-full bg-purple-500/15 border border-purple-500/30 text-purple-300 font-mono text-sm font-bold shrink-0">
                  {i + 1}
                </div>
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-sm font-bold text-ink">{step.attack_name}</span>
                    <VerdictBadge label={step.result.verdict.label} score={step.result.verdict.threat_score} />
                    <span className="inline-flex items-center gap-1 text-[11px] text-ink-muted">
                      <Flag className="w-3 h-3" /> {step.result.kill_chain.current_label}
                    </span>
                  </div>
                  <p className="text-xs text-ink-muted mt-0.5">{step.beat}</p>
                </div>
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={() => setExpanded((p) => ({ ...p, [i]: !p[i] }))}
                  aria-expanded={isOpen}
                  aria-controls={detailsId}
                  leftIcon={isOpen ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                >
                  {isOpen ? 'Hide' : 'Details'}
                </Button>
              </div>
              {isOpen && (
                <div id={detailsId} role="region" aria-label={`${step.attack_name} detection details`} className="border-t border-line p-5 bg-app/40">
                  <DetectionResultsPanel analysis={step.result} />
                </div>
              )}
              {!last && <div className="ml-9 h-3 w-px bg-app" />}
            </div>
          );
        })}

        {!done && (
          <div className="flex items-center gap-2 text-xs text-purple-300/80 px-2">
            <Play className="w-3.5 h-3.5 animate-pulse" /> Attack progressing to next stage...
          </div>
        )}
      </div>
    </div>
  );
};
