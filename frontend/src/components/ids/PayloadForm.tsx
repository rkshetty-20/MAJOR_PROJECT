// Payload submission form: category-grouped attack selector, traffic volume,
// packet-count slider, detection sensitivity, and one-click preset launcher.
import React, { useMemo, useState } from 'react';
import {
  Play,
  Zap,
  Layers,
  Sparkles,
  SlidersHorizontal,
  ChevronRight,
} from 'lucide-react';
import type { CatalogCategory, CatalogAttack, Preset, Volume } from './types';
import { SeverityBadge, Tooltip } from './primitives';
import { Button } from '../ui';

interface PayloadFormProps {
  catalog: CatalogCategory[];
  presets: Preset[];
  selectedAttackId: string;
  volume: Volume;
  packetCount: number;
  sensitivity: number;
  isRunning: boolean;
  isPresetRunning: boolean;
  onSelectAttack: (id: string) => void;
  onVolumeChange: (v: Volume) => void;
  onPacketCountChange: (n: number) => void;
  onSensitivityChange: (n: number) => void;
  onSubmit: () => void;
  onRunPreset: (presetId: string) => void;
}

const VOLUME_DEFAULTS: Record<Volume, number> = { low: 8, medium: 20, high: 60 };

export const PayloadForm: React.FC<PayloadFormProps> = ({
  catalog,
  presets,
  selectedAttackId,
  volume,
  packetCount,
  sensitivity,
  isRunning,
  isPresetRunning,
  onSelectAttack,
  onVolumeChange,
  onPacketCountChange,
  onSensitivityChange,
  onSubmit,
  onRunPreset,
}) => {
  const [categoryFilter, setCategoryFilter] = useState<string>('all');

  const flat: CatalogAttack[] = useMemo(
    () => catalog.flatMap((c) => c.attacks),
    [catalog],
  );
  const selected: CatalogAttack | undefined = useMemo(
    () => flat.find((a) => a.id === selectedAttackId),
    [flat, selectedAttackId],
  );

  const visibleCategories = useMemo(() => {
    if (categoryFilter === 'all') return catalog;
    return catalog.filter((c) => c.id === categoryFilter);
  }, [catalog, categoryFilter]);

  const sensitivityLabel = sensitivity < 0.34 ? 'Conservative' : sensitivity < 0.67 ? 'Balanced' : 'Aggressive';
  const busy = isRunning || isPresetRunning;

  return (
    <div className="bg-panel/90 border border-line rounded-panel overflow-hidden">
      <div className="px-6 py-4 border-b border-line bg-app/60 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Zap className="w-4 h-4 text-accent-soft" />
          <h2 className="text-sm font-bold text-ink tracking-wide uppercase">Payload Submission</h2>
        </div>
        {selected && (
          <div className="flex items-center gap-2">
            <span className="text-xs text-ink-muted hidden sm:inline">Selected:</span>
            <span className="text-xs font-semibold text-accent-soft">{selected.name}</span>
            <SeverityBadge severity={selected.severity} />
          </div>
        )}
      </div>

      <div className="p-6 space-y-6">
        {/* Preset quick-launch */}
        {presets.length > 0 && (
          <div>
            <div className="flex items-center gap-2 mb-2">
              <Sparkles className="w-4 h-4 text-purple-400" />
              <span className="text-xs font-semibold uppercase tracking-wider text-ink-soft">
                Quick-Launch Attack Presets
              </span>
              <Tooltip label="One-click multi-stage scenarios that unfold step-by-step across the kill chain." />
            </div>
            <div className="flex gap-2 overflow-x-auto pb-2 -mx-1 px-1">
              {presets.map((p) => (
                <button
                  key={p.id}
                  type="button"
                  disabled={busy}
                  onClick={() => onRunPreset(p.id)}
                  title={p.tagline}
                  className="shrink-0 group text-left px-3.5 py-2.5 rounded-panel border border-line-strong bg-app hover:border-purple-500/50 hover:bg-purple-500/5 disabled:opacity-40 disabled:cursor-not-allowed transition-all duration-base max-w-[240px]"
                >
                  <div className="flex items-center gap-1.5">
                    <span className="text-xs font-bold text-ink truncate">{p.name}</span>
                    <ChevronRight className="w-3.5 h-3.5 text-purple-400 opacity-0 group-hover:opacity-100 transition-opacity" />
                  </div>
                  <p className="text-[11px] text-ink-muted mt-0.5 line-clamp-2">{p.tagline}</p>
                </button>
              ))}
            </div>
          </div>
        )}

        {/* Category filter chips */}
        <div>
          <div className="flex items-center gap-2 mb-2">
            <Layers className="w-4 h-4 text-accent-soft" />
            <span className="text-xs font-semibold uppercase tracking-wider text-ink-soft">Attack Category</span>
          </div>
          <div className="flex flex-wrap gap-1.5" role="group" aria-label="Filter attacks by category">
            <CategoryChip active={categoryFilter === 'all'} onClick={() => setCategoryFilter('all')} label="All" />
            {catalog.map((c) => (
              <CategoryChip
                key={c.id}
                active={categoryFilter === c.id}
                onClick={() => setCategoryFilter(c.id)}
                label={c.name}
              />
            ))}
          </div>
        </div>

        {/* Attack selector grid */}
        <div>
          <span className="block text-xs font-semibold uppercase tracking-wider text-ink-soft mb-1.5">
            Payload Type
          </span>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2 max-h-[300px] overflow-y-auto pr-1">
            {visibleCategories.map((cat) =>
              cat.attacks.map((a) => (
                <button
                  key={a.id}
                  type="button"
                  disabled={busy}
                  aria-pressed={selectedAttackId === a.id}
                  onClick={() => onSelectAttack(a.id)}
                  className={`text-left px-3 py-2 rounded-lg border transition-all duration-base disabled:opacity-50 ${
                    selectedAttackId === a.id
                      ? 'border-accent bg-accent/10 ring-1 ring-accent/40'
                      : 'border-line-strong bg-app hover:border-accent/40'
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-semibold text-ink truncate">{a.name}</span>
                    <SeverityBadge severity={a.severity} />
                  </div>
                  <p className="text-[11px] text-ink-faint mt-0.5 line-clamp-1">{a.description}</p>
                </button>
              )),
            )}
          </div>
        </div>

        {/* Volume / packet count / sensitivity */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <div>
            <div className="flex items-center gap-1.5 mb-1.5">
              <span className="text-xs font-semibold uppercase tracking-wider text-ink-soft">Traffic Volume</span>
              <Tooltip label="Synthetic traffic density: affects rate, jitter and source fan-out." />
            </div>
            <div className="grid grid-cols-3 gap-1 bg-app p-1 rounded-panel border border-line-strong" role="group" aria-label="Traffic volume">
              {(['low', 'medium', 'high'] as const).map((level) => (
                <button
                  key={level}
                  type="button"
                  disabled={busy}
                  aria-pressed={volume === level}
                  onClick={() => {
                    onVolumeChange(level);
                    onPacketCountChange(VOLUME_DEFAULTS[level]);
                  }}
                  className={`py-1.5 text-xs font-medium rounded-lg capitalize transition-all duration-base ${
                    volume === level ? 'bg-accent text-white' : 'text-ink-muted hover:text-ink'
                  }`}
                >
                  {level}
                </button>
              ))}
            </div>
          </div>

          <div>
            <div className="flex justify-between items-center mb-1.5">
              <label htmlFor="ids-packet-count" className="text-xs font-semibold uppercase tracking-wider text-ink-soft">Packet Count</label>
              <span className="text-xs font-mono text-accent-soft font-bold">{packetCount}</span>
            </div>
            <input
              id="ids-packet-count"
              type="range"
              min={1}
              max={200}
              value={packetCount}
              disabled={busy}
              aria-label="Packet count"
              onChange={(e) => onPacketCountChange(parseInt(e.target.value, 10))}
              className="w-full h-2 bg-elevated rounded-lg appearance-none cursor-pointer accent-accent"
            />
          </div>

          <div>
            <div className="flex items-center justify-between mb-1.5">
              <div className="flex items-center gap-1.5">
                <SlidersHorizontal className="w-3.5 h-3.5 text-ink-muted" />
                <label htmlFor="ids-sensitivity" className="text-xs font-semibold uppercase tracking-wider text-ink-soft">Sensitivity</label>
              </div>
              <span className="text-[11px] font-mono text-purple-400 font-bold">{sensitivityLabel}</span>
            </div>
            <input
              id="ids-sensitivity"
              type="range"
              min={0}
              max={1}
              step={0.05}
              value={sensitivity}
              disabled={busy}
              aria-label="Detection sensitivity"
              aria-valuetext={sensitivityLabel}
              onChange={(e) => onSensitivityChange(parseFloat(e.target.value))}
              className="w-full h-2 bg-elevated rounded-lg appearance-none cursor-pointer accent-purple-500"
            />
          </div>
        </div>

        {/* Submit */}
        <div className="flex flex-col sm:flex-row items-center justify-between gap-4 p-4 rounded-panel bg-app/60 border border-line">
          <div className="text-xs text-ink-faint">
            Submitting generates synthetic packets, then runs the rules engine &amp; ML anomaly scorer.
          </div>
          <Button
            variant="primary"
            size="lg"
            onClick={onSubmit}
            disabled={busy || !selectedAttackId}
            loading={isRunning}
            leftIcon={!isRunning ? <Play className="w-4 h-4" /> : undefined}
          >
            {isRunning ? 'Processing...' : 'Submit Payload'}
          </Button>
        </div>
      </div>
    </div>
  );
};

const CategoryChip: React.FC<{ active: boolean; onClick: () => void; label: string }> = ({
  active,
  onClick,
  label,
}) => (
  <button
    type="button"
    onClick={onClick}
    aria-pressed={active}
    className={`px-3 py-1 rounded-pill text-[11px] font-medium border transition-all duration-base ${
      active
        ? 'bg-accent text-white border-accent'
        : 'bg-app text-ink-muted border-line-strong hover:text-ink hover:border-line-strong'
    }`}
  >
    {label}
  </button>
);
