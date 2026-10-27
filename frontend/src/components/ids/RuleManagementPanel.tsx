// Rule management panel: enumerate the registry by detection layer with
// enable/disable toggles, tunable thresholds, live hit counters and JSON I/O.
import React, { useMemo, useRef, useState } from 'react';
import {
  Sliders,
  ToggleRight,
  ToggleLeft,
  Upload,
  Download,
  RotateCcw,
  Signature,
  Gauge,
  Workflow,
} from 'lucide-react';
import type { RuleMeta } from './types';
import { Card, SeverityBadge, Tooltip } from './primitives';
import { Button } from '../ui';

interface RuleManagementPanelProps {
  rules: RuleMeta[];
  enabledMap: Record<string, boolean>;
  hitCounts: Record<string, number>;
  onChangeEnabled: (ruleId: string, enabled: boolean) => void;
  onReset: () => void;
}

const LAYER_META: Record<string, { label: string; icon: React.ReactNode; hint: string }> = {
  signature: { label: 'Signature-Based', icon: <Signature className="w-3.5 h-3.5" />, hint: 'Regex / pattern matching against packet payloads and headers.' },
  threshold: { label: 'Threshold-Based', icon: <Gauge className="w-3.5 h-3.5" />, hint: 'Rate and volume limits that trigger an alert when exceeded.' },
  stateful: { label: 'Stateful', icon: <Workflow className="w-3.5 h-3.5" />, hint: 'Session/flow correlation across the packet stream.' },
};

export const RuleManagementPanel: React.FC<RuleManagementPanelProps> = ({
  rules,
  enabledMap,
  hitCounts,
  onChangeEnabled,
  onReset,
}) => {
  const fileRef = useRef<HTMLInputElement>(null);
  const [error, setError] = useState<string | null>(null);

  const groups = useMemo(() => {
    const g: Record<string, RuleMeta[]> = { signature: [], threshold: [], stateful: [] };
    rules.forEach((r) => (g[r.layer] ??= []).push(r));
    return g;
  }, [rules]);

  const activeCount = rules.filter((r) => (enabledMap[r.rule_id] ?? r.enabled)).length;

  const exportRules = () => {
    const payload = rules.map((r) => ({
      rule_id: r.rule_id,
      layer: r.layer,
      severity: r.severity,
      enabled: enabledMap[r.rule_id] ?? r.enabled,
      threshold: r.threshold,
    }));
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'ids-rules-config.json';
    a.click();
    URL.revokeObjectURL(url);
  };

  const importRules = (file: File) => {
    setError(null);
    const reader = new FileReader();
    reader.onload = () => {
      try {
        const parsed = JSON.parse(String(reader.result));
        if (!Array.isArray(parsed)) throw new Error('Expected an array of rule configs.');
        parsed.forEach((item: { rule_id?: string; enabled?: boolean }) => {
          if (item.rule_id && typeof item.enabled === 'boolean') {
            onChangeEnabled(item.rule_id, item.enabled);
          }
        });
      } catch (e) {
        setError(`Import failed: ${e instanceof Error ? e.message : 'invalid JSON'}`);
      }
    };
    reader.readAsText(file);
  };

  return (
    <Card
      title="Rule Management"
      icon={<Sliders className="w-4 h-4" />}
      right={
        <div className="flex items-center gap-1.5">
          <span className="text-[11px] text-ink-muted mr-1">
            {activeCount}/{rules.length} active
          </span>
          <Button variant="secondary" size="sm" className="p-1.5" onClick={exportRules} aria-label="Export rules (JSON)" title="Export rules (JSON)">
            <Download className="w-3.5 h-3.5" />
          </Button>
          <Button variant="secondary" size="sm" className="p-1.5" onClick={() => fileRef.current?.click()} aria-label="Import rules (JSON)" title="Import rules (JSON)">
            <Upload className="w-3.5 h-3.5" />
          </Button>
          <Button variant="secondary" size="sm" className="p-1.5" onClick={onReset} aria-label="Reset to defaults" title="Reset to defaults">
            <RotateCcw className="w-3.5 h-3.5" />
          </Button>
          <input
            ref={fileRef}
            type="file"
            accept="application/json"
            className="hidden"
            onChange={(e) => {
              const f = e.target.files?.[0];
              if (f) importRules(f);
              e.target.value = '';
            }}
          />
        </div>
      }
    >
      {error && (
        <div className="mb-3 text-[11px] text-danger bg-danger/10 border border-danger/25 rounded-lg px-3 py-2">{error}</div>
      )}

      <div className="space-y-5">
        {(['signature', 'threshold', 'stateful'] as const).map((layer) => {
          const meta = LAYER_META[layer];
          const list = groups[layer] ?? [];
          return (
            <div key={layer}>
              <div className="flex items-center gap-2 mb-2">
                <span className="text-accent-soft">{meta.icon}</span>
                <span className="text-xs font-bold uppercase tracking-wider text-ink-soft">{meta.label}</span>
                <Tooltip label={meta.hint} />
                <span className="text-[11px] text-ink-faint ml-auto">{list.length} rules</span>
              </div>
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-2">
                {list.map((r) => {
                  const on = enabledMap[r.rule_id] ?? r.enabled;
                  const hits = hitCounts[r.rule_id] ?? 0;
                  return (
                    <div
                      key={r.rule_id}
                      className={`rounded-lg border p-2.5 flex items-start gap-2.5 transition-colors duration-base ${
                        on ? 'border-line-strong bg-app/70' : 'border-line bg-app/30 opacity-60'
                      }`}
                    >
                      <button
                        onClick={() => onChangeEnabled(r.rule_id, !on)}
                        aria-pressed={on}
                        aria-label={`${on ? 'Disable' : 'Enable'} rule ${r.name}`}
                        className="mt-0.5 shrink-0 text-ink-muted hover:text-accent-soft focus:outline-none focus-visible:ring-2 focus-visible:ring-accent/40 rounded"
                      >
                        {on ? <ToggleRight className="w-5 h-5 text-accent-soft" /> : <ToggleLeft className="w-5 h-5" />}
                      </button>
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-semibold text-ink truncate">{r.name}</span>
                          <SeverityBadge severity={r.severity} />
                        </div>
                        <p className="text-[11px] text-ink-faint mt-0.5 line-clamp-2">{r.description}</p>
                        {r.tunable && r.threshold && (
                          <div className="flex flex-wrap gap-1 mt-1.5">
                            {Object.entries(r.threshold).map(([k, v]) => (
                              <span key={k} className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-elevated text-ink-muted">
                                {k}: {v}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                      <div className="text-right shrink-0">
                        <div className={`text-sm font-bold font-mono ${hits > 0 ? 'text-rose-400' : 'text-ink-faint'}`}>{hits}</div>
                        <div className="text-[9px] uppercase text-ink-faint">hits</div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          );
        })}
      </div>
    </Card>
  );
};
