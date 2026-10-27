// Session history + comparison: list all submissions this session, re-open any,
// and compare two analyses side by side (verdict, scores, rule overlap).
import React, { useMemo, useState } from 'react';
import { History, Search, Columns2, Trash2, Eye } from 'lucide-react';
import type { IdsAnalysis } from './types';
import { Card, SeverityBadge, VerdictBadge } from './primitives';
import { Button } from '../ui';

export interface HistoryEntry {
  id: string;
  createdAt: number;
  analysis: IdsAnalysis;
}

interface HistoryPanelProps {
  history: HistoryEntry[];
  currentId?: string;
  onSelect: (entry: HistoryEntry) => void;
  onClear: () => void;
}

export const HistoryPanel: React.FC<HistoryPanelProps> = ({ history, currentId, onSelect, onClear }) => {
  const [query, setQuery] = useState('');
  const [compareMode, setCompareMode] = useState(false);
  const [picked, setPicked] = useState<string[]>([]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return history;
    return history.filter((h) => h.analysis.attack.name.toLowerCase().includes(q) || h.analysis.verdict.label.toLowerCase().includes(q));
  }, [history, query]);

  const togglePick = (id: string) => {
    setPicked((prev) => (prev.includes(id) ? prev.filter((x) => x !== id) : prev.length >= 2 ? [prev[1], id] : [...prev, id]));
  };

  const a = history.find((h) => h.id === picked[0])?.analysis;
  const b = history.find((h) => h.id === picked[1])?.analysis;

  return (
    <Card
      title={`Detection History (${history.length})`}
      icon={<History className="w-4 h-4" />}
      right={
        <div className="flex items-center gap-1.5">
          <button
            type="button"
            onClick={() => { setCompareMode((v) => !v); setPicked([]); }}
            aria-pressed={compareMode}
            className={`inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-[11px] font-medium border transition-colors duration-base ${
              compareMode ? 'bg-purple-600 text-white border-purple-500' : 'bg-elevated text-ink border border-line-strong hover:border-purple-500/50'
            }`}
          >
            <Columns2 className="w-3.5 h-3.5" />
            {compareMode ? 'Comparing' : 'Compare'}
          </button>
          <Button
            variant="secondary"
            size="sm"
            className="p-1.5"
            onClick={onClear}
            disabled={history.length === 0}
            aria-label="Clear history"
            title="Clear history"
          >
            <Trash2 className="w-3.5 h-3.5" />
          </Button>
        </div>
      }
    >
      <div className="relative mb-3">
        <Search className="w-3.5 h-3.5 text-ink-faint absolute left-2.5 top-1/2 -translate-y-1/2" />
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search history by attack or verdict..."
          aria-label="Search history by attack or verdict"
          className="w-full bg-app border border-line-strong rounded-lg pl-8 pr-3 py-1.5 text-xs text-ink focus:outline-none focus:ring-2 focus:ring-accent/40"
        />
      </div>

      {compareMode && a && b && (
        <CompareView a={a} b={b} />
      )}
      {compareMode && picked.length < 2 && (
        <p className="text-[11px] text-purple-300/80 mb-3">Select two detections below to compare.</p>
      )}

      <div className="space-y-1.5 max-h-[360px] overflow-y-auto pr-1">
        {filtered.length === 0 && <div className="text-xs text-ink-muted italic">No history yet. Submit a payload or run a preset.</div>}
        {filtered.map((h) => {
          const isCurrent = h.id === currentId;
          const isPicked = picked.includes(h.id);
          return (
            <div
              key={h.id}
              className={`flex items-center gap-2.5 rounded-lg border px-3 py-2 transition-colors duration-base ${
                isCurrent ? 'border-accent/50 bg-accent/5' : 'border-line bg-app/50 hover:border-line-strong'
              }`}
            >
              {compareMode && (
                <input
                  type="checkbox"
                  checked={isPicked}
                  onChange={() => togglePick(h.id)}
                  aria-label={`Select ${h.analysis.attack.name} for comparison`}
                  className="accent-purple-500 w-4 h-4 shrink-0"
                />
              )}
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-semibold text-ink truncate">{h.analysis.attack.name}</span>
                  <SeverityBadge severity={h.analysis.attack.severity} />
                </div>
                <div className="text-[11px] text-ink-faint font-mono">
                  {new Date(h.createdAt).toLocaleTimeString()} · {h.analysis.generation.packet_count} pkts · {h.analysis.generation.volume}
                </div>
              </div>
              <VerdictBadge label={h.analysis.verdict.label} score={h.analysis.verdict.threat_score} />
              {!compareMode && (
                <Button
                  variant="ghost"
                  size="sm"
                  className="p-1.5"
                  onClick={() => onSelect(h)}
                  aria-label={`Open detection ${h.analysis.attack.name}`}
                  title="Open"
                >
                  <Eye className="w-4 h-4" />
                </Button>
              )}
            </div>
          );
        })}
      </div>
    </Card>
  );
};

const CompareView: React.FC<{ a: IdsAnalysis; b: IdsAnalysis }> = ({ a, b }) => {
  const rulesA = new Set(a.rules.triggered.map((r) => r.rule_id));
  const rulesB = new Set(b.rules.triggered.map((r) => r.rule_id));
  const overlap = [...rulesA].filter((r) => rulesB.has(r));
  const rows: Array<{ label: string; av: React.ReactNode; bv: React.ReactNode }> = [
    { label: 'Attack', av: a.attack.name, bv: b.attack.name },
    { label: 'Verdict', av: <VerdictBadge label={a.verdict.label} />, bv: <VerdictBadge label={b.verdict.label} /> },
    { label: 'Threat Score', av: <span className="font-mono">{a.verdict.threat_score}</span>, bv: <span className="font-mono">{b.verdict.threat_score}</span> },
    { label: 'Rules Score', av: <span className="font-mono">{a.verdict.rule_score}</span>, bv: <span className="font-mono">{b.verdict.rule_score}</span> },
    { label: 'ML Score', av: <span className="font-mono">{a.verdict.ml_score}</span>, bv: <span className="font-mono">{b.verdict.ml_score}</span> },
    { label: 'Rules Fired', av: a.rules.triggered_count, bv: b.rules.triggered_count },
    { label: 'Kill Chain', av: a.kill_chain.current_label, bv: b.kill_chain.current_label },
  ];

  return (
    <div className="mb-4 rounded-panel border border-purple-500/25 bg-purple-500/5 overflow-hidden">
      <div className="px-3 py-2 border-b border-purple-500/20 text-[11px] font-semibold uppercase tracking-wider text-purple-300">
        Side-by-Side Comparison
      </div>
      <table className="w-full text-[11px]">
        <caption className="sr-only">Comparison of two detections across key metrics.</caption>
        <thead>
          <tr className="text-ink-muted">
            <th scope="col" className="text-left px-3 py-1.5 font-semibold">Metric</th>
            <th scope="col" className="text-left px-3 py-1.5 font-semibold">Left</th>
            <th scope="col" className="text-left px-3 py-1.5 font-semibold">Right</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.label} className="border-t border-line">
              <td className="px-3 py-1.5 text-ink-faint">{r.label}</td>
              <td className="px-3 py-1.5 text-ink">{r.av}</td>
              <td className="px-3 py-1.5 text-ink">{r.bv}</td>
            </tr>
          ))}
          <tr className="border-t border-line">
            <td className="px-3 py-1.5 text-ink-faint">Shared Rules</td>
            <td className="px-3 py-1.5 text-ink-soft" colSpan={2}>
              {overlap.length ? <span className="font-mono text-emerald-300">{overlap.join(', ')}</span> : <span className="italic text-ink-muted">none</span>}
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  );
};
