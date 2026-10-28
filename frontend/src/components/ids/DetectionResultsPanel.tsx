// Results & analysis dashboard: verdict, threat gauge, kill-chain progression,
// triggered rules, MITRE ATT&CK mapping and the ML anomaly breakdown.
import React from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  Brain,
  Crosshair,
  Flag,
  Boxes,
  Target,
  Gauge as GaugeIcon,
} from 'lucide-react';
import type { IdsAnalysis, Severity } from './types';
import {
  Card,
  MeterBar,
  SeverityBadge,
  ThreatGauge,
  Tooltip,
  VERDICT_STYLES,
} from './primitives';
import { Mono } from '../ui';

const MODEL_LABELS: Record<string, string> = {
  isolation_forest: 'Isolation Forest',
  autoencoder: 'Autoencoder',
  statistical_zscore: 'Statistical Z-Score',
  dbscan_density: 'DBSCAN Density',
};

const MODEL_COLORS: Record<string, string> = {
  isolation_forest: '#818cf8',
  autoencoder: '#c084fc',
  statistical_zscore: '#38bdf8',
  dbscan_density: '#f472b6',
};

const severityBarColor = (s: Severity): string =>
  ({ info: '#94a3b8', low: '#38bdf8', medium: '#fbbf24', high: '#fb923c', critical: '#fb7185' }[s]);

export const DetectionResultsPanel: React.FC<{ analysis: IdsAnalysis }> = ({ analysis }) => {
  const { verdict, ml, kill_chain, mitre, rules } = analysis;
  const vStyle = VERDICT_STYLES[verdict.label];
  const VerdictIcon = verdict.label === 'Clean' ? ShieldCheck : ShieldAlert;

  return (
    <div className="space-y-6">
      {/* Verdict hero */}
      <div className="bg-panel/90 border border-line rounded-panel overflow-hidden">
        <div className="p-6 flex flex-col md:flex-row gap-6 items-center">
          <ThreatGauge score={verdict.threat_score} label="Threat" />

          <div className="flex-1 w-full space-y-4">
            <div className="flex items-center gap-3 flex-wrap">
              <span
                className={`inline-flex items-center gap-2 px-4 py-1.5 rounded-pill text-sm font-black uppercase tracking-wider border ${vStyle.chip}`}
              >
                <VerdictIcon className="w-4 h-4" />
                {verdict.label}
              </span>
              <span className="text-lg font-bold text-ink">{analysis.attack.name}</span>
              <SeverityBadge severity={analysis.attack.severity} />
            </div>
            <p className="text-sm text-ink-muted leading-relaxed">{analysis.attack.description}</p>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-1">
              <ScoreTile icon={<ShieldAlert className="w-4 h-4" />} label="Rules Score" value={verdict.rule_score} color="#6366f1" />
              <ScoreTile icon={<Brain className="w-4 h-4" />} label="ML Anomaly" value={verdict.ml_score} color="#c084fc" />
              <ScoreTile icon={<GaugeIcon className="w-4 h-4" />} label="Confidence" value={Math.round(ml.confidence * 100)} suffix="%" color="#38bdf8" />
            </div>

            <div className="flex items-center gap-4 text-[11px] text-ink-faint pt-1">
              <span>
                False-positive probability:{' '}
                <span className="font-mono text-ink-soft">{(ml.false_positive_probability * 100).toFixed(1)}%</span>
              </span>
              <span>
                Rules triggered: <span className="font-mono text-ink-soft">{rules.triggered_count}</span> /{' '}
                {rules.evaluated.length} evaluated
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Kill chain */}
      <Card title="Cyber Kill Chain" icon={<Flag className="w-4 h-4" />}
        right={<span className="text-[11px] text-ink-muted">Current: <span className="text-accent-soft font-semibold">{kill_chain.current_label}</span></span>}>
        <KillChainStages stages={kill_chain.stages} currentIndex={kill_chain.index} />
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Triggered rules */}
        <Card title={`Triggered Rules (${rules.triggered_count})`} icon={<ShieldAlert className="w-4 h-4" />}
          right={rules.registry_size ? (
            <span className="text-[11px] text-ink-muted font-mono">
              {rules.evaluated.length}/{rules.registry_size} rules evaluated · v{rules.ruleset_version}
            </span>
          ) : undefined}>
          {rules.triggered.length === 0 ? (
            <EmptyNote text="No signature, threshold or stateful rules fired for this traffic." />
          ) : (
            <div className="space-y-2.5">
              {rules.triggered.map((r) => (
                <div key={r.rule_id} className="rounded-lg border border-line bg-app/60 p-3">
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2 min-w-0">
                      <span
                        className="w-1.5 h-8 rounded-full shrink-0"
                        style={{ backgroundColor: severityBarColor(r.severity) }}
                      />
                      <div className="min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="text-sm font-semibold text-ink truncate">{r.name}</span>
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-elevated text-ink-muted uppercase font-mono shrink-0">
                            {r.layer}
                          </span>
                        </div>
                        <div className="text-[10px] font-mono text-ink-faint mt-0.5">
                          {r.rule_id}{r.version ? ` · v${r.version}` : ''}
                        </div>
                        <p className="text-[11px] text-ink-muted mt-0.5">{r.detail}</p>
                        {(r.explanation || r.evidence?.length) && (
                          <p className="text-[11px] text-ink-soft mt-1 leading-relaxed">
                            {r.explanation}
                            {r.evidence?.length > 0 && (
                              <span className="text-ink-faint">
                                {' '}Evidence: {r.matched_packets.length} packet{r.matched_packets.length === 1 ? '' : 's'} (
                                {r.matched_packets.slice(0, 5).join(', ')}
                                {r.matched_packets.length > 5 ? ', …' : ''}) captured in the packet view.
                              </span>
                            )}
                          </p>
                        )}
                      </div>
                    </div>
                    <div className="text-right shrink-0">
                      <SeverityBadge severity={r.severity} />
                      <div className="text-[10px] font-mono text-ink-faint mt-1">conf {(r.confidence * 100).toFixed(0)}%</div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </Card>

        {/* MITRE */}
        <Card title="MITRE ATT&CK Mapping" icon={<Crosshair className="w-4 h-4" />}>
          {mitre.length === 0 ? (
            <EmptyNote text="No ATT&CK technique attributed to this observation." />
          ) : (
            <div className="space-y-2">
              {mitre.map((m) => (
                <div key={m.technique_id + m.source} className="flex items-center justify-between gap-3 rounded-lg border border-line bg-app/60 px-3 py-2">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <Mono>{m.technique_id}</Mono>
                      <span className="text-sm text-ink truncate">{m.technique_name}</span>
                    </div>
                    <span className="text-[11px] text-ink-faint">{m.tactic}</span>
                  </div>
                  {m.source && (
                    <span className="text-[10px] px-2 py-0.5 rounded bg-elevated text-ink-muted font-mono shrink-0">{m.source}</span>
                  )}
                </div>
              ))}
            </div>
          )}
        </Card>
      </div>

      {/* Anomaly breakdown - deterministic proxies, explicitly not trained models */}
      <Card title="Anomaly Score Breakdown" icon={<Boxes className="w-4 h-4" />}>
        {analysis.pipeline && (
          <div className="mb-4 rounded-lg border border-line bg-app/40 px-3 py-2">
            <div className="text-[11px] font-semibold uppercase tracking-wider text-ink-faint mb-1">
              Input scope
            </div>
            <p className="text-[11px] text-ink-muted leading-relaxed">
              {analysis.pipeline.live_traffic_claim} Source: {analysis.pipeline.input_source}.
            </p>
          </div>
        )}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="space-y-4">
            <div>
              <div className="text-xs font-semibold uppercase tracking-wider text-ink-muted mb-2 flex items-center gap-1.5">
                Anomaly Proxies{' '}
                <Tooltip label="Four deterministic statistical proxies, weighted and combined. They are modelled on isolation forests, autoencoders, z-scores and density clustering - they are not trained models." />
              </div>
              <div className="space-y-2.5">
                {Object.entries(ml.models).map(([key, val]) => (
                  <MeterBar
                    key={key}
                    value={val}
                    color={MODEL_COLORS[key] ?? '#6366f1'}
                    label={MODEL_LABELS[key] ?? key}
                    rightText={val.toFixed(3)}
                  />
                ))}
              </div>
            </div>
            {ml.model_status && (
              <div className="rounded-lg border border-line bg-app/40 p-3">
                <div className="text-[11px] font-semibold uppercase tracking-wider text-ink-faint mb-1">
                  Model status{ml.feature_count ? ` - ${ml.feature_count} packet features` : ''}
                </div>
                <p className="text-[11px] text-ink-muted leading-relaxed">{ml.model_status}</p>
              </div>
            )}
            <div className="rounded-lg border border-accent/20 bg-accent/5 p-3">
              <div className="text-[11px] font-semibold uppercase tracking-wider text-accent-soft mb-1">Explanation</div>
              <p className="text-xs text-ink-soft leading-relaxed">{ml.explanation}</p>
            </div>
          </div>

          <div>
            <div className="text-xs font-semibold uppercase tracking-wider text-ink-muted mb-2 flex items-center gap-1.5">
              <Target className="w-3.5 h-3.5" /> Top Feature Contributions
            </div>
            <div className="space-y-2">
              {ml.top_contributors.length === 0 ? (
                <EmptyNote text="No feature deviated meaningfully from baseline." />
              ) : (
                ml.top_contributors.map((f) => (
                  <div key={f.feature} className="flex items-center gap-3">
                    <div className="w-40 shrink-0">
                      <div className="text-[11px] text-ink-soft truncate">{f.label}</div>
                      <div className="text-[10px] font-mono text-ink-faint">
                        val {formatVal(f.value)}
                      </div>
                    </div>
                    <MeterBar value={f.anomaly} color="#c084fc" className="flex-1" />
                    <span className="text-[11px] font-mono text-ink-muted w-10 text-right">{f.anomaly.toFixed(2)}</span>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      </Card>
    </div>
  );
};

const ScoreTile: React.FC<{
  icon: React.ReactNode;
  label: string;
  value: number;
  suffix?: string;
  color: string;
}> = ({ icon, label, value, suffix = '', color }) => (
  <div className="rounded-panel border border-line bg-app/60 p-3 flex items-center gap-3">
    <div className="p-2 rounded-lg" style={{ backgroundColor: `${color}22`, color }}>
      {icon}
    </div>
    <div>
      <div className="text-[10px] uppercase tracking-wider text-ink-faint font-semibold">{label}</div>
      <div className="text-lg font-bold text-ink font-mono">
        {value}
        {suffix}
      </div>
    </div>
  </div>
);

const KillChainStages: React.FC<{
  stages: IdsAnalysis['kill_chain']['stages'];
  currentIndex: number;
}> = ({ stages, currentIndex }) => (
  <div className="flex items-stretch gap-1 overflow-x-auto pb-1">
    {stages.map((s, i) => {
      const active = i === currentIndex;
      return (
        <div key={s.key} className="flex items-center gap-1 min-w-fit">
          <div
            className={`px-3 py-2 rounded-lg text-[11px] font-semibold border transition-all duration-base ${
              active
                ? 'bg-rose-500/15 text-rose-300 border-rose-500/40'
                : s.reached
                ? 'bg-amber-500/10 text-amber-300/80 border-amber-500/25'
                : 'bg-app text-ink-faint border-line'
            }`}
          >
            {s.label}
          </div>
          {i < stages.length - 1 && <span className="text-ink-faint text-xs">→</span>}
        </div>
      );
    })}
  </div>
);

const EmptyNote: React.FC<{ text: string }> = ({ text }) => (
  <div className="text-xs text-ink-muted italic py-2">{text}</div>
);

function formatVal(v: number): string {
  if (Number.isInteger(v)) return String(v);
  return v.toFixed(2);
}
