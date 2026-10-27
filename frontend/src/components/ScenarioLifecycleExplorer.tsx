import React, { useState } from 'react';
import {
  GitBranch,
  Database,
  Tag,
  Radar,
  Gauge,
  Fingerprint,
  CheckCircle2,
  XCircle,
  AlertTriangle,
} from 'lucide-react';
import type { LifecycleResponse } from '../api';
import { Mono } from './ui';

/**
 * Scenario Lifecycle Explorer (Milestone 5).
 *
 * Presents the five kept-separate lifecycle layers so an analyst can verify that
 * ground truth never leaks into telemetry and that detections/evaluation are
 * distinct artifacts traceable to the scenario plan and its provenance.
 */

type LayerId = 'plan' | 'telemetry' | 'ground_truth' | 'detections' | 'evaluation';

const LAYERS: { id: LayerId; label: string; icon: React.FC<{ className?: string }>; hint: string }[] = [
  { id: 'plan', label: 'Scenario Plan', icon: GitBranch, hint: 'The validated specification (a plan, not real events).' },
  { id: 'telemetry', label: 'Compiled Telemetry', icon: Database, hint: 'Observable events only — no labels.' },
  { id: 'ground_truth', label: 'Ground Truth', icon: Tag, hint: 'Design-time labels, kept separate.' },
  { id: 'detections', label: 'Detections', icon: Radar, hint: 'What the rule/ML engines actually produced.' },
  { id: 'evaluation', label: 'Expected vs Actual', icon: Gauge, hint: 'Comparison against trusted expectations.' },
];

const Pill: React.FC<{ tone: 'ok' | 'warn' | 'bad'; children: React.ReactNode }> = ({ tone, children }) => {
  const cls =
    tone === 'ok'
      ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
      : tone === 'warn'
      ? 'bg-amber-500/10 text-amber-400 border-amber-500/20'
      : 'bg-rose-500/10 text-rose-400 border-rose-500/20';
  return <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-pill border text-[11px] font-medium ${cls}`}>{children}</span>;
};

const ProvenanceCard: React.FC<{ data: LifecycleResponse }> = ({ data }) => {
  const p = data.provenance;
  const rows: [string, React.ReactNode][] = [
    ['Scenario ID', String(p.scenario_id ?? '-')],
    ['Generator', String(p.generator_version ?? '-')],
    ['Source', String(p.source ?? '-')],
    ['Model', String(p.model ?? 'deterministic')],
    ['Dataset Role', String(p.dataset_role ?? '-')],
    ['Analyst Prompt SHA-256', p.llm_input_sha256 ? <Mono title={String(p.llm_input_sha256)}>{String(p.llm_input_sha256).slice(0, 16)}…</Mono> : '—'],
    ['Correlation ID', String(p.correlation_id ?? '-')],
  ];
  return (
    <div className="rounded-panel border border-line bg-panel/40 p-4">
      <div className="flex items-center gap-2 mb-3 text-accent-soft">
        <Fingerprint className="w-4 h-4" />
        <h3 className="text-sm font-semibold">Evidence Provenance</h3>
      </div>
      <dl className="grid grid-cols-2 gap-x-4 gap-y-2">
        {rows.map(([k, v]) => (
          <div key={k} className="flex flex-col">
            <dt className="text-[10px] uppercase tracking-wider text-ink-faint">{k}</dt>
            <dd className="text-sm text-ink">{v}</dd>
          </div>
        ))}
      </dl>
    </div>
  );
};

const PlanLayer: React.FC<{ data: LifecycleResponse }> = ({ data }) => {
  const plan = data.layer_plan;
  return (
    <div className="space-y-4">
      <div>
        <h4 className="text-base font-semibold text-ink">{plan.title}</h4>
        <p className="text-sm text-ink-muted mt-1">{plan.description}</p>
        <div className="flex flex-wrap gap-2 mt-2">
          <Pill tone="ok">category: {plan.attack_category}</Pill>
          <Pill tone="ok">intensity: {plan.intensity}</Pill>
        </div>
        <p className="text-xs text-ink-faint mt-2 italic">{plan.evaluation_objective}</p>
      </div>
      <div>
        <h5 className="text-xs font-bold uppercase tracking-wider text-ink-faint mb-2">Lifecycle Stages</h5>
        <ol className="space-y-2">
          {plan.stages.map((s: any, i: number) => (
            <li key={s.stage_id} className="rounded-card border border-line bg-panel/40 p-3">
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium text-ink">{i + 1}. {s.description}</span>
                <Pill tone="ok">{s.stage_type}</Pill>
              </div>
              <p className="text-xs text-ink-faint mt-1">Observable: {s.expected_observable_behavior}</p>
              {s.depends_on?.length > 0 && (
                <p className="text-[11px] text-ink-faint mt-1">depends on: {s.depends_on.join(', ')}</p>
              )}
            </li>
          ))}
        </ol>
      </div>
    </div>
  );
};

const TelemetryLayer: React.FC<{ data: LifecycleResponse }> = ({ data }) => (
  <div>
    <div className="flex items-center justify-between mb-2">
      <h5 className="text-xs font-bold uppercase tracking-wider text-ink-faint">Observable Events ({data.layer_telemetry.events_count})</h5>
      <Pill tone="ok">no labels present</Pill>
    </div>
    <div className="max-h-64 overflow-auto rounded-card border border-line">
      <table className="w-full text-left text-xs">
        <caption className="sr-only">Compiled telemetry observable events: type, timestamp, source, target, and template</caption>
        <thead className="sticky top-0 bg-elevated text-ink-muted">
          <tr>
            <th scope="col" className="px-3 py-2">type</th>
            <th scope="col" className="px-3 py-2">timestamp</th>
            <th scope="col" className="px-3 py-2">source</th>
            <th scope="col" className="px-3 py-2">target</th>
            <th scope="col" className="px-3 py-2">template</th>
          </tr>
        </thead>
        <tbody>
          {data.layer_telemetry.events.map((e: any, i: number) => (
            <tr key={i} className="border-t border-line/60 text-ink-soft">
              <td className="px-3 py-1.5">{e.type}</td>
              <td className="px-3 py-1.5 font-mono text-[11px]">{String(e.timestamp).replace('T', ' ').slice(0, 19)}</td>
              <td className="px-3 py-1.5">{e.src_ip || e.source || '-'}</td>
              <td className="px-3 py-1.5">{e.dest_ip || e.target || '-'}</td>
              <td className="px-3 py-1.5 text-ink-faint">{e._template_id}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  </div>
);

const GroundTruthLayer: React.FC<{ data: LifecycleResponse }> = ({ data }) => {
  const gt = data.layer_ground_truth;
  return (
    <div className="space-y-3">
      <p className="text-xs text-ink-faint">{gt.note}</p>
      <div className="flex gap-2">
        {gt.is_verified ? (
          <Pill tone="ok"><CheckCircle2 className="w-3 h-3" /> Verified labels</Pill>
        ) : (
          <Pill tone="warn"><AlertTriangle className="w-3 h-3" /> Unverified — excluded from training</Pill>
        )}
      </div>
      <table className="w-full text-left text-xs border border-line rounded-card overflow-hidden">
        <caption className="sr-only">Ground truth labels per template with their source</caption>
        <thead className="bg-elevated text-ink-muted">
          <tr><th scope="col" className="px-3 py-2">template</th><th scope="col" className="px-3 py-2">label</th><th scope="col" className="px-3 py-2">source</th></tr>
        </thead>
        <tbody>
          {gt.per_template.map((t: any) => (
            <tr key={t.template_id} className="border-t border-line/60 text-ink-soft">
              <td className="px-3 py-1.5">{t.template_id}</td>
              <td className="px-3 py-1.5">{t.ground_truth_label === 1 ? 'attack (1)' : 'benign (0)'}</td>
              <td className="px-3 py-1.5"><Pill tone={t.ground_truth_source === 'unverified' ? 'warn' : 'ok'}>{t.ground_truth_source}</Pill></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

const DetectionsLayer: React.FC<{ data: LifecycleResponse }> = ({ data }) => (
  <div>
    <h5 className="text-xs font-bold uppercase tracking-wider text-ink-faint mb-2">Actual Detections ({data.layer_detections.length})</h5>
    {data.layer_detections.length === 0 ? (
      <p className="text-sm text-ink-faint">No detections recorded for this dataset yet. Run a replay to populate this layer.</p>
    ) : (
      <ul className="space-y-2">
        {data.layer_detections.map((d: any) => (
          <li key={d.id} className="rounded-card border border-line bg-panel/40 p-3">
            <div className="flex items-center justify-between">
              <span className="text-sm font-medium text-ink">{d.label}</span>
              <div className="flex items-center gap-2">
                <Pill tone="ok">{d.source}</Pill>
                <span className="text-xs text-ink-faint">conf {Math.round((d.confidence ?? 0) * 100)}%</span>
              </div>
            </div>
            <p className="text-xs text-ink-faint mt-1">{d.explanation}</p>
          </li>
        ))}
      </ul>
    )}
  </div>
);

const EvaluationLayer: React.FC<{ data: LifecycleResponse }> = ({ data }) => {
  const ev = data.layer_evaluation;
  if (!ev || !ev.comparison) {
    return <p className="text-sm text-ink-faint">No evaluation yet. Run a replay to compute expected-vs-actual metrics.</p>;
  }
  const c = ev.comparison;
  const m = ev.metrics;
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-3 gap-3">
        {(['precision', 'recall', 'f1_score'] as const).map((k) => (
          <div key={k} className="rounded-card border border-line bg-panel/40 p-3 text-center">
            <div className="text-[10px] uppercase tracking-wider text-ink-faint">{k}</div>
            <div className="text-xl font-bold text-accent-soft">{m ? (m[k] as number).toFixed(2) : '—'}</div>
          </div>
        ))}
      </div>
      <div className="space-y-2">
        <LabelList title="True Positives (expected & detected)" tone="ok" items={c.true_positive_labels} icon={CheckCircle2} />
        <LabelList title="False Negatives (expected, missed)" tone="bad" items={c.false_negative_labels} icon={XCircle} />
        <LabelList title="False Positives (detected, not expected)" tone="warn" items={c.false_positive_labels} icon={AlertTriangle} />
      </div>
    </div>
  );
};

const LabelList: React.FC<{ title: string; tone: 'ok' | 'warn' | 'bad'; items: string[]; icon: React.FC<{ className?: string }> }> = ({ title, tone, items, icon: Icon }) => (
  <div>
    <div className="text-[11px] uppercase tracking-wider text-ink-faint mb-1">{title}</div>
    <div className="flex flex-wrap gap-2">
      {items && items.length > 0 ? (
        items.map((it) => (
          <Pill key={it} tone={tone}><Icon className="w-3 h-3" /> {it}</Pill>
        ))
      ) : (
        <span className="text-xs text-ink-faint">none</span>
      )}
    </div>
  </div>
);

export const ScenarioLifecycleExplorer: React.FC<{ data: LifecycleResponse }> = ({ data }) => {
  const [active, setActive] = useState<LayerId>('plan');
  const renderers: Record<LayerId, React.FC<{ data: LifecycleResponse }>> = {
    plan: PlanLayer,
    telemetry: TelemetryLayer,
    ground_truth: GroundTruthLayer,
    detections: DetectionsLayer,
    evaluation: EvaluationLayer,
  };
  const Active = renderers[active];

  return (
    <div className="space-y-4">
      <ProvenanceCard data={data} />
      <div className="flex flex-wrap gap-2" role="tablist" aria-label="Lifecycle layers">
        {LAYERS.map(({ id, label, icon: Icon }) => {
          const isActive = active === id;
          return (
            <button
              key={id}
              type="button"
              role="tab"
              aria-selected={isActive}
              onClick={() => setActive(id)}
              className={`inline-flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm font-medium border transition-colors duration-base ${
                isActive
                  ? 'bg-accent/20 text-accent-soft border-accent/30'
                  : 'text-ink-muted border-line hover:text-ink hover:bg-elevated/40'
              }`}
            >
              <Icon className="w-4 h-4" />
              {label}
            </button>
          );
        })}
      </div>
      <div role="tabpanel" className="rounded-panel border border-line bg-panel/30 p-4">
        <p className="text-[11px] text-ink-faint mb-3">{LAYERS.find((l) => l.id === active)?.hint}</p>
        <Active data={data} />
      </div>
    </div>
  );
};
