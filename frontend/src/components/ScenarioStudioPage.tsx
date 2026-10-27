import React, { useEffect, useState } from 'react';
import {
  Sparkles,
  ShieldCheck,
  Wrench,
  PlayCircle,
  RefreshCw,
  AlertTriangle,
  Code2,
  Brain,
  Upload,
} from 'lucide-react';
import {
  studioListCategories,
  studioPropose,
  studioValidate,
  studioCompile,
  studioReplay,
  studioLifecycle,
  studioLearningEligibility,
  studioImportLearning,
  StudioCategory,
  StudioControls,
  ProposeResponse,
  ValidationReport,
  CompileResponse,
  ReplayResponse,
  LifecycleResponse,
  LearningEligibilityResponse,
} from '../api';
import { ScenarioLifecycleExplorer } from './ScenarioLifecycleExplorer';
import { PageHeader, Button, Mono } from './ui';

/**
 * Attack Scenario Studio (Milestone 5).
 *
 * Implements the analyst-facing workflow: natural-language request -> LLM proposal
 * -> strict validation -> safe editing -> deterministic compile -> replay ->
 * expected-vs-actual evaluation -> lifecycle exploration.
 *
 * The LLM only ever produces a plan; every downstream step is a validated,
 * deterministic operation surfaced with explicit provenance.
 */

const Report: React.FC<{ report: ValidationReport | null }> = ({ report }) => {
  if (!report) return null;
  const all = [...report.violations, ...report.warnings];
  if (all.length === 0) {
    return (
      <div className="flex items-center gap-2 text-emerald-400 text-sm mt-2">
        <ShieldCheck className="w-4 h-4" /> Validation passed — safe, well-formed, feasible.
      </div>
    );
  }
  return (
    <div className="mt-2 space-y-1">
      {report.violations.map((v, i) => (
        <div key={`v${i}`} className="flex items-start gap-2 text-rose-400 text-xs">
          <AlertTriangle className="w-3.5 h-3.5 mt-0.5 shrink-0" />
          <span><b>{v.location || v.code}:</b> {v.message}</span>
        </div>
      ))}
      {report.warnings.map((w, i) => (
        <div key={`w${i}`} className="flex items-start gap-2 text-amber-400 text-xs">
          <AlertTriangle className="w-3.5 h-3.5 mt-0.5 shrink-0" />
          <span><b>{w.location || w.code}:</b> {w.message}</span>
        </div>
      ))}
    </div>
  );
};

export const ScenarioStudioPage: React.FC = () => {
  const [categories, setCategories] = useState<StudioCategory[]>([]);
  const [request, setRequest] = useState('');
  const [controls, setControls] = useState<StudioControls>({ intensity: 'high', event_count: 20, seed: 42, dataset_role: 'validation' });
  const [busy, setBusy] = useState<string | null>(null);

  const [proposal, setProposal] = useState<ProposeResponse | null>(null);
  const [specText, setSpecText] = useState('');
  const [validateReport, setValidateReport] = useState<ValidationReport | null>(null);
  const [compiled, setCompiled] = useState<CompileResponse | null>(null);
  const [replayed, setReplayed] = useState<ReplayResponse | null>(null);
  const [lifecycle, setLifecycle] = useState<LifecycleResponse | null>(null);
  const [eligibility, setEligibility] = useState<LearningEligibilityResponse | null>(null);
  const [importedCount, setImportedCount] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    studioListCategories().then((r) => setCategories(r.data)).catch(() => setCategories([]));
  }, []);

  const resetDownstream = () => {
    setValidateReport(null);
    setCompiled(null);
    setReplayed(null);
    setLifecycle(null);
    setEligibility(null);
    setImportedCount(null);
    setError(null);
  };

  const onPropose = async () => {
    setBusy('propose');
    setError(null);
    resetDownstream();
    try {
      const res = await studioPropose(request, controls);
      setProposal(res.data);
      if (res.data.spec) setSpecText(JSON.stringify(res.data.spec, null, 2));
      if (res.data.status === 'unsafe_request') setError('Request screened as unsafe. FraudGuard only simulates safe, synthetic telemetry.');
      if (res.data.status === 'invalid') setError('The proposal failed validation. Try refining the request or edit the spec manually.');
    } catch (e: any) {
      if (e?.response?.status === 503) {
        setError('AI provider unavailable (503). The deterministic simulator remains available; you can still edit a spec below and compile it.');
      } else {
        setError(e?.message || 'Failed to propose scenario.');
      }
    } finally {
      setBusy(null);
    }
  };

  const onValidate = async () => {
    setBusy('validate');
    setError(null);
    resetDownstream();
    try {
      const spec = JSON.parse(specText);
      const res = await studioValidate(spec);
      setValidateReport(res.data.validation);
      if (res.data.spec) setSpecText(JSON.stringify(res.data.spec, null, 2));
    } catch (e: any) {
      setError(e?.response?.data?.detail?.error || e?.message || 'Invalid JSON spec.');
    } finally {
      setBusy(null);
    }
  };

  const onCompile = async () => {
    setBusy('compile');
    setError(null);
    try {
      const spec = JSON.parse(specText);
      const res = await studioCompile(spec);
      setCompiled(res.data);
      setReplayed(null);
      setLifecycle(null);
    } catch (e: any) {
      setError(e?.response?.data?.detail?.error || e?.message || 'Compilation failed.');
    } finally {
      setBusy(null);
    }
  };

  const onReplay = async () => {
    if (!compiled) return;
    setBusy('replay');
    setError(null);
    try {
      const res = await studioReplay(compiled.dataset_id);
      setReplayed(res.data);
      const lc = await studioLifecycle(compiled.dataset_id);
      setLifecycle(lc.data);
      const el = await studioLearningEligibility(compiled.dataset_id);
      setEligibility(el.data);
      setImportedCount(null);
    } catch (e: any) {
      setError(e?.response?.data?.detail?.error || e?.message || 'Replay failed.');
    } finally {
      setBusy(null);
    }
  };

  const onImportLearning = async () => {
    if (!compiled) return;
    setBusy('import');
    setError(null);
    try {
      const res = await studioImportLearning(compiled.dataset_id);
      setImportedCount(res.data.imported);
      const el = await studioLearningEligibility(compiled.dataset_id);
      setEligibility(el.data);
    } catch (e: any) {
      setError(e?.response?.data?.detail?.error || e?.message || 'Learning import failed.');
    } finally {
      setBusy(null);
    }
  };

  const setControl = (patch: Partial<StudioControls>) => setControls((c) => ({ ...c, ...patch }));

  return (
    <div className="w-full max-w-[1400px] mx-auto space-y-6">
      <PageHeader
        title="Attack Scenario Studio"
        description="Describe a defensive scenario in natural language. The LLM proposes a plan; deterministic services validate, compile, replay and evaluate it. Nothing is ever executed against real systems."
        icon={<Sparkles className="w-5 h-5" />}
      />

      {/* Step 1: request + controls */}
      <section className="rounded-panel border border-line bg-panel/40 p-4 space-y-3">
        <div className="flex items-center gap-2 text-ink-soft text-sm font-semibold"><span className="text-accent-soft">1.</span> Describe the scenario</div>
        <textarea
          aria-label="Scenario request"
          value={request}
          onChange={(e) => setRequest(e.target.value)}
          rows={3}
          placeholder="e.g. Simulate a synthetic port scan across many distinct ports with a benign baseline."
          className="w-full rounded-card bg-app border border-line p-3 text-sm text-ink focus:outline-none focus:ring-2 focus:ring-accent/50"
        />
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
          <label className="flex flex-col gap-1">
            <span className="text-ink-faint">Category</span>
            <select
              value={controls.attack_category ?? ''}
              onChange={(e) => setControl({ attack_category: e.target.value || undefined })}
              className="rounded bg-app border border-line p-2 text-ink focus:outline-none focus:ring-2 focus:ring-accent/50"
            >
              <option value="">(let model decide)</option>
              {categories.map((c) => <option key={c.attack_category} value={c.attack_category}>{c.attack_category}</option>)}
            </select>
          </label>
          <label className="flex flex-col gap-1">
            <span className="text-ink-faint">Intensity</span>
            <select value={controls.intensity ?? 'medium'} onChange={(e) => setControl({ intensity: e.target.value })} className="rounded bg-app border border-line p-2 text-ink focus:outline-none focus:ring-2 focus:ring-accent/50">
              <option value="low">low</option><option value="medium">medium</option><option value="high">high</option>
            </select>
          </label>
          <label className="flex flex-col gap-1">
            <span className="text-ink-faint">Event count</span>
            <input type="number" min={1} max={100} value={controls.event_count ?? 20} onChange={(e) => setControl({ event_count: Number(e.target.value) })} className="rounded bg-app border border-line p-2 text-ink focus:outline-none focus:ring-2 focus:ring-accent/50" />
          </label>
          <label className="flex flex-col gap-1">
            <span className="text-ink-faint">Seed</span>
            <input type="number" value={controls.seed ?? 42} onChange={(e) => setControl({ seed: Number(e.target.value) })} className="rounded bg-app border border-line p-2 text-ink focus:outline-none focus:ring-2 focus:ring-accent/50" />
          </label>
          <label className="flex flex-col gap-1">
            <span className="text-ink-faint">Dataset role</span>
            <select value={controls.dataset_role ?? 'validation'} onChange={(e) => setControl({ dataset_role: e.target.value })} className="rounded bg-app border border-line p-2 text-ink focus:outline-none focus:ring-2 focus:ring-accent/50">
              <option value="validation">validation</option><option value="training">training</option><option value="test">test</option>
            </select>
          </label>
        </div>
        <Button
          variant="primary"
          onClick={onPropose}
          disabled={busy !== null || !request.trim()}
          loading={busy === 'propose'}
          leftIcon={<Sparkles className="w-4 h-4" />}
        >
          Propose scenario
        </Button>
      </section>

      {error && (
        <div role="alert" className="rounded-card border border-rose-500/30 bg-rose-500/10 text-rose-300 text-sm px-4 py-3 flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 shrink-0" /> {error}
        </div>
      )}

      {/* Step 2: proposal + editable spec */}
      {proposal && (
        <section className="rounded-panel border border-line bg-panel/40 p-4 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-ink-soft text-sm font-semibold"><span className="text-accent-soft">2.</span> Review & edit the proposal</div>
            <div className="flex items-center gap-2 text-xs text-ink-faint">
              status: <b className="text-ink-soft">{proposal.status}</b>
              {proposal.model && <span>· model: {proposal.model}</span>}
              <span>· attempts: {proposal.attempts}</span>
            </div>
          </div>
          <div>
            <div className="flex items-center gap-2 text-ink-faint text-xs mb-1"><Code2 className="w-3.5 h-3.5" /> Scenario specification (JSON)</div>
            <textarea
              aria-label="Scenario specification JSON"
              value={specText}
              onChange={(e) => setSpecText(e.target.value)}
              rows={14}
              spellCheck={false}
              className="w-full rounded-card bg-app border border-line p-3 text-[12px] font-mono text-ink focus:outline-none focus:ring-2 focus:ring-accent/50"
            />
          </div>
          <Report report={validateReport} />
          <div className="flex flex-wrap gap-2">
            <Button
              variant="secondary"
              onClick={onValidate}
              disabled={busy !== null}
              loading={busy === 'validate'}
              leftIcon={<ShieldCheck className="w-4 h-4" />}
            >
              Validate
            </Button>
            <Button
              variant="secondary"
              onClick={onCompile}
              disabled={busy !== null || !specText}
              loading={busy === 'compile'}
              leftIcon={<Wrench className="w-4 h-4" />}
            >
              Compile dataset
            </Button>
          </div>
        </section>
      )}

      {/* Step 3: compile result + replay */}
      {compiled && (
        <section className="rounded-panel border border-line bg-panel/40 p-4 space-y-3">
          <div className="flex items-center gap-2 text-ink-soft text-sm font-semibold"><span className="text-accent-soft">3.</span> Compiled dataset</div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
            <Meta label="Dataset ID" value={compiled.dataset_id} mono />
            <Meta label="Events" value={String(compiled.events_count)} />
            <Meta label="Role" value={compiled.dataset_role} />
            <Meta label="Training eligible" value={compiled.is_training_eligible ? 'yes' : 'no'} />
          </div>
          <Button
            variant="primary"
            onClick={onReplay}
            disabled={busy !== null}
            loading={busy === 'replay'}
            leftIcon={<PlayCircle className="w-4 h-4" />}
          >
            Replay & evaluate
          </Button>
        </section>
      )}

      {replayed && (
        <section className="rounded-panel border border-line bg-panel/40 p-4">
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-2 text-ink-soft text-sm font-semibold"><span className="text-accent-soft">4.</span> Evaluation result</div>
            <div className="flex gap-2 text-xs">
              <span className="text-emerald-400">TP {replayed.true_positive_labels.length}</span>
              <span className="text-rose-400">FN {replayed.false_negative_labels.length}</span>
              <span className="text-amber-400">FP {replayed.false_positive_labels.length}</span>
            </div>
          </div>
          <div className="grid grid-cols-3 gap-3 text-center">
            {(['precision', 'recall', 'f1_score'] as const).map((k) => (
              <div key={k} className="rounded-card border border-line bg-app/40 p-3">
                <div className="text-[10px] uppercase tracking-wider text-ink-faint">{k}</div>
                <div className="text-xl font-bold text-accent-soft">{replayed.metrics[k].toFixed(2)}</div>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* Step 5: adaptive learning import (guarded) */}
      {eligibility && (
        <section className="rounded-panel border border-line bg-panel/40 p-4 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-ink-soft text-sm font-semibold">
              <span className="text-accent-soft">5.</span> Adaptive Learning integration
            </div>
            <span className="text-xs text-ink-faint">task: {eligibility.task_name ?? 'none'}</span>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
            <Meta label="Dataset role" value={eligibility.dataset_role ?? '-'} />
            <Meta label="Trusted ground truth" value={eligibility.ground_truth_available ? 'yes' : 'no'} />
            <Meta label="Evaluated" value={eligibility.is_evaluated ? 'yes' : 'no'} />
            <Meta label="Already imported" value={String(eligibility.already_imported)} />
          </div>
          {eligibility.reasons.length > 0 ? (
            <div className="space-y-1">
              {eligibility.reasons.map((r, i) => (
                <div key={i} className="flex items-start gap-2 text-amber-400 text-xs">
                  <AlertTriangle className="w-3.5 h-3.5 mt-0.5 shrink-0" /> <span>{r}</span>
                </div>
              ))}
            </div>
          ) : eligibility.eligible ? (
            <p className="text-xs text-emerald-400 flex items-center gap-2">
              <ShieldCheck className="w-3.5 h-3.5" /> Eligible — trusted, evaluated, ML-compatible training examples. Import will never train or activate a model automatically.
            </p>
          ) : null}
          <div className="flex items-center gap-3">
            <Button
              variant="primary"
              onClick={onImportLearning}
              disabled={busy !== null || !eligibility.eligible}
              loading={busy === 'import'}
              leftIcon={<Upload className="w-4 h-4" />}
            >
              Import learning examples
            </Button>
            {importedCount !== null && (
              <span className="text-sm text-accent-soft flex items-center gap-2">
                <Brain className="w-4 h-4" /> {importedCount} example(s) added to the training pool.
              </span>
            )}
          </div>
        </section>
      )}

      {/* Step 6: lifecycle explorer */}
      {lifecycle && (
        <section className="rounded-panel border border-line bg-panel/40 p-4 space-y-3">
          <div className="flex items-center gap-2 text-ink-soft text-sm font-semibold">
            <span className="text-accent-soft">6.</span> Scenario Lifecycle Explorer
            <Button
              variant="secondary"
              size="sm"
              onClick={onReplay}
              className="ml-auto"
              leftIcon={<RefreshCw className="w-3.5 h-3.5" />}
            >
              Re-run
            </Button>
          </div>
          <ScenarioLifecycleExplorer data={lifecycle} />
        </section>
      )}
    </div>
  );
};

const Meta: React.FC<{ label: string; value: string; mono?: boolean }> = ({ label, value, mono }) => (
  <div className="flex flex-col">
    <span className="text-[10px] uppercase tracking-wider text-ink-faint">{label}</span>
    {mono ? <Mono className="break-all self-start">{value}</Mono> : <span className="text-ink break-all">{value}</span>}
  </div>
);
