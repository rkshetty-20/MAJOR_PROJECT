import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Sparkles,
  RefreshCw,
  AlertTriangle,
  FileWarning,
  ShieldCheck,
  Link2,
  Brain,
  Gauge,
  ListChecks,
} from 'lucide-react';
import {
  AnalysisMode,
  AnalystCapabilities,
  AnalystRecommendation,
  AnalysisReport,
  EvalRunSummary,
  analystAnalysisRuns,
  analystAnalyze,
  analystCapabilities,
  analystEvaluationRuns,
  analystAnalysisRun,
  PersistedAnalysisRun,
} from '../api';

const MODE_LABELS: Record<string, string> = {
  MISSED_DETECTION: 'Missed-detection analysis',
  FALSE_POSITIVE: 'False-positive analysis',
  DATASET_QUALITY: 'Dataset-quality analysis',
  FEATURE_IMPROVEMENT: 'Feature-improvement review',
  MODEL_EVALUATION: 'Model-evaluation interpretation',
  NEXT_EXPERIMENT: 'Recommended next experiment',
};

const CONFIDENCE_STYLES: Record<string, string> = {
  low: 'bg-slate-800 text-slate-300 border-slate-700',
  medium: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
  high: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
};

const pct = (v?: number | null) => (v === undefined || v === null ? '—' : `${(v * 100).toFixed(1)}%`);

const RecommendationCard = ({ rec }: { rec: AnalystRecommendation }) => (
  <div className="bg-slate-950 border border-slate-800 rounded p-3 flex flex-col gap-2">
    <div className="flex items-start justify-between gap-3">
      <div className="flex items-center gap-2 flex-wrap">
        <span className="text-[9px] px-2 py-0.5 rounded font-bold uppercase tracking-wider bg-indigo-500/10 text-indigo-400 border border-indigo-500/30">
          {rec.recommendation_type}
        </span>
        <span className="text-[10px] text-slate-500 font-mono">{rec.attack_category}</span>
      </div>
      <span
        className={`text-[9px] px-2 py-0.5 rounded font-bold uppercase tracking-wider border ${
          CONFIDENCE_STYLES[rec.confidence] || CONFIDENCE_STYLES.low
        }`}
        title="Qualitative LLM self-report (not a calibrated probability)"
      >
        conf: {rec.confidence}
      </span>
    </div>

    <p className="text-xs text-slate-200 leading-relaxed">{rec.summary}</p>

    {rec.hypothesis && (
      <div className="flex gap-2 items-start bg-slate-900/60 rounded border border-slate-800 p-2">
        <Brain className="w-3 h-3 text-purple-400 mt-0.5 shrink-0" />
        <div>
          <span className="text-[9px] uppercase tracking-wider text-purple-400/80 font-bold">Hypothesis (LLM)</span>
          <p className="text-[11px] text-slate-400 leading-relaxed">{rec.hypothesis}</p>
        </div>
      </div>
    )}

    <div className="flex flex-wrap gap-1.5">
      {rec.evidence_refs.length === 0 ? (
        <span className="text-[10px] text-slate-600 italic">no evidence refs</span>
      ) : (
        rec.evidence_refs.map((ref, i) => (
          <span
            key={i}
            className="inline-flex items-center gap-1 text-[10px] font-mono bg-slate-900 border border-slate-700 rounded px-1.5 py-0.5 text-slate-300"
            title={ref.detail || ref.kind}
          >
            <Link2 className="w-2.5 h-2.5 text-sky-400" />
            <span className="text-slate-500">{ref.kind}:</span>
            {ref.id}
          </span>
        ))
      )}
    </div>

    {(rec.required_features.length > 0 || rec.proposed_change || rec.validation_plan) && (
      <dl className="grid grid-cols-1 gap-1 text-[10px] mt-1">
        {rec.proposed_change && (
          <div className="flex gap-2"><dt className="text-slate-500 shrink-0 w-28">Proposed change</dt><dd className="text-slate-400">{rec.proposed_change}</dd></div>
        )}
        {rec.required_features.length > 0 && (
          <div className="flex gap-2"><dt className="text-slate-500 shrink-0 w-28">Required features</dt><dd className="text-slate-400 font-mono">{rec.required_features.join(', ')}</dd></div>
        )}
        {rec.required_data && (
          <div className="flex gap-2"><dt className="text-slate-500 shrink-0 w-28">Required data</dt><dd className="text-slate-400">{rec.required_data}</dd></div>
        )}
        {rec.expected_benefit && (
          <div className="flex gap-2"><dt className="text-slate-500 shrink-0 w-28">Expected benefit</dt><dd className="text-emerald-400/90">{rec.expected_benefit}</dd></div>
        )}
        {rec.potential_risks && (
          <div className="flex gap-2"><dt className="text-slate-500 shrink-0 w-28">Potential risks</dt><dd className="text-rose-400/90">{rec.potential_risks}</dd></div>
        )}
        {rec.validation_plan && (
          <div className="flex gap-2"><dt className="text-slate-500 shrink-0 w-28">Validation plan</dt><dd className="text-slate-400">{rec.validation_plan}</dd></div>
        )}
      </dl>
    )}
  </div>
);

export const LLMLearningAnalyst: React.FC = () => {
  const [capabilities, setCapabilities] = useState<AnalystCapabilities | null>(null);
  const [runs, setRuns] = useState<EvalRunSummary[]>([]);
  const [history, setHistory] = useState<PersistedAnalysisRun[]>([]);
  const [selectedRun, setSelectedRun] = useState<string>('');
  const [mode, setMode] = useState<AnalysisMode>('MISSED_DETECTION');
  const [report, setReport] = useState<AnalysisReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [bootLoading, setBootLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadHistory = useCallback(async () => {
    try {
      const res = await analystAnalysisRuns({ limit: 10 });
      setHistory(res.data.analysis_runs);
    } catch {
      /* history is best-effort; do not block the analyst */
    }
  }, []);

  useEffect(() => {
    const boot = async () => {
      setBootLoading(true);
      try {
        const [capRes, runRes] = await Promise.all([analystCapabilities(), analystEvaluationRuns()]);
        setCapabilities(capRes.data);
        setRuns(runRes.data.evaluation_runs);
        if (runRes.data.evaluation_runs.length > 0) {
          setSelectedRun(runRes.data.evaluation_runs[0].id);
        }
        await loadHistory();
      } catch (e: any) {
        setError(e?.response?.data?.detail || 'Failed to load analyst resources');
      } finally {
        setBootLoading(false);
      }
    };
    boot();
  }, [loadHistory]);

  const selectedSummary = useMemo(
    () => runs.find((r) => r.id === selectedRun) || null,
    [runs, selectedRun],
  );

  const analyze = async () => {
    if (!selectedRun) return;
    setLoading(true);
    setError(null);
    setReport(null);
    try {
      const res = await analystAnalyze(selectedRun, mode);
      setReport(res.data);
      await loadHistory();
    } catch (e: any) {
      setError(e?.response?.data?.detail || 'Analysis request failed');
    } finally {
      setLoading(false);
    }
  };

  const viewHistory = async (id: string) => {
    setLoading(true);
    setError(null);
    try {
      const res = await analystAnalysisRun(id);
      const recs = (res.data.recommendations || []).map((r: any): AnalystRecommendation => ({
        recommendation_id: r.id,
        analysis_run_id: r.analysis_run_id,
        attack_category: r.attack_category || '',
        recommendation_type: r.recommendation_type,
        summary: r.summary,
        evidence_refs: r.evidence_refs || [],
        hypothesis: r.hypothesis,
        confidence: (r.confidence || 'low') as AnalystRecommendation['confidence'],
        proposed_change: r.proposed_change,
        required_features: r.required_features || [],
        required_data: r.required_data,
        expected_benefit: r.expected_benefit,
        potential_risks: r.potential_risks,
        validation_plan: r.validation_plan,
        status: r.status,
        created_at: r.created_at,
      }));
      setReport({
        analysis_run_id: res.data.id,
        evaluation_run_id: res.data.evaluation_run_id,
        mode: res.data.mode as AnalysisMode,
        summary: res.data.summary || '',
        findings: res.data.findings || [],
        recommendations: recs,
        model: res.data.model,
        correlation_id: res.data.correlation_id,
        provider_status: (res.data.provider_status || 'ok') as AnalysisReport['provider_status'],
      });
    } catch (e: any) {
      setError(e?.response?.data?.detail || 'Failed to load analysis');
    } finally {
      setLoading(false);
    }
  };

  if (bootLoading) {
    return (
      <div className="flex flex-col items-center justify-center py-16 text-slate-500">
        <RefreshCw className="w-6 h-6 animate-spin mb-3 text-emerald-500/50" />
        <span className="text-sm">Loading LLM analyst...</span>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-4">
      {/* Control bar */}
      <div className="bg-slate-950 border border-slate-800 rounded p-3 flex flex-col gap-3">
        <div className="flex items-center gap-2 text-emerald-400">
          <Sparkles className="w-4 h-4" />
          <h3 className="text-xs font-bold uppercase tracking-widest">LLM Learning Analyst</h3>
          <span className="text-[10px] text-slate-500 font-normal ml-1">
            Analyst only — cannot train, edit rules, or activate models.
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
          <label className="flex flex-col gap-1">
            <span className="text-[10px] text-slate-500 uppercase tracking-wider font-bold">Evaluation run</span>
            <select
              value={selectedRun}
              onChange={(e) => setSelectedRun(e.target.value)}
              className="bg-slate-900 border border-slate-700 rounded px-2 py-1.5 text-xs text-white focus:outline-none"
            >
              {runs.length === 0 && <option value="">No completed evaluation runs</option>}
              {runs.map((r) => (
                <option key={r.id} value={r.id}>
                  {r.id} · {r.attack_category || 'unknown'} · F1 {pct(r.f1_score)}
                </option>
              ))}
            </select>
          </label>

          <label className="flex flex-col gap-1">
            <span className="text-[10px] text-slate-500 uppercase tracking-wider font-bold">Analysis mode</span>
            <select
              value={mode}
              onChange={(e) => setMode(e.target.value as AnalysisMode)}
              className="bg-slate-900 border border-slate-700 rounded px-2 py-1.5 text-xs text-white focus:outline-none"
            >
              {(capabilities?.supported_modes || (Object.keys(MODE_LABELS) as AnalysisMode[])).map((m) => (
                <option key={m} value={m}>{MODE_LABELS[m] || m}</option>
              ))}
            </select>
          </label>

          <div className="flex items-end">
            <button
              onClick={analyze}
              disabled={loading || !selectedRun}
              className={`w-full py-2 rounded text-xs font-bold uppercase tracking-wider flex items-center justify-center gap-2 transition-all border ${
                loading || !selectedRun
                  ? 'bg-slate-900/50 text-slate-600 cursor-not-allowed border-slate-800'
                  : 'bg-emerald-600 hover:bg-emerald-500 text-white border-emerald-500'
              }`}
            >
              {loading ? (
                <><RefreshCw className="w-4 h-4 animate-spin" /> Analyzing...</>
              ) : (
                <><Sparkles className="w-4 h-4" /> Analyze Run</>
              )}
            </button>
          </div>
        </div>
      </div>

      {error && (
        <div className="bg-rose-950/20 border border-rose-500/30 rounded p-3 flex items-center gap-2 text-rose-300 text-xs">
          <FileWarning className="w-4 h-4 shrink-0" />
          {error}
        </div>
      )}

      {/* Measured facts banner (deterministic, from the selected run) */}
      {selectedSummary && (
        <div className="bg-slate-950 border border-slate-800 rounded p-3">
          <div className="flex items-center gap-2 mb-2">
            <Gauge className="w-4 h-4 text-sky-400" />
            <span className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">Measured facts (deterministic)</span>
          </div>
          <div className="grid grid-cols-3 md:grid-cols-6 gap-2 text-center">
            {[
              ['TP', selectedSummary.true_positives, 'text-emerald-400'],
              ['FP', selectedSummary.false_positives, 'text-rose-400'],
              ['FN', selectedSummary.false_negatives, 'text-amber-400'],
              ['Precision', pct(selectedSummary.precision), 'text-purple-400'],
              ['Recall', pct(selectedSummary.recall), 'text-sky-400'],
              ['F1', pct(selectedSummary.f1_score), 'text-emerald-400'],
            ].map(([label, value, cls], i) => (
              <div key={i} className="bg-slate-900/50 rounded border border-slate-800 p-2">
                <div className="text-[9px] text-slate-500 uppercase font-bold">{label}</div>
                <div className={`text-sm font-mono ${cls}`}>{value as string}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Provider degradation / result */}
      {report && report.provider_status !== 'ok' && (
        <div className={`rounded p-3 border flex items-start gap-2 text-xs ${
          report.provider_status === 'unavailable'
            ? 'bg-amber-950/20 border-amber-500/30 text-amber-300'
            : 'bg-slate-950 border-slate-700 text-slate-300'
        }`}>
          <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
          <div>
            <strong className="uppercase tracking-wider text-[10px]">
              {report.provider_status === 'unavailable' ? 'Analyst unavailable' : 'Analysis could not be validated'}
            </strong>
            <p className="mt-1 leading-relaxed">{report.summary}</p>
            <p className="mt-1 text-slate-400">Deterministic simulation, replay, evaluation and training are unaffected.</p>
          </div>
        </div>
      )}

      {report && report.provider_status === 'ok' && (
        <div className="flex flex-col gap-3">
          <div className="bg-slate-950 border border-slate-800 rounded p-3">
            <div className="flex items-center gap-2 mb-2">
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
              <span className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">Analysis summary</span>
            </div>
            <p className="text-xs text-slate-200 leading-relaxed">{report.summary}</p>

            {report.findings.length > 0 && (
              <div className="mt-3">
                <div className="flex items-center gap-2 mb-1.5">
                  <ListChecks className="w-3.5 h-3.5 text-indigo-400" />
                  <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">Findings</span>
                </div>
                <ul className="list-disc list-inside text-[11px] text-slate-400 space-y-1">
                  {report.findings.map((f, i) => (
                    <li key={i}>{f}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>

          <div className="flex items-center justify-between">
            <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">
              Recommendations ({report.recommendations.length})
            </span>
            <span className="text-[10px] text-slate-600 font-mono">
              {report.model || 'model n/a'} · {report.correlation_id || ''}
            </span>
          </div>

          {report.recommendations.length === 0 ? (
            <div className="text-xs text-slate-500 italic p-6 text-center bg-slate-950/50 rounded border border-slate-800 border-dashed">
              No recommendations were returned.
            </div>
          ) : (
            report.recommendations.map((rec) => (
              <RecommendationCard key={rec.recommendation_id} rec={rec} />
            ))
          )}
        </div>
      )}

      {/* Recent persisted analyses */}
      {history.length > 0 && (
        <div className="bg-slate-950 border border-slate-800 rounded p-3">
          <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">Recent analyses</span>
          <div className="mt-2 flex flex-col gap-1.5">
            {history.map((h) => (
              <button
                key={h.id}
                onClick={() => viewHistory(h.id)}
                className="text-left text-[11px] bg-slate-900/50 hover:border-slate-600 border border-slate-800 rounded px-2 py-1.5 flex items-center justify-between transition-colors"
              >
                <span className="font-mono text-slate-300 truncate">{h.evaluation_run_id} · {h.mode}</span>
                <span className={`ml-2 text-[9px] px-1.5 py-0.5 rounded uppercase font-bold shrink-0 ${
                  h.status === 'completed' ? 'bg-emerald-500/10 text-emerald-400' : 'bg-slate-800 text-slate-400'
                }`}>{h.status}</span>
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
