import React, { useEffect, useState } from 'react';
import { RefreshCw, Cpu, CheckCircle, Database, ShieldAlert, GitCommit, PlayCircle, FileWarning, AlertTriangle } from 'lucide-react';
import api from '../api';
import { LLMLearningAnalyst } from './LLMLearningAnalyst';

interface MLMetrics {
  accuracy: number;
  f1_score: number;
  precision: number;
  recall: number;
  confusion_matrix?: { tn: number; fp: number; fn: number; tp: number; };
}

interface HistoryRecord {
  version: string;
  f1_score: number;
  is_accepted: boolean;
  created_at: string;
  training_samples: number;
}

interface MLStatus {
  current_version: string;
  training_samples: number;
  total_examples: number;
  new_examples: number;
  status: string; 
  metrics: MLMetrics | null;
  last_trained: string | null;
  history: HistoryRecord[];
}

interface TrainResult {
  status: string;
  decision: string;
  reason: string;
  candidate_version?: string;
  previous_active_version?: string;
  f1_difference?: number;
  training_examples?: number;
  test_examples?: number;
  class_distribution?: { normal: number; port_scan: number };
  candidate_metrics?: MLMetrics;
  active_metrics?: { f1_score: number };
}

export const AdaptiveLearningMetrics: React.FC = () => {
  const [status, setStatus] = useState<MLStatus | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [training, setTraining] = useState(false);
  const [trainResult, setTrainResult] = useState<TrainResult | null>(null);
  const [activeTab, setActiveTab] = useState<'status' | 'history' | 'lifecycle' | 'analyst'>('status');

  const fetchStatus = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.get<MLStatus>('/api/ml/status');
      setStatus(res.data);
    } catch (e: any) {
      console.error(e);
      setError(e.response?.data?.detail || "Failed to load ML engine status");
    } finally {
      setLoading(false);
    }
  };

  const triggerTraining = async () => {
    setTraining(true);
    setTrainResult(null);
    try {
      const res = await api.post<TrainResult>('/api/ml/train', { task_name: 'port_scan' });
      setTrainResult(res.data);
      await fetchStatus();
      setActiveTab('status');
    } catch (e: any) {
      console.error(e);
      setError(e.response?.data?.detail || "Failed to train model");
    } finally {
      setTraining(false);
    }
  };

  const rollback = async (version: string) => {
    if (!window.confirm(`Rollback to ${version}?`)) return;
    try {
      await api.post('/api/ml/rollback', { task_name: 'port_scan', version_string: version });
      fetchStatus();
    } catch (e) {
      alert("Rollback failed.");
    }
  };

  useEffect(() => {
    fetchStatus();
  }, []);

  if (loading && !status) {
    return (
      <div className="bg-slate-900 rounded-lg border border-slate-800 p-5 h-full text-slate-400 flex flex-col items-center justify-center">
        <RefreshCw className="w-6 h-6 animate-spin mb-3 text-emerald-500/50" />
        <span className="text-sm font-medium">Loading ML engine status...</span>
      </div>
    );
  }

  if (error && !status) {
    return (
      <div className="bg-slate-900 rounded-lg border border-slate-800 p-5 h-full text-slate-400 flex flex-col items-center justify-center">
        <FileWarning className="w-8 h-8 text-rose-500 mb-3 opacity-80" />
        <span className="text-sm font-medium text-slate-300">Engine Unavailable</span>
        <span className="text-xs text-slate-500 mt-1">{error}</span>
        <button onClick={fetchStatus} className="mt-4 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs rounded transition-colors">Retry</button>
      </div>
    );
  }

  if (!status) return null;

  return (
    <div className="bg-slate-900 rounded-lg border border-slate-800 flex flex-col h-full shadow-none overflow-hidden">
      <div className="p-4 border-b border-slate-800 flex flex-col gap-3">
        <div className="flex justify-between items-center">
          <div className="flex items-center gap-3">
            <div className="bg-emerald-500/10 p-2 rounded-md text-emerald-500 border border-emerald-500/20">
              <Cpu className="w-4 h-4" />
            </div>
            <h2 className="text-sm font-semibold text-slate-200">Adaptive ML — Port Scan</h2>
          </div>
          <div className="flex items-center gap-3">
            <input 
              type="text" 
              placeholder="Dataset ID..." 
              id="import_dataset_id"
              className="bg-slate-950 border border-slate-700 rounded px-2 py-1 text-[10px] text-white focus:outline-none w-32"
            />
            <button 
              onClick={async () => {
                const id = (document.getElementById('import_dataset_id') as HTMLInputElement).value;
                if (!id) return;
                try {
                  const res = await api.post(`/api/datasets/${id}/import_learning`);
                  alert(`Successfully imported ${res.data.added} examples to Adaptive Learning.`);
                  fetchStatus();
                } catch (e: any) {
                  alert(e.response?.data?.detail || 'Import failed');
                }
              }}
              className="text-[10px] px-2.5 py-1 rounded-sm font-bold uppercase tracking-wider bg-indigo-500/20 text-indigo-400 border border-indigo-500/30 hover:bg-indigo-500/30 transition-colors"
            >
              Import Data
            </button>
          </div>
          <div className="flex items-center gap-3">
            <span className={`text-[10px] px-2.5 py-1 rounded-sm font-bold uppercase tracking-wider ${
              status.status === 'READY_FOR_TRAINING' ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' :
              status.status === 'NEW_DATA_AVAILABLE' ? 'bg-sky-500/20 text-sky-400 border border-sky-500/30' :
              status.status === 'NOT_READY' || status.status === 'INSUFFICIENT_CLASSES' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' :
              'bg-slate-800 text-slate-400 border border-slate-700'
            }`}>
              {training ? 'TRAINING & EVALUATING...' : status.status.replace(/_/g, ' ')}
            </span>
            <button onClick={fetchStatus} disabled={loading || training} className="text-slate-500 hover:text-slate-300 transition-colors disabled:opacity-50">
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            </button>
          </div>
        </div>

        <div className="flex gap-4 text-xs font-medium border-t border-slate-800 pt-2 -mx-4 px-4">
          <button className={`pb-2 border-b-2 transition-colors ${activeTab === 'status' ? 'border-emerald-500 text-emerald-400' : 'border-transparent text-slate-400 hover:text-slate-200'}`} onClick={() => setActiveTab('status')}>Overview & Evaluation</button>
          <button className={`pb-2 border-b-2 transition-colors ${activeTab === 'history' ? 'border-emerald-500 text-emerald-400' : 'border-transparent text-slate-400 hover:text-slate-200'}`} onClick={() => setActiveTab('history')}>Model History</button>
          <button className={`pb-2 border-b-2 transition-colors ${activeTab === 'lifecycle' ? 'border-emerald-500 text-emerald-400' : 'border-transparent text-slate-400 hover:text-slate-200'}`} onClick={() => setActiveTab('lifecycle')}>SOC Lifecycle</button>
          <button className={`pb-2 border-b-2 transition-colors ${activeTab === 'analyst' ? 'border-emerald-500 text-emerald-400' : 'border-transparent text-slate-400 hover:text-slate-200'}`} onClick={() => setActiveTab('analyst')}>LLM Analyst</button>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto p-4 bg-slate-900/50">
        {activeTab === 'status' && (
          <div className="flex flex-col gap-4">
            
            {/* Top row: Data & Model Version */}
            <div className="grid grid-cols-2 gap-3">
              <div className="bg-slate-950 p-3 rounded border border-slate-800">
                <div className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-1 flex items-center justify-between">
                  <span>Collected Examples</span>
                  {status.new_examples > 0 && <span className="text-[9px] bg-sky-500/10 text-sky-400 px-1.5 py-0.5 rounded">+{status.new_examples} New</span>}
                </div>
                <div className="text-xl font-bold text-slate-200">{status.total_examples}</div>
                <div className="text-[10px] text-slate-500 mt-1">Sourced from simulation telemetry</div>
              </div>

              <div className="bg-slate-950 p-3 rounded border border-slate-800">
                <div className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-1">Active Model Version</div>
                <div className="text-sm font-mono text-emerald-400 truncate mt-1">
                  {status.current_version !== 'N/A' && status.current_version !== 'base_model' ? status.current_version : 'base_model (Static)'}
                </div>
                {status.training_samples > 0 && (
                  <div className="text-[10px] text-slate-500 mt-1">Trained on {status.training_samples} examples</div>
                )}
              </div>
            </div>

            {/* Active Model Metrics */}
            <div className="bg-slate-950 p-4 rounded border border-slate-800">
              <div className="flex items-center justify-between mb-3">
                <h3 className="text-xs font-bold text-slate-300 uppercase tracking-widest">Active Model Synthetic Evaluation</h3>
                <span className="text-[10px] text-amber-500/80 flex items-center gap-1 bg-amber-950/20 px-2 py-0.5 rounded border border-amber-500/20">
                  <AlertTriangle className="w-3 h-3" /> Note: Evaluated on synthetic holdout set. This does not establish real-world detection accuracy.
                </span>
              </div>
              
              {status.metrics ? (
                <div className="grid grid-cols-4 gap-3">
                  <div className="bg-slate-900/50 p-2 rounded border border-slate-800 text-center">
                    <div className="text-[10px] text-slate-500 font-bold uppercase mb-1">Accuracy</div>
                    <div className="text-base font-mono text-emerald-400">{(status.metrics.accuracy * 100).toFixed(1)}%</div>
                  </div>
                  <div className="bg-slate-900/50 p-2 rounded border border-slate-800 text-center">
                    <div className="text-[10px] text-slate-500 font-bold uppercase mb-1">F1 Score</div>
                    <div className="text-base font-mono text-sky-400">{(status.metrics.f1_score * 100).toFixed(1)}%</div>
                  </div>
                  <div className="bg-slate-900/50 p-2 rounded border border-slate-800 text-center">
                    <div className="text-[10px] text-slate-500 font-bold uppercase mb-1">Precision</div>
                    <div className="text-base font-mono text-purple-400">{(status.metrics.precision * 100).toFixed(1)}%</div>
                  </div>
                  <div className="bg-slate-900/50 p-2 rounded border border-slate-800 text-center">
                    <div className="text-[10px] text-slate-500 font-bold uppercase mb-1">Recall</div>
                    <div className="text-base font-mono text-amber-400">{(status.metrics.recall * 100).toFixed(1)}%</div>
                  </div>
                </div>
              ) : (
                <div className="text-xs text-slate-500 text-center py-2 italic bg-slate-900/50 rounded border border-slate-800 border-dashed">
                  Metrics unavailable for current model
                </div>
              )}
            </div>

            {/* Training Result Panel */}
            {trainResult && (
              <div className={`p-4 rounded border shadow-sm ${
                trainResult.decision === 'ACCEPTED' ? 'bg-emerald-950/20 border-emerald-500/30' : 
                trainResult.decision === 'REJECTED' ? 'bg-rose-950/10 border-rose-500/20' : 
                'bg-slate-950 border-slate-800'
              }`}>
                <div className="flex justify-between items-start mb-4 border-b border-slate-800/50 pb-3">
                  <div>
                    <h3 className={`text-sm font-bold uppercase tracking-wider mb-1 ${
                      trainResult.decision === 'ACCEPTED' ? 'text-emerald-400' : 
                      trainResult.decision === 'REJECTED' ? 'text-rose-400' : 
                      'text-slate-300'
                    }`}>
                      {trainResult.decision === 'ACCEPTED' ? 'Candidate Accepted & Activated' : 
                       trainResult.decision === 'REJECTED' ? 'Candidate Rejected' : 
                       'Evaluation Aborted'}
                    </h3>
                    <p className="text-xs text-slate-400 leading-relaxed font-mono">{trainResult.reason}</p>
                  </div>
                  {trainResult.f1_difference !== undefined && (
                    <div className={`text-sm font-mono font-bold px-2 py-1 rounded bg-slate-900 border ${
                      trainResult.f1_difference > 0 ? 'text-emerald-400 border-emerald-500/30' : 
                      trainResult.f1_difference < 0 ? 'text-rose-400 border-rose-500/30' : 
                      'text-slate-400 border-slate-700'
                    }`}>
                      {trainResult.f1_difference > 0 ? '+' : ''}{(trainResult.f1_difference * 100).toFixed(1)}% F1 Delta
                    </div>
                  )}
                </div>

                {/* Candidate vs Active Comparison */}
                {trainResult.candidate_metrics && trainResult.active_metrics && (
                  <div className="space-y-4">
                    <div className="grid grid-cols-2 gap-3">
                      <div className="bg-slate-900/80 p-3 rounded border border-slate-800 flex flex-col">
                        <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-1">Previous Active</span>
                        <span className="text-xs font-mono text-slate-400 truncate mb-2">{trainResult.previous_active_version || 'base_model'}</span>
                        <div className="mt-auto pt-2 border-t border-slate-800 flex justify-between items-end">
                          <span className="text-xs text-slate-500">Synthetic F1</span>
                          <span className="text-sm font-mono font-bold text-slate-300">{(trainResult.active_metrics.f1_score * 100).toFixed(1)}%</span>
                        </div>
                      </div>
                      <div className="bg-slate-900/80 p-3 rounded border border-slate-800 flex flex-col">
                        <span className="text-[10px] font-bold text-emerald-600/80 uppercase tracking-widest mb-1">Candidate Model</span>
                        <span className="text-xs font-mono text-emerald-400/80 truncate mb-2">{trainResult.candidate_version || 'unknown'}</span>
                        <div className="mt-auto pt-2 border-t border-slate-800 flex justify-between items-end">
                          <span className="text-xs text-slate-500">Synthetic F1</span>
                          <span className="text-sm font-mono font-bold text-emerald-400">{(trainResult.candidate_metrics.f1_score * 100).toFixed(1)}%</span>
                        </div>
                      </div>
                    </div>

                    {/* Dataset Info for Candidate */}
                    {trainResult.training_examples !== undefined && (
                      <div className="flex gap-4 text-[10px] text-slate-400 bg-slate-900/50 p-2 rounded border border-slate-800/50">
                        <div className="flex gap-1.5 items-center"><Database className="w-3 h-3" /> Train: {trainResult.training_examples} | Test: {trainResult.test_examples}</div>
                        {trainResult.class_distribution && (
                          <div className="border-l border-slate-700 pl-4 font-mono">
                            Class Split: Normal ({trainResult.class_distribution.normal}) / Scan ({trainResult.class_distribution.port_scan})
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {activeTab === 'history' && (
          <div className="flex flex-col gap-3">
            {status.history.length === 0 ? (
              <div className="text-xs text-slate-500 p-8 text-center bg-slate-950/50 rounded border border-slate-800 border-dashed">
                No model evaluation history available.
              </div>
            ) : (
              status.history.map((h, i) => {
                const isActive = h.version === status.current_version;
                return (
                  <div key={i} className={`p-3 rounded border flex flex-col gap-2 transition-colors ${
                    isActive ? 'bg-emerald-950/10 border-emerald-500/30' : 'bg-slate-950 border-slate-800 hover:border-slate-700'
                  }`}>
                    <div className="flex justify-between items-start">
                      <div>
                        <div className="flex items-center gap-2 mb-1">
                          <span className="text-xs font-mono font-bold text-slate-200">{h.version}</span>
                          {isActive && (
                            <span className="text-[9px] bg-emerald-500/20 text-emerald-400 px-1.5 py-0.5 rounded font-bold uppercase tracking-wider border border-emerald-500/30">
                              Active
                            </span>
                          )}
                        </div>
                        <div className="text-[10px] text-slate-500 flex items-center gap-2">
                          <span>{new Date(h.created_at).toLocaleString()}</span>
                          <span className="w-1 h-1 rounded-full bg-slate-700" />
                          <span>Trained on {h.training_samples} examples</span>
                        </div>
                      </div>
                      
                      <div className="flex flex-col items-end gap-1">
                        <span className={`text-[10px] px-2 py-0.5 rounded font-bold uppercase tracking-wider ${
                          h.is_accepted ? 'text-emerald-400 bg-emerald-500/10' : 'text-slate-400 bg-slate-800'
                        }`}>
                          {h.is_accepted ? 'Accepted' : 'Rejected'}
                        </span>
                        <span className="text-xs font-mono text-sky-400">F1: {(h.f1_score * 100).toFixed(1)}%</span>
                      </div>
                    </div>
                    
                    {h.is_accepted && !isActive && (
                      <div className="pt-2 mt-1 border-t border-slate-800/50">
                        <button onClick={() => rollback(h.version)} className="text-[10px] text-sky-400 hover:text-sky-300 underline font-medium transition-colors">
                          Rollback to this version
                        </button>
                      </div>
                    )}
                  </div>
                );
              })
            )}
          </div>
        )}

        {activeTab === 'lifecycle' && (
          <div className="p-5 bg-slate-950 rounded border border-slate-800 h-full">
            <h3 className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-4">ML Pipeline Stages</h3>
            <div className="flex flex-col gap-4 relative before:absolute before:inset-y-2 before:left-[15px] before:w-px before:bg-slate-800">
              <div className="flex gap-4 items-start relative z-10">
                <div className="w-8 h-8 rounded-full bg-slate-900 border border-slate-700 flex items-center justify-center shrink-0 mt-0.5">
                  <ShieldAlert className="w-4 h-4 text-slate-400"/>
                </div>
                <div className="flex-1">
                  <strong className="text-xs text-slate-200 block mb-0.5">1. Observe</strong>
                  <p className="text-[10px] text-slate-500 leading-relaxed">Collect synthetic network telemetry during active attack simulations.</p>
                </div>
              </div>
              <div className="flex gap-4 items-start relative z-10">
                <div className="w-8 h-8 rounded-full bg-slate-900 border border-slate-700 flex items-center justify-center shrink-0 mt-0.5">
                  <Database className="w-4 h-4 text-slate-400"/>
                </div>
                <div className="flex-1">
                  <strong className="text-xs text-slate-200 block mb-0.5">2. Extract & Label</strong>
                  <p className="text-[10px] text-slate-500 leading-relaxed">Extract behavioral features and assign ground truth labels using independent IDS signatures.</p>
                </div>
              </div>
              <div className="flex gap-4 items-start relative z-10">
                <div className="w-8 h-8 rounded-full bg-sky-950/30 border border-sky-500/30 flex items-center justify-center shrink-0 mt-0.5">
                  <Cpu className="w-4 h-4 text-sky-400"/>
                </div>
                <div className="flex-1">
                  <strong className="text-xs text-sky-300 block mb-0.5">3. Train & Evaluate</strong>
                  <p className="text-[10px] text-slate-500 leading-relaxed">Train a candidate Random Forest model and evaluate strictly against a synthetic holdout set.</p>
                </div>
              </div>
              <div className="flex gap-4 items-start relative z-10">
                <div className="w-8 h-8 rounded-full bg-purple-950/30 border border-purple-500/30 flex items-center justify-center shrink-0 mt-0.5">
                  <GitCommit className="w-4 h-4 text-purple-400"/>
                </div>
                <div className="flex-1">
                  <strong className="text-xs text-purple-300 block mb-0.5">4. Acceptance Gate</strong>
                  <p className="text-[10px] text-slate-500 leading-relaxed">Candidate F1 score must exceed both the baseline threshold (85%) and the active model's F1 score.</p>
                </div>
              </div>
              <div className="flex gap-4 items-start relative z-10">
                <div className="w-8 h-8 rounded-full bg-emerald-950/30 border border-emerald-500/30 flex items-center justify-center shrink-0 mt-0.5">
                  <CheckCircle className="w-4 h-4 text-emerald-400"/>
                </div>
                <div className="flex-1">
                  <strong className="text-xs text-emerald-300 block mb-0.5">5. Activate</strong>
                  <p className="text-[10px] text-slate-500 leading-relaxed">If accepted, version the model and deploy it to the live inference pipeline.</p>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'analyst' && <LLMLearningAnalyst />}
      </div>

      {activeTab === 'status' && (
        <div className="p-4 border-t border-slate-800 bg-slate-950 shrink-0">
          <button
            onClick={triggerTraining}
            disabled={training || status.status !== 'READY_FOR_TRAINING'}
            className={`w-full py-2.5 rounded text-xs font-bold uppercase tracking-wider flex items-center justify-center gap-2 transition-all border
              ${training || status.status !== 'READY_FOR_TRAINING'
                ? 'bg-slate-900/50 text-slate-600 cursor-not-allowed border-slate-800' 
                : 'bg-emerald-600 hover:bg-emerald-500 text-white shadow-lg shadow-emerald-900/20 border-emerald-500'}`}
          >
            {training ? (
              <><RefreshCw className="w-4 h-4 animate-spin" /> Training & Evaluating Candidate...</>
            ) : (
              <><PlayCircle className="w-4 h-4" /> Train & Evaluate Candidate</>
            )}
          </button>
          
          {status.status === 'NOT_READY' && !training && (
            <p className="text-center mt-2 text-[10px] text-slate-500">Need at least 10 total examples to train.</p>
          )}
          {status.status === 'INSUFFICIENT_CLASSES' && !training && (
            <p className="text-center mt-2 text-[10px] text-amber-500/80">Requires at least 2 examples of both Normal and Port Scan classes.</p>
          )}
          {status.status === 'NO_NEW_DATA' && !training && (
            <p className="text-center mt-2 text-[10px] text-slate-500">No new telemetry collected since last training.</p>
          )}
          {status.status === 'NEW_DATA_AVAILABLE' && !training && (
            <p className="text-center mt-2 text-[10px] text-sky-500/80">Need 5 new examples to trigger evaluation (currently {status.new_examples}).</p>
          )}
        </div>
      )}
    </div>
  );
};
