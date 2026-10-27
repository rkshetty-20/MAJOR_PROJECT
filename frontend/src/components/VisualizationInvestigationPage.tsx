import React, { useState, useEffect } from 'react';
import { AttackTimeline } from './AttackTimeline';
import { AttackAnatomy } from './visualization/AttackAnatomy';
import { SimulationResult } from './AttackSimulation';
import { DetectionItem } from './DetectionRiskOverview';
import api from '../api';
import { Activity, ShieldCheck, ShieldAlert, Link as LinkIcon, ArrowLeft, Search, AlertTriangle, Layers, Clock, Zap, ChevronRight, FileSearch } from 'lucide-react';

import { IncidentVisualization } from './visualization/IncidentVisualization';
import { AttackWalkthrough } from './visualization/AttackWalkthrough';
import { InvestigationRelationshipGraph } from './visualization/InvestigationRelationshipGraph';
import { CheckCircle, XCircle, Play } from 'lucide-react';

export const AttackLifecycleExplorer: React.FC<{ context: any }> = ({ context }) => {
  return (
    <div className="w-full space-y-8 animate-in fade-in duration-500">
      <div className="flex flex-col md:flex-row gap-4 items-start md:items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-white tracking-tight">Attack Lifecycle Explorer</h2>
          <p className="text-slate-400 mt-1">Interactive expected-vs-actual pipeline analysis.</p>
        </div>
      </div>
      
      <div className="flex overflow-x-auto pb-4 gap-4 custom-scrollbar">
        {[
          { icon: Play, title: 'Attack Configuration', desc: 'Parameters & Scope' },
          { icon: Activity, title: 'Simulation Execution', desc: 'Synthetic event gen' },
          { icon: Layers, title: 'Generated Telemetry', desc: 'Dataset payloads' },
          { icon: ShieldCheck, title: 'Detection Processing', desc: 'Rules & ML inference' },
          { icon: Activity, title: 'Evaluation', desc: 'Expected vs Actual' },
          { icon: CheckCircle, title: 'Investigation', desc: 'Evidence & Provenance' },
          { icon: Activity, title: 'Learning Eligibility', desc: 'Training pipeline import' }
        ].map((stage, i) => (
          <div key={i} className="flex-shrink-0 w-64 p-4 rounded-xl border border-slate-800 bg-slate-900">
            <div className="flex items-center gap-2 mb-2">
              <div className="p-1.5 bg-indigo-500/10 text-indigo-400 rounded-md">
                <stage.icon className="w-4 h-4" />
              </div>
              <h3 className="text-sm font-bold text-slate-200">{stage.title}</h3>
            </div>
            <p className="text-xs text-slate-400">{stage.desc}</p>
            <div className="mt-3 text-[10px] font-mono font-bold px-2 py-1 bg-slate-950 rounded uppercase text-slate-500 inline-block border border-slate-800">
               Status: {context?.type === 'replay' ? <span className="text-emerald-500">COMPLETED</span> : 'UNAVAILABLE'}
            </div>
          </div>
        ))}
      </div>
      
      <div className="bg-slate-900 border border-slate-800 p-6 rounded-xl min-h-[300px]">
        {context?.type === 'replay' ? (
          <div>
            <h3 className="text-lg font-bold text-white mb-4">Lifecycle Stage Details</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="bg-slate-950 p-5 rounded-lg border border-slate-800 relative overflow-hidden">
                 <div className="absolute top-0 right-0 p-4 opacity-5"><Activity className="w-16 h-16" /></div>
                 <h4 className="text-sm font-bold text-slate-400 uppercase mb-3">Attacker Track (Expected)</h4>
                 <div className="text-sm font-mono text-emerald-400 mb-1">Dataset: {context.datasetId}</div>
                 <div className="text-xs text-slate-300">Synthetic attack telemetry successfully synthesized and staged for evaluation.</div>
              </div>
              <div className="bg-slate-950 p-5 rounded-lg border border-slate-800 relative overflow-hidden">
                 <div className="absolute top-0 right-0 p-4 opacity-5"><ShieldCheck className="w-16 h-16" /></div>
                 <h4 className="text-sm font-bold text-slate-400 uppercase mb-3">Defender Track (Actual)</h4>
                 <div className="text-sm font-mono text-indigo-400 mb-1">Eval Run: {context.evalRunId}</div>
                 <div className="text-xs text-slate-300">Processed by Detection Orchestrator. Output: {context.detections} detections.</div>
              </div>
            </div>
            
            <div className="mt-6 p-5 bg-slate-950 rounded-lg border border-slate-800">
               <h4 className="text-sm font-bold text-slate-400 uppercase mb-3">Evidence & Ground Truth Integration</h4>
               <p className="text-sm text-slate-300 mb-4">Based on ground truth validation, this dataset was evaluated with an F1 Score of {(context.metrics?.f1_score ?? 0).toFixed(2)}.</p>
               <div className="flex gap-4">
                 <div className="p-4 bg-emerald-900/20 border border-emerald-500/20 rounded flex-1">
                   <span className="text-[10px] font-bold text-emerald-400 block mb-1 uppercase tracking-wider">True Positives</span>
                   <span className="text-2xl text-emerald-300 font-mono">{context.metrics?.true_positives ?? 0}</span>
                 </div>
                 <div className="p-4 bg-rose-900/20 border border-rose-500/20 rounded flex-1">
                   <span className="text-[10px] font-bold text-rose-400 block mb-1 uppercase tracking-wider">Missed Detections (FN)</span>
                   <span className="text-2xl text-rose-300 font-mono">{context.metrics?.false_negatives ?? 0}</span>
                 </div>
                 <div className="p-4 bg-amber-900/20 border border-amber-500/20 rounded flex-1">
                   <span className="text-[10px] font-bold text-amber-400 block mb-1 uppercase tracking-wider">False Positives</span>
                   <span className="text-2xl text-amber-300 font-mono">{context.metrics?.false_positives ?? 0}</span>
                 </div>
               </div>
            </div>
          </div>
        ) : (
          <div className="flex flex-col items-center justify-center h-full text-slate-500 py-12">
            <XCircle className="w-12 h-12 mb-4 opacity-50" />
            <h3 className="text-lg font-bold mb-2">No Active Replay Context</h3>
            <p className="max-w-md text-center text-sm">Start a dataset replay from the Attack Simulation dashboard to populate the attacker and defender tracks with validated evidence.</p>
          </div>
        )}
      </div>
    </div>
  );
};

export type InvestigationContext =
  | { type: 'intrusion'; detectionId: number; simulationResult: SimulationResult | null; simulationId: string | null; scenarioName: string | undefined; incidentId?: string | null }
  | { type: 'phishing'; url: string; result: any; incidentId?: string | null }
  | { type: 'incident'; incidentId: string }
  | { type: 'replay'; datasetId: string; evalRunId: string; metrics: any; detections: number }
  | null;

interface Props {
  context: InvestigationContext;
  onAskChatbot: (telemetryContext: Record<string, unknown>, promptMessage: string) => void;
  onOpenInvestigation: (id: number) => void;
  onVisualizeIncident?: (incidentId: string) => void;
  onBack: () => void;
}

export const VisualizationInvestigationPage: React.FC<Props> = ({
  context,
  onAskChatbot,
  onOpenInvestigation,
  onVisualizeIncident,
  onBack
}) => {
  const [mode, setMode] = useState<'walkthrough' | 'investigation' | 'lifecycle'>(
    context?.type === 'replay' ? 'lifecycle' : (context ? 'investigation' : 'walkthrough')
  );

  useEffect(() => {
    if (context?.type === 'replay') {
      setMode('lifecycle');
    } else if (context) {
      setMode('investigation');
    }
  }, [context]);

  const [recentDetections, setRecentDetections] = useState<DetectionItem[]>([]);
  const [isLoading, setIsLoading] = useState(false);

  useEffect(() => {
    if (!context) {
      setIsLoading(true);
      api.get<DetectionItem[]>('/api/detections')
        .then(res => setRecentDetections(res.data))
        .catch(err => console.error("Failed to fetch detections:", err))
        .finally(() => setIsLoading(false));
    }
  }, [context]);

  const renderInvestigationContent = () => {
    if (!context) {
      return (
        <div className="w-full space-y-8 animate-in fade-in duration-500">
          <div className="flex flex-col md:flex-row gap-4 items-start md:items-center justify-between">
            <div>
              <h2 className="text-2xl font-bold text-white tracking-tight">Investigation Discovery</h2>
              <p className="text-slate-400 mt-1">Review recent detections and select an event to begin a detailed investigation.</p>
            </div>
            <div className="flex gap-3">
              <button 
                onClick={() => onBack()}
                className="px-4 py-2 bg-slate-800 text-slate-200 border border-slate-700 rounded-lg text-sm font-semibold hover:bg-slate-700 transition-colors flex items-center gap-2"
              >
                <Activity className="w-4 h-4" /> Go to Event Logs
              </button>
            </div>
          </div>

          {/* A. Investigation overview cards */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="p-5 bg-slate-900 border border-slate-800 rounded-xl shadow-sm flex flex-col relative overflow-hidden">
              <div className="absolute top-0 right-0 p-4 opacity-10"><Layers className="w-16 h-16" /></div>
              <span className="text-slate-400 text-sm font-semibold mb-1 uppercase tracking-wider">Stored Detections</span>
              <span className="text-3xl font-black text-white">{recentDetections.length}</span>
              <span className="text-xs text-slate-500 mt-2">Total detection records available</span>
            </div>
            
            <div className="p-5 bg-indigo-900/20 border border-indigo-500/20 rounded-xl shadow-sm flex flex-col relative overflow-hidden">
              <div className="absolute top-0 right-0 p-4 opacity-10"><Zap className="w-16 h-16 text-indigo-400" /></div>
              <span className="text-indigo-400 text-sm font-semibold mb-1 uppercase tracking-wider">Active Investigations</span>
              <span className="text-3xl font-black text-white">0</span>
              <span className="text-xs text-indigo-400/60 mt-2">No persisted incident lifecycle found</span>
            </div>
            
            <div className="p-5 bg-rose-900/20 border border-rose-500/20 rounded-xl shadow-sm flex flex-col relative overflow-hidden cursor-pointer hover:bg-rose-900/30 transition-colors">
              <div className="absolute top-0 right-0 p-4 opacity-10"><AlertTriangle className="w-16 h-16 text-rose-400" /></div>
              <span className="text-rose-400 text-sm font-semibold mb-1 uppercase tracking-wider">High Confidence Detections</span>
              <span className="text-3xl font-black text-white">
                {recentDetections.filter(d => d.confidence > 0.8).length}
              </span>
              <span className="text-xs text-rose-400/60 mt-2">Detections with &gt;80% confidence</span>
            </div>
          </div>

          {/* B. Recent detections table */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
            <div className="p-4 border-b border-slate-800 flex justify-between items-center bg-slate-900/50">
              <h3 className="text-lg font-bold text-white flex items-center gap-2">
                <Search className="w-5 h-5 text-slate-400" /> Recent Detections
              </h3>
            </div>
            
            {isLoading ? (
              <div className="p-12 text-center text-slate-500 flex flex-col items-center">
                <div className="w-8 h-8 border-4 border-indigo-500 border-t-transparent rounded-full animate-spin mb-4"></div>
                Loading detections...
              </div>
            ) : recentDetections.length === 0 ? (
              <div className="p-12 text-center flex flex-col items-center">
                <ShieldCheck className="w-12 h-12 text-emerald-500/50 mb-4" />
                <h4 className="text-slate-300 font-bold text-lg mb-2">No stored detections</h4>
                <p className="text-slate-500 text-sm max-w-sm">
                  There are no detection records in the database. Run a supported attack simulation to generate data.
                </p>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm whitespace-nowrap">
                  <thead className="bg-slate-950/50 text-slate-400 uppercase text-xs font-semibold tracking-wider">
                    <tr>
                      <th className="px-4 py-3">Detection ID</th>
                      <th className="px-4 py-3">Category</th>
                      <th className="px-4 py-3">Source Module</th>
                      <th className="px-4 py-3">Confidence</th>
                      <th className="px-4 py-3">Timestamp</th>
                      <th className="px-4 py-3">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/50">
                    {recentDetections.map((detection) => (
                      <tr key={detection.id} className="hover:bg-slate-800/50 transition-colors group">
                        <td className="px-4 py-3 font-mono text-xs text-slate-300">#{detection.id}</td>
                        <td className="px-4 py-3 text-slate-200">
                          {detection.label.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}
                        </td>
                        <td className="px-4 py-3">
                          <span className="px-2 py-1 rounded bg-slate-800 text-slate-300 text-xs font-medium">
                            {detection.source}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            <div className="w-16 h-2 bg-slate-800 rounded-full overflow-hidden">
                              <div 
                                className={`h-full ${detection.confidence > 0.7 ? 'bg-rose-500' : 'bg-amber-500'}`}
                                style={{ width: `${Math.min(100, Math.max(0, detection.confidence * 100))}%` }}
                              />
                            </div>
                            <span className="text-xs text-slate-400">{(detection.confidence * 100).toFixed(0)}%</span>
                          </div>
                        </td>
                        <td className="px-4 py-3 text-slate-400 text-xs flex items-center gap-1.5">
                          <Clock className="w-3 h-3" />
                          {new Date(detection.timestamp).toLocaleString()}
                        </td>
                        <td className="px-4 py-3">
                          <button 
                            onClick={() => onOpenInvestigation(detection.id)}
                            className="flex items-center gap-1 text-indigo-400 hover:text-indigo-300 text-xs font-bold transition-colors"
                          >
                            Investigate <ChevronRight className="w-3 h-3" />
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
          
          {/* C. Quick-start investigation actions */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-indigo-500/10 text-indigo-400 rounded-lg">
                  <FileSearch className="w-5 h-5" />
                </div>
                <div>
                  <h4 className="text-slate-200 font-bold text-sm">Browse Event Logs</h4>
                  <p className="text-slate-500 text-xs mt-0.5">View raw security events and network traffic.</p>
                </div>
              </div>
              <button onClick={() => onBack()} className="text-slate-400 hover:text-white transition-colors">
                <ChevronRight className="w-5 h-5" />
              </button>
            </div>
            <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-emerald-500/10 text-emerald-400 rounded-lg">
                  <Activity className="w-5 h-5" />
                </div>
                <div>
                  <h4 className="text-slate-200 font-bold text-sm">Run Simulation</h4>
                  <p className="text-slate-500 text-xs mt-0.5">Generate synthetic attacks for investigation.</p>
                </div>
              </div>
              <button onClick={() => onBack()} className="text-slate-400 hover:text-white transition-colors">
                <ChevronRight className="w-5 h-5" />
              </button>
            </div>
          </div>
        </div>
      );
    }

    if (context.type === 'incident') {
      return (
        <div className="w-full space-y-8">
          <div className="flex items-center justify-between">
            <h2 className="text-xl font-bold text-white flex items-center gap-2">
              <ShieldAlert className="w-5 h-5 text-indigo-400" />
              Unified Incident Investigation
            </h2>
          </div>
          <IncidentVisualization incidentId={context.incidentId} />
        </div>
      );
    }

    if (context.type === 'intrusion') {
      const nodes = [];
      const edges = [];
      
      nodes.push({ id: 'det', type: 'detection', label: `Detection #${context.detectionId}`, details: { Type: 'Network Intrusion', Scenario: context.scenarioName || 'Unknown' } });
      if (context.simulationId) {
        nodes.push({ id: 'sim', type: 'network', label: 'Network Session', details: { SimulationID: context.simulationId } });
        edges.push({ id: 'e1', sourceId: 'det', targetId: 'sim', label: 'generated_from', reason: 'Detection triggered by network traffic.', type: 'rule' });
      }
      
      if (context.incidentId) {
        nodes.push({ id: 'inc', type: 'incident', label: `Incident ${context.incidentId}`, details: { Status: 'Open' } });
        edges.push({ id: 'e2', sourceId: 'det', targetId: 'inc', label: 'included_in', reason: 'Correlation engine grouped this detection.', type: 'rule' });
      }

      return (
        <div className="w-full space-y-8">
          <div className="flex items-center justify-between border-b border-slate-800 pb-4">
            <div>
              <h2 className="text-xl font-bold text-white flex items-center gap-2">
                <Activity className="w-5 h-5 text-indigo-400" />
                Network Intrusion Investigation
              </h2>
              <p className="text-sm text-slate-400 mt-1">
                Visualizing attack timeline and anatomy for detection ID: {context.detectionId || 'Unknown'}
              </p>
            </div>
            {context.incidentId && onVisualizeIncident && (
              <button 
                onClick={() => onVisualizeIncident(context.incidentId as string)}
                className="flex items-center gap-2 px-4 py-2 bg-amber-500/10 text-amber-400 border border-amber-500/20 rounded-lg text-sm font-bold hover:bg-amber-500/20 transition-colors"
              >
                <LinkIcon className="w-4 h-4" /> View Associated Incident
              </button>
            )}
          </div>
          
          <InvestigationRelationshipGraph nodes={nodes as any} edges={edges as any} />

          {context.simulationResult ? (
            <>
              <AttackAnatomy 
                activeSimulationResult={context.simulationResult}
                onAskChatbot={onAskChatbot}
                onOpenInvestigation={onOpenInvestigation}
              />
              <AttackTimeline
                simulationId={context.simulationId}
                scenarioName={context.scenarioName}
              />
            </>
          ) : (
            <div className="p-8 bg-slate-900 rounded-xl border border-slate-800 text-center">
              <p className="text-slate-400">Detailed telemetry is unavailable for this detection.</p>
            </div>
          )}
        </div>
      );
    }

    if (context.type === 'replay') {
      return (
        <div className="w-full space-y-6">
          <div className="p-6 bg-slate-900 border border-slate-800 rounded-xl mb-6">
            <h2 className="text-xl font-bold text-white mb-2 flex items-center gap-2">
              <Activity className="w-6 h-6 text-indigo-400" /> Phase 5 & 6: Replay Evaluation Results
            </h2>
            <p className="text-slate-400 text-sm mb-6">Showing expected vs actual detection outcomes for Dataset <span className="text-emerald-400 font-mono">{context.datasetId}</span>.</p>
            
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="p-4 bg-slate-800 rounded-lg">
                <span className="text-xs text-slate-400 block uppercase mb-1">True Positives</span>
                <span className="text-2xl font-bold text-emerald-400">{context.metrics.true_positives ?? 0}</span>
              </div>
              <div className="p-4 bg-slate-800 rounded-lg">
                <span className="text-xs text-slate-400 block uppercase mb-1">False Positives</span>
                <span className="text-2xl font-bold text-rose-400">{context.metrics.false_positives ?? 0}</span>
              </div>
              <div className="p-4 bg-slate-800 rounded-lg">
                <span className="text-xs text-slate-400 block uppercase mb-1">False Negatives</span>
                <span className="text-2xl font-bold text-amber-400">{context.metrics.false_negatives ?? 0}</span>
              </div>
              <div className="p-4 bg-slate-800 rounded-lg border border-indigo-500/30">
                <span className="text-xs text-indigo-400 block uppercase mb-1">F1 Score</span>
                <span className="text-2xl font-bold text-indigo-400">{(context.metrics.f1_score ?? 0).toFixed(2)}</span>
              </div>
            </div>
            
            <div className="mt-8 p-6 bg-slate-950 rounded-lg border border-slate-800">
              <h3 className="text-md font-bold text-slate-200 mb-4">Replay Provenance & Metadata</h3>
              <ul className="space-y-2 text-sm text-slate-400 font-mono">
                <li><span className="text-slate-500">Evaluation Run ID:</span> {context.evalRunId}</li>
                <li><span className="text-slate-500">Total Detections Triggered:</span> {context.detections}</li>
                <li><span className="text-slate-500">Investigation Integration:</span> Full telemetry is available in Event Logs.</li>
              </ul>
            </div>
          </div>
        </div>
      );
    }

    if (context.type === 'phishing') {
      const { url, result } = context;
      const isMalicious = result?.is_phishing;
      const confidence = result?.heuristic_confidence || 0;
      const reputationResult = result?.reputation;

      let parsedUrl: URL | null = null;
      try {
        parsedUrl = new URL(url);
      } catch (e) {
        // Handled
      }

      const nodes = [];
      const edges = [];
      
      nodes.push({ id: 'phish', type: 'phishing', label: 'Suspicious URL', details: { URL: url, Score: confidence } });
      if (parsedUrl?.hostname) {
        nodes.push({ id: 'domain', type: 'domain', label: parsedUrl.hostname, details: { Scheme: parsedUrl.protocol } });
        edges.push({ id: 'e1', sourceId: 'phish', targetId: 'domain', label: 'hosted_on', reason: 'URL belongs to this domain.', type: 'direct' });
      }
      
      if (context.incidentId) {
        nodes.push({ id: 'inc', type: 'incident', label: `Incident ${context.incidentId}`, details: { Status: 'Open' } });
        edges.push({ id: 'e2', sourceId: 'phish', targetId: 'inc', label: 'included_in', reason: 'Correlation engine grouped this detection.', type: 'rule' });
      }

      return (
        <div className="w-full space-y-8">
          <div className="flex items-center justify-between border-b border-slate-800 pb-4">
            <div>
              <h2 className="text-xl font-bold text-white flex items-center gap-2">
                <LinkIcon className="w-5 h-5 text-indigo-400" />
                Phishing URL Investigation
              </h2>
              <p className="text-sm text-slate-400 truncate max-w-xl mt-1">
                {url}
              </p>
            </div>
            {context.incidentId && onVisualizeIncident && (
              <button 
                onClick={() => onVisualizeIncident(context.incidentId as string)}
                className="flex items-center gap-2 px-4 py-2 bg-amber-500/10 text-amber-400 border border-amber-500/20 rounded-lg text-sm font-bold hover:bg-amber-500/20 transition-colors"
              >
                <LinkIcon className="w-4 h-4" /> View Associated Incident
              </button>
            )}
          </div>
          
          <InvestigationRelationshipGraph nodes={nodes as any} edges={edges as any} />

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="lg:col-span-2 space-y-6">
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-sm">
                <h3 className="text-sm font-bold text-slate-300 uppercase tracking-wider mb-4 border-b border-slate-800 pb-2">
                  URL Anatomy & Extracted Features
                </h3>
                
                <div className="space-y-4 mb-6">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between p-3 bg-slate-950 rounded-lg border border-slate-800 gap-2">
                    <span className="text-xs text-slate-500 font-mono">SCHEME</span>
                    <span className={`text-sm font-medium ${parsedUrl?.protocol === 'https:' ? 'text-emerald-400' : 'text-amber-400'}`}>
                      {parsedUrl?.protocol || 'N/A'}
                    </span>
                  </div>
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between p-3 bg-slate-950 rounded-lg border border-slate-800 gap-2">
                    <span className="text-xs text-slate-500 font-mono">DOMAIN</span>
                    <span className="text-sm text-slate-200 truncate max-w-[300px]">
                      {result?.features?.domain || 'N/A'}
                    </span>
                  </div>
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between p-3 bg-slate-950 rounded-lg border border-slate-800 gap-2">
                    <span className="text-xs text-slate-500 font-mono">HOSTNAME</span>
                    <span className="text-sm text-slate-200 truncate max-w-[300px]" title={parsedUrl?.hostname || ''}>
                      {parsedUrl?.hostname || 'N/A'}
                    </span>
                  </div>
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between p-3 bg-slate-950 rounded-lg border border-slate-800 gap-2">
                    <span className="text-xs text-slate-500 font-mono">PORT</span>
                    <span className="text-sm text-slate-200 truncate max-w-[300px]">
                      {parsedUrl?.port || (parsedUrl?.protocol === 'https:' ? '443' : parsedUrl?.protocol === 'http:' ? '80' : 'N/A')}
                    </span>
                  </div>
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between p-3 bg-slate-950 rounded-lg border border-slate-800 gap-2">
                    <span className="text-xs text-slate-500 font-mono">PATH & QUERY</span>
                    <span className="text-sm text-slate-200 truncate max-w-[300px]" title={(parsedUrl?.pathname || '') + (parsedUrl?.search || '')}>
                      {(parsedUrl?.pathname || '') + (parsedUrl?.search || '') || '/'}
                    </span>
                  </div>
                </div>

                {result?.features && (
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-4">
                    <div className="p-3 bg-slate-950 rounded-lg border border-slate-800">
                      <div className="text-[10px] text-slate-500 uppercase font-bold mb-1">Length</div>
                      <div className={`text-lg font-mono ${result.features.url_length > 75 ? 'text-amber-400' : 'text-slate-200'}`}>
                        {result.features.url_length}
                      </div>
                    </div>
                    <div className="p-3 bg-slate-950 rounded-lg border border-slate-800">
                      <div className="text-[10px] text-slate-500 uppercase font-bold mb-1">Subdomains</div>
                      <div className={`text-lg font-mono ${result.features.num_subdomains >= 3 ? 'text-amber-400' : 'text-slate-200'}`}>
                        {result.features.num_subdomains}
                      </div>
                    </div>
                    <div className="p-3 bg-slate-950 rounded-lg border border-slate-800">
                      <div className="text-[10px] text-slate-500 uppercase font-bold mb-1">Suspicious Keywords</div>
                      <div className={`text-lg font-mono ${result.features.keyword_count > 0 ? 'text-rose-400' : 'text-slate-200'}`}>
                        {result.features.keyword_count}
                      </div>
                    </div>
                    <div className="p-3 bg-slate-950 rounded-lg border border-slate-800">
                      <div className="text-[10px] text-slate-500 uppercase font-bold mb-1">IP Hostname</div>
                      <div className={`text-lg font-mono ${result.features.is_ip ? 'text-rose-400' : 'text-slate-200'}`}>
                        {result.features.is_ip ? 'Yes' : 'No'}
                      </div>
                    </div>
                  </div>
                )}
              </div>
              
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-sm">
                <h3 className="text-sm font-bold text-slate-300 uppercase tracking-wider mb-4 border-b border-slate-800 pb-2">
                  Triggered Rules & Evidence
                </h3>
                
                {result?.triggered_rules && result.triggered_rules.length > 0 ? (
                  <div className="space-y-3">
                    {result.triggered_rules.map((rule: any, idx: number) => (
                      <div key={idx} className="flex flex-col sm:flex-row justify-between gap-3 p-3 bg-slate-950 rounded-lg border border-slate-800">
                        <div>
                          <span className="text-sm font-bold text-amber-400">{rule.name}</span>
                          <p className="text-xs text-slate-400 mt-1">{rule.explanation}</p>
                        </div>
                        <div className="text-xs font-mono font-bold text-slate-300 shrink-0">
                          +{ (rule.contribution * 100).toFixed(0) }%
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-sm text-slate-400">No specific heuristic rules triggered.</p>
                )}
              </div>
            </div>

            <div className="space-y-6">
              <div className={`p-6 rounded-xl border ${isMalicious ? 'bg-amber-500/10 border-amber-500/30' : 'bg-emerald-500/10 border-emerald-500/30'} flex flex-col items-center text-center shadow-sm`}>
                <div className={`p-4 rounded-full mb-4 ${isMalicious ? 'bg-amber-500/20 text-amber-400' : 'bg-emerald-500/20 text-emerald-400'}`}>
                  {isMalicious ? <ShieldAlert className="w-10 h-10" /> : <ShieldCheck className="w-10 h-10" />}
                </div>
                <h3 className={`text-xl font-bold mb-2 ${isMalicious ? 'text-amber-400' : 'text-emerald-400'}`}>
                  {isMalicious ? 'Suspicious URL' : 'Benign URL'}
                </h3>
                <div className="text-3xl font-black text-white my-2">{(confidence * 100).toFixed(0)}%</div>
                <div className="text-xs text-slate-400 uppercase tracking-wider font-bold">Heuristic Score</div>
                <p className="text-[11px] text-slate-500 mt-4 leading-relaxed">
                  Note: This score is a heuristic risk indicator based on identifiable features, not a calibrated probability of phishing.
                </p>
              </div>
              
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-sm">
                <h3 className="text-sm font-bold text-slate-300 uppercase tracking-wider mb-4 border-b border-slate-800 pb-2">
                  External Reputation
                </h3>
                {reputationResult ? (
                  <div>
                    <div className={`p-3 rounded-lg border ${
                      reputationResult.status === 'match' ? 'bg-rose-500/10 border-rose-500/30' :
                      reputationResult.status === 'no_match' ? 'bg-emerald-500/10 border-emerald-500/30' :
                      'bg-slate-800 border-slate-700'
                    }`}>
                      <h4 className="text-sm font-bold text-white mb-1">VirusTotal v3</h4>
                      <p className={`text-xs ${
                        reputationResult.status === 'match' ? 'text-rose-400' :
                        reputationResult.status === 'no_match' ? 'text-emerald-400' :
                        'text-slate-400'
                      }`}>
                        {reputationResult.details}
                      </p>
                    </div>
                    {reputationResult.status === 'no_match' && (
                      <p className="text-[11px] text-slate-500 mt-3">
                        Absence of records is not sufficient evidence to declare a URL safe. Provider failures or inconclusive responses are not proof of safety.
                      </p>
                    )}
                    {reputationResult.status === 'unavailable' && (
                      <p className="text-[11px] text-slate-500 mt-3">
                        Reputation lookup failed or is disabled. Ensure valid API credentials and network access.
                      </p>
                    )}
                  </div>
                ) : (
                  <p className="text-xs text-slate-500">Reputation data not available.</p>
                )}
              </div>
            </div>
          </div>
        </div>
      );
    }

    return null;
  };

  return (
    <div className="w-full max-w-[1400px] mx-auto space-y-6">
      <div className="flex flex-col space-y-4 md:space-y-0 md:flex-row md:items-center justify-between border-b border-slate-800 pb-4">
        <div className="flex items-center gap-4">
          <button
            onClick={onBack}
            className="p-2 hover:bg-slate-800 rounded-lg text-slate-400 hover:text-white transition-colors"
            title="Go Back"
          >
            <ArrowLeft className="w-5 h-5" />
          </button>
          <div>
            <h2 className="text-xl font-bold text-white">Visualization & Investigation</h2>
            <p className="text-sm text-slate-400">
              {mode === 'walkthrough' ? 'Educational Mode' : 'Investigation Mode'}
            </p>
          </div>
        </div>
        
        <div className="flex bg-slate-900 rounded-lg p-1 border border-slate-800 self-start md:self-auto overflow-x-auto max-w-full">
          <button
            onClick={() => setMode('walkthrough')}
            className={`px-4 py-2 text-sm font-bold rounded-md transition-colors whitespace-nowrap ${mode === 'walkthrough' ? 'bg-indigo-600 text-white shadow' : 'text-slate-400 hover:text-white'}`}
          >
            Attack Walkthrough
          </button>
          <button
            onClick={() => setMode('investigation')}
            className={`px-4 py-2 text-sm font-bold rounded-md transition-colors whitespace-nowrap ${mode === 'investigation' ? 'bg-indigo-600 text-white shadow' : 'text-slate-400 hover:text-white'}`}
          >
            Investigation Explorer
          </button>
          <button
            onClick={() => setMode('lifecycle')}
            className={`px-4 py-2 text-sm font-bold rounded-md transition-colors whitespace-nowrap ${mode === 'lifecycle' ? 'bg-emerald-600 text-white shadow' : 'text-slate-400 hover:text-white'}`}
          >
            Attack Lifecycle Explorer
          </button>
        </div>
      </div>

      {mode === 'walkthrough' ? (
        <AttackWalkthrough />
      ) : mode === 'lifecycle' ? (
        <AttackLifecycleExplorer context={context} />
      ) : (
        renderInvestigationContent()
      )}
    </div>
  );
};
