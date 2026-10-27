import React, { useState, useEffect } from 'react';
import { 
  X, 
  Search, 
  ShieldAlert,
  Activity,
  Server,
  Zap,
  MessageSquare,
  Lock
} from 'lucide-react';
import api from '../api';
import { SecurityEventItem } from './RecentEventsTable';
import { AttackTimeline } from './AttackTimeline';

interface DetectionInvestigationModalProps {
  detectionId: number;
  onClose: () => void;
  onEventClick: (event: SecurityEventItem) => void;
  onAskChatbot: (telemetryContext: Record<string, unknown>, promptMessage: string) => void;
}

export const DetectionInvestigationModal: React.FC<DetectionInvestigationModalProps> = ({
  detectionId,
  onClose,
  onEventClick,
  onAskChatbot,
}) => {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [investigationData, setInvestigationData] = useState<any>(null);

  useEffect(() => {
    const fetchInvestigation = async () => {
      try {
        setLoading(true);
        setError(null);
        const response = await api.get(`/api/investigations/${detectionId}`);
        setInvestigationData(response.data);
      } catch (err: any) {
        console.error(err);
        setError(err.response?.data?.detail || "Unable to load investigation data.");
      } finally {
        setLoading(false);
      }
    };
    fetchInvestigation();
  }, [detectionId]);

  if (loading) {
    return (
      <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-md flex items-center justify-center">
        <div className="bg-slate-900 border border-slate-700/80 rounded-2xl p-8 flex flex-col items-center">
          <Activity className="w-8 h-8 text-indigo-400 animate-spin mb-4" />
          <p className="text-slate-300 font-medium">Loading investigation...</p>
        </div>
      </div>
    );
  }

  if (error || !investigationData) {
    return (
      <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-md flex items-center justify-center p-4">
        <div className="bg-slate-900 border border-slate-700/80 rounded-2xl max-w-md w-full p-6 text-center space-y-4 shadow-2xl">
          <div className="mx-auto w-12 h-12 bg-rose-500/10 rounded-full flex items-center justify-center mb-2">
            <X className="w-6 h-6 text-rose-400" />
          </div>
          <h3 className="text-lg font-bold text-white">Detection not found</h3>
          <p className="text-slate-400 text-sm">{error || "No investigation data available."}</p>
          <button onClick={onClose} className="px-4 py-2 bg-slate-800 text-white rounded-lg hover:bg-slate-700 transition-colors w-full">
            Close
          </button>
        </div>
      </div>
    );
  }

  const { detection, related_events, risk } = investigationData;
  const simulationId = related_events.length > 0 ? related_events[0].simulation_id : null;

  const handleAskAssistant = () => {
    const contextPayload = {
      detection_id: detection.id,
      label: detection.label,
      explanation: detection.explanation,
      risk_score: risk?.score,
      risk_band: risk?.band,
      contributing_factors: risk?.contributing_factors,
      evidence_events_count: related_events.length,
    };
    const question = `Why was this ${detection.label} detected with risk score ${risk?.score || 'unknown'} and what evidence supports it?`;
    onAskChatbot(contextPayload, question);
    onClose();
  };

  const isPhishing = detection?.label?.toLowerCase().includes('phishing') || 
                     (related_events.length > 0 && related_events[0].scenario?.toLowerCase().includes('phishing'));
  const accentText = isPhishing ? 'text-amber-400' : 'text-emerald-400';
  const accentBg = isPhishing ? 'bg-amber-500/10 border-amber-500/20' : 'bg-emerald-500/10 border-emerald-500/20';
  const accentBorder = isPhishing ? 'border-l-amber-500' : 'border-l-emerald-500';

  return (
    <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-md flex items-center justify-center p-4 animate-fade-in">
      <div className="bg-slate-900 border border-slate-700/80 rounded-lg max-w-4xl w-full max-h-[90vh] overflow-y-auto shadow-2xl flex flex-col">
        {/* Header */}
        <div className="p-5 border-b border-slate-800 flex items-center justify-between bg-slate-950/60 sticky top-0 z-10">
          <div className="flex items-center gap-3">
            <div className={`p-2.5 rounded-lg border ${accentBg} ${accentText}`}>
              <Search className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-bold text-white">
                Detection Investigation
              </h3>
              <p className="text-xs text-slate-400 font-mono">
                Detection ID: #{detection.id} • Confidence: {Math.round(detection.confidence * 100)}%
              </p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            {risk && (
              <div className="px-3 py-1.5 rounded-lg bg-slate-800/80 border border-slate-700 flex items-center gap-2">
                <span className="text-xs text-slate-400 uppercase">Risk:</span>
                <span className={`text-sm font-bold ${risk.band === 'CRITICAL' ? 'text-rose-500' : risk.band === 'HIGH' ? 'text-amber-500' : 'text-sky-500'}`}>
                  {risk.band} — {risk.score}
                </span>
              </div>
            )}
            <button
              onClick={onClose}
              className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-all"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Body */}
        <div className="p-6 space-y-8">
          
          {/* Why it was detected */}
          <section className="space-y-3">
            <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider flex items-center gap-2">
              <ShieldAlert className="w-4 h-4" /> Why this was detected
            </h4>
            <div className={`p-4 rounded-lg bg-slate-950/50 border border-slate-800/80 border-l-4 ${accentBorder}`}>
              <p className="text-sm text-slate-200 leading-relaxed font-mono">
                {detection.explanation || "No detailed explanation available."}
              </p>
              <div className="mt-3 text-xs text-slate-500 flex flex-wrap items-center gap-4">
                <span className="flex items-center gap-1">
                  <Activity className="w-3.5 h-3.5" />
                  Detected: {new Date(detection.timestamp).toLocaleString()}
                </span>
                <span className="flex items-center gap-1">
                  <Server className="w-3.5 h-3.5" />
                  Source Engine: {detection.source.toUpperCase()}
                </span>
                {detection.integrity_status === 'verified' && (
                  <span className="flex items-center gap-1 text-emerald-400/80 bg-emerald-500/10 px-2 py-0.5 rounded-full border border-emerald-500/20" title={`HMAC Verified: ${detection.evidence_hash}`}>
                    <Lock className="w-3 h-3" />
                    HMAC Verified
                  </span>
                )}
                {detection.integrity_status === 'verified_legacy' && (
                  <span className="flex items-center gap-1 text-indigo-400/80 bg-indigo-500/10 px-2 py-0.5 rounded-full border border-indigo-500/20" title={`Legacy SHA-256 Verified: ${detection.evidence_hash}`}>
                    <Lock className="w-3 h-3" />
                    SHA-256 Verified
                  </span>
                )}
                {detection.integrity_status === 'mismatch' && (
                  <span className="flex items-center gap-1 text-rose-400/80 bg-rose-500/10 px-2 py-0.5 rounded-full border border-rose-500/20" title={`Integrity Mismatch! Stored: ${detection.evidence_hash}`}>
                    <ShieldAlert className="w-3 h-3" />
                    Tampered!
                  </span>
                )}
                {(detection.integrity_status === 'missing_hash' || detection.integrity_status === 'verification_error' || detection.integrity_status === 'verification_unavailable' || !detection.integrity_status) && (
                  <span className="flex items-center gap-1 text-amber-400/80 bg-amber-500/10 px-2 py-0.5 rounded-full border border-amber-500/20" title="Integrity could not be verified.">
                    <Lock className="w-3 h-3" />
                    {detection.integrity_status === 'verification_unavailable' ? 'Unavailable' : 'Unverified'}
                  </span>
                )}
                {detection.integrity_status === 'chain_broken' && (
                  <span className="flex items-center gap-1 text-amber-400/80 bg-amber-500/10 px-2 py-0.5 rounded-full border border-amber-500/20" title="This record is valid, but a prior record in the chain is missing.">
                    <ShieldAlert className="w-3 h-3" />
                    Chain Broken
                  </span>
                )}
              </div>
            </div>
          </section>

          {/* Evidence Events */}
          <section className="space-y-3">
            <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider flex items-center gap-2">
              <Server className="w-4 h-4" /> Evidence ({related_events.length} related events)
            </h4>
            {related_events.length > 0 ? (
              <div className="rounded-lg border border-slate-800/80 overflow-hidden bg-slate-950/30">
                <table className="w-full text-left text-xs text-slate-300">
                  <thead className="bg-slate-900/50 text-slate-400 font-semibold border-b border-slate-800/80">
                    <tr>
                      <th className="px-4 py-2.5">Time</th>
                      <th className="px-4 py-2.5">Source</th>
                      <th className="px-4 py-2.5">Target</th>
                      <th className="px-4 py-2.5">Correlation Reason</th>
                      <th className="px-4 py-2.5">Type</th>
                      <th className="px-4 py-2.5">Integrity</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/50">
                    {related_events.map((ev: any) => (
                      <tr 
                        key={ev.id} 
                        className="hover:bg-slate-800/30 transition-colors cursor-pointer"
                        onClick={() => onEventClick(ev)}
                      >
                        <td className="px-4 py-2.5 font-mono text-[11px] whitespace-nowrap">
                          {new Date(ev.timestamp).toLocaleTimeString()}
                        </td>
                        <td className="px-4 py-2.5 text-indigo-300 truncate max-w-[120px]">{ev.source}</td>
                        <td className="px-4 py-2.5 truncate max-w-[120px]">{ev.target}</td>
                        <td className="px-4 py-2.5 truncate max-w-[200px] text-slate-400" title={ev.correlation_reason}>
                          {ev.is_hypothesis && <span className="text-amber-500 mr-1 font-bold">[Hypothesis]</span>}
                          {ev.correlation_reason || 'Inferred'}
                        </td>
                        <td className="px-4 py-2.5 font-mono text-[11px]">
                          <span className={`px-2 py-0.5 rounded-full ${ev.event_type.includes('failed') ? 'bg-rose-500/10 text-rose-400' : 'bg-slate-800 text-slate-300'}`}>
                            {ev.event_type}
                          </span>
                        </td>
                        <td className="px-4 py-2.5">
                          {ev.integrity_status === 'verified' ? (
                            <div className="flex items-center gap-1 text-emerald-500/80 font-mono text-[10px]" title={`HMAC Verified: ${ev.evidence_hash}`}>
                              <Lock className="w-3 h-3" />
                              HMAC
                            </div>
                          ) : ev.integrity_status === 'verified_legacy' ? (
                            <div className="flex items-center gap-1 text-indigo-500/80 font-mono text-[10px]" title={`Legacy SHA-256 Verified: ${ev.evidence_hash}`}>
                              <Lock className="w-3 h-3" />
                              SHA256
                            </div>
                          ) : ev.integrity_status === 'mismatch' ? (
                            <div className="flex items-center gap-1 text-rose-500/80 font-mono text-[10px] font-bold" title={`Integrity Mismatch! Stored: ${ev.evidence_hash}`}>
                              <ShieldAlert className="w-3 h-3" />
                              Tampered
                            </div>
                          ) : ev.integrity_status === 'verification_unavailable' ? (
                            <span className="text-amber-500/80 text-[10px]" title="Key unavailable">Unavailable</span>
                          ) : ev.integrity_status === 'chain_broken' ? (
                            <div className="flex items-center gap-1 text-amber-500/80 font-mono text-[10px]" title="Valid record, but prior record missing">
                              <ShieldAlert className="w-3 h-3" />
                              Broken Chain
                            </div>
                          ) : (
                            <span className="text-amber-500/80 text-[10px]" title="Integrity could not be verified">Unverified</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="p-4 rounded-lg bg-slate-950/30 border border-slate-800/80 text-center text-slate-500 text-sm">
                No telemetry events explicitly correlated with this detection.
              </div>
            )}
          </section>

          {/* Risk Breakdown */}
          {risk && risk.contributing_factors && (
            <section className="space-y-3">
              <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider flex items-center gap-2">
                <Zap className="w-4 h-4" /> Risk Breakdown
              </h4>
              <div className="p-5 rounded-xl bg-slate-950/50 border border-slate-800/80">
                <div className="space-y-4 text-sm">
                  <div className="flex items-center justify-between">
                    <span className="text-slate-300">Rule Detection</span>
                    <div className="flex items-center gap-3">
                      <div className="w-32 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                        <div className="h-full bg-indigo-500" style={{ width: `${(risk.contributing_factors.rule_detected / 40) * 100}%` }} />
                      </div>
                      <span className="font-mono text-indigo-400 w-8 text-right">+{risk.contributing_factors.rule_detected || 0}</span>
                    </div>
                  </div>
                  
                  <div className="flex items-center justify-between">
                    <span className="text-slate-300">Multi-Signal Bonus</span>
                    <div className="flex items-center gap-3">
                      <div className="w-32 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                        <div className="h-full bg-rose-500" style={{ width: `${(risk.contributing_factors.multi_signal_bonus / 30) * 100}%` }} />
                      </div>
                      <span className="font-mono text-rose-400 w-8 text-right">+{risk.contributing_factors.multi_signal_bonus || 0}</span>
                    </div>
                  </div>
                  
                  <div className="flex items-center justify-between">
                    <span className="text-slate-300">ML Confidence Contribution</span>
                    <div className="flex items-center gap-3">
                      <div className="w-32 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                        <div className="h-full bg-emerald-500" style={{ width: `${(risk.contributing_factors.ml_confidence_term / 40) * 100}%` }} />
                      </div>
                      <span className="font-mono text-emerald-400 w-8 text-right">+{risk.contributing_factors.ml_confidence_term || 0}</span>
                    </div>
                  </div>
                  
                  <div className="flex items-center justify-between">
                    <span className="text-slate-300">Rule / ML Agreement</span>
                    <div className="flex items-center gap-3">
                      <div className="w-32 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                        <div className="h-full bg-sky-500" style={{ width: `${(risk.contributing_factors.agreement_bonus / 10) * 100}%` }} />
                      </div>
                      <span className="font-mono text-sky-400 w-8 text-right">+{risk.contributing_factors.agreement_bonus || 0}</span>
                    </div>
                  </div>
                  
                  <div className="flex items-center justify-between">
                    <span className="text-slate-300">Severity Metric</span>
                    <div className="flex items-center gap-3">
                      <div className="w-32 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                        <div className="h-full bg-amber-500" style={{ width: `${(risk.contributing_factors.severity_term / 10) * 100}%` }} />
                      </div>
                      <span className="font-mono text-amber-400 w-8 text-right">+{risk.contributing_factors.severity_term || 0}</span>
                    </div>
                  </div>

                  <div className="pt-3 border-t border-slate-800 flex justify-between items-center text-base font-bold">
                    <span className="text-white">FINAL RISK SCORE</span>
                    <span className="font-mono text-white">{risk.score} <span className="text-xs text-slate-400 ml-1">{risk.band}</span></span>
                  </div>
                </div>
              </div>
            </section>
          )}

          {/* Attack Timeline */}
          {simulationId && (
            <section className="space-y-3">
              <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider flex items-center gap-2">
                <Activity className="w-4 h-4" /> Attack Timeline
              </h4>
              <div className="bg-slate-950/30 rounded-xl overflow-hidden border border-slate-800/80">
                <AttackTimeline simulationId={simulationId} />
              </div>
            </section>
          )}

        </div>

        {/* Footer Actions */}
        <div className="p-5 border-t border-slate-800 bg-slate-950/60 sticky bottom-0 z-10 flex justify-between items-center">
          <button
            onClick={handleAskAssistant}
            className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg transition-colors font-semibold shadow-lg shadow-indigo-900/20 flex items-center gap-2 text-sm"
          >
            <MessageSquare className="w-4 h-4" /> Ask Security Assistant
          </button>
          
          <button
            onClick={onClose}
            className="px-4 py-2 border border-slate-700 text-slate-300 hover:bg-slate-800 rounded-lg transition-colors font-medium text-sm"
          >
            Close Investigation
          </button>
        </div>
      </div>
    </div>
  );
};
