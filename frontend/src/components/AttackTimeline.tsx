import React, { useEffect, useState } from 'react';
import { 
  Clock, 
  Zap, 
  ShieldAlert, 
  Activity, 
  Bot,
  AlertTriangle,
  RefreshCw
} from 'lucide-react';
import api from '../api';

export interface RealTimelineStep {
  step: string;
  timestamp: string;
  status: string;
  label: string;
  details?: string;
  score?: number;
  band?: string;
  related_id?: number;
  severity?: number;
  risk_score?: number;
  simulation_id?: string;
}

interface AttackTimelineProps {
  simulationId: string | null;
  scenarioName?: string;
}

export const AttackTimeline: React.FC<AttackTimelineProps> = ({
  simulationId,
  scenarioName,
}) => {
  const [timeline, setTimeline] = useState<RealTimelineStep[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!simulationId) {
      setTimeline(null);
      return;
    }

    const fetchTimeline = async () => {
      setLoading(true);
      setError(null);
      try {
        const response = await api.get<RealTimelineStep[]>(`/api/simulation/${simulationId}/timeline`);
        setTimeline(response.data);
      } catch (err) {
        console.error("Failed to fetch timeline:", err);
        setError("Failed to load timeline progression.");
      } finally {
        setLoading(false);
      }
    };

    fetchTimeline();
  }, [simulationId]);

  if (!simulationId) {
    return (
      <div className="w-full p-5 rounded-lg bg-slate-900 border border-slate-800 shadow-none">
        <div className="flex items-center gap-2 mb-2">
          <Clock className="w-4 h-4 text-slate-400" />
          <h3 className="text-sm font-bold text-white tracking-wide uppercase">
            Attack Progression Timeline
          </h3>
        </div>
        <p className="text-xs text-slate-500 italic">
          Run an attack simulation above to visualize the real-time detection lifecycle progression.
        </p>
      </div>
    );
  }

  const formatStepTime = (raw: string) => {
    try {
      const d = new Date(raw);
      if (isNaN(d.getTime())) return raw;
      return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    } catch {
      return raw;
    }
  };

  const isPhishing = scenarioName?.toLowerCase().includes('phishing');
  const accentText = isPhishing ? 'text-amber-400' : 'text-emerald-400';
  const accentBg = isPhishing ? 'bg-amber-500/10 border-amber-500/20' : 'bg-emerald-500/10 border-emerald-500/20';

  const getStepIcon = (stepType: string) => {
    switch (stepType) {
      case 'simulation_started':
        return <Zap className={`w-3.5 h-3.5 ${accentText}`} />;
      case 'event_generated':
      case 'suricata_event_generated':
        return <Activity className={`w-3.5 h-3.5 ${accentText}`} />;
      case 'detection_triggered':
        return <ShieldAlert className={`w-3.5 h-3.5 ${accentText}`} />;
      case 'risk_calculated':
        return <AlertTriangle className="w-3.5 h-3.5 text-slate-400" />;
      default:
        return <Bot className="w-3.5 h-3.5 text-slate-400" />;
    }
  };

  return (
    <div className="w-full p-5 rounded-lg bg-slate-900 border border-slate-800 shadow-none space-y-4">
      <div className="flex items-center justify-between border-b border-slate-800 pb-3 flex-wrap gap-2">
        <div className="flex flex-col gap-0.5">
          <div className="flex items-center gap-2">
            <Clock className="w-4 h-4 text-slate-400" />
            <h3 className="text-sm font-bold text-white tracking-wide uppercase">
              Verified Security Timeline
            </h3>
          </div>
          <p className="text-[10px] text-slate-400 ml-6">
            Chronology reconstructed from persisted backend telemetry.
          </p>
        </div>
        {scenarioName && (
          <span className={`text-[10px] font-mono px-2 py-0.5 rounded uppercase tracking-wider ${accentText} ${accentBg} border`}>
            Active: {scenarioName}
          </span>
        )}
      </div>

      {loading && (
        <div className="flex items-center gap-2 text-indigo-400 text-sm py-4">
          <RefreshCw className="w-4 h-4 animate-spin" />
          <span>Loading timeline data...</span>
        </div>
      )}

      {error && (
        <div className="flex items-center gap-2 text-rose-400 text-sm py-4">
          <AlertTriangle className="w-4 h-4" />
          <span>{error}</span>
        </div>
      )}

      {!loading && !error && timeline && timeline.length === 0 && (
        <p className="text-xs text-slate-500 italic py-4">
          No timeline events found for this simulation.
        </p>
      )}

      {!loading && !error && timeline && timeline.length > 0 && (
        <div className="relative pl-6 space-y-4 before:content-[''] before:absolute before:left-2.5 before:top-2 before:bottom-2 before:w-0.5 before:bg-slate-800">
          {timeline.map((step, idx) => (
            <div key={idx} className="relative flex items-start gap-3">
              {/* Dot */}
              <div className="absolute -left-6 mt-1 flex items-center justify-center w-5 h-5 rounded-full bg-slate-900 border border-slate-700 shadow-sm">
                {getStepIcon(step.step)}
              </div>

              <div className="flex-1 p-3 rounded-lg bg-slate-950 border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-1 text-xs">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-semibold text-white block">
                      {step.label}
                    </span>
                    {step.related_id && (
                      <span className="text-[9px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
                        ID: {step.related_id}
                      </span>
                    )}
                    {step.severity !== undefined && (
                      <span className="text-[9px] px-1.5 py-0.5 rounded bg-rose-500/10 text-rose-400 border border-rose-500/20">
                        IDS Severity: {step.severity}
                      </span>
                    )}
                    {step.risk_score !== undefined && (
                      <span className="text-[9px] px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20">
                        Risk Score: {step.risk_score}/100
                      </span>
                    )}
                  </div>
                  {step.details && (
                    <span className="text-[11px] text-slate-400 block mt-1 leading-relaxed">
                      {step.details}
                    </span>
                  )}
                </div>

                <div className="font-mono text-[10px] text-slate-500 shrink-0 mt-2 sm:mt-0">
                  {formatStepTime(step.timestamp)}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
