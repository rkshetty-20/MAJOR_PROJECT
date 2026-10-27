import React, { useEffect, useState } from 'react';
import { ShieldAlert, ShieldCheck, Activity, Link as LinkIcon, Search, Server, Clock, User } from 'lucide-react';
import api from '../../api';

interface Props {
  incidentId: string;
  onAskChatbot?: (context: any, prompt: string) => void;
}

export const IncidentVisualization: React.FC<Props> = ({ incidentId }) => {
  const [incident, setIncident] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchIncident = async () => {
      try {
        const res = await api.get(`/api/incidents/${incidentId}`);
        setIncident(res.data);
      } catch (err) {
        console.error(err);
      } finally {
        setLoading(false);
      }
    };
    fetchIncident();
  }, [incidentId]);

  if (loading) return <div className="p-8 text-center text-slate-400">Loading incident...</div>;
  if (!incident) return <div className="p-8 text-center text-rose-400">Incident not found or could not be loaded.</div>;

  const events = incident.related_events || [];
  
  return (
    <div className="space-y-6 animate-fade-in w-full">
      {/* Overview */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="md:col-span-2 bg-slate-900 rounded-xl border border-slate-800 p-6">
          <div className="flex justify-between items-start mb-4">
            <div>
              <h3 className="text-xl font-bold text-white mb-2">{incident.title}</h3>
              <div className="flex gap-3 text-xs font-mono text-slate-400">
                <span className="flex items-center gap-1"><Search className="w-3 h-3" /> ID: {incident.id}</span>
                <span className="flex items-center gap-1"><Clock className="w-3 h-3" /> Created: {new Date(incident.created_at).toLocaleString()}</span>
              </div>
            </div>
            <div className={`px-3 py-1 rounded-full text-xs font-bold border ${
              incident.status === 'OPEN' ? 'bg-amber-500/10 text-amber-400 border-amber-500/20' : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
            }`}>
              {incident.status}
            </div>
          </div>
          <p className="text-sm text-slate-300">
            This incident correlates evidence across {incident.source_modules.length} modules: {incident.source_modules.join(', ')}
          </p>
        </div>
        
        <div className="bg-slate-900 rounded-xl border border-slate-800 p-6 flex flex-col justify-center items-center">
          <div className="text-xs font-bold text-slate-500 uppercase tracking-widest mb-2">Unified Risk Score</div>
          <div className={`text-4xl font-black ${
            incident.severity === 'CRITICAL' ? 'text-rose-500' : incident.severity === 'HIGH' ? 'text-amber-500' : 'text-emerald-500'
          }`}>
            {incident.risk_score}
          </div>
          <div className="text-sm font-bold text-slate-400 mt-1">{incident.severity}</div>
        </div>
      </div>

      {/* Relationship Graph / Timeline */}
      <div className="bg-slate-900 rounded-xl border border-slate-800 p-6">
        <h3 className="text-sm font-bold text-slate-300 uppercase tracking-wider mb-6 flex items-center gap-2">
          <Activity className="w-4 h-4 text-indigo-400" /> Correlated Event Timeline & Reasons
        </h3>
        {events.length === 0 ? (
          <p className="text-sm text-slate-400">No events attached to this incident yet.</p>
        ) : (
          <div className="relative pl-6 border-l-2 border-slate-800 space-y-8">
            {events.map((ev: any, idx: number) => (
              <div key={idx} className="relative">
                <div className="absolute -left-[31px] bg-slate-900 p-1 rounded-full border border-slate-700">
                  {ev.source_module === 'IDS' ? <Server className="w-4 h-4 text-indigo-400" /> :
                   ev.source_module === 'SecurityTelemetry' ? <Activity className="w-4 h-4 text-rose-400" /> :
                   <LinkIcon className="w-4 h-4 text-amber-400" />}
                </div>
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-xs font-mono text-slate-500">{new Date(ev.timestamp).toLocaleString()}</span>
                    <span className="text-xs font-bold px-2 py-0.5 rounded-full bg-slate-800 text-slate-300">{ev.event_type}</span>
                    {ev.correlation_reason && (
                      <span className="text-xs text-indigo-300 font-medium ml-2">Reason: {ev.correlation_reason}</span>
                    )}
                  </div>
                  <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 mt-2 text-sm text-slate-300">
                    <div className="grid grid-cols-2 gap-4">
                      {ev.source_ip && <div><span className="text-slate-500 text-xs">Source IP:</span> {ev.source_ip}</div>}
                      {ev.destination_ip && <div><span className="text-slate-500 text-xs">Dest IP:</span> {ev.destination_ip}</div>}
                      {ev.user_id && <div><span className="text-slate-500 text-xs">User/Target:</span> {ev.user_id}</div>}
                      {ev.domain && <div><span className="text-slate-500 text-xs">Domain:</span> {ev.domain}</div>}
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Analyst Feedback */}
      <div className="bg-slate-900 rounded-xl border border-slate-800 p-6">
         <h3 className="text-sm font-bold text-slate-300 uppercase tracking-wider mb-4 flex items-center gap-2">
          <User className="w-4 h-4 text-emerald-400" /> Analyst Feedback
        </h3>
        <p className="text-sm text-slate-400 mb-4">
          Provide your assessment. This will be recorded for audit purposes but does not automatically change model thresholds.
        </p>
        <div className="flex gap-4">
          <button 
            onClick={async () => { await api.post(`/api/incidents/${incidentId}/feedback`, { analyst_id: "soc_analyst", decision: "benign", rationale: "User confirmed" }); window.location.reload(); }}
            className="flex items-center gap-2 px-4 py-2 bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 rounded-lg text-sm font-bold transition-colors"
          >
            <ShieldCheck className="w-4 h-4" /> Mark Benign (Close)
          </button>
          <button 
            onClick={async () => { await api.post(`/api/incidents/${incidentId}/feedback`, { analyst_id: "soc_analyst", decision: "malicious", rationale: "Confirmed attack" }); window.location.reload(); }}
            className="flex items-center gap-2 px-4 py-2 bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border border-rose-500/30 rounded-lg text-sm font-bold transition-colors"
          >
            <ShieldAlert className="w-4 h-4" /> Confirm Malicious
          </button>
        </div>
        {incident.feedback && incident.feedback.length > 0 && (
          <div className="mt-6 space-y-3">
             {incident.feedback.map((fb: any, idx: number) => (
                <div key={idx} className="text-xs text-slate-400 p-3 bg-slate-950 border border-slate-800 rounded-lg">
                  <span className="font-bold text-white">{fb.analyst_id}</span> marked as <span className="text-indigo-400 uppercase">{fb.decision}</span> on {new Date(fb.created_at).toLocaleString()}
                </div>
             ))}
          </div>
        )}
      </div>
    </div>
  );
};
