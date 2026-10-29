import React, { useState, useEffect, useRef } from 'react';
import { 
  Play, Pause, SkipForward, SkipBack, RotateCcw, 
  Shield, Zap, Activity, Server, AlertTriangle, 
  Brain, Network, BookOpen, Search, ArrowRight, Database, 
  Code, Target, CheckCircle2, ChevronRight, 
  ActivitySquare, Layers
} from 'lucide-react';
import api from '../../api';
import { PortScanAttack, PortScanTelemetry, PortScanSuricata, PortScanFeatures, PortScanMLModel, PortScanDetection, PortScanRisk, readRiskTerms } from './PortScanVisuals';

interface AnatomyStage {
  id: string;
  label: string;
  type: 'concept' | 'telemetry' | 'processing' | 'ml' | 'detection' | 'risk';
  description: string;
  concept_text: string;
}

const PORT_SCAN_STAGES: AnatomyStage[] = [
  { id: 'attack', label: 'Attack Initiated', type: 'concept', description: 'Attacker probes multiple ports.', concept_text: 'A port scan probes multiple network ports on a host to discover which services may be reachable.' },
  { id: 'telemetry', label: 'Network Telemetry', type: 'telemetry', description: 'Raw packets observed.', concept_text: 'Local network interfaces observe the traffic patterns.' },
  { id: 'suricata', label: 'Suricata IDS', type: 'processing', description: 'IDS generates raw signatures.', concept_text: 'Suricata rules may generate low-level alerts.' },
  { id: 'feature_extraction', label: 'Feature Extraction', type: 'processing', description: 'Data transformed into ML features.', concept_text: 'Features like distinct_dest_ports and events_per_second are computed.' },
  { id: 'ml_model', label: 'Adaptive ML Model', type: 'ml', description: 'Active model evaluates features.', concept_text: 'The active Random Forest model predicts if this is a port scan.' },
  { id: 'detection', label: 'Detection Triggered', type: 'detection', description: 'System flags the event.', concept_text: 'A formal detection record is created.' },
  { id: 'risk', label: 'Risk Fusion', type: 'risk', description: 'Final risk score computed.', concept_text: 'ML confidence, severity, and context fuse into a risk score.' }
];

const STANDARD_STAGES: AnatomyStage[] = [
  { id: 'attack', label: 'Attack Initiated', type: 'concept', description: 'Attacker performs malicious action.', concept_text: 'The attacker attempts a known exploit or behavioral anomaly.' },
  { id: 'telemetry', label: 'System Telemetry', type: 'telemetry', description: 'Events logged in system.', concept_text: 'The system records authentication failures, endpoint changes, or network connections.' },
  { id: 'rule_engine', label: 'Rule Engine', type: 'processing', description: 'Deterministic rules evaluated.', concept_text: 'Pre-configured thresholds and correlation rules analyze the telemetry.' },
  { id: 'evidence', label: 'Evidence Chain', type: 'processing', description: 'Supporting data linked.', concept_text: 'The rule engine associates the triggering events as evidence.' },
  { id: 'detection', label: 'Detection Triggered', type: 'detection', description: 'System flags the event.', concept_text: 'A formal detection record is created based on the rule.' },
  { id: 'risk', label: 'Risk Fusion', type: 'risk', description: 'Final risk score computed.', concept_text: 'Severity, frequency, and contextual factors fuse into a risk score.' }
];

const PHISHING_STAGES: AnatomyStage[] = [
  { id: 'attack', label: 'Phishing URL Input', type: 'concept', description: 'Malicious link encountered.', concept_text: 'A user or system encounters a potentially malicious URL.' },
  { id: 'telemetry', label: 'URL Characteristics', type: 'telemetry', description: 'URL structure parsed.', concept_text: 'The URL is broken down into domain, path, and parameters.' },
  { id: 'rule_engine', label: 'Domain Analysis', type: 'processing', description: 'Checks against known patterns.', concept_text: 'The system checks for typosquatting, hidden chars, and known malicious indicators.' },
  { id: 'detection', label: 'Phishing Detection', type: 'detection', description: 'URL flagged as phishing.', concept_text: 'A formal phishing detection record is created.' },
  { id: 'risk', label: 'Risk Fusion', type: 'risk', description: 'Final risk score computed.', concept_text: 'The severity of the phishing indicator determines the risk.' }
];

const COMBINED_STAGES: AnatomyStage[] = [
  { id: 'attack', label: 'Concurrent Attacks', type: 'concept', description: 'Multiple attack vectors active.', concept_text: 'Attacker is simultaneously generating anomalous behaviors (e.g., brute force + new device + anomalous time).' },
  { id: 'telemetry', label: 'Independent Signals', type: 'telemetry', description: 'Multiple signals observed.', concept_text: 'The system logs independent authentication and endpoint anomalies.' },
  { id: 'processing', label: 'Signal Convergence', type: 'processing', description: 'Signals are aggregated.', concept_text: 'The rule engine identifies that these independent signals belong to the same session or actor.' },
  { id: 'evidence', label: 'Evidence Chain', type: 'processing', description: 'Supporting data linked.', concept_text: 'All related events are chained together as multi-signal evidence.' },
  { id: 'detection', label: 'Multi-Signal Detection', type: 'detection', description: 'System flags the compound event.', concept_text: 'A formal combined detection record is created.' },
  { id: 'risk', label: 'Risk Fusion', type: 'risk', description: 'Final risk score computed.', concept_text: 'The compounded severity of multiple signals results in a HIGH or CRITICAL risk score.' }
];

const SCENARIOS = [
  { id: 'port_scan', name: 'Port Scan', stages: PORT_SCAN_STAGES, category: 'NETWORK INTRUSION' },
  { id: 'brute_force', name: 'Brute Force Login', stages: STANDARD_STAGES, category: 'AUTHENTICATION' },
  { id: 'credential_stuffing', name: 'Credential Stuffing', stages: STANDARD_STAGES, category: 'AUTHENTICATION' },
  { id: 'suspicious_login', name: 'Suspicious Login', stages: STANDARD_STAGES, category: 'AUTHENTICATION' },
  { id: 'new_device', name: 'New Device Login', stages: STANDARD_STAGES, category: 'AUTHENTICATION' },
  { id: 'anomalous_login_time', name: 'Anomalous Login Time', stages: STANDARD_STAGES, category: 'AUTHENTICATION' },
  { id: 'impossible_travel', name: 'Impossible Travel', stages: STANDARD_STAGES, category: 'AUTHENTICATION' },
  { id: 'multiple_failed_logins', name: 'Multiple Failed Logins', stages: STANDARD_STAGES, category: 'AUTHENTICATION' },
  { id: 'phishing_url', name: 'Phishing URL', stages: PHISHING_STAGES, category: 'PHISHING' },
  { id: 'combined_multi_signal', name: 'Combined Multi-Signal', stages: COMBINED_STAGES, category: 'COMBINED' }
];

const getStageMetadata = (stageId: string) => {
  const meta: Record<string, any> = {
    'attack': {
      purpose: "Initialize synthetic threat actor behavior.",
      why: "Sets the baseline context for the investigation.",
      receives: "User configuration (intensity, count).",
      produces: "Targeted malicious actions.",
      next: "System sensors observe the actions."
    },
    'telemetry': {
      purpose: "Capture and normalize raw observables.",
      why: "Provides the foundational evidence required for detection.",
      receives: "Raw packets, logs, or user inputs.",
      produces: "Structured SecurityEvent records.",
      next: "Analysis engines process the events."
    },
    'suricata': {
      purpose: "Network Intrusion Detection System processing.",
      why: "Identifies known malicious network signatures.",
      receives: "Network Telemetry.",
      produces: "Suricata alerts and signatures.",
      next: "Feature extraction aggregates the alerts."
    },
    'feature_extraction': {
      purpose: "Transform raw telemetry into ML-ready features.",
      why: "Models cannot process raw events directly; they require mathematical representations.",
      receives: "Batches of SecurityEvents and Suricata alerts.",
      produces: "Feature vectors (e.g., event frequencies, distinct port counts).",
      next: "Inference by the Adaptive ML Model."
    },
    'ml_model': {
      purpose: "Evaluate features using trained machine learning.",
      why: "Detects novel or complex patterns that evade static rules.",
      receives: "Feature vectors.",
      produces: "Classification label and confidence score.",
      next: "Detection record is created if confidence > threshold."
    },
    'rule_engine': {
      purpose: "Apply deterministic correlation logic.",
      why: "Provides zero-false-positive detection for known TTPs.",
      receives: "Structured SecurityEvents.",
      produces: "Trigger conditions met or failed.",
      next: "Evidence chain is assembled."
    },
    'processing': {
      purpose: "Aggregate disparate signals.",
      why: "Multi-signal attacks require grouping by session or entity.",
      receives: "Independent telemetry signals.",
      produces: "Correlated signal group.",
      next: "Evidence chain."
    },
    'evidence': {
      purpose: "Link supporting telemetry to a pending detection.",
      why: "Enables SOC analysts to verify the detection logic.",
      receives: "Trigger conditions and source events.",
      produces: "Evidence payload.",
      next: "Formal detection creation."
    },
    'detection': {
      purpose: "Formalize the threat identification.",
      why: "Creates an actionable alert for the SOC.",
      receives: "Engine output (Rule or ML).",
      produces: "Detection record with ID and explanation.",
      next: "Risk scoring."
    },
    'risk': {
      purpose: "Prioritize the detection.",
      why: "SOCs suffer from alert fatigue; risk scoring highlights critical threats.",
      receives: "Detection records, severity, contextual penalties/bonuses.",
      produces: "Risk score (0-100) and Severity Band.",
      next: "SOC Mitigation."
    }
  };
  return meta[stageId] || meta['attack'];
};

interface AttackAnatomyProps {
  activeSimulationResult?: any | null;
  onAskChatbot: (context: any, prompt: string) => void;
  onOpenInvestigation: (detectionId: number) => void;
}

export const AttackAnatomy: React.FC<AttackAnatomyProps> = ({
  activeSimulationResult,
  onAskChatbot,
  onOpenInvestigation
}) => {
  const [mode, setMode] = useState<'learn' | 'investigate'>('learn');
  const [selectedScenarioId, setSelectedScenarioId] = useState('port_scan');
  
  const [currentStageIdx, setCurrentStageIdx] = useState(0);
  const [isPlaying, setIsPlaying] = useState(false);
  
  const [realData, setRealData] = useState<any>(null);
  const [timelineData, setTimelineData] = useState<any[] | null>(null);
  const [eventsData, setEventsData] = useState<any[] | null>(null);
  
  const timerRef = useRef<NodeJS.Timeout | null>(null);

  const scenario = SCENARIOS.find(s => s.id === selectedScenarioId) || SCENARIOS[0];
  const stages = scenario.stages;
  
  useEffect(() => {
    if (mode === 'investigate' && activeSimulationResult) {
      if (activeSimulationResult.scenario === selectedScenarioId) {
        const loadExtraData = async () => {
          let extra = { ...activeSimulationResult };
          try {
            if (selectedScenarioId === 'port_scan') {
              const res = await api.get('/api/ml/status');
              extra.adaptive_ml = res.data;
            }
            const tlRes = await api.get(`/api/simulation/${extra.simulation_id}/timeline`);
            setTimelineData(tlRes.data);
             
            const evRes = await api.get(`/api/events?simulation_id=${extra.simulation_id}`);
            setEventsData(evRes.data);
          } catch (e) {
            console.error("Failed to load extra data", e);
          }
          setRealData(extra);
        };
        loadExtraData();
      } else {
        setRealData(null);
        setTimelineData(null);
        setEventsData(null);
      }
    } else {
      setRealData(null);
      setTimelineData(null);
      setEventsData(null);
    }
  }, [mode, activeSimulationResult, selectedScenarioId]);

  useEffect(() => {
    if (isPlaying) {
      timerRef.current = setInterval(() => {
        setCurrentStageIdx(prev => {
          if (prev >= stages.length - 1) {
            setIsPlaying(false);
            return prev;
          }
          return prev + 1;
        });
      }, 1500);
    } else if (timerRef.current) {
      clearInterval(timerRef.current);
    }
    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [isPlaying, stages.length]);

  const handlePlayPause = () => {
    if (currentStageIdx >= stages.length - 1 && !isPlaying) {
      setCurrentStageIdx(0);
    }
    setIsPlaying(!isPlaying);
  };
  
  const currentStage = stages[currentStageIdx];
  const isPhishing = scenario.id === 'phishing_url';
  
  const renderNode = (stage: AnatomyStage, idx: number) => {
    const isActive = idx === currentStageIdx;
    const isPast = idx < currentStageIdx;
    
    let colorClass = "border-slate-800 bg-slate-900 text-slate-500 shadow-none";
    if (isActive) {
      colorClass = isPhishing 
        ? "border-amber-500 bg-amber-500/20 text-amber-300 ring-4 ring-amber-500/30 shadow-[0_0_15px_rgba(245,158,11,0.3)] scale-110" 
        : "border-emerald-500 bg-emerald-500/20 text-emerald-300 ring-4 ring-emerald-500/30 shadow-[0_0_15px_rgba(16,185,129,0.3)] scale-110";
    } else if (isPast) {
      colorClass = isPhishing
        ? "border-amber-600 bg-amber-500/10 text-amber-600"
        : "border-emerald-600 bg-emerald-500/10 text-emerald-600";
    }

    return (
      <div 
        key={stage.id} 
        className="flex flex-col items-center flex-1 relative min-w-[130px] group transition-all duration-300 cursor-pointer"
        onClick={() => {
            setCurrentStageIdx(idx);
            setIsPlaying(false);
        }}
        tabIndex={0}
        onKeyDown={(e) => {
            if (e.key === 'Enter' || e.key === ' ') {
                setCurrentStageIdx(idx);
                setIsPlaying(false);
            }
        }}
        aria-label={`Select stage ${stage.label}`}
      >
        {idx < stages.length - 1 && (
          <div className="absolute top-6 left-[50%] w-full h-1 flex items-center justify-center -z-10 px-4">
             <div className={`w-full h-[2px] ${isPast ? (isPhishing ? 'bg-amber-600' : 'bg-emerald-600') : 'bg-slate-800'} transition-colors duration-500`} />
             <div className={`w-0 h-0 border-t-4 border-t-transparent border-b-4 border-b-transparent border-l-4 ${isPast ? (isPhishing ? 'border-l-amber-600' : 'border-l-emerald-600') : 'border-l-slate-800'} absolute right-2`} />
          </div>
        )}
        
        <div className={`w-12 h-12 rounded-xl border-2 flex items-center justify-center z-10 transition-all duration-500 ${colorClass}`}>
          {stage.type === 'concept' && <Shield className="w-5 h-5" />}
          {stage.type === 'telemetry' && <Activity className="w-5 h-5" />}
          {stage.type === 'processing' && <Server className="w-5 h-5" />}
          {stage.type === 'ml' && <Brain className="w-5 h-5" />}
          {stage.type === 'detection' && <AlertTriangle className="w-5 h-5" />}
          {stage.type === 'risk' && <Zap className="w-5 h-5" />}
        </div>
        
        <div className="mt-4 text-center px-1">
          <p className={`text-[10px] font-bold uppercase tracking-widest transition-colors duration-300 ${isActive ? 'text-white' : (isPast ? 'text-slate-400' : 'text-slate-600')}`}>
            {stage.label}
          </p>
        </div>
      </div>
    );
  };

  const UnavailableBadge = ({ msg = "No investigation data available for this scenario." }) => (
    <div className="flex flex-col items-center justify-center h-full min-h-[200px] text-center border border-dashed border-slate-700 bg-slate-900/50 rounded-xl p-6">
       <ActivitySquare className="w-8 h-8 text-slate-600 mb-3" />
       <span className="text-sm font-semibold text-slate-400 uppercase tracking-widest bg-slate-800 px-3 py-1 rounded">Unavailable</span>
       <p className="text-xs text-slate-400 mt-4 max-w-xs font-semibold">{msg}</p>
       <p className="text-[10px] text-slate-500 mt-2 max-w-xs">The selected scenario has no matching simulation evidence yet. Switch to Learn Mode or run a simulation.</p>
       
       <button
         type="button"
         onClick={() => {
           const el = document.getElementById('attack-simulation-section');
           if (el) {
             el.scrollIntoView({ behavior: 'smooth' });
             const select = document.getElementById('simulation-scenario-select') as HTMLSelectElement;
             if (select && select.value !== selectedScenarioId) {
                if (select instanceof HTMLSelectElement) {
                   const nativeInputValueSetter = Object.getOwnPropertyDescriptor(window.HTMLSelectElement.prototype, "value")?.set;
                   if (nativeInputValueSetter) {
                      nativeInputValueSetter.call(select, selectedScenarioId);
                      select.dispatchEvent(new Event('change', { bubbles: true }));
                   }
                } else {
                   // Fallback for tests
                   (select as any).value = selectedScenarioId;
                   (select as any).dispatchEvent(new Event('change', { bubbles: true }));
                }
             }
           }
         }}
         className="mt-6 px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-bold rounded-lg transition-colors cursor-pointer shadow-lg shadow-indigo-900/20"
       >
         Go to Simulation Handler
       </button>
    </div>
  );

  const LabelProvenence = ({ type }: { type: 'Verified Telemetry' | 'Educational Concept' | 'Model Metadata' | 'Derived from Telemetry' }) => (
    <div className="flex items-center gap-1.5 mb-4 border-b border-slate-800/80 pb-2">
      {type === 'Verified Telemetry' && <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />}
      {type === 'Educational Concept' && <BookOpen className="w-3.5 h-3.5 text-indigo-400" />}
      {type === 'Model Metadata' && <Layers className="w-3.5 h-3.5 text-sky-400" />}
      {type === 'Derived from Telemetry' && <ActivitySquare className="w-3.5 h-3.5 text-indigo-400" />}
      <span className="text-[10px] font-bold uppercase tracking-widest text-slate-400">{type}</span>
    </div>
  );

  const renderLearnVisualization = (stage: AnatomyStage) => {
    if (selectedScenarioId === 'port_scan') {
      const props = { isLearnMode: true };
      return (
        <div className="flex flex-col h-full">
          <LabelProvenence type="Educational Concept" />
          <div className="flex-1 mt-4">
            {stage.id === 'attack' && <PortScanAttack {...props} />}
            {stage.id === 'telemetry' && <PortScanTelemetry {...props} />}
            {stage.id === 'suricata' && <PortScanSuricata {...props} />}
            {stage.id === 'feature_extraction' && <PortScanFeatures {...props} />}
            {stage.id === 'ml_model' && <PortScanMLModel {...props} />}
            {stage.id === 'detection' && <PortScanDetection {...props} />}
            {stage.id === 'risk' && <PortScanRisk {...props} />}
          </div>
        </div>
      );
    }

    return (
      <div className="flex flex-col h-full">
         <LabelProvenence type="Educational Concept" />
         <div className="flex-1 flex flex-col items-center justify-center space-y-6">
            <div className="bg-slate-900 p-6 rounded-xl border border-slate-700 w-full max-w-md shadow-lg shadow-black/50">
               <h4 className="text-white text-sm font-bold mb-2 flex items-center gap-2">
                 <Shield className="w-4 h-4 text-indigo-400" />
                 Mechanism Explanation
               </h4>
               <p className="text-slate-300 text-xs leading-relaxed mb-4">{stage.concept_text}</p>
               
               <div className="bg-slate-950 p-4 rounded border border-slate-800">
                 <span className="text-[10px] font-mono text-slate-500 block mb-2 uppercase">Illustrative Example</span>
                 <div className="flex items-center justify-between gap-2 text-xs">
                    <div className="flex-1 bg-slate-900 p-2 rounded border border-slate-800 text-center text-slate-300">Input</div>
                    <ArrowRight className="w-4 h-4 text-slate-600" />
                    <div className="flex-1 bg-indigo-500/10 p-2 rounded border border-indigo-500/20 text-center text-indigo-300 font-medium">Processing</div>
                    <ArrowRight className="w-4 h-4 text-slate-600" />
                    <div className="flex-1 bg-slate-900 p-2 rounded border border-slate-800 text-center text-slate-300">Output</div>
                 </div>
               </div>
            </div>
         </div>
      </div>
    );
  };

  const renderLiveVisualization = (stage: AnatomyStage) => {
    if (!realData) return <UnavailableBadge msg="No investigation data available for this scenario." />;

    if (selectedScenarioId === 'port_scan') {
      const props = { isLearnMode: false, liveData: { ...realData, timelineData, eventsData } };
      return (
        <div className="flex flex-col h-full">
          <LabelProvenence type={stage.id === 'ml_model' ? "Model Metadata" : "Verified Telemetry"} />
          <div className="flex-1 mt-4">
            {stage.id === 'attack' && <PortScanAttack {...props} />}
            {stage.id === 'telemetry' && <PortScanTelemetry {...props} />}
            {stage.id === 'suricata' && <PortScanSuricata {...props} />}
            {stage.id === 'feature_extraction' && <PortScanFeatures {...props} />}
            {stage.id === 'ml_model' && <PortScanMLModel {...props} />}
            {stage.id === 'detection' && <PortScanDetection {...props} />}
            {stage.id === 'risk' && <PortScanRisk {...props} />}
          </div>
        </div>
      );
    }

    switch(stage.id) {
      case 'telemetry':
        if (!eventsData || eventsData.length === 0) return <UnavailableBadge />;
        if (selectedScenarioId === 'port_scan') {
           const src = eventsData[0].source;
           const target = eventsData[0].target;
           const uniquePorts = new Set(eventsData.map(e => e.payload?.dest_port)).size;
           return (
             <div className="flex flex-col h-full">
               <LabelProvenence type="Verified Telemetry" />
               <div className="flex-1 flex items-center justify-center p-4">
                 <div className="flex items-center gap-4 w-full max-w-2xl bg-slate-900 p-6 rounded-xl border border-slate-800">
                    <div className="text-center flex-1">
                      <div className="w-16 h-16 bg-slate-950 rounded-full border-2 border-slate-700 flex items-center justify-center mx-auto mb-2 shadow-lg shadow-black">
                         <Network className="w-8 h-8 text-slate-400" />
                      </div>
                      <div className="text-xs font-mono text-slate-300">{src}</div>
                      <div className="text-[10px] text-slate-500">Source Attacker</div>
                    </div>
                    
                    <div className="flex-1 flex flex-col items-center">
                       <div className="text-[10px] font-bold text-emerald-400 mb-1">{eventsData.length} packets</div>
                       <div className="w-full h-0.5 bg-emerald-500/50 relative overflow-hidden">
                          <div className="absolute top-0 left-0 h-full bg-emerald-400 w-1/3 animate-[slide_1s_infinite]" style={{ animation: "slide 1s linear infinite" }} />
                       </div>
                       <div className="text-[10px] text-slate-500 mt-1">{uniquePorts} distinct ports</div>
                    </div>
                    
                    <div className="text-center flex-1">
                      <div className="w-16 h-16 bg-slate-950 rounded-full border-2 border-emerald-500/50 flex items-center justify-center mx-auto mb-2 shadow-[0_0_15px_rgba(16,185,129,0.15)]">
                         <Server className="w-8 h-8 text-emerald-400" />
                      </div>
                      <div className="text-xs font-mono text-emerald-300">{target}</div>
                      <div className="text-[10px] text-slate-500">Target Host</div>
                    </div>
                 </div>
               </div>
               <style dangerouslySetInnerHTML={{__html: `
                 @keyframes slide {
                    0% { transform: translateX(-100%); }
                    100% { transform: translateX(300%); }
                 }
               `}} />
             </div>
           );
        } else if (selectedScenarioId === 'phishing_url') {
           const ev = eventsData.find(e => e.event_type === 'phishing_url');
           if (!ev || !ev.payload) return <UnavailableBadge />;
           return (
             <div className="flex flex-col h-full">
               <LabelProvenence type="Verified Telemetry" />
               <div className="bg-slate-900 rounded-xl border border-slate-800 p-5 mt-4">
                  <div className="text-xs font-bold text-slate-400 mb-3">URL Characteristics Parsed:</div>
                  <div className="grid grid-cols-2 gap-4">
                     <div className="bg-slate-950 p-3 rounded border border-slate-800">
                        <span className="text-[10px] text-slate-500 block mb-1">Target URL</span>
                        <span className="text-xs text-amber-400 font-mono break-all">{ev.payload.url || ev.target}</span>
                     </div>
                     <div className="bg-slate-950 p-3 rounded border border-slate-800">
                        <span className="text-[10px] text-slate-500 block mb-1">Domain Age (Days)</span>
                        <span className="text-sm text-white font-mono">{ev.payload.domain_age_days ?? 'Unknown'}</span>
                     </div>
                     <div className="bg-slate-950 p-3 rounded border border-slate-800 col-span-2">
                        <span className="text-[10px] text-slate-500 block mb-1">Suspicious Keywords</span>
                        <div className="flex gap-2 mt-1">
                          {(ev.payload.suspicious_keywords || []).map((k: string) => (
                             <span key={k} className="px-2 py-0.5 bg-rose-500/10 border border-rose-500/20 text-rose-400 rounded text-xs">{k}</span>
                          ))}
                        </div>
                     </div>
                  </div>
               </div>
             </div>
           );
        } else if (selectedScenarioId === 'combined_multi_signal') {
           // Independently observed signals as separate branches
           const distinctTypes = Array.from(new Set(eventsData.map(e => e.event_type)));
           return (
             <div className="flex flex-col h-full">
               <LabelProvenence type="Verified Telemetry" />
               <div className="flex flex-col gap-3 mt-4">
                 {distinctTypes.map(t => {
                   const count = eventsData.filter(e => e.event_type === t).length;
                   return (
                     <div key={t} className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex items-center justify-between">
                       <div className="flex items-center gap-3">
                          <Activity className="w-5 h-5 text-indigo-400" />
                          <span className="text-sm font-bold text-white capitalize">{t.replace(/_/g, ' ')}</span>
                       </div>
                       <span className="text-xs font-mono bg-indigo-500/20 text-indigo-300 px-2 py-1 rounded">Count: {count}</span>
                     </div>
                   );
                 })}
               </div>
             </div>
           );
        } else {
           return (
             <div className="flex flex-col h-full">
               <LabelProvenence type="Verified Telemetry" />
               <div className="overflow-x-auto mt-4 rounded-xl border border-slate-800">
                 <table className="w-full text-left text-xs">
                    <thead className="bg-slate-900 border-b border-slate-800 text-slate-400">
                      <tr>
                        <th className="p-3 font-semibold">Time</th>
                        <th className="p-3 font-semibold">Type</th>
                        <th className="p-3 font-semibold">Source</th>
                        <th className="p-3 font-semibold">Target</th>
                      </tr>
                    </thead>
                    <tbody className="bg-slate-950/50 divide-y divide-slate-800/50">
                      {eventsData.slice(0, 8).map(e => (
                        <tr key={e.id}>
                          <td className="p-3 font-mono text-[10px] text-slate-500">{new Date(e.timestamp).toLocaleTimeString()}</td>
                          <td className="p-3 text-slate-300">{e.event_type}</td>
                          <td className="p-3 font-mono text-[10px]">{e.source}</td>
                          <td className="p-3 font-mono text-[10px]">{e.target}</td>
                        </tr>
                      ))}
                    </tbody>
                 </table>
                 {eventsData.length > 8 && <div className="p-2 text-center text-[10px] text-slate-500 bg-slate-900">+ {eventsData.length - 8} more events</div>}
               </div>
             </div>
           );
        }

      case 'suricata':
        if (!timelineData) return <UnavailableBadge />;
        const suricataEvents = timelineData.filter(t => t.step === 'suricata_event_generated');
        if (suricataEvents.length === 0) return <UnavailableBadge msg="No Suricata alerts generated for this simulation." />;
        
        return (
          <div className="flex flex-col h-full">
             <LabelProvenence type="Verified Telemetry" />
             <div className="bg-slate-900 rounded-xl border border-slate-800 p-5 mt-4">
               <div className="text-xs font-bold text-slate-400 mb-4 uppercase tracking-widest flex items-center gap-2">
                 <Target className="w-4 h-4" /> IDS Signatures Triggered
               </div>
               <div className="space-y-3 max-h-64 overflow-y-auto pr-2 custom-scrollbar">
                 {suricataEvents.slice(0, 5).map(se => (
                   <div key={se.related_id} className="bg-slate-950 border border-slate-800 rounded p-3">
                      <div className="flex justify-between items-center mb-2">
                        <span className="text-[10px] font-mono text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">{se.label}</span>
                        <span className="text-[10px] text-rose-400">Sev: {se.severity}</span>
                      </div>
                      <div className="text-xs text-slate-300 font-mono break-all">{se.details}</div>
                   </div>
                 ))}
                 {suricataEvents.length > 5 && <div className="text-center text-xs text-slate-500 pt-2">...and {suricataEvents.length - 5} more</div>}
               </div>
             </div>
          </div>
        );

      case 'feature_extraction':
        const mlDetExt = realData?.detections?.find((d: any) => d.source.toLowerCase() === 'ml');
        if (!mlDetExt || !mlDetExt.explanation) return <UnavailableBadge msg="No ML features persisted in the current telemetry." />;
        
        // Try parsing distinct_dest_ports etc from explanation. 
        // e.g. "Triggered by ML model prediction... (distinct_dest_ports > threshold)"
        // But actual extraction values are in DB not in response directly, we just show explanation.
        return (
          <div className="flex flex-col h-full">
            <LabelProvenence type="Derived from Telemetry" />
            <div className="flex items-center gap-6 mt-6">
               <div className="flex-1 bg-slate-900 p-5 rounded-xl border border-slate-700">
                  <div className="text-[10px] font-bold text-slate-400 uppercase mb-3">Aggregated Feature Vector</div>
                  <div className="space-y-3">
                     <div className="flex justify-between border-b border-slate-800 pb-2">
                       <span className="text-xs text-slate-300">distinct_dest_ports</span>
                       <span className="text-xs font-mono text-indigo-400">Calculated</span>
                     </div>
                     <div className="flex justify-between border-b border-slate-800 pb-2">
                       <span className="text-xs text-slate-300">events_per_second</span>
                       <span className="text-xs font-mono text-indigo-400">Calculated</span>
                     </div>
                     <div className="flex justify-between pb-2">
                       <span className="text-xs text-slate-300">protocol_diversity</span>
                       <span className="text-xs font-mono text-indigo-400">Calculated</span>
                     </div>
                  </div>
               </div>
               <ArrowRight className="w-6 h-6 text-slate-600 shrink-0" />
               <div className="flex-1 bg-indigo-500/10 p-5 rounded-xl border border-indigo-500/30 text-center">
                  <Brain className="w-8 h-8 text-indigo-400 mx-auto mb-2" />
                  <div className="text-xs font-medium text-indigo-300">Ready for ML Inference</div>
                  <div className="text-[10px] text-slate-400 mt-2 line-clamp-3">{mlDetExt.explanation}</div>
               </div>
            </div>
          </div>
        );

      case 'ml_model':
        const mlDet = realData?.detections?.find((d: any) => d.source.toLowerCase() === 'ml');
        if (!mlDet) return <UnavailableBadge msg="No ML detection triggered for this simulation." />;
        return (
          <div className="flex flex-col h-full">
             <LabelProvenence type="Model Metadata" />
             <div className="grid grid-cols-2 gap-4 mt-4">
                <div className="bg-slate-900 rounded-xl border border-slate-700 p-5 col-span-2 sm:col-span-1">
                   <div className="text-[10px] font-bold text-slate-400 uppercase mb-3 flex items-center gap-1.5"><Database className="w-3.5 h-3.5"/> Global Model Info</div>
                   <div className="space-y-2">
                      <div><span className="text-xs text-slate-500">Algorithm:</span> <span className="text-xs text-slate-200">Random Forest</span></div>
                      <div><span className="text-xs text-slate-500">Version:</span> <span className="text-xs font-mono text-emerald-400">{realData.adaptive_ml?.current_version || 'v1.0.0'}</span></div>
                      <div><span className="text-xs text-slate-500">Scope:</span> <span className="text-xs text-slate-200">Port Scan Detection</span></div>
                   </div>
                </div>
                <div className="bg-indigo-500/10 rounded-xl border border-indigo-500/30 p-5 col-span-2 sm:col-span-1 flex flex-col justify-center">
                   <div className="text-[10px] font-bold text-indigo-400 uppercase mb-2">Inference Result</div>
                   <div className="text-2xl font-black text-white">{mlDet.label}</div>
                   <div className="text-xs text-indigo-300 mt-1">Confidence: {(mlDet.confidence * 100).toFixed(1)}%</div>
                </div>
             </div>
          </div>
        );

      case 'rule_engine':
        if (!realData?.triggered_rules?.length) return <UnavailableBadge msg="No deterministic rules triggered." />;
        return (
          <div className="flex flex-col h-full">
            <LabelProvenence type="Verified Telemetry" />
            <div className="mt-4 bg-slate-900 rounded-xl border border-slate-700 p-5">
               <div className="text-[10px] font-bold text-slate-400 uppercase mb-4">Evaluated Rules Triggered</div>
               <div className="space-y-3">
                 {realData.triggered_rules.map((rule: string) => (
                    <div key={rule} className="flex items-center justify-between p-3 bg-slate-950 border border-slate-800 rounded text-sm font-mono text-emerald-400">
                       <div className="flex items-center gap-2"><Code className="w-4 h-4"/> {rule}</div>
                       <CheckCircle2 className="w-4 h-4 text-emerald-500" />
                    </div>
                 ))}
               </div>
            </div>
          </div>
        );

      case 'evidence':
      case 'processing': // for combined multi-signal
        if (!eventsData || eventsData.length === 0) return <UnavailableBadge />;
        return (
          <div className="flex flex-col h-full">
            <LabelProvenence type="Verified Telemetry" />
            <div className="mt-4 bg-slate-900 rounded-xl border border-slate-700 p-5 h-full flex flex-col justify-center text-center">
               <Layers className="w-10 h-10 text-indigo-400 mx-auto mb-3" />
               <h4 className="text-white font-bold mb-1">Evidence Chain Assembled</h4>
               <p className="text-slate-400 text-xs mb-4">All {eventsData.length} related events have been correlated under Session ID {realData.session_id}.</p>
               <div className="inline-block mx-auto bg-slate-950 px-4 py-2 rounded border border-slate-800 font-mono text-xs text-slate-300">
                  correlation_key: session_{realData.session_id}
               </div>
            </div>
          </div>
        );

      case 'detection':
        const det = realData?.detections?.[0];
        if (!det) return <UnavailableBadge msg="No detection records found." />;
        return (
          <div className="flex flex-col h-full">
             <LabelProvenence type="Verified Telemetry" />
             <div className="mt-4 bg-rose-500/10 rounded-xl border border-rose-500/30 p-5 flex-1 flex flex-col justify-center relative overflow-hidden">
                <AlertTriangle className="w-32 h-32 text-rose-500/10 absolute -right-4 -bottom-4 z-0" />
                <div className="relative z-10">
                   <div className="text-[10px] font-bold text-rose-400 uppercase mb-1">Detection Record #{det.id}</div>
                   <h3 className="text-xl font-black text-rose-300 mb-2">{det.label}</h3>
                   <div className="flex items-center gap-3 mb-4">
                      <span className="text-[10px] px-2 py-0.5 rounded bg-rose-500/20 text-rose-200 border border-rose-500/30 uppercase">Source: {det.source}</span>
                      <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">Confidence: {(det.confidence * 100).toFixed(1)}%</span>
                   </div>
                   <div className="text-xs text-rose-200/80 bg-rose-950/50 p-3 rounded border border-rose-500/20 leading-relaxed">
                     <span className="font-bold block mb-1">Evidence Summary:</span>
                     {det.explanation}
                   </div>
                </div>
             </div>
          </div>
        );

      case 'risk':
        if (!realData?.risk) return <UnavailableBadge msg="No risk score calculated." />;
        const { score, band, contributing_factors } = realData.risk;
        return (
          <div className="flex flex-col h-full">
             <LabelProvenence type="Verified Telemetry" />
             <div className="mt-4 grid grid-cols-2 gap-4 h-full">
                <div className="col-span-2 sm:col-span-1 bg-slate-900 rounded-xl border border-slate-700 p-5 flex flex-col items-center justify-center">
                   <div className="text-[10px] font-bold text-slate-400 uppercase mb-3">Final Risk Fusion</div>
                   <div className="text-4xl font-black text-white mb-1">{score}<span className="text-lg text-slate-500">/100</span></div>
                   <div className={`text-sm font-bold px-3 py-1 rounded-full uppercase mt-2 ${
                     band.toLowerCase() === 'critical' ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30' :
                     band.toLowerCase() === 'high' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' :
                     band.toLowerCase() === 'medium' ? 'bg-sky-500/20 text-sky-400 border border-sky-500/30' :
                     'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                   }`}>{band}</div>
                </div>
                
                <div className="col-span-2 sm:col-span-1 bg-slate-900 rounded-xl border border-slate-700 p-5">
                   <div className="text-[10px] font-bold text-slate-400 uppercase mb-3">Contributing Factors</div>
                   {readRiskTerms(contributing_factors).length > 0 ? (
                     <div className="space-y-2">
                        {readRiskTerms(contributing_factors).map(([k, v]) => (
                           <div key={k} className="flex justify-between items-center text-xs">
                              <span className="text-slate-300 capitalize">{k.replace(/_/g, ' ')}</span>
                              <span className="font-mono text-indigo-400">+{v}</span>
                           </div>
                        ))}
                     </div>
                   ) : (
                     <p className="text-xs text-slate-500 italic">No specific factor breakdown provided by the backend.</p>
                   )}
                </div>
             </div>
          </div>
        );

      case 'attack':
        return (
          <div className="flex flex-col h-full">
            <LabelProvenence type="Educational Concept" />
            <div className="flex-1 flex items-center justify-center">
               <div className="text-center bg-slate-900 p-6 rounded-xl border border-slate-800">
                  <Shield className="w-12 h-12 text-slate-500 mx-auto mb-4" />
                  <h3 className="text-white font-bold mb-2">Simulated Attack Initiated</h3>
                  <p className="text-slate-400 text-xs">The synthetic threat actor has been configured and executes the payload.</p>
               </div>
            </div>
          </div>
        );

      default:
        return <UnavailableBadge />;
    }
  };

  const renderStageWorkspace = () => {
    const stage = currentStage;
    const meta = getStageMetadata(stage.id);
    return (
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Stage Overview Panel (A) */}
        <div className="col-span-1 bg-slate-950/60 border border-slate-800 rounded-xl p-6 shadow-xl">
           <div className="flex items-center gap-3 mb-6 pb-4 border-b border-slate-800/80">
              <div className="bg-indigo-500/10 border border-indigo-500/20 text-indigo-400 px-2.5 py-1 rounded-md text-[10px] font-black tracking-widest uppercase shrink-0">
                Stage {currentStageIdx + 1}
              </div>
              <h3 className="text-base font-bold text-white">{stage.label}</h3>
           </div>
           
           <div className="space-y-5 text-sm">
              <div>
                 <div className="text-xs font-semibold text-slate-400 mb-1">Purpose</div>
                 <div className="text-slate-300 leading-relaxed text-sm">{meta.purpose} {meta.why}</div>
              </div>
              <div className="bg-slate-900 p-3 rounded-lg border border-slate-800">
                 <div className="flex items-start gap-2 mb-2">
                    <ArrowRight className="w-4 h-4 text-emerald-500 mt-0.5 shrink-0" />
                    <div>
                      <div className="text-xs font-semibold text-slate-400">Receives</div>
                      <div className="text-emerald-400/90 text-xs">{meta.receives}</div>
                    </div>
                 </div>
                 <div className="flex items-start gap-2">
                    <ArrowRight className="w-4 h-4 text-amber-500 mt-0.5 shrink-0" />
                    <div>
                      <div className="text-xs font-semibold text-slate-400">Produces</div>
                      <div className="text-amber-400/90 text-xs">{meta.produces}</div>
                    </div>
                 </div>
              </div>
              <div>
                 <div className="text-xs font-semibold text-slate-400 mb-1">Next phase</div>
                 <div className="text-slate-400 text-xs flex items-center gap-1.5"><ChevronRight className="w-3.5 h-3.5"/> {meta.next}</div>
              </div>
           </div>
        </div>

        {/* Internal processing visualization Panel (B) */}
        <div className="col-span-1 lg:col-span-2 bg-slate-950/80 border border-slate-800 rounded-xl p-6 shadow-xl relative min-h-[400px]">
           {mode === 'learn' ? renderLearnVisualization(stage) : renderLiveVisualization(stage)}
           
           {/* Investigation Actions (only in Live mode on detection stage) */}
           {mode === 'investigate' && currentStage.type === 'detection' && realData?.detections?.[0]?.id && (
             <div className="absolute bottom-6 right-6 flex gap-2">
               <button 
                 onClick={() => onOpenInvestigation(realData.detections[0].id)}
                 className="bg-indigo-500/20 hover:bg-indigo-500/30 text-indigo-300 text-xs font-bold py-2 px-4 rounded border border-indigo-500/30 transition-colors shadow-lg"
               >
                 Open Investigation
               </button>
               <button 
                 onClick={() => onAskChatbot({ type: 'detection', detection_id: realData.detections[0].id }, "Why was this detected?")}
                 className="bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-bold py-2 px-4 rounded border border-slate-700 transition-colors shadow-lg flex items-center gap-1.5"
               >
                 Ask Copilot
               </button>
             </div>
           )}
        </div>
      </div>
    );
  };

  return (
    <div className="w-full bg-[#020617] border border-slate-800 rounded-2xl shadow-2xl overflow-hidden mt-8">
      {/* Header */}
      <div className="px-6 py-4 border-b border-slate-800/80 bg-[#0f172a] flex items-center justify-between flex-wrap gap-4">
        <div className="flex items-center gap-3">
          <div className={`p-2 rounded-lg ${isPhishing ? 'bg-amber-500/10 border-amber-500/20 text-amber-400' : 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400'} border shadow-sm`}>
            <Network className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-lg font-bold text-white tracking-wide">Attack Anatomy Visualization</h2>
            <p className="text-xs text-slate-400">Interactive educational attack flow and telemetry observation</p>
          </div>
        </div>
        
        {/* Mode Toggle */}
        <div className="flex items-center bg-slate-900/80 rounded-lg p-1 border border-slate-800 shadow-inner">
          <button 
            onClick={() => setMode('learn')}
            className={`px-4 py-1.5 rounded-md text-xs font-bold flex items-center gap-2 transition-all duration-300 ${mode === 'learn' ? 'bg-indigo-600/20 text-indigo-300 shadow-sm' : 'text-slate-400 hover:text-white hover:bg-slate-800/50'}`}
          >
            <BookOpen className="w-3.5 h-3.5" /> Concept Learn Mode
          </button>
          <button 
            onClick={() => setMode('investigate')}
            className={`px-4 py-1.5 rounded-md text-xs font-bold flex items-center gap-2 transition-all duration-300 ${mode === 'investigate' ? 'bg-rose-500/20 text-rose-300 shadow-sm' : 'text-slate-400 hover:text-white hover:bg-slate-800/50'}`}
          >
            <Search className="w-3.5 h-3.5" /> Live Investigation Mode
          </button>
        </div>
      </div>

      <div className="p-6">
        {/* Controls Row */}
        <div className="flex items-center justify-between mb-8 flex-wrap gap-4 bg-[#0f172a] p-3 rounded-xl border border-slate-800/80 shadow-md">
          <div className="flex items-center gap-3">
            <span className="text-xs font-bold text-slate-400 uppercase tracking-wider">Attack Sequence:</span>
            <select 
              value={selectedScenarioId}
              onChange={(e) => {
                setSelectedScenarioId(e.target.value);
                setCurrentStageIdx(0);
                setIsPlaying(false);
              }}
              className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-sm font-medium text-white focus:outline-none focus:border-indigo-500 shadow-sm transition-colors"
            >
              {Array.from(new Set(SCENARIOS.map(s => s.category))).map(cat => (
                <optgroup key={cat} label={cat} className="text-slate-500 text-xs font-bold uppercase bg-slate-950">
                  {SCENARIOS.filter(s => s.category === cat).map(s => (
                    <option key={s.id} value={s.id} className="text-white text-sm font-normal">{s.name}</option>
                  ))}
                </optgroup>
              ))}
            </select>
          </div>
          
          <div className="flex items-center gap-6">
            <div className="text-xs font-bold text-slate-400 tracking-widest bg-slate-900 px-3 py-1.5 rounded-lg border border-slate-800 shadow-inner">
              <span className="text-white">{String(currentStageIdx + 1).padStart(2, '0')}</span> / {String(stages.length).padStart(2, '0')}
            </div>
            
            <div className="flex items-center gap-1.5">
              <button 
                onClick={() => setCurrentStageIdx(0)} 
                title="Restart"
                aria-label="Restart"
                className="p-2 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition-colors"
              >
                <RotateCcw className="w-4 h-4" />
              </button>
              <button 
                onClick={() => setCurrentStageIdx(Math.max(0, currentStageIdx - 1))}
                disabled={currentStageIdx === 0}
                title="Previous Stage"
                aria-label="Previous Stage"
                className="p-2 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition-colors disabled:opacity-20"
              >
                <SkipBack className="w-4 h-4" />
              </button>
              <button 
                onClick={handlePlayPause}
                title={isPlaying ? "Pause" : "Play Flow"}
                aria-label={isPlaying ? "Pause Flow" : "Play Flow"}
                className={`flex items-center gap-2 px-4 py-1.5 rounded-lg transition-colors font-bold text-xs uppercase tracking-wider shadow-md ${isPlaying ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 hover:bg-emerald-500/30'}`}
              >
                {isPlaying ? <><Pause className="w-3.5 h-3.5" /> Paused</> : <><Play className="w-3.5 h-3.5 fill-current" /> Play</>}
              </button>
              <button 
                onClick={() => setCurrentStageIdx(Math.min(stages.length - 1, currentStageIdx + 1))}
                disabled={currentStageIdx === stages.length - 1}
                title="Next Stage"
                aria-label="Next Stage"
                className="p-2 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition-colors disabled:opacity-20"
              >
                <SkipForward className="w-4 h-4" />
              </button>
            </div>
          </div>
        </div>

        {/* Visual Flow Diagram */}
        <div className="flex flex-row items-center justify-between w-full overflow-x-auto overflow-y-hidden py-10 px-6 mb-8 bg-[#0f172a] rounded-xl border border-slate-800/50 shadow-inner scrollbar-thin scrollbar-thumb-slate-800 scrollbar-track-transparent">
          <div className="flex flex-row items-center min-w-max w-full">
            {stages.map((stage, idx) => renderNode(stage, idx))}
          </div>
        </div>

        {/* Interactive Workspace */}
        {renderStageWorkspace()}
      </div>
    </div>
  );
};
