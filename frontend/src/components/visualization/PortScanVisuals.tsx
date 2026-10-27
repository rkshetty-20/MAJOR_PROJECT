import React, { useEffect, useState } from 'react';
import { AlertTriangle, Brain, Shield, Zap, ActivitySquare } from 'lucide-react';

interface StageProps {
  isLearnMode: boolean;
  liveData?: any;
}

const UnavailableBadge = ({ msg = "Not available in current telemetry." }) => (
  <div className="flex flex-col items-center justify-center h-full min-h-[200px] text-center border border-dashed border-slate-700 bg-slate-900/50 rounded-xl p-6">
    <ActivitySquare className="w-8 h-8 text-slate-600 mb-3" />
    <span className="text-sm font-semibold text-slate-400 uppercase tracking-widest bg-slate-800 px-3 py-1 rounded">Unavailable</span>
    <p className="text-xs text-slate-500 mt-4 max-w-xs">{msg}</p>
  </div>
);

// 1. Attack Initiated
export const PortScanAttack: React.FC<StageProps> = ({ isLearnMode, liveData }) => {
  const [activePortIdx, setActivePortIdx] = useState(-1);

  let ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 1433, 1521, 3306, 3389, 8080];

  if (!isLearnMode) {
    if (!liveData || !liveData.eventsData) return <UnavailableBadge />;
    const scanEvents = liveData.eventsData.filter((e: any) => e.event_type === 'port_scan');
    if (scanEvents.length === 0) return <UnavailableBadge msg="No port scan events found in telemetry." />;
    ports = scanEvents.map((e: any) => e.payload?.dest_port).filter(Boolean);
  }

  useEffect(() => {
    if (ports.length > 0) {
      const interval = setInterval(() => {
        setActivePortIdx(prev => (prev + 1) % ports.length);
      }, 300);
      return () => clearInterval(interval);
    }
  }, [ports.length]);

  return (
    <div className="flex flex-col h-full items-center justify-center">
      <div className="bg-slate-950 p-6 rounded-xl border border-slate-800 w-full max-w-md">
        {isLearnMode && <span className="text-[10px] font-mono text-indigo-400 block mb-4 uppercase">Illustrative Example</span>}
        <h4 className="text-white text-sm font-bold mb-4 text-center">Port Sweep Sequence</h4>
        <div className="grid grid-cols-4 gap-3">
          {ports.slice(0, 16).map((port, idx) => (
            <div
              key={idx}
              className={`flex items-center justify-center p-2 rounded text-xs font-mono transition-all duration-200 border
                ${idx === activePortIdx
                  ? 'bg-rose-500 text-white border-rose-400 shadow-[0_0_10px_rgba(244,63,94,0.5)] scale-110'
                  : idx < activePortIdx
                    ? 'bg-rose-500/20 text-rose-300 border-rose-500/30'
                    : 'bg-slate-900 text-slate-500 border-slate-800'}`}
            >
              :{port}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

// 2. Network Telemetry
export const PortScanTelemetry: React.FC<StageProps> = ({ isLearnMode, liveData }) => {
  let events = [];
  if (isLearnMode) {
    events = [
      { timestamp: new Date(Date.now() - 5000), source: '10.0.0.50', target: '10.0.0.10', port: 21 },
      { timestamp: new Date(Date.now() - 4000), source: '10.0.0.50', target: '10.0.0.10', port: 22 },
      { timestamp: new Date(Date.now() - 3000), source: '10.0.0.50', target: '10.0.0.10', port: 23 },
      { timestamp: new Date(Date.now() - 2000), source: '10.0.0.50', target: '10.0.0.10', port: 25 },
      { timestamp: new Date(Date.now() - 1000), source: '10.0.0.50', target: '10.0.0.10', port: 53 },
    ];
  } else {
    if (!liveData || !liveData.eventsData) return <UnavailableBadge />;
    const scanEvents = liveData.eventsData.filter((e: any) => e.event_type === 'port_scan');
    if (scanEvents.length === 0) return <UnavailableBadge msg="No port scan events found in telemetry." />;
    events = scanEvents.slice(0, 5).map((e: any) => ({
      timestamp: new Date(e.timestamp),
      source: e.source,
      target: e.target.split(':')[0],
      port: e.payload?.dest_port
    }));
  }

  return (
    <div className="flex flex-col h-full justify-center">
      <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 w-full">
        {isLearnMode && <span className="text-[10px] font-mono text-indigo-400 block mb-4 uppercase">Illustrative Example</span>}
        <table className="w-full text-left text-xs">
          <thead className="bg-slate-900 text-slate-400">
            <tr>
              <th className="p-2 font-semibold rounded-tl">Time</th>
              <th className="p-2 font-semibold">Source IP</th>
              <th className="p-2 font-semibold">Dest IP</th>
              <th className="p-2 font-semibold rounded-tr">Port</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/50">
            {events.map((e: any, i: number) => (
              <tr key={i} className="hover:bg-slate-800/30 transition-colors">
                <td className="p-2 font-mono text-[10px] text-slate-500">{e.timestamp.toLocaleTimeString()}</td>
                <td className="p-2 font-mono text-slate-300">{e.source}</td>
                <td className="p-2 font-mono text-slate-300">{e.target}</td>
                <td className="p-2 font-mono text-rose-400">:{e.port}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

// 3. Suricata IDS
export const PortScanSuricata: React.FC<StageProps> = ({ isLearnMode, liveData }) => {
  let alerts = [];
  if (isLearnMode) {
    alerts = [
      { signature: "ET SCAN Possible Nmap User-Agent Observed", severity: 2 },
      { signature: "ET SCAN Potential SSH Scan", severity: 2 }
    ];
  } else {
    if (!liveData || !liveData.timelineData) return <UnavailableBadge />;
    const suricataEvents = liveData.timelineData.filter((t: any) => t.step === 'suricata_event_generated');
    if (suricataEvents.length === 0) return <UnavailableBadge msg="No Suricata alerts generated." />;
    alerts = suricataEvents.slice(0, 2).map((e: any) => ({
      signature: e.label,
      severity: e.severity || 2
    }));
  }

  return (
    <div className="flex flex-col h-full justify-center">
      <div className="bg-slate-950 p-6 rounded-xl border border-slate-800 w-full max-w-md mx-auto">
        {isLearnMode && <span className="text-[10px] font-mono text-indigo-400 block mb-4 uppercase">Illustrative Example</span>}
        <div className="flex items-center gap-3 mb-4">
          <Shield className="w-6 h-6 text-emerald-500" />
          <h4 className="text-white text-sm font-bold">Suricata IDS Alerts</h4>
        </div>
        <div className="space-y-3">
          {alerts.map((alert: any, i: number) => (
            <div key={i} className="bg-slate-900 border-l-4 border-l-rose-500 p-3 rounded-r flex justify-between items-start gap-4 shadow-sm">
              <div>
                <div className="text-[10px] text-slate-500 uppercase font-bold mb-1">Signature</div>
                <div className="text-xs text-rose-200 font-mono break-all">{alert.signature}</div>
              </div>
              <div className="text-center shrink-0">
                <div className="text-[10px] text-slate-500 uppercase font-bold mb-1">Severity</div>
                <div className="text-lg font-black text-rose-500">{alert.severity}</div>
              </div>
            </div>
          ))}
        </div>
        <p className="text-[10px] text-slate-500 mt-4 text-center">Note: Suricata severity 1 is the highest risk.</p>
      </div>
    </div>
  );
};

// 4. Feature Extraction
export const PortScanFeatures: React.FC<StageProps> = ({ isLearnMode, liveData }) => {
  let features: Record<string, number> = {};
  if (isLearnMode) {
    features = {
      "distinct_dest_ports": 42,
      "events_per_second": 8.5,
      "distinct_dest_ips": 1,
      "avg_severity": 2.0,
      "protocol_diversity": 1
    };
  } else {
    const det = liveData?.detections?.find((d: any) => d.source.toLowerCase() === 'ml' && d.label === 'port_scan_detected');
    if (!det || !det.features) return <UnavailableBadge msg="Feature vector not persisted for this detection." />;
    try {
      features = JSON.parse(det.features);
    } catch (e) {
      return <UnavailableBadge msg="Failed to parse feature vector." />;
    }
  }

  // Normalize for bars (illustrative max values for visual scaling)
  const maxVals: Record<string, number> = {
    "distinct_dest_ports": 100,
    "events_per_second": 20,
    "distinct_dest_ips": 5,
    "avg_severity": 3,
    "protocol_diversity": 3
  };

  return (
    <div className="flex flex-col h-full justify-center">
      <div className="bg-slate-950 p-6 rounded-xl border border-slate-800 w-full max-w-md mx-auto">
        {isLearnMode && <span className="text-[10px] font-mono text-indigo-400 block mb-4 uppercase">Illustrative Example</span>}
        <h4 className="text-white text-sm font-bold mb-4">ML Feature Vector</h4>
        <div className="space-y-4">
          {Object.entries(features).map(([key, val]) => {
            const max = maxVals[key] || Math.max(10, val * 2);
            const pct = Math.min(100, (val / max) * 100);
            return (
              <div key={key}>
                <div className="flex justify-between text-xs mb-1">
                  <span className="text-slate-300">{key}</span>
                  <span className="font-mono text-indigo-400">{val.toFixed(key === 'events_per_second' || key === 'avg_severity' ? 2 : 0)}</span>
                </div>
                <div className="bg-slate-800 rounded-full h-2 w-full mt-1 overflow-hidden">
                  <div className="bg-indigo-500 h-2 rounded-full transition-all duration-1000" style={{ width: `${pct}%` }} />
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};

// 5. ML Model
export const PortScanMLModel: React.FC<StageProps> = ({ isLearnMode, liveData }) => {
  let confidence = 0;
  const threshold = 0.7; // From backend logic

  if (isLearnMode) {
    confidence = 0.89;
  } else {
    const det = liveData?.detections?.find((d: any) => d.source.toLowerCase() === 'ml' && d.label === 'port_scan_detected');
    if (!det) return <UnavailableBadge msg="No ML detection triggered." />;
    confidence = det.confidence;
  }

  const thresholdRotation = -90 + (threshold * 180);
  const isTriggered = confidence > threshold;

  return (
    <div className="flex flex-col h-full items-center justify-center">
      <div className="bg-slate-950 p-6 rounded-xl border border-slate-800 w-full max-w-md flex flex-col items-center">
        {isLearnMode && <span className="text-[10px] font-mono text-indigo-400 block mb-4 uppercase self-start">Illustrative Example</span>}
        <Brain className="w-8 h-8 text-indigo-400 mb-2" />
        <h4 className="text-white text-sm font-bold mb-6">Random Forest Prediction</h4>

        {/* Gauge */}
        <div className="relative w-48 h-24 overflow-hidden mb-4">
          {/* Background arc */}
          <div className="absolute top-0 left-0 w-48 h-48 rounded-full border-[16px] border-slate-800" />

          {/* Threshold marker */}
          <div
            className="absolute top-24 left-24 w-0 h-0 origin-top"
            style={{ transform: `rotate(${thresholdRotation}deg)` }}
          >
            <div className="w-1 h-4 bg-slate-400 absolute -top-24 -translate-x-1/2 rounded" />
          </div>

          {/* Value arc (clip path approach simplified to CSS rotation) */}
          <div className="absolute top-0 left-0 w-48 h-48 rounded-full border-[16px] border-transparent border-t-indigo-500 border-r-indigo-500 rotate-45 transition-transform duration-1000"
            style={{ transform: `rotate(${-135 + (confidence * 180)}deg)` }} />

          {/* Center text */}
          <div className="absolute bottom-0 left-0 w-full text-center pb-2">
            <span className="text-3xl font-black text-white">{(confidence * 100).toFixed(1)}<span className="text-lg text-slate-500">%</span></span>
          </div>
        </div>

        <div className="flex justify-between w-full px-4 text-[10px] text-slate-500 font-bold uppercase mb-4">
          <span>0%</span>
          <span className="text-slate-400">Threshold: {threshold * 100}%</span>
          <span>100%</span>
        </div>

        <div className={`px-4 py-1.5 rounded-full text-xs font-bold uppercase ${isTriggered ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30' : 'bg-slate-800 text-slate-400'}`}>
          {isTriggered ? 'Detection Triggered' : 'Normal'}
        </div>
      </div>
    </div>
  );
};

// 6. Detection Triggered
export const PortScanDetection: React.FC<StageProps> = ({ isLearnMode, liveData }) => {
  let label = "port_scan_detected";
  let explanation = "";

  if (isLearnMode) {
    explanation = "ML model flagged 42 distinct ports / 1 IPs from 10.0.0.50 as port-scan-like (confidence 89.0%)";
  } else {
    const det = liveData?.detections?.find((d: any) => d.source.toLowerCase() === 'ml' && d.label === 'port_scan_detected');
    if (!det) return <UnavailableBadge msg="No ML detection triggered." />;
    label = det.label;
    explanation = det.explanation;
  }

  return (
    <div className="flex flex-col h-full justify-center">
      <div className="bg-rose-500/10 p-6 rounded-xl border border-rose-500/30 w-full max-w-md mx-auto relative overflow-hidden">
        {isLearnMode && <span className="text-[10px] font-mono text-rose-400 block mb-4 uppercase relative z-10">Illustrative Example</span>}
        <AlertTriangle className="w-32 h-32 text-rose-500/10 absolute -right-4 -bottom-4 z-0" />
        <div className="relative z-10">
          <div className="text-[10px] font-bold text-rose-400 uppercase mb-1">Detection Record created</div>
          <h3 className="text-xl font-black text-rose-300 mb-4">{label}</h3>
          <div className="bg-rose-950/50 p-4 rounded border border-rose-500/20">
            <div className="text-[10px] text-rose-400 uppercase font-bold mb-1">Observed Value vs Threshold</div>
            <p className="text-sm text-rose-200 leading-relaxed font-mono">{explanation}</p>
          </div>
        </div>
      </div>
    </div>
  );
};

// 7. Risk Fusion
export const PortScanRisk: React.FC<StageProps> = ({ isLearnMode, liveData }) => {
  let factors: Record<string, number> = {};
  let score = 0;
  let band = "";

  if (isLearnMode) {
    factors = {
      "ml_confidence_term": 89,
      "multi_signal_bonus": 0,
      "severity_term": 5
    };
    score = 94;
    band = "CRITICAL";
  } else {
    if (!liveData?.risk) return <UnavailableBadge msg="No risk score calculated." />;
    try {
      factors = JSON.parse(liveData.risk.contributing_factors || "{}");
    } catch {
      factors = {};
    }
    score = liveData.risk.score;
    band = liveData.risk.band.toUpperCase();
  }

  // Filter non-zero terms
  const nonZeroFactors = Object.entries(factors).filter(([_, val]) => val !== 0);

  return (
    <div className="flex flex-col h-full justify-center">
      <div className="bg-slate-950 p-6 rounded-xl border border-slate-800 w-full max-w-md mx-auto">
        {isLearnMode && <span className="text-[10px] font-mono text-indigo-400 block mb-4 uppercase">Illustrative Example</span>}
        <div className="flex items-center gap-2 mb-6">
          <Zap className="w-5 h-5 text-amber-500" />
          <h4 className="text-white text-sm font-bold">Risk Score Waterfall</h4>
        </div>

        <div className="space-y-3 mb-6">
          <div className="flex justify-between items-center text-xs text-slate-500 font-bold uppercase pb-2 border-b border-slate-800">
            <span>Factor</span>
            <span>Impact</span>
          </div>
          {nonZeroFactors.map(([key, val]) => (
            <div key={key} className="flex justify-between items-center">
              <span className="text-sm text-slate-300 capitalize flex items-center gap-2">
                <div className="w-1.5 h-1.5 rounded-full bg-amber-500" />
                {key.replace(/_/g, ' ')}
              </span>
              <span className="font-mono text-amber-400 font-bold">+{val}</span>
            </div>
          ))}
        </div>

        <div className="pt-4 border-t-2 border-slate-700 flex justify-between items-end">
          <div>
            <div className="text-[10px] font-bold text-slate-500 uppercase mb-1">Total Risk Score</div>
            <div className={`text-xs font-bold px-2 py-1 rounded-sm uppercase inline-block ${band === 'CRITICAL' ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30' :
                band === 'HIGH' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' :
                  band === 'MEDIUM' ? 'bg-sky-500/20 text-sky-400 border border-sky-500/30' :
                    'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
              }`}>{band}</div>
          </div>
          <div className="text-4xl font-black text-white">{score}<span className="text-lg text-slate-500 font-normal">/100</span></div>
        </div>
      </div>
    </div>
  );
};
