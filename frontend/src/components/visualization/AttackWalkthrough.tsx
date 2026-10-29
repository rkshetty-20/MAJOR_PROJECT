import React, { useState } from 'react';
import { Mail, Link as LinkIcon, Key, Network, Shield, ArrowRight, ShieldAlert, ShieldCheck, Activity } from 'lucide-react';

export type ProtectionMode = 'without' | 'with';
export type StageId = 'bait' | 'click' | 'entry' | 'spread' | 'response';

interface StageData {
  id: StageId;
  title: string;
  category: string;
  icon: React.ElementType;
  attackerAction: string;
  potentialImpact: string;
  plainLanguage: string;
  technicalExplanation: string;
  mitreTechnique?: string;
  illustrativeEvidence?: any;
  withoutProtection: {
    outcome: string;
  };
  withProtection: {
    opportunity: string;
    defensiveAction: string;
    outcome: string;
  };
}

const STAGES: StageData[] = [
  {
    id: 'bait',
    title: 'Bait',
    category: 'Phishing Delivery',
    icon: Mail,
    attackerAction: 'An attacker sends a fake parcel-delivery email containing a suspicious URL.',
    potentialImpact: 'User deception leading to credential exposure.',
    plainLanguage: 'A suspicious message introduces a link that may lead to a fake sign-in page.',
    technicalExplanation: 'Attackers utilize social engineering and look-alike domains to bypass initial suspicion. The message often contains urgency triggers (e.g., "Missed Delivery").',
    mitreTechnique: 'T1566.002 - Phishing: Spearphishing Link',
    illustrativeEvidence: {
      type: 'email',
      sender: 'notifications@delivery-update-tracker.com',
      subject: 'URGENT: Your parcel could not be delivered',
      isIllustrative: true
    },
    withoutProtection: {
      outcome: 'The user receives the email in their main inbox, increasing the chance they will interact with the deceptive content.',
    },
    withProtection: {
      opportunity: 'Email authentication, sender reputation, and message analysis can identify suspicious messages.',
      defensiveAction: '(Illustrative) Email gateway flags message as suspicious or moves it to quarantine.',
      outcome: 'The message is flagged or blocked before reaching the user, neutralizing the threat early.',
    }
  },
  {
    id: 'click',
    title: 'Click',
    category: 'Suspicious URL',
    icon: LinkIcon,
    attackerAction: 'The user follows a suspicious link that could lead to a credential-harvesting page.',
    potentialImpact: 'Exposure of valid credentials or session tokens to the attacker.',
    plainLanguage: 'The deceptive link directs the user to a webpage designed to look exactly like a legitimate login portal.',
    technicalExplanation: 'The URL scorer identifies lexical characteristics such as long lengths, excessive subdomains, or IP-based hosts. Reputation feeds can additionally tell whether a domain is already known to be malicious; this project deliberately performs no reputation lookup and never fetches the URL, so its verdict is structural only.',
    mitreTechnique: 'T1204.001 - User Execution: Malicious Link',
    illustrativeEvidence: {
      type: 'url',
      url: 'https://login.secure-auth-gateway-update.com/verify?token=123',
      heuristicScore: '87%',
      reputation: 'Flagged by 4 security vendors',
      isIllustrative: true
    },
    withoutProtection: {
      outcome: 'The user accesses the fake login page, submits their credentials, and the attacker captures them for later use.',
    },
    withProtection: {
      opportunity: 'URL analysis, reputation checks, browser warnings, and strong authentication can reduce risk.',
      defensiveAction: 'URL analysis flags suspicious characteristics. (Illustrative) Browser or proxy blocks access.',
      outcome: 'The connection is interrupted or flagged. Even if accessed, strong MFA prevents captured passwords from being useful.',
    }
  },
  {
    id: 'entry',
    title: 'Entry',
    category: 'Suspicious Authentication',
    icon: Key,
    attackerAction: 'An attacker attempts to use compromised credentials to access an account.',
    potentialImpact: 'Unauthorized access to protected systems or sensitive data.',
    plainLanguage: 'The attacker logs in using the stolen password, often from a new location or unrecognized device.',
    technicalExplanation: 'Authentication anomaly rules monitor for impossible travel, unusual times, and unrecognized devices. Repeated failures suggest credential stuffing.',
    mitreTechnique: 'T1078 - Valid Accounts',
    illustrativeEvidence: {
      type: 'auth',
      user: 'alice.smith',
      ip: '198.51.100.44',
      status: 'Success',
      isIllustrative: true
    },
    withoutProtection: {
      outcome: 'The attacker successfully logs in and gains the same access rights as the compromised user.',
    },
    withProtection: {
      opportunity: 'Authentication anomaly rules flag anomalous login activity such as unfamiliar devices or locations.',
      defensiveAction: 'Existing authentication rules flag the anomalous login.',
      outcome: 'The login is flagged as highly suspicious, triggering an alert for the SOC to investigate.',
    }
  },
  {
    id: 'spread',
    title: 'Spread',
    category: 'Intrusion Activity',
    icon: Network,
    attackerAction: 'An attacker who has gained access may attempt further movement or suspicious outbound communication.',
    potentialImpact: 'Broader network compromise, discovery of sensitive targets, or data staging.',
    plainLanguage: 'Once inside, the attacker scans the internal network to find other vulnerable systems to exploit.',
    technicalExplanation: 'Network intrusion detection systems (IDS) identify signature-based anomalies (e.g. port scans, lateral movement attempts) and behavioral deviations from baseline traffic.',
    mitreTechnique: 'T1046 - Network Service Discovery',
    illustrativeEvidence: {
      type: 'network',
      event: 'TCP Port Scan detected against internal subnet 10.0.0.0/24',
      isIllustrative: true
    },
    withoutProtection: {
      outcome: 'The attacker maps the network silently, identifies critical assets, and moves laterally without triggering alarms.',
    },
    withProtection: {
      opportunity: 'Network signatures, port-scan detection, and endpoint telemetry can detect suspicious activity.',
      defensiveAction: 'Existing network detection rules or the port-scan model flag supported activity.',
      outcome: 'The port scan triggers an intrusion alert, exposing the attacker\'s presence on the network.',
    }
  },
  {
    id: 'response',
    title: 'Response',
    category: 'Correlated Investigation',
    icon: Shield,
    attackerAction: 'The attacker attempts to access valuable data or continue the attack.',
    potentialImpact: 'Data exfiltration, ransomware deployment, or long-term persistence.',
    plainLanguage: 'The security team pieces together the initial phishing click, the anomalous login, and the internal network scan to understand the full attack.',
    technicalExplanation: 'A correlation engine links disparate signals (e.g. same user, close time window) into a unified incident. This provides a holistic risk score and a clear timeline.',
    illustrativeEvidence: {
      type: 'correlation',
      events: ['Phishing Click', 'Anomalous Login', 'Port Scan'],
      isIllustrative: true
    },
    withoutProtection: {
      outcome: 'Individual alerts are lost in the noise, or no alerts are generated, leaving the attack undiscovered until significant damage occurs.',
    },
    withProtection: {
      opportunity: 'Correlation can connect related evidence when identifiers and relationships support it.',
      defensiveAction: '(Illustrative) Raise unified incident, recommend account protection.',
      outcome: 'A unified incident is raised. Individual alerts can look unrelated. Correlating supported evidence can reveal a larger attack pattern.',
    }
  }
];

export const AttackWalkthrough: React.FC = () => {
  const [selectedStageIdx, setSelectedStageIdx] = useState(0);
  const [protectionMode, setProtectionMode] = useState<ProtectionMode>('without');

  const stage = STAGES[selectedStageIdx];

  return (
    <div className="w-full max-w-[1400px] mx-auto space-y-6 animate-fade-in">
      
      {/* Mode Toggle */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between bg-slate-900 border border-slate-800 p-4 rounded-xl gap-4">
        <div>
          <h3 className="text-white font-bold text-lg">Phishing-to-Intrusion Attack Walkthrough</h3>
          <p className="text-sm text-slate-400">Explore how an attack progresses and how defenses operate.</p>
        </div>
        
        <div className="flex bg-slate-950 rounded-lg p-1 border border-slate-700 self-start sm:self-auto">
          <button
            onClick={() => setProtectionMode('without')}
            className={`px-4 py-2 text-sm font-bold rounded-md transition-colors ${protectionMode === 'without' ? 'bg-slate-800 text-rose-400 shadow' : 'text-slate-400 hover:text-white'}`}
            aria-pressed={protectionMode === 'without'}
          >
            Without protection
          </button>
          <button
            onClick={() => setProtectionMode('with')}
            className={`px-4 py-2 text-sm font-bold rounded-md transition-colors ${protectionMode === 'with' ? 'bg-indigo-600 text-white shadow' : 'text-slate-400 hover:text-white'}`}
            aria-pressed={protectionMode === 'with'}
          >
            With our system
          </button>
        </div>
      </div>

      {/* Stepper */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 overflow-x-auto custom-scrollbar">
        <div className="flex items-center min-w-[700px]">
          {STAGES.map((s, idx) => {
            const isSelected = idx === selectedStageIdx;
            const isPast = idx < selectedStageIdx;
            const Icon = s.icon;
            
            return (
              <React.Fragment key={s.id}>
                <button
                  onClick={() => setSelectedStageIdx(idx)}
                  className={`flex flex-col items-center gap-2 group focus:outline-none focus:ring-2 focus:ring-indigo-500 rounded-lg p-2 ${isSelected ? 'opacity-100' : 'opacity-60 hover:opacity-100'}`}
                  aria-label={`Select stage ${idx + 1}: ${s.title}`}
                  aria-current={isSelected ? 'step' : undefined}
                >
                  <div className={`w-12 h-12 rounded-full flex items-center justify-center border-2 transition-colors ${
                    isSelected ? 'bg-indigo-500/20 border-indigo-500 text-indigo-400' :
                    isPast ? 'bg-slate-800 border-slate-700 text-slate-300' :
                    'bg-slate-950 border-slate-800 text-slate-500'
                  }`}>
                    <Icon className="w-5 h-5" />
                  </div>
                  <div className="text-center">
                    <div className="text-[10px] font-bold text-slate-500 uppercase">Stage {idx + 1}</div>
                    <div className={`text-sm font-bold ${isSelected ? 'text-white' : 'text-slate-400'}`}>{s.title}</div>
                  </div>
                </button>
                {idx < STAGES.length - 1 && (
                  <div className="flex-1 px-4">
                    <div className={`h-0.5 w-full ${isPast ? 'bg-indigo-500/50' : 'bg-slate-800'}`} />
                  </div>
                )}
              </React.Fragment>
            );
          })}
        </div>
      </div>

      {/* Main Content */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        
        {/* Left Column: Attack Details */}
        <div className="space-y-6">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6">
            <div className="flex items-center gap-3 mb-4 border-b border-slate-800 pb-4">
               <div className="p-2 bg-indigo-500/10 text-indigo-400 rounded-lg">
                 <stage.icon className="w-6 h-6" />
               </div>
               <div>
                 <div className="text-xs text-indigo-400 font-bold uppercase tracking-wider">Stage {selectedStageIdx + 1}: {stage.title}</div>
                 <h2 className="text-xl font-bold text-white">{stage.category}</h2>
               </div>
            </div>
            
            <div className="space-y-4">
              <div>
                <h4 className="text-xs font-bold text-slate-500 uppercase mb-1">Attacker Action</h4>
                <p className="text-sm text-slate-200">{stage.attackerAction}</p>
              </div>
              
              <div>
                <h4 className="text-xs font-bold text-slate-500 uppercase mb-1">Potential Impact</h4>
                <p className="text-sm text-slate-400">{stage.potentialImpact}</p>
              </div>
              
              <div className="p-4 bg-slate-950 rounded-lg border border-slate-800">
                <h4 className="text-xs font-bold text-slate-500 uppercase mb-2 flex items-center gap-2">
                   <Activity className="w-4 h-4 text-amber-500" /> Illustrative Evidence
                </h4>
                <div className="text-sm font-mono text-slate-300 space-y-1">
                  {stage.illustrativeEvidence.type === 'email' && (
                    <>
                      <div><span className="text-slate-500">From:</span> {stage.illustrativeEvidence.sender}</div>
                      <div><span className="text-slate-500">Subject:</span> {stage.illustrativeEvidence.subject}</div>
                    </>
                  )}
                  {stage.illustrativeEvidence.type === 'url' && (
                    <>
                      <div><span className="text-slate-500">URL:</span> {stage.illustrativeEvidence.url}</div>
                      <div><span className="text-slate-500">Score:</span> <span className="text-amber-400">{stage.illustrativeEvidence.heuristicScore}</span></div>
                      <div><span className="text-slate-500">Vendor flags:</span> {stage.illustrativeEvidence.reputation} <span className="text-slate-500">(illustrative - no reputation provider is integrated in this project)</span></div>
                    </>
                  )}
                  {stage.illustrativeEvidence.type === 'auth' && (
                    <>
                      <div><span className="text-slate-500">User:</span> {stage.illustrativeEvidence.user}</div>
                      <div><span className="text-slate-500">Source IP:</span> {stage.illustrativeEvidence.ip}</div>
                      <div><span className="text-slate-500">Status:</span> {stage.illustrativeEvidence.status}</div>
                    </>
                  )}
                  {stage.illustrativeEvidence.type === 'network' && (
                    <>
                      <div><span className="text-slate-500">Event:</span> {stage.illustrativeEvidence.event}</div>
                    </>
                  )}
                  {stage.illustrativeEvidence.type === 'correlation' && (
                    <>
                      <div><span className="text-slate-500">Linked:</span> {stage.illustrativeEvidence.events.join(' ➔ ')}</div>
                    </>
                  )}
                  <div className="text-[10px] text-amber-500 mt-2 font-sans italic">* This evidence is strictly illustrative and does not represent real detection telemetry.</div>
                </div>
              </div>
            </div>
          </div>
          
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
             <h3 className="text-sm font-bold text-white uppercase border-b border-slate-800 pb-2">Explanations</h3>
             <div>
                <h4 className="text-xs font-bold text-slate-500 uppercase mb-1">Plain Language</h4>
                <p className="text-sm text-slate-300">{stage.plainLanguage}</p>
             </div>
             <div>
                <h4 className="text-xs font-bold text-slate-500 uppercase mb-1">Technical Context</h4>
                <p className="text-sm text-slate-400">{stage.technicalExplanation}</p>
             </div>
             {stage.mitreTechnique && (
               <div>
                  <h4 className="text-xs font-bold text-slate-500 uppercase mb-1">MITRE ATT&CK</h4>
                  <span className="inline-block px-2 py-1 bg-slate-800 rounded text-xs font-mono text-slate-300 border border-slate-700">
                    {stage.mitreTechnique}
                  </span>
               </div>
             )}
          </div>
        </div>

        {/* Right Column: Outcome Comparison */}
        <div className="h-full">
          <div className={`h-full bg-slate-900 border-2 rounded-xl p-6 flex flex-col transition-colors ${protectionMode === 'without' ? 'border-rose-500/30' : 'border-indigo-500/50'}`}>
            
            <div className="flex items-center gap-3 mb-6">
               <div className={`p-2 rounded-lg ${protectionMode === 'without' ? 'bg-rose-500/10 text-rose-400' : 'bg-indigo-500/10 text-indigo-400'}`}>
                 {protectionMode === 'without' ? <ShieldAlert className="w-6 h-6" /> : <ShieldCheck className="w-6 h-6" />}
               </div>
               <div>
                 <h2 className="text-xl font-bold text-white">
                   {protectionMode === 'without' ? 'Without Protection' : 'With Our System'}
                 </h2>
                 <p className="text-sm text-slate-400">
                   {protectionMode === 'without' ? 'Hypothetical outcome without effective protection' : 'Detection or mitigation opportunity'}
                 </p>
               </div>
            </div>

            <div className="flex-1 space-y-6">
              {protectionMode === 'without' ? (
                <div>
                  <h4 className="text-sm font-bold text-rose-400 uppercase mb-2">Outcome</h4>
                  <p className="text-base text-slate-200 leading-relaxed border-l-2 border-rose-500/50 pl-4">{stage.withoutProtection.outcome}</p>
                </div>
              ) : (
                <div className="space-y-6">
                  <div>
                    <h4 className="text-sm font-bold text-indigo-400 uppercase mb-2">Opportunity</h4>
                    <p className="text-base text-slate-200 leading-relaxed border-l-2 border-indigo-500/50 pl-4">{stage.withProtection.opportunity}</p>
                  </div>
                  
                  <div className="p-4 bg-slate-950 rounded-lg border border-slate-800">
                    <h4 className="text-xs font-bold text-emerald-400 uppercase mb-1">Defensive Action</h4>
                    <p className="text-sm text-slate-300 font-medium">{stage.withProtection.defensiveAction}</p>
                  </div>

                  <div>
                    <h4 className="text-sm font-bold text-indigo-400 uppercase mb-2">Protected Outcome</h4>
                    <p className="text-base text-slate-200 leading-relaxed border-l-2 border-emerald-500/50 pl-4">{stage.withProtection.outcome}</p>
                    
                    {stage.id === 'response' && (
                       <div className="mt-4 p-4 bg-indigo-500/10 border border-indigo-500/30 rounded-lg text-indigo-300 font-bold text-center">
                         "Individual alerts can look unrelated. Correlating supported evidence can reveal a larger attack pattern."
                       </div>
                    )}
                  </div>
                </div>
              )}
            </div>

            <div className="mt-8 pt-4 border-t border-slate-800 flex justify-between">
               <button
                 onClick={() => setSelectedStageIdx(Math.max(0, selectedStageIdx - 1))}
                 disabled={selectedStageIdx === 0}
                 className="px-4 py-2 text-sm font-bold rounded-lg bg-slate-800 text-white disabled:opacity-50 disabled:cursor-not-allowed hover:bg-slate-700 transition-colors"
               >
                 Previous Stage
               </button>
               <button
                 onClick={() => setSelectedStageIdx(Math.min(STAGES.length - 1, selectedStageIdx + 1))}
                 disabled={selectedStageIdx === STAGES.length - 1}
                 className="flex items-center gap-2 px-4 py-2 text-sm font-bold rounded-lg bg-indigo-600 text-white disabled:opacity-50 disabled:cursor-not-allowed hover:bg-indigo-500 transition-colors"
               >
                 Next Stage <ArrowRight className="w-4 h-4" />
               </button>
            </div>
            
          </div>
        </div>
      </div>
    </div>
  );
};
