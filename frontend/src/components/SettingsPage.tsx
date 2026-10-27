import React, { useEffect, useState } from 'react';
import { 
  Server, Database, Shield, ShieldCheck, 
  Settings, Save, Activity, HardDrive, 
  Key, RefreshCw, AlertTriangle
} from 'lucide-react';
import { getSystemConfig, SystemConfig } from '../api';

export const SettingsPage: React.FC = () => {
  const [config, setConfig] = useState<SystemConfig | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [theme, setTheme] = useState<'dark' | 'light'>(
    (localStorage.getItem('theme') as 'dark' | 'light') || 'dark'
  );
  const [landingPage, setLandingPage] = useState<string>(
    localStorage.getItem('landingPage') || 'dashboard'
  );

  const fetchConfig = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await getSystemConfig();
      setConfig(res.data);
    } catch (err: any) {
      setError(err.message || 'Failed to fetch system configuration');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchConfig();
  }, []);

  const savePreferences = () => {
    localStorage.setItem('theme', theme);
    localStorage.setItem('landingPage', landingPage);
    alert('Preferences saved successfully. (Only visually reflected in local storage for now)');
  };

  if (loading) {
    return (
      <div className="w-full h-full flex items-center justify-center min-h-[400px]">
        <div className="flex flex-col items-center gap-4 text-slate-400">
          <RefreshCw className="w-8 h-8 animate-spin text-indigo-500" />
          <p>Loading system configuration...</p>
        </div>
      </div>
    );
  }

  if (error || !config) {
    return (
      <div className="w-full h-full flex items-center justify-center min-h-[400px]">
        <div className="bg-rose-500/10 border border-rose-500/20 rounded-xl p-6 text-center max-w-md">
          <AlertTriangle className="w-12 h-12 text-rose-500 mx-auto mb-4" />
          <h2 className="text-xl font-bold text-white mb-2">Configuration Unavailable</h2>
          <p className="text-slate-400 mb-6">{error || 'Failed to load configuration'}</p>
          <button 
            onClick={fetchConfig}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-white rounded-lg transition-colors"
          >
            Retry Connection
          </button>
        </div>
      </div>
    );
  }

  const Section = ({ title, icon: Icon, children }: any) => (
    <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden mb-6 h-full flex flex-col shadow-lg shadow-black/20">
      <div className="flex items-center gap-3 px-6 py-4 border-b border-slate-800/80 bg-slate-900/80">
        <Icon className="w-5 h-5 text-indigo-400" />
        <h2 className="text-lg font-semibold text-white">{title}</h2>
      </div>
      <div className="p-6 flex-1 flex flex-col">
        {children}
      </div>
    </div>
  );

  return (
    <div className="max-w-5xl mx-auto space-y-6 animate-in fade-in duration-500">
      <div>
        <h1 className="text-2xl font-bold text-white mb-2">System Configuration & Health</h1>
        <p className="text-slate-400">Monitor platform health, verify configurations, and adjust application preferences.</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 items-stretch">
        {/* 1. System Health */}
        <Section title="System Health" icon={Activity}>
          <div className="space-y-4">
            <div className="flex items-center justify-between p-4 bg-slate-950/50 rounded-lg border border-slate-800/50 hover:border-slate-700 transition-colors">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-slate-800 rounded-lg">
                  <Server className="w-5 h-5 text-slate-300" />
                </div>
                <div>
                  <div className="text-sm font-medium text-slate-200">Backend API</div>
                  <div className="text-xs text-slate-500">FastAPI Connectivity</div>
                </div>
              </div>
              <div className={`px-3 py-1.5 rounded text-xs font-bold uppercase tracking-wider ${
                config.health.api === 'online' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' : 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
              }`}>
                {config.health.api}
              </div>
            </div>

            <div className="flex items-center justify-between p-4 bg-slate-950/50 rounded-lg border border-slate-800/50 hover:border-slate-700 transition-colors">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-slate-800 rounded-lg">
                  <Database className="w-5 h-5 text-slate-300" />
                </div>
                <div>
                  <div className="text-sm font-medium text-slate-200">Database</div>
                  <div className="text-xs text-slate-500">SQLite Connectivity</div>
                </div>
              </div>
              <div className={`px-3 py-1.5 rounded text-xs font-bold uppercase tracking-wider ${
                config.health.database === 'connected' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' : 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
              }`}>
                {config.health.database}
              </div>
            </div>
          </div>
        </Section>

        {/* 2. Detection Configuration */}
        <Section title="Detection Configuration" icon={Shield}>
          <div className="space-y-6">
            <div>
              <div className="text-sm font-medium text-slate-300 mb-2">Phishing Heuristic Threshold</div>
              <div className="flex items-center gap-4">
                <div className="flex-1 h-2.5 bg-slate-800 rounded-full overflow-hidden border border-slate-700/50">
                  <div 
                    className="h-full bg-indigo-500 shadow-[0_0_10px_rgba(99,102,241,0.5)] transition-all duration-1000" 
                    style={{ width: `${config.detection.phishing_threshold * 100}%` }}
                  />
                </div>
                <span className="text-sm font-bold text-white bg-slate-800 px-2 py-1 rounded border border-slate-700">
                  {Math.round(config.detection.phishing_threshold * 100)}%
                </span>
              </div>
            </div>

            <div>
              <div className="text-sm font-medium text-slate-300 mb-3">Supported Intrusion Rules</div>
              <div className="flex flex-wrap gap-2">
                {config.detection.supported_rules.map(rule => (
                  <span key={rule} className="px-2.5 py-1 text-[11px] font-medium bg-slate-800 text-slate-300 rounded border border-slate-700/80 capitalize">
                    {rule.replace(/_/g, ' ')}
                  </span>
                ))}
              </div>
            </div>

            <div className="flex items-center justify-between p-4 bg-slate-950/50 rounded-lg border border-slate-800/50">
              <div>
                <div className="text-sm font-medium text-slate-200">Port-Scan Model Version</div>
                <div className="text-xs text-slate-500 mt-1">{config.detection.ml_model_version}</div>
              </div>
              <div className={`px-2.5 py-1 rounded text-[10px] font-bold uppercase tracking-widest ${
                config.detection.ml_training_ready ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' : 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
              }`}>
                {config.detection.ml_training_ready ? 'Ready for Training' : 'Training Unavailable'}
              </div>
            </div>
          </div>
        </Section>

        {/* 3. Evidence Integrity */}
        <Section title="Evidence Integrity" icon={ShieldCheck}>
          <div className="flex flex-col justify-center h-full">
            <div className="flex items-start gap-4 p-5 bg-slate-950/50 rounded-lg border border-slate-800/50">
              <div className={`p-3 rounded-xl mt-1 ${
                config.integrity.hmac_configured ? 'bg-emerald-500/10 text-emerald-400 shadow-[0_0_15px_rgba(16,185,129,0.1)]' : 'bg-amber-500/10 text-amber-400'
              }`}>
                <Key className="w-6 h-6" />
              </div>
              <div>
                <h3 className="text-base font-medium text-slate-200">HMAC Verification</h3>
                <p className="text-sm text-slate-400 mt-1.5 mb-3 leading-relaxed">
                  Cryptographic hashing ensures logs and detections cannot be tampered with after creation. 
                  Used to establish a non-repudiation chain of custody.
                </p>
                <div className="flex items-center gap-2">
                  <span className="relative flex h-3 w-3">
                    {config.integrity.hmac_configured && (
                      <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                    )}
                    <span className={`relative inline-flex rounded-full h-3 w-3 ${config.integrity.hmac_configured ? 'bg-emerald-500' : 'bg-amber-500'}`}></span>
                  </span>
                  <span className="text-xs font-bold text-slate-300 uppercase tracking-wider">
                    {config.integrity.hmac_configured ? 'Configured & Active' : 'Not Configured (Missing Secret)'}
                  </span>
                </div>
              </div>
            </div>
          </div>
        </Section>

        {/* 4. Data & Retention */}
        <Section title="Data & Retention" icon={HardDrive}>
          <div className="space-y-5 h-full flex flex-col justify-between">
            <div className="grid grid-cols-2 gap-4">
              <div className="p-5 bg-slate-950/50 rounded-lg border border-slate-800/50 text-center hover:bg-slate-900 transition-colors">
                <div className="text-3xl font-bold text-white mb-1.5">{config.data.event_count.toLocaleString()}</div>
                <div className="text-xs font-bold text-slate-500 uppercase tracking-widest">Total Events</div>
              </div>
              <div className="p-5 bg-slate-950/50 rounded-lg border border-slate-800/50 text-center hover:bg-slate-900 transition-colors">
                <div className="text-3xl font-bold text-rose-400 mb-1.5">{config.data.detection_count.toLocaleString()}</div>
                <div className="text-xs font-bold text-slate-500 uppercase tracking-widest">Total Detections</div>
              </div>
            </div>

            <div>
              <div className="text-sm font-medium text-slate-300 mb-2">Retention Policy</div>
              <div className="p-3.5 bg-slate-950 border border-slate-800 rounded-lg text-slate-300 text-sm font-mono">
                {config.data.retention_policy}
              </div>
            </div>
          </div>
        </Section>

        {/* 5. Application Preferences */}
        <Section title="Application Preferences" icon={Settings}>
          <div className="space-y-5 flex-1 flex flex-col">
            <div>
              <label htmlFor="theme-select" className="block text-sm font-medium text-slate-300 mb-2">UI Theme</label>
              <select 
                id="theme-select"
                value={theme}
                onChange={(e) => setTheme(e.target.value as 'dark' | 'light')}
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-4 py-2.5 text-sm text-white focus:outline-none focus:ring-2 focus:ring-indigo-500/50 focus:border-indigo-500 transition-shadow appearance-none"
              >
                <option value="dark">Dark Navy (SOC Standard)</option>
                <option value="light">Light Mode (Not recommended for SOC)</option>
              </select>
            </div>

            <div>
              <label htmlFor="landing-select" className="block text-sm font-medium text-slate-300 mb-2">Default Landing Page</label>
              <select 
                id="landing-select"
                value={landingPage}
                onChange={(e) => setLandingPage(e.target.value)}
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-4 py-2.5 text-sm text-white focus:outline-none focus:ring-2 focus:ring-indigo-500/50 focus:border-indigo-500 transition-shadow appearance-none"
              >

                <option value="dashboard">Dashboard Overview</option>
                <option value="phishing">Phishing Detection</option>
                <option value="intrusion">Intrusion Detection</option>
                <option value="logs">Event Logs</option>
              </select>
              <p className="text-[11px] text-slate-500 mt-2 leading-relaxed">
                Preferences are saved locally in your browser session and only apply to your current environment.
              </p>
            </div>

            <div className="pt-4 mt-auto">
              <button 
                onClick={savePreferences}
                className="w-full flex items-center justify-center gap-2 px-4 py-3 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg transition-all duration-200 text-sm font-bold shadow-[0_0_15px_rgba(79,70,229,0.3)] hover:shadow-[0_0_20px_rgba(79,70,229,0.5)]"
              >
                <Save className="w-4 h-4" />
                Save Preferences
              </button>
            </div>
          </div>
        </Section>
      </div>
    </div>
  );
};
