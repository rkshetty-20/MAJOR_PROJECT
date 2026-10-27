import React from 'react';
import {
  LayoutDashboard,
  ShieldAlert,
  Crosshair,
  Play,
  ActivitySquare,
  Brain,
  MessageSquare,
  List,
  Settings,
  Shield,
  Server,
  RefreshCw,
  Sparkles,
} from 'lucide-react';

export type PageId =
  | 'dashboard'
  | 'intrusion'
  | 'phishing'
  | 'simulation'
  | 'studio'
  | 'visualization'
  | 'adaptive'
  | 'copilot'
  | 'logs'
  | 'settings';

export type ConnectionState = 'checking' | 'connected' | 'degraded' | 'disconnected';
export type SubsystemState = 'ready' | 'unavailable' | 'unknown';

interface SidebarProps {
  activePage: PageId;
  onNavigate: (page: PageId) => void;
  connectionState: ConnectionState;
  responseTime: number | null;
  onPing: () => void;
  apiUrl: string;
  // Optional per-service health (Phase 3.3). When omitted (e.g. unit tests),
  // only the overall connectivity indicator is shown.
  mlStatus?: SubsystemState;
  integrityStatus?: SubsystemState;
}

const CONN_META: Record<ConnectionState, { label: string; dot: string }> = {
  checking: { label: 'Checking', dot: 'bg-warning animate-pulse' },
  connected: { label: 'Connected', dot: 'bg-success' },
  degraded: { label: 'Degraded', dot: 'bg-warning' },
  disconnected: { label: 'Disconnected', dot: 'bg-danger' },
};

const SUBSYS_META: Record<SubsystemState, { label: string; dot: string }> = {
  ready: { label: 'Ready', dot: 'bg-success' },
  unavailable: { label: 'Unavailable', dot: 'bg-danger' },
  unknown: { label: 'Unknown', dot: 'bg-ink-faint' },
};

export const Sidebar: React.FC<SidebarProps> = ({
  activePage,
  onNavigate,
  connectionState,
  responseTime,
  onPing,
  apiUrl,
  mlStatus,
  integrityStatus,
}) => {
  const NavItem = ({ id, icon: Icon, label }: { id: PageId; icon: React.ComponentType<{ className?: string }>; label: string }) => {
    const isActive = activePage === id;
    return (
      <button
        type="button"
        onClick={() => onNavigate(id)}
        aria-current={isActive ? 'page' : undefined}
        className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-colors duration-base focus:outline-none ${
          isActive
            ? 'bg-accent/15 text-accent-soft'
            : 'text-ink-muted hover:text-ink hover:bg-elevated/60'
        }`}
      >
        <Icon className={`w-4 h-4 ${isActive ? 'text-accent-soft' : 'text-ink-faint'}`} />
        <span className="truncate">{label}</span>
      </button>
    );
  };

  const NavGroup = ({ title, children }: { title: string; children: React.ReactNode }) => (
    <nav aria-label={title} className="mb-6">
      <div className="px-3 mb-2 text-[10px] font-bold text-ink-faint uppercase tracking-wider">
        {title}
      </div>
      <div className="space-y-1">{children}</div>
    </nav>
  );

  const SubsystemRow = ({ name, state }: { name: string; state: SubsystemState }) => {
    const meta = SUBSYS_META[state];
    return (
      <div className="flex items-center justify-between gap-2 px-1">
        <span className="text-[10px] text-ink-faint uppercase tracking-wide">{name}</span>
        <span className="inline-flex items-center gap-1.5 text-[10px] text-ink-soft">
          <span className={`w-1.5 h-1.5 rounded-full ${meta.dot}`} aria-hidden />
          {meta.label}
        </span>
      </div>
    );
  };

  const conn = CONN_META[connectionState];

  return (
    <div className="w-64 h-full bg-surface border-r border-line flex flex-col hidden md:flex shrink-0">
      {/* Brand Header */}
      <div className="p-4 border-b border-line/80">
        <div className="flex items-center gap-3 px-2">
          <div className="p-1.5 rounded-lg bg-accent/10 border border-accent/20 text-accent-soft shadow-panel">
            <Shield className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-sm font-bold text-ink tracking-wide">AOD-IPS</h2>
            <p className="text-[10px] text-ink-muted uppercase tracking-widest">Adaptive SOC Platform</p>
          </div>
        </div>
      </div>

      {/* Navigation */}
      <div className="flex-1 overflow-y-auto py-4 px-3 custom-scrollbar">
        <NavGroup title="Overview">
          <NavItem id="dashboard" icon={LayoutDashboard} label="Dashboard" />
        </NavGroup>

        <NavGroup title="Detection">
          <NavItem id="intrusion" icon={Crosshair} label="Intrusion Detection" />
          <NavItem id="phishing" icon={ShieldAlert} label="Phishing Detection" />
        </NavGroup>

        <NavGroup title="Operations">
          <NavItem id="simulation" icon={Play} label="Attack Simulation" />
          <NavItem id="studio" icon={Sparkles} label="Scenario Studio" />
          <NavItem id="visualization" icon={ActivitySquare} label="Visualization & Investigation" />
        </NavGroup>

        <NavGroup title="Intelligence">
          <NavItem id="adaptive" icon={Brain} label="Adaptive Learning" />
          <NavItem id="copilot" icon={MessageSquare} label="Security Copilot" />
        </NavGroup>

        <NavGroup title="System">
          <NavItem id="logs" icon={List} label="Event Logs" />
          <NavItem id="settings" icon={Settings} label="Settings" />
        </NavGroup>
      </div>

      {/* Connection Status Footer */}
      <div className="p-4 border-t border-line/80 bg-elevated/30" role="status" aria-live="polite">
        <div className="flex items-center justify-between mb-2">
          <div className="flex items-center gap-2">
            <Server className={`w-3.5 h-3.5 ${connectionState === 'connected' ? 'text-success' : connectionState === 'disconnected' ? 'text-danger' : 'text-warning'}`} />
            <span className="text-[11px] font-medium text-ink-soft">Backend Status</span>
          </div>
          <button
            type="button"
            onClick={onPing}
            disabled={connectionState === 'checking'}
            aria-label="Re-check backend connection"
            className="text-ink-faint hover:text-ink transition-colors focus:outline-none"
          >
            <RefreshCw className={`w-3 h-3 ${connectionState === 'checking' ? 'animate-spin' : ''}`} />
          </button>
        </div>
        <div className="flex items-center justify-between gap-2 px-1 mb-1">
          <span className="inline-flex items-center gap-1.5 text-[11px] font-semibold text-ink-soft">
            <span className={`w-2 h-2 rounded-full ${conn.dot}`} aria-hidden />
            {conn.label}
          </span>
          <span className="text-[10px] text-ink-faint">
            {connectionState === 'connected' || connectionState === 'degraded' ? `${responseTime ?? '--'}ms` : 'Offline'}
          </span>
        </div>
        <div className="text-[10px] text-ink-faint px-1 mb-2">
          <span className="truncate block" title={apiUrl}>{apiUrl.replace('http://', '')}</span>
        </div>

        {(mlStatus || integrityStatus) && (
          <div className="space-y-1 pt-2 mt-1 border-t border-line/60">
            {mlStatus && <SubsystemRow name="ML Engine" state={mlStatus} />}
            {integrityStatus && <SubsystemRow name="Evidence Integrity" state={integrityStatus} />}
          </div>
        )}

        <div className="mt-3 py-1 text-center rounded bg-warning/10 border border-warning/20 text-warning/90 text-[10px] font-bold uppercase tracking-widest">
          Simulation Mode
        </div>
      </div>
    </div>
  );
};
