// IDS workspace: orchestrates the payload lab, results, packet analysis, threat
// intel, rule management and history. Self-contained (no DB / legacy contract).
import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Crosshair,
  FlaskConical,
  Sliders,
  History as HistoryIcon,
  RefreshCw,
  MessageSquareQuote,
  X,
} from 'lucide-react';
import {
  analyzePayload,
  extractError,
  fetchCatalog,
  fetchPresets,
  fetchRules,
  runPreset,
} from './api';
import type {
  CatalogCategory,
  IdsAnalysis,
  Preset,
  PresetRunResult,
  RuleMeta,
  Volume,
} from './types';
import { PayloadForm } from './PayloadForm';
import { DetectionResultsPanel } from './DetectionResultsPanel';
import { PacketAnalysisView } from './PacketAnalysisView';
import { ThreatIntelPanel } from './ThreatIntelPanel';
import { RuleManagementPanel } from './RuleManagementPanel';
import { HistoryPanel, HistoryEntry } from './HistoryPanel';
import { PresetRunView } from './PresetRunView';
import { SkeletonPanel } from './primitives';
import { PageHeader, Button, EmptyState, ErrorState } from '../ui';

type Tab = 'lab' | 'rules' | 'history';

interface WorkspaceProps {
  onAskChatbot?: (telemetryContext: Record<string, unknown>, promptMessage: string) => void;
}

export const IntrusionDetectionWorkspace: React.FC<WorkspaceProps> = ({ onAskChatbot }) => {
  // Reference data
  const [catalog, setCatalog] = useState<CatalogCategory[]>([]);
  const [presets, setPresets] = useState<Preset[]>([]);
  const [rules, setRules] = useState<RuleMeta[]>([]);
  const [loadingMeta, setLoadingMeta] = useState(true);
  const [metaError, setMetaError] = useState<string | null>(null);

  // Form state
  const [selectedAttackId, setSelectedAttackId] = useState<string>('');
  const [volume, setVolume] = useState<Volume>('medium');
  const [packetCount, setPacketCount] = useState<number>(20);
  const [sensitivity, setSensitivity] = useState<number>(0.5);
  const [ruleEnabled, setRuleEnabled] = useState<Record<string, boolean>>({});

  // Run state
  const [isRunning, setIsRunning] = useState(false);
  const [isPresetRunning, setIsPresetRunning] = useState(false);
  const [analysis, setAnalysis] = useState<IdsAnalysis | null>(null);
  const [presetRun, setPresetRun] = useState<PresetRunResult | null>(null);
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [showHelp, setShowHelp] = useState<boolean>(() => {
    try { return localStorage.getItem('ids_help_seen') !== '1'; } catch { return true; }
  });

  const [tab, setTab] = useState<Tab>('lab');

  // Load catalog / presets / rules once.
  useEffect(() => {
    let mounted = true;
    (async () => {
      setLoadingMeta(true);
      setMetaError(null);
      try {
        const [cat, pre, rl] = await Promise.all([fetchCatalog(), fetchPresets(), fetchRules()]);
        if (!mounted) return;
        setCatalog(cat);
        setPresets(pre);
        setRules(rl);
        // Default-select first non-baseline attack for a useful starting point.
        const firstAttack = cat.flatMap((c) => c.attacks)[0];
        if (firstAttack) setSelectedAttackId((cur) => cur || firstAttack.id);
      } catch (err) {
        if (mounted) setMetaError(extractError(err, 'Failed to load IDS reference data. Is the backend running?'));
      } finally {
        if (mounted) setLoadingMeta(false);
      }
    })();
    return () => { mounted = false; };
  }, []);

  const handleSubmit = useCallback(async () => {
    if (!selectedAttackId || isRunning || isPresetRunning) return;
    setIsRunning(true);
    setError(null);
    setPresetRun(null);
    try {
      const result = await analyzePayload(
        { attack_id: selectedAttackId, volume, packet_count: packetCount, sensitivity, seed: null },
        ruleEnabled,
      );
      setAnalysis(result);
      setTab('lab');
      setHistory((prev) => [
        { id: result.analysis_id + '_' + Date.now(), createdAt: Date.now(), analysis: result },
        ...prev,
      ].slice(0, 40));
    } catch (err) {
      setError(extractError(err, 'IDS analysis failed.'));
    } finally {
      setIsRunning(false);
    }
  }, [selectedAttackId, volume, packetCount, sensitivity, ruleEnabled, isRunning, isPresetRunning]);

  const handleRunPreset = useCallback(async (presetId: string) => {
    if (isRunning || isPresetRunning) return;
    setIsPresetRunning(true);
    setError(null);
    setAnalysis(null);
    setTab('lab');
    try {
      const result = await runPreset(presetId, volume, Math.max(packetCount, 15), sensitivity);
      setPresetRun(result);
    } catch (err) {
      setError(extractError(err, 'Preset run failed.'));
    } finally {
      setIsPresetRunning(false);
    }
  }, [volume, packetCount, sensitivity, isRunning, isPresetRunning]);

  // Rule hit counters derive from the current analysis.
  const hitCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    if (analysis) analysis.rules.triggered.forEach((r) => { counts[r.rule_id] = (counts[r.rule_id] ?? 0) + 1; });
    return counts;
  }, [analysis]);

  const handleToggleRule = useCallback((ruleId: string, enabled: boolean) => {
    setRuleEnabled((prev) => ({ ...prev, [ruleId]: enabled }));
  }, []);

  const handleResetRules = useCallback(() => setRuleEnabled({}), []);

  const handleSelectHistory = useCallback((entry: HistoryEntry) => {
    setAnalysis(entry.analysis);
    setPresetRun(null);
    setTab('lab');
  }, []);

  const dismissHelp = () => {
    setShowHelp(false);
    try { localStorage.setItem('ids_help_seen', '1'); } catch { /* ignore */ }
  };

  // Keyboard shortcut: Ctrl/Cmd+Enter submits.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') { e.preventDefault(); handleSubmit(); }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [handleSubmit]);

  const askCopilot = () => {
    if (!analysis || !onAskChatbot) return;
    const ctx = {
      module: 'ids',
      attack: analysis.attack.name,
      verdict: analysis.verdict.label,
      threat_score: analysis.verdict.threat_score,
      triggered_rules: analysis.rules.triggered.map((r) => r.name),
      kill_chain: analysis.kill_chain.current_label,
      mitre: analysis.mitre.map((m) => m.technique_id),
    };
    onAskChatbot(
      ctx,
      `Explain this IDS detection for "${analysis.attack.name}" (verdict ${analysis.verdict.label}, threat ${analysis.verdict.threat_score}) and recommend next steps.`,
    );
  };

  const tabs = (
    <div role="tablist" aria-label="IDS views" className="flex items-center gap-1 bg-panel p-1 rounded-panel border border-line">
      <TabButton active={tab === 'lab'} onClick={() => setTab('lab')} icon={<FlaskConical className="w-4 h-4" />} label="Payload Lab" />
      <TabButton active={tab === 'rules'} onClick={() => setTab('rules')} icon={<Sliders className="w-4 h-4" />} label={`Rules (${rules.length})`} />
      <TabButton active={tab === 'history'} onClick={() => setTab('history')} icon={<HistoryIcon className="w-4 h-4" />} label={`History (${history.length})`} />
    </div>
  );

  if (loadingMeta) {
    return (
      <div className="max-w-[1400px] mx-auto space-y-4">
        <PageHeader
          title="Intrusion Detection"
          description="Generate synthetic attack traffic, run a multi-layer rules engine and ML anomaly scoring."
          icon={<Crosshair className="w-5 h-5" />}
        />
        <div className="bg-panel border border-line rounded-panel p-6">
          <div className="flex items-center gap-2 text-xs text-accent-soft mb-4">
            <RefreshCw className="w-4 h-4 animate-spin" /> Loading attack catalog, presets and rule registry...
          </div>
          <SkeletonPanel lines={6} />
        </div>
      </div>
    );
  }

  if (metaError) {
    return (
      <div className="max-w-[1400px] mx-auto space-y-4">
        <PageHeader
          title="Intrusion Detection"
          description="Generate synthetic attack traffic, run a multi-layer rules engine and ML anomaly scoring."
          icon={<Crosshair className="w-5 h-5" />}
        />
        <ErrorState title="Could not reach the IDS service" message={metaError} />
      </div>
    );
  }

  return (
    <div className="w-full space-y-6 max-w-[1400px] mx-auto pb-20">
      <PageHeader
        title="Intrusion Detection"
        description="Generate synthetic attack traffic, run a multi-layer rules engine and ML anomaly scoring."
        icon={<Crosshair className="w-5 h-5" />}
        actions={tabs}
      />

      {showHelp && <HelpBanner onDismiss={dismissHelp} />}

      {error && <ErrorState title="Detection failed" message={error} />}

      {tab === 'lab' && (
        <>
          <PayloadForm
            catalog={catalog}
            presets={presets}
            selectedAttackId={selectedAttackId}
            volume={volume}
            packetCount={packetCount}
            sensitivity={sensitivity}
            isRunning={isRunning}
            isPresetRunning={isPresetRunning}
            onSelectAttack={setSelectedAttackId}
            onVolumeChange={setVolume}
            onPacketCountChange={setPacketCount}
            onSensitivityChange={setSensitivity}
            onSubmit={handleSubmit}
            onRunPreset={handleRunPreset}
          />

          {isRunning && (
            <div className="bg-panel border border-line rounded-panel p-6">
              <div className="flex items-center gap-2 text-xs text-accent-soft mb-4">
                <RefreshCw className="w-4 h-4 animate-spin" /> Generating packets, running rules & scoring anomalies...
              </div>
              <SkeletonPanel lines={6} />
            </div>
          )}

          {isPresetRunning && !presetRun && (
            <div className="bg-panel border border-accent/25 rounded-panel p-6 flex items-center gap-3">
              <RefreshCw className="w-5 h-5 animate-spin text-accent-soft" />
              <span className="text-sm text-accent-soft">Running multi-stage attack preset...</span>
            </div>
          )}

          {presetRun && !isPresetRunning && <PresetRunView run={presetRun} />}

          {!isRunning && analysis && !presetRun && (
            <div className="space-y-6">
              <div className="flex justify-end">
                {onAskChatbot && (
                  <Button variant="primary" size="sm" leftIcon={<MessageSquareQuote className="w-4 h-4" />} onClick={askCopilot}>
                    Ask Copilot about this detection
                  </Button>
                )}
              </div>
              <DetectionResultsPanel analysis={analysis} />
              <PacketAnalysisView analysis={analysis} />
              <ThreatIntelPanel analysis={analysis} />
            </div>
          )}

          {!isRunning && !analysis && !presetRun && !error && (
            <div className="rounded-panel border border-dashed border-line bg-panel/40">
              <EmptyState
                icon={<Crosshair className="w-10 h-10" />}
                title="No analysis yet"
                description="Select a payload type above and submit, or launch one of the quick-attack presets to watch a multi-stage intrusion unfold."
              />
            </div>
          )}
        </>
      )}

      {tab === 'rules' && (
        <RuleManagementPanel
          rules={rules}
          enabledMap={ruleEnabled}
          hitCounts={hitCounts}
          onChangeEnabled={handleToggleRule}
          onReset={handleResetRules}
        />
      )}

      {tab === 'history' && (
        <HistoryPanel
          history={history}
          currentId={analysis?.analysis_id ? history.find((h) => h.analysis.analysis_id === analysis.analysis_id)?.id : undefined}
          onSelect={handleSelectHistory}
          onClear={() => setHistory([])}
        />
      )}
    </div>
  );
};

// ---------------------------------------------------------------------------
const TabButton: React.FC<{ active: boolean; onClick: () => void; icon: React.ReactNode; label: string }> = ({
  active,
  onClick,
  icon,
  label,
}) => (
  <button
    type="button"
    role="tab"
    aria-selected={active}
    onClick={onClick}
    className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-accent/40 ${
      active ? 'bg-accent text-white' : 'text-ink-muted hover:text-ink'
    }`}
  >
    {icon}
    <span className="hidden sm:inline">{label}</span>
  </button>
);

const HelpBanner: React.FC<{ onDismiss: () => void }> = ({ onDismiss }) => (
  <div className="flex items-start gap-3 p-4 rounded-panel bg-accent/5 border border-accent/20">
    <div className="flex-1 text-xs text-ink-soft leading-relaxed">
      <span className="font-bold text-accent-soft uppercase tracking-wider">Getting started · </span>
      Pick an attack type (or launch a preset), tune traffic volume and detection sensitivity, then submit.
      The <b>Payload Lab</b> shows verdicts &amp; packet analysis, the <b>Rules</b> tab lets you toggle/tune the detection
      registry, and <b>History</b> stores this session for side-by-side comparison. Press{' '}
      <kbd className="px-1.5 py-0.5 rounded bg-elevated border border-line-strong font-mono text-[10px]">Ctrl/⌘ + Enter</kbd> to submit.
    </div>
    <Button variant="ghost" size="sm" onClick={onDismiss} aria-label="Dismiss getting started help" className="shrink-0">
      <X className="w-4 h-4" />
    </Button>
  </div>
);
