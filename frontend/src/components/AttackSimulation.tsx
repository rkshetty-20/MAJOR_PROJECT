import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  Play,
  RefreshCw,
  Zap,
  CheckCircle2,
  AlertTriangle,
  MessageSquare,
  Info,
  Sparkles,
} from 'lucide-react';
import api, { getSimulationRecommendation, AdaptiveRecommendation } from '../api';
import { Button, Mono } from './ui';

export interface SimulationFlowStep {
  step: string;
  status: string;
  count?: number;
  detections?: number;
  score?: number;
  band?: string;
}

export interface SimulationResult {
  simulation_id: string;
  scenario: string;
  scenario_name: string;
  session_id: number;
  events_generated: number;
  status: string;
  detections_count: number;
  detections: Array<{
    id: number;
    source: string;
    label: string;
    confidence: number;
    explanation: string;
  }>;
  risk: {
    score: number;
    band: string;
    contributing_factors?: Record<string, unknown>;
  };
  triggered_rules: string[];
  mitigation: string;
  simulation_flow: Array<SimulationFlowStep>;
}

interface AttackSimulationProps {
  onSimulationCompleted: (result: SimulationResult) => void;
  onAskChatbot: (telemetryContext: Record<string, unknown>, promptMessage: string) => void;
  onViewAttackAnatomy?: () => void;
}

const SCENARIOS = [
  { id: 'brute_force', name: 'Brute Force Login', category: 'Auth' },
  { id: 'credential_stuffing', name: 'Credential Stuffing', category: 'Auth' },
  { id: 'suspicious_login', name: 'Suspicious Login / Account Takeover', category: 'Behavioral' },
  { id: 'impossible_travel', name: 'Impossible Travel Anomaly', category: 'Geo' },
  { id: 'new_device', name: 'New Device Login', category: 'Endpoint' },
  { id: 'phishing_url', name: 'Phishing URL Simulation', category: 'Web' },
  { id: 'port_scan', name: 'Port Scan Event Simulation', category: 'Network' },
  { id: 'anomalous_login_time', name: 'Anomalous Login Time', category: 'Temporal' },
  { id: 'multiple_failed_logins', name: 'Multiple Failed Login Attempts', category: 'Auth' },
  { id: 'combined_multi_signal', name: 'Combined Multi-Signal Attack', category: 'Compound' },
];

export const AttackSimulation: React.FC<AttackSimulationProps> = ({
  onSimulationCompleted,
  onAskChatbot,
  onViewAttackAnatomy,
}) => {
  const [selectedScenario, setSelectedScenario] = useState('brute_force');
  const [intensity, setIntensity] = useState<'low' | 'medium' | 'high'>('medium');
  const [customEventCount, setCustomEventCount] = useState<number>(8);
  const [isRunning, setIsRunning] = useState(false);
  const [currentStepIndex, setCurrentStepIndex] = useState<number>(0);
  const [simulationResult, setSimulationResult] = useState<SimulationResult | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [recommendation, setRecommendation] = useState<AdaptiveRecommendation | null>(null);
  const [loadingRecommendation, setLoadingRecommendation] = useState(false);

  const fetchRecommendation = async () => {
    setLoadingRecommendation(true);
    try {
      const res = await getSimulationRecommendation('simulation_operator');
      setRecommendation(res.data);
    } catch (e) {
      console.error("Failed to fetch adaptive recommendation:", e);
    } finally {
      setLoadingRecommendation(false);
    }
  };

  useEffect(() => {
    fetchRecommendation();
  }, []);

  const applyRecommendation = () => {
    if (!recommendation) return;
    setSelectedScenario(recommendation.recommended_scenario);
    setIntensity(recommendation.recommended_intensity);
    const count = recommendation.recommended_intensity === 'low' ? 4 : recommendation.recommended_intensity === 'medium' ? 8 : 18;
    setCustomEventCount(count);
  };

  const PROGRESS_STEPS = [
    "Preparing simulation environment...",
    "Generating synthetic security events...",
    "Sending events to detection engine (Rule + ML)...",
    "Fusing multi-signal risk telemetry...",
    "Completed.",
  ];

  const handleRunSimulation = async () => {
    if (isRunning) return;
    setIsRunning(true);
    setErrorMessage(null);
    setCurrentStepIndex(0);

    // Simulate animated step transitions for realistic SOC user experience
    const stepInterval = setInterval(() => {
      setCurrentStepIndex((prev) => (prev < PROGRESS_STEPS.length - 2 ? prev + 1 : prev));
    }, 450);

    try {
      const response = await api.post<SimulationResult>('/api/simulation/run', {
        scenario: selectedScenario,
        intensity: intensity,
        event_count: customEventCount,
      });

      clearInterval(stepInterval);
      setCurrentStepIndex(PROGRESS_STEPS.length - 1);
      setSimulationResult(response.data);
      onSimulationCompleted(response.data);
      fetchRecommendation(); // Auto-refresh adaptive recommendation based on new outcome
    } catch (err: unknown) {
      clearInterval(stepInterval);
      console.error("Simulation run error:", err);
      let msg = "Failed to complete simulation. Please verify backend is running.";
      if (typeof err === 'object' && err !== null && 'response' in err) {
        const resp = (err as { response?: { data?: { detail?: string } } }).response;
        if (resp?.data?.detail) msg = resp.data.detail;
      }
      setErrorMessage(msg);
    } finally {
      setIsRunning(false);
    }
  };

  const getRiskBadgeColor = (band: string) => {
    switch (band?.toUpperCase()) {
      case 'CRITICAL':
        return 'bg-rose-500/20 text-rose-300 border-rose-500/30';
      case 'HIGH':
        return 'bg-amber-500/20 text-amber-300 border-amber-500/30';
      case 'MEDIUM':
        return 'bg-sky-500/20 text-sky-300 border-sky-500/30';
      default:
        return 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30';
    }
  };

  return (
    <div className="w-full bg-panel/90 border border-line rounded-panel shadow-raised backdrop-blur-xl overflow-hidden transition-all duration-300 hover:border-line-strong">
      {/* Header */}
      <div className="px-6 py-4 border-b border-line bg-app/60 flex items-center justify-between flex-wrap gap-2">
        <div className="flex items-center gap-2.5">
          <div className="p-2 rounded-lg bg-accent/10 border border-accent/20 text-accent-soft">
            <Zap className="w-4 h-4 text-accent-soft" />
          </div>
          <div>
            <h2 className="text-sm font-bold text-ink tracking-wide uppercase">
              Controlled Attack Simulator
            </h2>
            <p className="text-xs text-ink-muted">
              Generate safe synthetic security events to test detection &amp; risk engines
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            id="btn-load-recommendation"
            onClick={fetchRecommendation}
            disabled={loadingRecommendation || isRunning}
            className="inline-flex items-center gap-1.5 px-3 py-1 rounded-pill text-[11px] font-medium bg-accent/15 text-accent-soft border border-accent/30 hover:bg-accent/25 transition-all cursor-pointer disabled:opacity-50"
            title="Refresh adaptive recommendation based on previous simulation outcomes"
          >
            <Sparkles className={`w-3.5 h-3.5 ${loadingRecommendation ? 'animate-spin' : ''}`} />
            {loadingRecommendation ? 'Loading...' : 'Adaptive Rec'}
          </button>
          <div className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-pill text-[11px] font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
            Zero Real-World Exploitation (Sandbox Mode)
          </div>
        </div>
      </div>

      <div className="p-6 space-y-6">
        {/* Adaptive Recommendation Banner */}
        {recommendation && (
          <div className="p-3.5 rounded-card bg-accent/10 border border-accent/25 flex items-center justify-between gap-3 flex-wrap">
            <div className="flex items-start gap-2.5">
              <Sparkles className="w-4 h-4 text-accent-soft mt-0.5 shrink-0" />
              <div>
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-xs font-bold text-accent-soft uppercase tracking-wider">
                    Adaptive Next Scenario:
                  </span>
                  <span className="text-xs font-semibold text-ink">
                    {recommendation.scenario_name}
                  </span>
                  <span className="px-1.5 py-0.5 rounded text-[10px] font-mono uppercase bg-accent/20 text-accent-soft border border-accent/30">
                    {recommendation.recommended_intensity}
                  </span>
                  <span className="text-[11px] text-ink-muted">
                    ({recommendation.coverage_summary.tested_scenarios}/{recommendation.coverage_summary.total_scenarios} scenarios tested)
                  </span>
                </div>
                <p className="text-xs text-ink-muted mt-0.5">
                  {recommendation.rationale}
                </p>
              </div>
            </div>
            <button
              type="button"
              id="btn-apply-recommendation"
              onClick={applyRecommendation}
              disabled={isRunning}
              className="px-3 py-1.5 text-xs font-semibold rounded-lg bg-accent text-white hover:bg-accent/90 transition-all cursor-pointer shrink-0 shadow-sm"
            >
              Apply Recommendation
            </button>
          </div>
        )}
        {/* Controls Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          {/* Scenario Selector */}
          <div>
            <label htmlFor="simulation-scenario-select" className="block text-xs font-semibold uppercase tracking-wider text-ink-soft mb-1.5">
              Attack Scenario
            </label>
            <select
              id="simulation-scenario-select"
              value={selectedScenario}
              onChange={(e) => setSelectedScenario(e.target.value)}
              disabled={isRunning}
              className="w-full bg-app border border-line-strong rounded-card px-3.5 py-2 text-sm text-ink focus:outline-none focus:ring-2 focus:ring-accent/50 disabled:opacity-50"
            >
              {SCENARIOS.map((sc) => (
                <option key={sc.id} value={sc.id}>
                  {sc.name} ({sc.category})
                </option>
              ))}
            </select>
          </div>

          {/* Intensity Selector */}
          <div>
            <span className="block text-xs font-semibold uppercase tracking-wider text-ink-soft mb-1.5">
              Intensity Level
            </span>
            <div className="grid grid-cols-3 gap-1 bg-app p-1 rounded-card border border-line-strong" role="group" aria-label="Intensity level">
              {(['low', 'medium', 'high'] as const).map((level) => (
                <button
                  key={level}
                  type="button"
                  aria-pressed={intensity === level}
                  onClick={() => {
                    setIntensity(level);
                    setCustomEventCount(level === 'low' ? 4 : level === 'medium' ? 8 : 18);
                  }}
                  disabled={isRunning}
                  className={`py-1.5 text-xs font-medium rounded-lg capitalize transition-all duration-base cursor-pointer ${
                    intensity === level
                      ? 'bg-accent text-white shadow-sm'
                      : 'text-ink-muted hover:text-ink'
                  }`}
                >
                  {level}
                </button>
              ))}
            </div>
          </div>

          {/* Events Count */}
          <div>
            <div className="flex justify-between items-center mb-1.5">
              <label htmlFor="simulation-event-count" className="text-xs font-semibold uppercase tracking-wider text-ink-soft">
                Synthetic Events Count
              </label>
              <span className="text-xs font-mono text-accent-soft font-bold">
                {customEventCount} events
              </span>
            </div>
            <input
              id="simulation-event-count"
              type="range"
              min="1"
              max="50"
              value={customEventCount}
              aria-label="Synthetic events count"
              onChange={(e) => setCustomEventCount(parseInt(e.target.value))}
              disabled={isRunning}
              className="w-full h-2 bg-elevated rounded-lg appearance-none cursor-pointer accent-accent"
            />
            <div className="flex justify-between text-[10px] text-ink-faint mt-1 font-mono">
              <span>1 event</span>
              <span>25 events</span>
              <span>50 events</span>
            </div>
          </div>
        </div>

        {/* Trigger Button & Status Stepper */}
        <div className="flex flex-col sm:flex-row items-center justify-between gap-4 p-4 rounded-card bg-app/60 border border-line">
          <div className="flex-1 w-full sm:w-auto">
            {isRunning ? (
              <div className="space-y-1.5">
                <div className="flex items-center gap-2 text-xs text-accent-soft font-medium">
                  <RefreshCw className="w-3.5 h-3.5 animate-spin text-accent-soft" />
                  <span role="status">{PROGRESS_STEPS[currentStepIndex]}</span>
                </div>
                <div
                  className="w-full bg-elevated h-1.5 rounded-full overflow-hidden"
                  role="progressbar"
                  aria-valuemin={1}
                  aria-valuemax={PROGRESS_STEPS.length}
                  aria-valuenow={currentStepIndex + 1}
                  aria-label="Simulation progress"
                >
                  <div
                    className="bg-accent h-full transition-all duration-slow"
                    style={{ width: `${((currentStepIndex + 1) / PROGRESS_STEPS.length) * 100}%` }}
                  />
                </div>
              </div>
            ) : (
              <div className="flex flex-col gap-1">
                <div className="flex items-center gap-2 text-xs font-bold text-ink-muted uppercase tracking-wider">
                  <Info className="w-4 h-4 text-ink-faint shrink-0" />
                  SIMULATION FLOW
                </div>
                <span className="text-xs text-ink-faint pl-6">
                  Conceptual representation of how the attack moves through AOD-IPS. Triggers synthetic telemetry, fires rules, and executes risk fusion.
                </span>
              </div>
            )}
          </div>

          <Button
            id="run-simulation-btn"
            variant="primary"
            size="lg"
            onClick={handleRunSimulation}
            disabled={isRunning}
            loading={isRunning}
            leftIcon={!isRunning ? <Play className="w-4 h-4 fill-white" /> : undefined}
            className="w-full sm:w-auto shrink-0"
          >
            {isRunning ? 'Simulating...' : 'Run Simulation'}
          </Button>
        </div>

        {/* Error Notice */}
        {errorMessage && (
          <div role="alert" className="p-3.5 rounded-card bg-rose-500/10 border border-rose-500/20 text-rose-300 text-xs flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            <span>Simulation Error: {errorMessage}</span>
          </div>
        )}

        {/* Live Simulation Feedback Card */}
        {simulationResult && (
          <div className="p-5 rounded-card bg-app/80 border border-accent/30 space-y-4 animate-fade-in shadow-raised">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-line pb-3">
              <div>
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  <span className="text-xs font-semibold text-emerald-400 uppercase tracking-wider">
                    Simulation Completed Successfully
                  </span>
                  <span className="text-[10px] text-ink-faint">
                    ID: <Mono>{simulationResult.simulation_id}</Mono>
                  </span>
                </div>
                <h3 className="text-base font-bold text-ink mt-0.5">
                  {simulationResult.scenario_name}
                </h3>
              </div>

              <div className="flex items-center gap-2">
                <span className={`inline-flex items-center px-3 py-1 rounded-pill text-xs font-bold border ${getRiskBadgeColor(simulationResult.risk.band)}`}>
                  Risk: {simulationResult.risk.band.toUpperCase()}
                </span>
                <span className="px-3 py-1 rounded-pill text-xs font-bold bg-elevated text-ink border border-line-strong font-mono">
                  Score: {simulationResult.risk.score}/100
                </span>
              </div>
            </div>

            {/* Quick Metrics */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
              <div className="p-3 rounded-lg bg-panel border border-line">
                <span className="text-ink-muted block mb-0.5">Synthetic Events</span>
                <span className="font-bold text-ink font-mono text-sm">
                  {simulationResult.events_generated} generated
                </span>
              </div>
              <div className="p-3 rounded-lg bg-panel border border-line">
                <span className="text-ink-muted block mb-0.5">Detections Fired</span>
                <span className="font-bold text-amber-400 font-mono text-sm">
                  {simulationResult.detections_count} triggered
                </span>
              </div>
              <div className="p-3 rounded-lg bg-panel border border-line">
                <span className="text-ink-muted block mb-0.5">Session Reference</span>
                <span className="font-bold text-ink-soft font-mono text-sm">
                  Session #{simulationResult.session_id}
                </span>
              </div>
              <div className="p-3 rounded-lg bg-panel border border-line">
                <span className="text-ink-muted block mb-0.5">Engine Consensus</span>
                <span className="font-bold text-accent-soft font-mono text-sm">
                  Rules + Risk Fusion
                </span>
              </div>
            </div>

            {/* Triggered Rules List */}
            {simulationResult.triggered_rules.length > 0 && (
              <div className="space-y-1.5">
                <span className="text-xs font-semibold text-ink-muted uppercase tracking-wider block">
                  Triggered Detection Rules:
                </span>
                <div className="flex flex-wrap gap-1.5">
                  {simulationResult.triggered_rules.map((rule, idx) => (
                    <span
                      key={idx}
                      className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-xs font-mono bg-accent/10 text-accent-soft border border-accent/20"
                    >
                      <ShieldAlert className="w-3 h-3 text-accent-soft" />
                      {rule}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Mitigation & Chatbot Trigger */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pt-2 border-t border-line">
              <div className="text-xs text-ink-soft">
                <span className="font-semibold text-ink-muted">SOC Mitigation Guidance: </span>
                {simulationResult.mitigation}
              </div>

              <div className="flex gap-2 w-full sm:w-auto">
                {onViewAttackAnatomy && (
                  <button
                    type="button"
                    onClick={onViewAttackAnatomy}
                    className="inline-flex flex-1 sm:flex-none justify-center items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-medium text-xs transition-colors duration-base cursor-pointer shadow-sm active:scale-95"
                  >
                    View Attack Anatomy
                  </button>
                )}

                <Button
                  type="button"
                  variant="primary"
                  size="sm"
                  className="shrink-0"
                  leftIcon={<MessageSquare className="w-3.5 h-3.5" />}
                  onClick={() => {
                    const telemetryContext = {
                      event_type: simulationResult.scenario,
                      simulation_id: simulationResult.simulation_id,
                      session_id: simulationResult.session_id,
                      scenario_name: simulationResult.scenario_name,
                      events_generated: simulationResult.events_generated,
                      risk_score: simulationResult.risk.score,
                      risk_level: simulationResult.risk.band,
                      triggered_rules: simulationResult.triggered_rules,
                      mitigation_guidance: simulationResult.mitigation,
                    };
                    const prompt = `Explain why the ${simulationResult.scenario_name} simulation was flagged as ${simulationResult.risk.band.toUpperCase()} risk with score ${simulationResult.risk.score}/100 and what defensive actions should be taken.`;
                    onAskChatbot(telemetryContext, prompt);
                  }}
                >
                  Ask Security Assistant
                </Button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
