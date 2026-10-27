import React from 'react';
import { AttackSimulation, SimulationResult } from './AttackSimulation';
import { SyntheticDataGenerator } from './SyntheticDataGenerator';
import { Play, Database, Download, Copy, RefreshCw, CheckCircle2, AlertTriangle } from 'lucide-react';
import api from '../api';
import { PageHeader, Button, Mono } from './ui';

interface AttackSimulationPageProps {
  activeSimulationResult: SimulationResult | null;
  activeSimulationId: string | null;
  activeScenarioName: string | undefined;
  onSimulationCompleted: (result: SimulationResult) => void;
  onAskChatbot: (telemetryContext: Record<string, unknown>, promptMessage: string) => void;
  onInvestigateDetection: (id: number) => void;
  onVisualizeReplay?: (datasetId: string, evalRunId: string, metrics: any, detections: number) => void;
}

export const AttackSimulationPage: React.FC<AttackSimulationPageProps> = ({
  onSimulationCompleted,
  onAskChatbot,
  onInvestigateDetection,
  onVisualizeReplay
}) => {
  const [dsScenario, setDsScenario] = React.useState('port_scan');
  const [dsIntensity, setDsIntensity] = React.useState('medium');
  const [dsCount, setDsCount] = React.useState(10);
  const [dataset, setDataset] = React.useState<any>(null);
  const [dsGenerating, setDsGenerating] = React.useState(false);
  const [dsMessage, setDsMessage] = React.useState<{type: 'success'|'error', text: string} | null>(null);

  const handleGenerateDs = async () => {
    setDsGenerating(true);
    setDsMessage(null);
    try {
      const response = await api.post('/api/datasets/generate', {
        scenario: dsScenario,
        intensity: dsIntensity,
        event_count: dsCount
      });
      setDataset(response.data);
      setDsMessage({ type: 'success', text: `Dataset ${response.data.id} generated successfully.` });
    } catch (err: any) {
      setDsMessage({ type: 'error', text: err.response?.data?.detail || err.message || 'Generation failed' });
    } finally {
      setDsGenerating(false);
    }
  };

  const copyDsJSON = () => {
    if (!dataset) return;
    navigator.clipboard.writeText(JSON.stringify(dataset.payload_json, null, 2));
    setDsMessage({ type: 'success', text: 'Copied dataset JSON to clipboard.' });
  };

  const exportDsJSON = async () => {
    if (!dataset) return;
    try {
      const response = await api.get(`/api/datasets/${dataset.id}/export`);
      const dataStr = JSON.stringify(response.data, null, 2);
      const dataUri = 'data:application/json;charset=utf-8,' + encodeURIComponent(dataStr);
      const linkElement = document.createElement('a');
      linkElement.setAttribute('href', dataUri);
      linkElement.setAttribute('download', `dataset_${dataset.id}.json`);
      linkElement.click();
    } catch (err: any) {
      setDsMessage({ type: 'error', text: 'Export failed' });
    }
  };

  const handleReplay = async () => {
    if (!dataset) return;
    setDsMessage(null);
    try {
      const res = await api.post(`/api/datasets/${dataset.id}/replay`);
      setDataset({ ...dataset, replayResult: res.data });
      setDsMessage({
        type: 'success',
        text: `Replay successful. F1 Score: ${res.data.metrics.f1_score.toFixed(2)} (${res.data.detections} detections)`
      });
    } catch (e: any) {
      setDsMessage({ type: 'error', text: 'Replay failed' });
    }
  };

  return (
    <div className="w-full space-y-8 max-w-[1400px] mx-auto pb-20">
      <PageHeader
        title="Attack Simulation"
        description="Configure and execute supported synthetic attack scenarios and view telemetry."
        icon={<Play className="w-5 h-5" />}
      />

      <div id="attack-simulation-section">
        <AttackSimulation
          onSimulationCompleted={onSimulationCompleted}
          onAskChatbot={onAskChatbot}
          onViewAttackAnatomy={() => onInvestigateDetection(0)} // Triggers visualize via App.tsx callback
        />

        {/* Phase 2/3 Dataset Generator */}
        <div className="w-full bg-panel border border-line rounded-panel overflow-hidden mt-8">
          <div className="px-6 py-4 border-b border-line bg-app/60 flex items-center gap-3">
            <div className="p-2 rounded-lg bg-accent/10 border border-accent/20 text-accent-soft">
              <Database className="w-4 h-4 text-accent-soft" />
            </div>
            <div>
              <h2 className="text-sm font-bold text-ink uppercase tracking-wide">Phase 3: Raw Dataset Generator</h2>
              <p className="text-xs text-ink-muted">Generate, copy, and export deterministic event schemas for replay testing.</p>
            </div>
          </div>

          <div className="p-6 space-y-6">
            <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
              <div className="sm:col-span-1">
                <label htmlFor="ds-scenario" className="block text-xs font-semibold uppercase tracking-wider text-ink-soft mb-1.5">Scenario</label>
                <select
                  id="ds-scenario"
                  aria-label="Dataset scenario"
                  value={dsScenario}
                  onChange={e => setDsScenario(e.target.value)}
                  className="w-full bg-app border border-line-strong rounded-lg px-3 py-2 text-sm text-ink focus:outline-none focus:ring-2 focus:ring-accent/50"
                >
                  <option value="port_scan">Port Scan</option>
                  <option value="brute_force">Brute Force</option>
                  <option value="credential_stuffing">Credential Stuffing</option>
                </select>
              </div>

              <div className="sm:col-span-1">
                <label htmlFor="ds-intensity" className="block text-xs font-semibold uppercase tracking-wider text-ink-soft mb-1.5">Intensity</label>
                <select
                  id="ds-intensity"
                  aria-label="Dataset intensity"
                  value={dsIntensity}
                  onChange={e => setDsIntensity(e.target.value)}
                  className="w-full bg-app border border-line-strong rounded-lg px-3 py-2 text-sm text-ink focus:outline-none focus:ring-2 focus:ring-accent/50"
                >
                  <option value="low">Low</option>
                  <option value="medium">Medium</option>
                  <option value="high">High</option>
                </select>
              </div>

              <div className="sm:col-span-1">
                <label htmlFor="ds-count" className="block text-xs font-semibold uppercase tracking-wider text-ink-soft mb-1.5">Event Count</label>
                <input
                  id="ds-count"
                  aria-label="Dataset event count"
                  type="number"
                  min="1"
                  max="100"
                  value={dsCount}
                  onChange={e => setDsCount(parseInt(e.target.value))}
                  className="w-full bg-app border border-line-strong rounded-lg px-3 py-2 text-sm text-ink focus:outline-none focus:ring-2 focus:ring-accent/50"
                />
              </div>

              <div className="sm:col-span-1 flex items-end">
                <Button
                  variant="primary"
                  onClick={handleGenerateDs}
                  disabled={dsGenerating}
                  loading={dsGenerating}
                  leftIcon={<RefreshCw className="w-4 h-4" />}
                  fullWidth
                >
                  Generate Dataset
                </Button>
              </div>
            </div>

            {dsMessage && (
              <div
                role={dsMessage.type === 'error' ? 'alert' : 'status'}
                className={`p-4 rounded-card flex items-center gap-3 ${dsMessage.type === 'error' ? 'bg-rose-500/10 border border-rose-500/20 text-rose-300' : 'bg-emerald-500/10 border border-emerald-500/20 text-emerald-300'}`}
              >
                {dsMessage.type === 'error' ? <AlertTriangle className="w-5 h-5 shrink-0" /> : <CheckCircle2 className="w-5 h-5 shrink-0" />}
                <span className="text-sm font-medium">{dsMessage.text}</span>
              </div>
            )}

            {dataset && (
              <div className="space-y-4">
                <div className="flex justify-between items-center bg-elevated/50 p-4 rounded-card border border-line">
                  <div>
                    <span className="text-xs text-ink-muted block mb-1">DATASET ID</span>
                    <Mono className="text-emerald-400">{dataset.id}</Mono>
                  </div>
                  <div className="text-right">
                    <span className="text-xs text-ink-muted block mb-1">EVENTS</span>
                    <span className="font-mono text-sm text-ink-soft">{dataset.events_count}</span>
                  </div>
                </div>

                <div className="flex gap-2 mt-4 flex-wrap">
                  <Button
                    variant="secondary"
                    onClick={copyDsJSON}
                    leftIcon={<Copy className="w-4 h-4" />}
                    className="flex-1 min-w-[200px]"
                  >
                    Copy JSON
                  </Button>
                  <Button
                    variant="secondary"
                    onClick={exportDsJSON}
                    leftIcon={<Download className="w-4 h-4" />}
                    className="flex-1 min-w-[200px]"
                  >
                    Download Dataset
                  </Button>
                  <Button
                    variant="primary"
                    onClick={handleReplay}
                    leftIcon={<Play className="w-4 h-4" />}
                    className="flex-1 min-w-[200px]"
                  >
                    Run Detection Replay
                  </Button>
                  {dataset.replayResult && onVisualizeReplay && (
                    <button
                      type="button"
                      onClick={() => {
                        const res = dataset.replayResult;
                        onVisualizeReplay(dataset.id, res.eval_run_id, res.metrics, res.detections);
                      }}
                      className="inline-flex items-center justify-center gap-2 px-4 py-2 w-full mt-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-sm font-bold transition-colors duration-base shadow-lg shadow-emerald-600/20 cursor-pointer active:scale-95"
                    >
                      <Play className="w-4 h-4" /> Visualize &amp; Investigate Replay
                    </button>
                  )}
                </div>
              </div>
            )}
          </div>
        </div>

        <SyntheticDataGenerator />
      </div>
    </div>
  );
};
