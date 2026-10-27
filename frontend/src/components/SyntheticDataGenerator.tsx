import React, { useState, useRef } from 'react';
import { Database, Download, Upload, Plus, AlertTriangle, RefreshCw, CheckCircle2 } from 'lucide-react';
import api from '../api';
import { Button } from './ui';

interface SyntheticExample {
  record_id: string;
  scenario: string;
  label: number;
  features: {
    distinct_dest_ports: number;
    events_per_second: number;
    distinct_dest_ips: number;
    avg_severity: number;
    protocol_diversity: number;
  };
  provenance: string;
}

export const SyntheticDataGenerator: React.FC = () => {
  const [scenario, setScenario] = useState<string>('Normal Traffic');
  const [count, setCount] = useState<number>(10);
  const [seed, setSeed] = useState<string>('');
  
  const [previewData, setPreviewData] = useState<SyntheticExample[]>([]);
  const [isGenerating, setIsGenerating] = useState(false);
  const [isAdding, setIsAdding] = useState(false);
  const [message, setMessage] = useState<{type: 'success' | 'error', text: string} | null>(null);
  
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleGenerate = async () => {
    setIsGenerating(true);
    setMessage(null);
    try {
      const response = await api.post<SyntheticExample[]>('/api/ml/data/generate', {
        scenario,
        count,
        seed: seed ? parseInt(seed) : null
      });
      setPreviewData(response.data);
    } catch (err: any) {
      setMessage({ type: 'error', text: err.response?.data?.detail || err.message || 'Generation failed' });
    } finally {
      setIsGenerating(false);
    }
  };

  const handleAddToDataset = async () => {
    if (previewData.length === 0) return;
    setIsAdding(true);
    setMessage(null);
    try {
      const response = await api.post('/api/ml/data/add', { examples: previewData });
      setMessage({ type: 'success', text: `Successfully added ${response.data.added} records to training dataset.` });
      setPreviewData([]); // clear preview
    } catch (err: any) {
      setMessage({ type: 'error', text: err.response?.data?.detail || err.message || 'Failed to add records' });
    } finally {
      setIsAdding(false);
    }
  };

  const exportJSON = () => {
    const dataStr = JSON.stringify(previewData, null, 2);
    const dataUri = 'data:application/json;charset=utf-8,' + encodeURIComponent(dataStr);
    const exportFileDefaultName = 'synthetic_training_data.json';
    const linkElement = document.createElement('a');
    linkElement.setAttribute('href', dataUri);
    linkElement.setAttribute('download', exportFileDefaultName);
    linkElement.click();
  };

  const exportCSV = () => {
    if (previewData.length === 0) return;
    const headers = ['record_id', 'scenario', 'label', 'provenance', 'distinct_dest_ports', 'events_per_second', 'distinct_dest_ips', 'avg_severity', 'protocol_diversity'];
    const rows = previewData.map(ex => [
      ex.record_id,
      ex.scenario,
      ex.label,
      ex.provenance,
      ex.features.distinct_dest_ports,
      ex.features.events_per_second,
      ex.features.distinct_dest_ips,
      ex.features.avg_severity,
      ex.features.protocol_diversity
    ]);
    
    const csvContent = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
    const dataUri = 'data:text/csv;charset=utf-8,' + encodeURIComponent(csvContent);
    const linkElement = document.createElement('a');
    linkElement.setAttribute('href', dataUri);
    linkElement.setAttribute('download', 'synthetic_training_data.csv');
    linkElement.click();
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    
    const reader = new FileReader();
    reader.onload = (event) => {
      try {
        const content = event.target?.result as string;
        let parsed: SyntheticExample[] = [];
        
        if (file.name.endsWith('.json')) {
          const jsonData = JSON.parse(content);
          if (Array.isArray(jsonData)) parsed = jsonData;
        } else if (file.name.endsWith('.csv')) {
          const lines = content.split('\n').map(l => l.trim()).filter(l => l);
          if (lines.length > 1) {
            const headers = lines[0].split(',');
            for (let i = 1; i < lines.length; i++) {
              const vals = lines[i].split(',');
              const obj: any = {};
              headers.forEach((h, idx) => obj[h] = vals[idx]);
              
              parsed.push({
                record_id: obj.record_id,
                scenario: obj.scenario,
                label: parseInt(obj.label),
                provenance: obj.provenance,
                features: {
                  distinct_dest_ports: parseFloat(obj.distinct_dest_ports),
                  events_per_second: parseFloat(obj.events_per_second),
                  distinct_dest_ips: parseFloat(obj.distinct_dest_ips),
                  avg_severity: parseFloat(obj.avg_severity),
                  protocol_diversity: parseFloat(obj.protocol_diversity)
                }
              } as SyntheticExample);
            }
          }
        }
        
        // Strict Validation
        const validExamples = parsed.filter(ex => {
          if (ex.scenario === 'Normal Traffic' && ex.label !== 0) return false;
          if (ex.scenario === 'Port Scan' && ex.label !== 1) return false;
          if (![0, 1].includes(ex.label)) return false;
          if (isNaN(ex.features.distinct_dest_ports) || isNaN(ex.features.events_per_second)) return false;
          return true;
        });
        
        if (validExamples.length < parsed.length) {
          setMessage({ type: 'error', text: `Rejected ${parsed.length - validExamples.length} records due to validation failures (e.g. tampered labels).` });
        } else {
          setMessage({ type: 'success', text: `Loaded ${validExamples.length} valid records.` });
        }
        
        // Ensure no duplicates in preview
        const existingIds = new Set(previewData.map(x => x.record_id));
        const newExamples = validExamples.filter(x => !existingIds.has(x.record_id));
        setPreviewData(prev => [...prev, ...newExamples]);
        
      } catch (err) {
        setMessage({ type: 'error', text: 'Failed to parse file.' });
      }
      
      // Reset input
      if (fileInputRef.current) fileInputRef.current.value = '';
    };
    reader.readAsText(file);
  };

  return (
    <div className="w-full bg-panel border border-line rounded-panel overflow-hidden mt-8">
      <div className="px-6 py-4 border-b border-line bg-app/60 flex items-center gap-3">
        <div className="p-2 rounded-lg bg-accent/10 border border-accent/20 text-accent-soft">
          <Database className="w-4 h-4 text-accent-soft" />
        </div>
        <div>
          <h2 className="text-sm font-bold text-ink uppercase tracking-wide">Synthetic Training Data Generator</h2>
          <p className="text-xs text-ink-muted">Generate deterministic, valid behavioral examples for Adaptive Learning.</p>
        </div>
      </div>

      <div className="p-6 space-y-6">
        <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
          <div className="sm:col-span-1">
            <label htmlFor="sdg-scenario" className="block text-xs font-semibold uppercase tracking-wider text-ink-soft mb-1.5">Scenario</label>
            <select
              id="sdg-scenario"
              aria-label="Scenario"
              value={scenario}
              onChange={e => setScenario(e.target.value)}
              className="w-full bg-app border border-line-strong rounded-lg px-3 py-2 text-sm text-ink focus:outline-none focus:ring-2 focus:ring-accent/50"
            >
              <option value="Normal Traffic">Normal Traffic (Benign)</option>
              <option value="Port Scan">Port Scan (Malicious)</option>
            </select>
          </div>

          <div className="sm:col-span-1">
            <label htmlFor="sdg-count" className="block text-xs font-semibold uppercase tracking-wider text-ink-soft mb-1.5">Count</label>
            <input
              id="sdg-count"
              aria-label="Count"
              type="number"
              min="1"
              max="1000"
              value={count}
              onChange={e => setCount(parseInt(e.target.value))}
              className="w-full bg-app border border-line-strong rounded-lg px-3 py-2 text-sm text-ink focus:outline-none focus:ring-2 focus:ring-accent/50"
            />
          </div>

          <div className="sm:col-span-1">
            <label htmlFor="sdg-seed" className="block text-xs font-semibold uppercase tracking-wider text-ink-soft mb-1.5">Random Seed (Optional)</label>
            <input
              id="sdg-seed"
              aria-label="Random seed"
              type="number"
              placeholder="e.g. 42"
              value={seed}
              onChange={e => setSeed(e.target.value)}
              className="w-full bg-app border border-line-strong rounded-lg px-3 py-2 text-sm text-ink focus:outline-none focus:ring-2 focus:ring-accent/50"
            />
          </div>

          <div className="sm:col-span-1 flex items-end">
            <Button
              variant="primary"
              onClick={handleGenerate}
              disabled={isGenerating}
              loading={isGenerating}
              leftIcon={<RefreshCw className="w-4 h-4" />}
              fullWidth
            >
              Generate
            </Button>
          </div>
        </div>

        {message && (
          <div
            role={message.type === 'error' ? 'alert' : 'status'}
            className={`p-4 rounded-card flex items-center gap-3 ${message.type === 'error' ? 'bg-rose-500/10 border border-rose-500/20 text-rose-300' : 'bg-emerald-500/10 border border-emerald-500/20 text-emerald-300'}`}
          >
            {message.type === 'error' ? <AlertTriangle className="w-5 h-5 shrink-0" /> : <CheckCircle2 className="w-5 h-5 shrink-0" />}
            <span className="text-sm font-medium">{message.text}</span>
          </div>
        )}

        {previewData.length > 0 && (
          <div className="space-y-4">
            <div className="flex justify-between items-center">
              <h3 className="text-sm font-semibold text-ink-soft">Preview ({previewData.length} records)</h3>
              <div className="flex gap-2">
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={exportCSV}
                  leftIcon={<Download className="w-3.5 h-3.5" />}
                >
                  CSV
                </Button>
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={exportJSON}
                  leftIcon={<Download className="w-3.5 h-3.5" />}
                >
                  JSON
                </Button>
                <input
                  type="file"
                  accept=".csv,.json"
                  className="hidden"
                  ref={fileInputRef}
                  onChange={handleFileUpload}
                  aria-label="Import CSV or JSON file"
                />
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={() => fileInputRef.current?.click()}
                  leftIcon={<Upload className="w-3.5 h-3.5" />}
                >
                  Import
                </Button>
              </div>
            </div>

            <div className="border border-line-strong rounded-card overflow-x-auto max-h-64 custom-scrollbar">
              <table className="w-full text-xs text-left">
                <caption className="sr-only">Synthetic training data preview rows with label, scenario, and feature values</caption>
                <thead className="bg-elevated text-ink-soft sticky top-0">
                  <tr>
                    <th scope="col" className="px-4 py-2">Label</th>
                    <th scope="col" className="px-4 py-2">Scenario</th>
                    <th scope="col" className="px-4 py-2 text-right">Ports</th>
                    <th scope="col" className="px-4 py-2 text-right">IPs</th>
                    <th scope="col" className="px-4 py-2 text-right">EPS</th>
                    <th scope="col" className="px-4 py-2 text-right">Severity</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-line">
                  {previewData.slice(0, 100).map((row, i) => (
                    <tr key={i} className="hover:bg-elevated/50">
                      <td className="px-4 py-2">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${row.label === 1 ? 'bg-rose-500/20 text-rose-400' : 'bg-emerald-500/20 text-emerald-400'}`}>
                          {row.label === 1 ? 'MALICIOUS' : 'BENIGN'}
                        </span>
                      </td>
                      <td className="px-4 py-2 text-ink-muted">{row.scenario}</td>
                      <td className="px-4 py-2 text-right font-mono">{row.features.distinct_dest_ports}</td>
                      <td className="px-4 py-2 text-right font-mono">{row.features.distinct_dest_ips}</td>
                      <td className="px-4 py-2 text-right font-mono">{row.features.events_per_second}</td>
                      <td className="px-4 py-2 text-right font-mono">{row.features.avg_severity}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {previewData.length > 100 && (
              <p className="text-[10px] text-ink-faint text-center">Showing first 100 rows</p>
            )}

            <div className="pt-2">
              <button
                type="button"
                onClick={handleAddToDataset}
                disabled={isAdding}
                className="w-full flex justify-center items-center gap-2 bg-emerald-600 hover:bg-emerald-500 text-white font-bold py-3 rounded-card shadow-lg shadow-emerald-600/20 transition-all duration-base text-sm cursor-pointer disabled:opacity-55 disabled:cursor-not-allowed active:scale-95"
              >
                {isAdding ? <RefreshCw className="w-5 h-5 animate-spin" /> : <Plus className="w-5 h-5" />}
                Add {previewData.length} Records to Training Dataset
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
