import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { DetectionResultsPanel } from '../DetectionResultsPanel';
import type { IdsAnalysis } from '../types';

const analysis: IdsAnalysis = {
  analysis_id: 'an_123',
  attack: { id: 'a1', name: 'SYN Flood', category: 'DoS', description: 'Volumetric SYN flood.', severity: 'high' },
  generation: { volume: 'high', seed: 42, packet_count: 60 },
  verdict: { label: 'Suspicious', threat_score: 68.5, rule_score: 55, ml_score: 71 },
  rules: {
    triggered_count: 1,
    evaluated: ['r1', 'r2', 'r3'],
    evaluated_count: 3,
    registry_size: 3,
    ruleset_version: '1.0.0',
    accepted_packets: 60,
    skipped_packets: [],
    triggered: [
      {
        rule_id: 'THR-1',
        name: 'SYN Rate Exceeded',
        layer: 'threshold',
        category: 'threshold',
        version: '1.0.0',
        severity: 'high',
        mitre: 'T1498.001',
        confidence: 0.82,
        detail: '42 SYN packets/sec from a single source.',
        explanation: 'Arrival rate from 192.0.2.10 exceeded the SYN ceiling (42 packets/sec).',
        inputs_used: ['index', 'unix_ts', 'src_ip', 'flags'],
        matched_packets: [1, 2, 3],
        weight: 3,
        evidence: [
          {
            type: 'packet', packet_index: 1, timestamp: '2026-10-27T10:00:00+00:00',
            src_ip: '192.0.2.10', dst_ip: '198.51.100.20', dst_port: 80, protocol: 'TCP',
            flags: 'SYN', size: 52, ttl: 64, payload_preview: '',
          },
        ],
      },
    ],
  },
  ml: {
    overall_score: 0.71,
    models: { isolation_forest: 0.42, autoencoder: 0.3 },
    ensemble_weights: { isolation_forest: 0.3, autoencoder: 0.28 },
    features: [],
    top_contributors: [],
    confidence: 0.8,
    false_positive_probability: 0.12,
    explanation: 'Traffic deviates from baseline arrival rate.',
    model_status: 'Deterministic statistical proxies over 14 packet features - not trained models.',
    feature_count: 14,
    scorers: ['isolation_forest', 'autoencoder', 'statistical_zscore', 'dbscan_density'],
  },
  pipeline: {
    input_source: 'seeded synthetic packet generator (deterministic replay)',
    live_traffic_capture: false,
    live_traffic_claim: 'Not claimed: no authorized live ingestion path is implemented or tested.',
  },
  kill_chain: {
    current: 'exploitation',
    current_label: 'Exploitation',
    index: 1,
    stages: [
      { key: 'recon', label: 'Reconnaissance', reached: true },
      { key: 'exploit', label: 'Exploitation', reached: true },
      { key: 'exfil', label: 'Exfiltration', reached: false },
    ],
  },
  mitre: [{ technique_id: 'T1498.001', technique_name: 'DDoS: SYN Floods', tactic: 'Impact', source: 'attack' }],
  packets: [],
  packet_analysis: {
    protocol_breakdown: { TCP: 60 },
    port_breakdown: { '80': 60 },
    flag_breakdown: { SYN: 60 },
    size_stats: { min: 40, max: 60, mean: 52 },
    suspicious_indices: [1, 2],
    total_bytes: 3120,
  },
  threat_intel: { cves: [], actors: [], nist: [], owasp: [], mitigations: [] },
};

describe('DetectionResultsPanel (Phase 5)', () => {
  it('renders verdict, gauge, triggered rules, MITRE mapping and ML models from the analysis', () => {
    render(<DetectionResultsPanel analysis={analysis} />);

    // Verdict chip + threat gauge label.
    expect(screen.getByText('Suspicious')).toBeInTheDocument();
    expect(screen.getByText('Threat')).toBeInTheDocument();

    // Triggered rule name + MITRE technique id + ensemble model label.
    expect(screen.getByText('SYN Rate Exceeded')).toBeInTheDocument();
    expect(screen.getByText('T1498.001')).toBeInTheDocument();
    expect(screen.getByText('Isolation Forest')).toBeInTheDocument();

    // Section headings render via the shared Card.
    expect(screen.getByRole('heading', { name: 'Anomaly Score Breakdown' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: /Triggered Rules \(1\)/ })).toBeInTheDocument();
  });

  it('shows which registry rules were evaluated, and the version of the one that fired', () => {
    render(<DetectionResultsPanel analysis={analysis} />);
    expect(screen.getByText('3/3 rules evaluated · v1.0.0')).toBeInTheDocument();
    expect(screen.getByText('THR-1 · v1.0.0')).toBeInTheDocument();
  });

  it('renders the detection explanation together with its packet evidence', () => {
    render(<DetectionResultsPanel analysis={analysis} />);
    expect(
      screen.getByText(/Arrival rate from 192\.0\.2\.10 exceeded the SYN ceiling/),
    ).toBeInTheDocument();
    expect(screen.getByText(/Evidence: 3 packets \(1, 2, 3\)/)).toBeInTheDocument();
  });

  it('never presents the anomaly proxies as trained models', () => {
    render(<DetectionResultsPanel analysis={analysis} />);
    expect(screen.getByText('Anomaly Proxies')).toBeInTheDocument();
    expect(
      screen.getByText('Deterministic statistical proxies over 14 packet features - not trained models.'),
    ).toBeInTheDocument();
    expect(screen.getByText(/no authorized live ingestion path/)).toBeInTheDocument();
  });
});
