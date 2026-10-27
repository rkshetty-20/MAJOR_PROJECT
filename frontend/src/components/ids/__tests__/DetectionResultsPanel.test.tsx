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
    triggered: [
      {
        rule_id: 'THR-1',
        name: 'SYN Rate Exceeded',
        layer: 'threshold',
        severity: 'high',
        mitre: 'T1498.001',
        confidence: 0.82,
        detail: '42 SYN packets/sec from a single source.',
        matched_packets: [1, 2, 3],
        weight: 3,
      },
    ],
  },
  ml: {
    overall_score: 0.71,
    models: { isolation_forest: 0.42, autoencoder: 0.3 },
    features: [],
    top_contributors: [],
    confidence: 0.8,
    false_positive_probability: 0.12,
    explanation: 'Traffic deviates from baseline arrival rate.',
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
    expect(screen.getByRole('heading', { name: 'ML Anomaly Breakdown' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: /Triggered Rules \(1\)/ })).toBeInTheDocument();
  });
});
