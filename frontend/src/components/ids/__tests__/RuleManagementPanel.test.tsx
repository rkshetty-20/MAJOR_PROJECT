import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { RuleManagementPanel } from '../RuleManagementPanel';
import type { RuleMeta } from '../types';

const rules: RuleMeta[] = [
  {
    rule_id: 'SIG-1', name: 'HTTP Scan', layer: 'signature', category: 'signature', version: '1.0.0',
    severity: 'high', weight: 24, description: 'Detects verbose HTTP scanning.',
    matching: 'Case-insensitive substring match on payload_text', explanation: 'Rule SIG-1 matched HTTP scanning markers in {detail}.',
    inputs: ['index', 'unix_ts', 'payload_text'], enabled: true, tunable: false, threshold: null,
  },
  {
    rule_id: 'THR-1', name: 'Rate Limit', layer: 'threshold', category: 'threshold', version: '1.0.0',
    severity: 'medium', weight: 14, description: 'Packet rate ceiling.',
    matching: 'Peak packet count per source inside a sliding window', explanation: 'Arrival rate exceeded {detail}.',
    inputs: ['index', 'unix_ts', 'src_ip'], enabled: true, tunable: true, threshold: { pps: 100 },
  },
  {
    rule_id: 'STF-1', name: 'Half-Open State', layer: 'stateful', category: 'stateful', version: '1.0.0',
    severity: 'low', weight: 6, description: 'Tracks session state.',
    matching: 'Stream context: SYN without matching SYN-ACK', explanation: 'Incomplete handshakes observed: {detail}.',
    inputs: ['index', 'unix_ts', 'flags', 'dst_port'], enabled: false, tunable: false, threshold: null,
  },
];

describe('RuleManagementPanel (Phase 5)', () => {
  it('shows the active-rule count derived from defaults', () => {
    render(
      <RuleManagementPanel rules={rules} enabledMap={{}} hitCounts={{}} onChangeEnabled={vi.fn()} onReset={vi.fn()} />,
    );
    expect(screen.getByText('2/3 active')).toBeInTheDocument();
  });

  it('shows each rule id, version and weight from the registry contract', () => {
    render(
      <RuleManagementPanel rules={rules} enabledMap={{}} hitCounts={{}} onChangeEnabled={vi.fn()} onReset={vi.fn()} />,
    );
    expect(screen.getByText('SIG-1 · v1.0.0 · weight 24 · inputs 3')).toBeInTheDocument();
    expect(screen.getByText('STF-1 · v1.0.0 · weight 6 · inputs 4')).toBeInTheDocument();
  });

  it('reflects toggle state via aria-pressed and calls onChangeEnabled with the flipped value', () => {
    const onChangeEnabled = vi.fn();
    render(
      <RuleManagementPanel rules={rules} enabledMap={{}} hitCounts={{ 'SIG-1': 5 }} onChangeEnabled={onChangeEnabled} onReset={vi.fn()} />,
    );

    const enabledToggle = screen.getByRole('button', { name: /Disable rule HTTP Scan/i });
    expect(enabledToggle).toHaveAttribute('aria-pressed', 'true');

    fireEvent.click(enabledToggle);
    expect(onChangeEnabled).toHaveBeenCalledWith('SIG-1', false);

    const disabledToggle = screen.getByRole('button', { name: /Enable rule Half-Open State/i });
    expect(disabledToggle).toHaveAttribute('aria-pressed', 'false');
    fireEvent.click(disabledToggle);
    expect(onChangeEnabled).toHaveBeenCalledWith('STF-1', true);
  });
});
