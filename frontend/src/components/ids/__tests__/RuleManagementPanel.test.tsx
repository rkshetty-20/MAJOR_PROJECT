import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { RuleManagementPanel } from '../RuleManagementPanel';
import type { RuleMeta } from '../types';

const rules: RuleMeta[] = [
  { rule_id: 'SIG-1', name: 'HTTP Scan', layer: 'signature', severity: 'high', description: 'Detects verbose HTTP scanning.', enabled: true, tunable: false, threshold: null },
  { rule_id: 'THR-1', name: 'Rate Limit', layer: 'threshold', severity: 'medium', description: 'Packet rate ceiling.', enabled: true, tunable: true, threshold: { pps: 100 } },
  { rule_id: 'STF-1', name: 'Half-Open State', layer: 'stateful', severity: 'low', description: 'Tracks session state.', enabled: false, tunable: false, threshold: null },
];

describe('RuleManagementPanel (Phase 5)', () => {
  it('shows the active-rule count derived from defaults', () => {
    render(
      <RuleManagementPanel rules={rules} enabledMap={{}} hitCounts={{}} onChangeEnabled={vi.fn()} onReset={vi.fn()} />,
    );
    expect(screen.getByText('2/3 active')).toBeInTheDocument();
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
