import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { DashboardPage } from '../DashboardPage';

const baseProps = {
  riskData: null,
  detections: [],
  isTelemetryLoading: false,
  onRefresh: vi.fn(),
  onInvestigateDetection: vi.fn(),
};

describe('DashboardPage (Phase 4)', () => {
  it('renders honest Unavailable states (never a fabricated zero) when metrics are absent', () => {
    render(<DashboardPage {...baseProps} overviewMetrics={null} />);

    // Count metrics fall back to the explicit unavailable label, not a fabricated value.
    // All 7 overview metrics are unavailable when the payload is null.
    expect(screen.getAllByText('Unavailable').length).toBe(7);

    // The three conditional metrics keep their honest reason text.
    expect(screen.getByText('No events evaluated')).toBeInTheDocument();
    expect(screen.getByText('Pending baseline')).toBeInTheDocument();
    expect(screen.getByText('No evaluation data')).toBeInTheDocument();
  });

  it('hoists a single working Refresh action to the page header', () => {
    const onRefresh = vi.fn();
    render(<DashboardPage {...baseProps} overviewMetrics={null} onRefresh={onRefresh} />);

    const refreshButtons = screen.getAllByRole('button', { name: /refresh/i });
    expect(refreshButtons).toHaveLength(1);
    fireEvent.click(refreshButtons[0]);
    expect(onRefresh).toHaveBeenCalledTimes(1);
  });

  it('renders both coverage cards', () => {
    render(<DashboardPage {...baseProps} overviewMetrics={null} />);
    expect(screen.getByText('Network Intrusion Coverage')).toBeInTheDocument();
    expect(screen.getByText('Phishing Detection Coverage')).toBeInTheDocument();
  });
});
