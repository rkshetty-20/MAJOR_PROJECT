import { render, screen, waitFor } from '@testing-library/react';
import { expect, test, vi } from 'vitest';
import { AttackTimeline } from '../AttackTimeline';
import api from '../../api';

// Mock the API
vi.mock('../../api', () => ({
  default: {
    get: vi.fn(),
  },
}));

test('AttackTimeline fetches and renders real chronological timeline stages', async () => {
  const mockTimeline = [
    {
      step: 'simulation_started',
      timestamp: '2026-10-07T12:00:00Z',
      status: 'completed',
      label: 'Simulation started',
      details: 'Scenario: Brute Force',
    },
    {
      step: 'event_generated',
      timestamp: '2026-10-07T12:00:05Z',
      status: 'completed',
      label: 'Event: Failed login',
      details: 'Source: 198.51.100.25 -> Target: admin',
    },
    {
      step: 'detection_triggered',
      timestamp: '2026-10-07T12:00:10Z',
      status: 'completed',
      label: '[RULE Detection] brute_force_detected',
      details: 'Rule matched',
    },
  ];

  (api.get as any).mockResolvedValueOnce({ data: mockTimeline });

  render(<AttackTimeline simulationId="sim_123" scenarioName="Test Scenario" />);

  // Should show loading state initially
  expect(screen.getByText('Loading timeline data...')).toBeInTheDocument();

  // Wait for the timeline to load and render the items
  await waitFor(() => {
    expect(screen.queryByText('Loading timeline data...')).not.toBeInTheDocument();
  });

  // Verify elements are rendered
  expect(screen.getByText('Simulation started')).toBeInTheDocument();
  expect(screen.getByText('Scenario: Brute Force')).toBeInTheDocument();
  expect(screen.getByText('Event: Failed login')).toBeInTheDocument();
  expect(screen.getByText('Source: 198.51.100.25 -> Target: admin')).toBeInTheDocument();
  expect(screen.getByText('[RULE Detection] brute_force_detected')).toBeInTheDocument();
  expect(screen.getByText('Rule matched')).toBeInTheDocument();

  // Verify API was called correctly
  expect(api.get).toHaveBeenCalledWith('/api/simulation/sim_123/timeline');
});
