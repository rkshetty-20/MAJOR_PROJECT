import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import api from '../../api';
import { AttackSimulation, SimulationResult } from '../AttackSimulation';

vi.mock('../../api', () => ({
  default: { post: vi.fn() },
}));

const completedResult: SimulationResult = {
  simulation_id: 'sim-abc-123',
  scenario: 'brute_force',
  scenario_name: 'Brute Force Login',
  session_id: 5,
  events_generated: 8,
  status: 'completed',
  detections_count: 2,
  detections: [],
  risk: { score: 82, band: 'high' },
  triggered_rules: ['RULE_BRUTE_FORCE'],
  mitigation: 'Block source IP and enforce MFA.',
  simulation_flow: [],
};

describe('AttackSimulation (Phase 7)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders labeled controls and shows a run button that is enabled by default', () => {
    render(<AttackSimulation onSimulationCompleted={vi.fn()} onAskChatbot={vi.fn()} />);
    expect(screen.getByLabelText('Attack Scenario')).toBeInTheDocument();
    expect(screen.getByLabelText('Intensity level')).toBeInTheDocument();
    expect(screen.getByLabelText('Synthetic events count')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /run simulation/i })).toBeEnabled();
  });

  it('posts the scenario and renders the real backend result without fabricating fields', async () => {
    (api.post as ReturnType<typeof vi.fn>).mockResolvedValue({ data: completedResult });
    render(<AttackSimulation onSimulationCompleted={vi.fn()} onAskChatbot={vi.fn()} />);

    fireEvent.click(screen.getByRole('button', { name: /run simulation/i }));

    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith('/api/simulation/run', {
        scenario: 'brute_force',
        intensity: 'medium',
        event_count: 8,
      }),
    );
    expect(await screen.findByText('Simulation Completed Successfully')).toBeInTheDocument();
    expect(screen.getByText(/Risk: HIGH/i)).toBeInTheDocument();
    expect(screen.getByText('RULE_BRUTE_FORCE')).toBeInTheDocument();
    expect(screen.getByText(/Block source IP/)).toBeInTheDocument();
  });

  it('surfaces a failed run as an honest alert with no fabricated result', async () => {
    (api.post as ReturnType<typeof vi.fn>).mockRejectedValue({
      response: { data: { detail: 'Simulator offline' } },
    });
    render(<AttackSimulation onSimulationCompleted={vi.fn()} onAskChatbot={vi.fn()} />);

    fireEvent.click(screen.getByRole('button', { name: /run simulation/i }));

    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent('Simulation Error: Simulator offline');
    expect(screen.queryByText('Simulation Completed Successfully')).not.toBeInTheDocument();
  });
});
