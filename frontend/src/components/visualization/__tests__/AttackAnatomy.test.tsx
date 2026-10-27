import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { AttackAnatomy } from '../AttackAnatomy';

vi.mock('../../../api', () => ({
  default: {
    get: vi.fn().mockResolvedValue({ data: [] }),
  },
}));

describe('AttackAnatomy', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  const mockOnAskChatbot = vi.fn();
  const mockOnOpenInvestigation = vi.fn();

  it('renders Learn Mode correctly with no simulation result (Requirement 4)', () => {
    render(<AttackAnatomy onAskChatbot={mockOnAskChatbot} onOpenInvestigation={mockOnOpenInvestigation} />);
    
    // By default it should be in learn mode and show the first scenario (Port Scan)
    expect(screen.getByText(/Educational Concept/i)).toBeInTheDocument();
  });

  it('shows unavailable state in Investigation Mode with no simulation result (Requirement 1)', () => {
    render(<AttackAnatomy onAskChatbot={mockOnAskChatbot} onOpenInvestigation={mockOnOpenInvestigation} />);
    
    // Switch to investigate mode
    fireEvent.click(screen.getByRole('button', { name: /investigation/i }));

    // Should show unavailable message
    expect(screen.getByText(/No investigation data available for this scenario/i)).toBeInTheDocument();
    expect(screen.getByText(/The selected scenario has no matching simulation evidence yet/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Go to Simulation Handler/i })).toBeInTheDocument();
  });

  it('shows unavailable state in Investigation Mode when simulation result is for a different scenario (Requirement 2)', () => {
    const wrongSimulationResult = {
      simulation_id: 'sim_123',
      scenario: 'phishing_url', // Different from default port_scan
      scenario_name: 'Phishing',
    };

    render(
      <AttackAnatomy 
        activeSimulationResult={wrongSimulationResult}
        onAskChatbot={mockOnAskChatbot} 
        onOpenInvestigation={mockOnOpenInvestigation} 
      />
    );
    
    // Switch to investigate mode
    fireEvent.click(screen.getByRole('button', { name: /investigation/i }));

    // Because default selected scenario is port_scan, but result is phishing_url, it should be unavailable
    expect(screen.getByText(/No investigation data available for this scenario/i)).toBeInTheDocument();
  });

  it('renders matching result in Investigation Mode (Requirement 3)', async () => {
    const matchingSimulationResult = {
      simulation_id: 'sim_123',
      scenario: 'port_scan',
      scenario_name: 'Port Scan Event Simulation',
    };

    render(
      <AttackAnatomy 
        activeSimulationResult={matchingSimulationResult}
        onAskChatbot={mockOnAskChatbot} 
        onOpenInvestigation={mockOnOpenInvestigation} 
      />
    );
    
    // Switch to investigate mode
    fireEvent.click(screen.getByRole('button', { name: /investigation/i }));

    // It should eventually NOT show the unavailable badge after data loads
    await waitFor(() => {
      expect(screen.queryByText(/No investigation data available for this scenario/i)).not.toBeInTheDocument();
    });
  });

  it('invokes the simulation handler correctly when button is clicked (Requirement 5)', () => {
    render(<AttackAnatomy onAskChatbot={mockOnAskChatbot} onOpenInvestigation={mockOnOpenInvestigation} />);
    
    // Switch to investigate mode
    fireEvent.click(screen.getByRole('button', { name: /investigation/i }));

    // Mock document methods
    const mockScrollIntoView = vi.fn();
    document.getElementById = vi.fn().mockImplementation((id) => {
      if (id === 'attack-simulation-section') return { scrollIntoView: mockScrollIntoView };
      if (id === 'simulation-scenario-select') return { 
        value: 'some_other', 
        dispatchEvent: vi.fn(),
      };
      return null;
    });

    const btn = screen.getByRole('button', { name: /Go to Simulation Handler/i });
    fireEvent.click(btn);

    expect(mockScrollIntoView).toHaveBeenCalledWith({ behavior: 'smooth' });
  });
});
