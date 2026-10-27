import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { expect, test, vi } from 'vitest';
import { DetectionInvestigationModal } from '../DetectionInvestigationModal';
import api from '../../api';

// Mock the API
vi.mock('../../api', () => ({
  default: {
    get: vi.fn(),
  },
}));

// Mock the AttackTimeline
vi.mock('../AttackTimeline', () => ({
  AttackTimeline: () => <div data-testid="mock-attack-timeline" />
}));

test('DetectionInvestigationModal fetches and renders investigation data', async () => {
  const mockInvestigation = {
    detection: {
      id: 101,
      label: 'brute_force_detected',
      timestamp: '2026-10-07T12:00:10Z',
      confidence: 0.95,
      explanation: 'Detected 15 failed logins within 60s',
      source: 'rule',
      session_id: 'sess_123',
    },
    related_events: [
      {
        id: 1,
        event_type: 'failed_login',
        timestamp: '2026-10-07T12:00:05Z',
        source: '198.51.100.25',
        target: 'admin',
        simulation_id: 'sim_123'
      }
    ],
    risk: {
      score: 85,
      band: 'CRITICAL',
      contributing_factors: {
        rule_detected: 40,
        multi_signal_bonus: 30,
        ml_confidence_term: 5,
        agreement_bonus: 5,
        severity_term: 5
      }
    }
  };

  (api.get as any).mockResolvedValueOnce({ data: mockInvestigation });

  const onCloseMock = vi.fn();
  const onEventClickMock = vi.fn();
  const onAskChatbotMock = vi.fn();

  render(
    <DetectionInvestigationModal 
      detectionId={101} 
      onClose={onCloseMock} 
      onEventClick={onEventClickMock} 
      onAskChatbot={onAskChatbotMock} 
    />
  );

  // 1. Investigation loading state
  expect(screen.getByText('Loading investigation...')).toBeInTheDocument();

  await waitFor(() => {
    expect(screen.queryByText('Loading investigation...')).not.toBeInTheDocument();
  });

  // 2. Detection details render
  expect(screen.getByText('Detection ID: #101 • Confidence: 95%')).toBeInTheDocument();
  expect(screen.getByText('Detected 15 failed logins within 60s')).toBeInTheDocument();
  
  // 3. Related events render
  expect(screen.getByText('198.51.100.25')).toBeInTheDocument();
  expect(screen.getByText('admin')).toBeInTheDocument();
  expect(screen.getByText('failed_login')).toBeInTheDocument();

  // 4. Risk breakdown renders backend-provided values
  expect(screen.getByText('CRITICAL — 85')).toBeInTheDocument();
  expect(screen.getByText('FINAL RISK SCORE')).toBeInTheDocument();
  
  // 7. Ask AI uses selected investigation context
  const askBtn = screen.getByText('Ask Security Assistant');
  fireEvent.click(askBtn);
  expect(onAskChatbotMock).toHaveBeenCalled();
  
  const callArgs = onAskChatbotMock.mock.calls[0];
  expect(callArgs[0]).toEqual({
    detection_id: 101,
    label: 'brute_force_detected',
    explanation: 'Detected 15 failed logins within 60s',
    risk_score: 85,
    risk_band: 'CRITICAL',
    contributing_factors: mockInvestigation.risk.contributing_factors,
    evidence_events_count: 1
  });
});

test('DetectionInvestigationModal handles error state', async () => {
  (api.get as any).mockRejectedValueOnce({
    response: { data: { detail: 'Detection not found' } }
  });

  const onCloseMock = vi.fn();
  
  render(
    <DetectionInvestigationModal 
      detectionId={999} 
      onClose={onCloseMock} 
      onEventClick={vi.fn()} 
      onAskChatbot={vi.fn()} 
    />
  );

  await waitFor(() => {
    expect(screen.getAllByText('Detection not found').length).toBeGreaterThan(0);
  });
});

test('DetectionInvestigationModal renders empty state when no events', async () => {
  const mockInvestigation = {
    detection: {
      id: 102,
      label: 'anomalous_behavior',
      timestamp: '2026-10-07T12:00:10Z',
      confidence: 0.5,
      explanation: 'Suspicious ML anomaly',
      source: 'ml',
      session_id: 'sess_123',
    },
    related_events: [],
    risk: null
  };

  (api.get as any).mockResolvedValueOnce({ data: mockInvestigation });

  render(
    <DetectionInvestigationModal 
      detectionId={102} 
      onClose={vi.fn()} 
      onEventClick={vi.fn()} 
      onAskChatbot={vi.fn()} 
    />
  );

  await waitFor(() => {
    // 5. Empty state
    expect(screen.getByText('No telemetry events explicitly correlated with this detection.')).toBeInTheDocument();
  });
});
