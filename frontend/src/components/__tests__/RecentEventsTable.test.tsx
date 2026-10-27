import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { RecentEventsTable, SecurityEventItem } from '../RecentEventsTable';
import { SecurityEventModal } from '../SecurityEventModal';

const sampleEvent: SecurityEventItem = {
  id: 1,
  session_id: 10,
  scenario: 'brute_force',
  event_type: 'auth_failure',
  timestamp: '2026-01-01T10:00:00Z',
  source: '10.0.0.5',
  target: 'admin',
  risk_score: 75,
  risk_level: 'HIGH',
  detection_status: 'DETECTED',
};

const otherEvent: SecurityEventItem = {
  ...sampleEvent,
  id: 2,
  scenario: 'phishing_url',
  event_type: 'url_scan',
  source: '10.0.0.9',
  target: 'user@example.com',
  risk_level: 'LOW',
  risk_score: 12,
};

const baseProps = {
  isLoading: false,
  onSelectEvent: vi.fn(),
  onAskChatbot: vi.fn(),
  onRefresh: vi.fn(),
};

describe('RecentEventsTable (Phase 11)', () => {
  it('shows an honest empty state when there are no events', () => {
    render(<RecentEventsTable {...baseProps} events={[]} />);
    expect(screen.getByText('No security telemetry events yet')).toBeInTheDocument();
  });

  it('renders a row with a text risk label + score and wires the action callbacks', () => {
    const onSelectEvent = vi.fn();
    const onAskChatbot = vi.fn();
    render(
      <RecentEventsTable {...baseProps} events={[sampleEvent]} onSelectEvent={onSelectEvent} onAskChatbot={onAskChatbot} />,
    );

    expect(screen.getByText('brute force')).toBeInTheDocument();
    expect(screen.getByText('HIGH (75)')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /ask ai/i }));
    expect(onAskChatbot).toHaveBeenCalledTimes(1);

    fireEvent.click(screen.getByRole('button', { name: /details/i }));
    expect(onSelectEvent).toHaveBeenCalledWith(sampleEvent);
  });

  it('narrows rows via the search filter', () => {
    render(<RecentEventsTable {...baseProps} events={[sampleEvent, otherEvent]} />);
    const input = screen.getByRole('textbox', { name: /filter events/i });
    fireEvent.change(input, { target: { value: 'phishing' } });

    expect(screen.getByText('phishing url')).toBeInTheDocument();
    expect(screen.queryByText('brute force')).not.toBeInTheDocument();
  });
});

describe('SecurityEventModal (Phase 11)', () => {
  it('renders an accessible dialog and closes on Escape', () => {
    const onClose = vi.fn();
    render(
      <SecurityEventModal
        event={sampleEvent}
        detections={[]}
        onClose={onClose}
        onAskChatbot={vi.fn()}
        onInvestigateDetection={vi.fn()}
      />,
    );

    expect(screen.getByRole('dialog', { name: /security telemetry inspector/i })).toBeInTheDocument();
    fireEvent.keyDown(document, { key: 'Escape' });
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('renders nothing when no event is selected', () => {
    const { container } = render(
      <SecurityEventModal
        event={null}
        detections={[]}
        onClose={vi.fn()}
        onAskChatbot={vi.fn()}
        onInvestigateDetection={vi.fn()}
      />,
    );
    expect(container).toBeEmptyDOMElement();
  });
});
