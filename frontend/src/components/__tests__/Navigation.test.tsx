import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { Sidebar } from '../Sidebar';
import { VisualizationInvestigationPage } from '../VisualizationInvestigationPage';

describe('Navigation and Visualization', () => {
  it('Sidebar destinations should be separate', () => {
    const onNavigate = vi.fn();
    render(
      <Sidebar 
        activePage="dashboard" 
        onNavigate={onNavigate} 
        connectionState="connected" 
        responseTime={50} 
        onPing={() => {}} 
        apiUrl="test" 
      />
    );
    
    expect(screen.getByText('Dashboard')).toBeInTheDocument();
    expect(screen.getByText('Intrusion Detection')).toBeInTheDocument();
    expect(screen.getByText('Phishing Detection')).toBeInTheDocument();
    expect(screen.getByText('Attack Simulation')).toBeInTheDocument();
    expect(screen.getByText('Visualization & Investigation')).toBeInTheDocument();
    
    expect(screen.queryByText('Attack Anatomy')).not.toBeInTheDocument();
    expect(screen.queryByText('Investigation Timeline')).not.toBeInTheDocument();
  });

  it('Visualization directly opened without a selected result shows empty state', () => {
    render(
      <VisualizationInvestigationPage 
        context={null}
        onAskChatbot={() => {}}
        onOpenInvestigation={() => {}}
        onBack={() => {}}
      />
    );
    expect(screen.getByText('Phishing-to-Intrusion Attack Walkthrough')).toBeInTheDocument();
  });

  it('Intrusion context renders intrusion visualization', () => {
    render(
      <VisualizationInvestigationPage 
        context={{
          type: 'intrusion',
          detectionId: 1,
          simulationResult: null,
          simulationId: null,
          scenarioName: undefined
        }}
        onAskChatbot={() => {}}
        onOpenInvestigation={() => {}}
        onBack={() => {}}
      />
    );
    expect(screen.getByText('Network Intrusion Investigation')).toBeInTheDocument();
    expect(screen.getByText('Detailed telemetry is unavailable for this detection.')).toBeInTheDocument();
  });

  it('Phishing context renders phishing visualization and safely handles URLs', () => {
    render(
      <VisualizationInvestigationPage 
        context={{
          type: 'phishing',
          url: 'http://malicious.com',
          result: {
            is_phishing: true,
            heuristic_confidence: 0.9,
            features: {
              url_length: 100,
              num_subdomains: 5,
              keyword_count: 2,
              is_ip: false
            }
          }
        }}
        onAskChatbot={() => {}}
        onOpenInvestigation={() => {}}
        onBack={() => {}}
      />
    );
    expect(screen.getByText('Phishing URL Investigation')).toBeInTheDocument();
    expect(screen.getByText('http://malicious.com')).toBeInTheDocument();
    expect(screen.getAllByText('Suspicious URL').length).toBeGreaterThan(0);
  });
});
