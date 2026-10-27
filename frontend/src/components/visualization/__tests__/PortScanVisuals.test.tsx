
import { render, screen } from '@testing-library/react';
import { describe, it, expect } from 'vitest';
import { PortScanRisk, PortScanFeatures, PortScanSuricata } from '../PortScanVisuals';
import '@testing-library/jest-dom';

describe('PortScanVisuals', () => {
  describe('Risk Waterfall (a)', () => {
    it('renders exactly the non-zero terms of a mocked contributing_factors and total score', () => {
      const mockLiveData = {
        risk: {
          score: 87,
          band: 'HIGH',
          contributing_factors: JSON.stringify({
            rule_detected: 0,
            ml_confidence_term: 75,
            agreement_bonus: 0,
            multi_signal_bonus: 5,
            severity_term: 7
          })
        }
      };

      render(<PortScanRisk isLearnMode={false} liveData={mockLiveData} />);

      // Ensure total score is rendered
      expect(screen.getByText('87')).toBeInTheDocument();
      expect(screen.getByText('HIGH')).toBeInTheDocument();

      // Ensure non-zero factors are rendered
      expect(screen.getByText('ml confidence term')).toBeInTheDocument();
      expect(screen.getByText('+75')).toBeInTheDocument();
      expect(screen.getByText('multi signal bonus')).toBeInTheDocument();
      expect(screen.getByText('+5')).toBeInTheDocument();
      expect(screen.getByText('severity term')).toBeInTheDocument();
      expect(screen.getByText('+7')).toBeInTheDocument();

      // Ensure zero factors are NOT rendered
      expect(screen.queryByText('rule detected')).not.toBeInTheDocument();
      expect(screen.queryByText('agreement bonus')).not.toBeInTheDocument();
      expect(screen.queryByText('+0')).not.toBeInTheDocument();
    });
  });

  describe('Live mode "Not available" handling (b)', () => {
    it('shows "Unavailable" when stage has no data for Risk', () => {
      render(<PortScanRisk isLearnMode={false} liveData={{}} />);
      expect(screen.getByText('Unavailable')).toBeInTheDocument();
      expect(screen.getByText('No risk score calculated.')).toBeInTheDocument();
    });

    it('shows "Unavailable" when stage has no data for Features', () => {
      render(<PortScanFeatures isLearnMode={false} liveData={{ detections: [] }} />);
      expect(screen.getByText('Unavailable')).toBeInTheDocument();
      expect(screen.getByText('Feature vector not persisted for this detection.')).toBeInTheDocument();
    });

    it('shows "Unavailable" when stage has no data for Suricata', () => {
      render(<PortScanSuricata isLearnMode={false} liveData={{ timelineData: [] }} />);
      expect(screen.getByText('Unavailable')).toBeInTheDocument();
      expect(screen.getByText('No Suricata alerts generated.')).toBeInTheDocument();
    });
  });
});
