
import { render, screen } from '@testing-library/react';
import { describe, it, expect } from 'vitest';
import { PortScanRisk, PortScanFeatures, PortScanSuricata, readRiskTerms } from '../PortScanVisuals';
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

    it('renders the object shape the API actually serves and never treats metadata as a term', () => {
      // GET /api/simulation/.../investigation returns contributing_factors as an
      // OBJECT. The previous implementation called JSON.parse on it, threw, and
      // silently drew an empty waterfall.
      const mockLiveData = {
        risk: {
          score: 60,
          band: 'HIGH',
          contributing_factors: {
            formula: 'S = round(clamp(r + m + c + a + s, 0, 100))',
            terms: { r: 40, m: 0, c: 0, a: 10, s: 10 },
            terms_pre_suppression: { r: 40, c: 40 },
            double_counting_suppression: { applied: true, kept: 'r', suppressed: 'c' },
            raw_total: 60,
            clamped: false,
            rule_detected: 40,
            multi_signal_bonus: 0,
            ml_confidence_term: 0,
            agreement_bonus: 10,
            severity_term: 10,
            agreed_labels: ['port_scan_detected'],
            severity_source: 'suricata',
          },
        },
      };

      render(<PortScanRisk isLearnMode={false} liveData={mockLiveData} />);

      expect(screen.getByText('60')).toBeInTheDocument();
      expect(screen.getByText('HIGH')).toBeInTheDocument();
      expect(screen.getByText('rule detected')).toBeInTheDocument();
      expect(screen.getByText('+40')).toBeInTheDocument();
      expect(screen.getAllByText('+10')).toHaveLength(2);

      // Metadata keys must never appear as score contributions.
      expect(screen.queryByText('formula')).not.toBeInTheDocument();
      expect(screen.queryByText('terms')).not.toBeInTheDocument();
      expect(screen.queryByText('raw total')).not.toBeInTheDocument();
      expect(screen.queryByText('severity source')).not.toBeInTheDocument();
      expect(screen.queryByText(/object Object/)).not.toBeInTheDocument();
    });

    it('readRiskTerms accepts both shapes and drops non-numeric or zero terms', () => {
      const object = { rule_detected: 40, severity_term: 0, formula: 'x', terms: { r: 40 } };
      expect(readRiskTerms(object)).toEqual([['rule_detected', 40]]);
      expect(readRiskTerms(JSON.stringify(object))).toEqual([['rule_detected', 40]]);
      expect(readRiskTerms(undefined)).toEqual([]);
      expect(readRiskTerms('not json')).toEqual([]);
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
