
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { AdaptiveLearningMetrics } from '../AdaptiveLearningMetrics';
import api from '../../api';
import '@testing-library/jest-dom';

vi.mock('../../api', () => ({
  default: {
    get: vi.fn(),
    post: vi.fn(),
  },
}));

describe('AdaptiveLearningMetrics', () => {
  const mockStatus = {
    current_version: 'v_20261009105900_abcd',
    training_samples: 42,
    total_examples: 150,
    new_examples: 10,
    status: 'READY_FOR_TRAINING',
    metrics: {
      accuracy: 0.95,
      f1_score: 0.94,
      precision: 0.93,
      recall: 0.96,
    },
    last_trained: '2026-10-09T10:00:00.000Z',
    history: [
      {
        version: 'v_20261009105900_abcd',
        f1_score: 0.94,
        is_accepted: true,
        created_at: '2026-10-09T10:00:00.000Z',
        training_samples: 42,
      },
    ],
  };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders explicit loading state initially', () => {
    // delay resolution to see loading state
    vi.mocked(api.get).mockImplementation(() => new Promise(() => {}));
    render(<AdaptiveLearningMetrics />);
    expect(screen.getByText(/Loading ML engine status/i)).toBeInTheDocument();
  });

  it('renders explicit error state if API fails', async () => {
    vi.mocked(api.get).mockRejectedValueOnce({ response: { data: { detail: 'Server Error' } } });
    render(<AdaptiveLearningMetrics />);
    
    await waitFor(() => {
      expect(screen.getByText('Engine Unavailable')).toBeInTheDocument();
      expect(screen.getByText('Server Error')).toBeInTheDocument();
    });
  });

  it('renders active model details and handles synthetic evaluation labeling', async () => {
    vi.mocked(api.get).mockResolvedValue({ data: mockStatus });
    render(<AdaptiveLearningMetrics />);
    
    await waitFor(() => {
      expect(screen.getByText('Adaptive ML — Port Scan')).toBeInTheDocument();
      expect(screen.getByText('v_20261009105900_abcd')).toBeInTheDocument();
      expect(screen.getByText('Trained on 42 examples')).toBeInTheDocument();
      
      // Scientific honesty: Synthetic labeling
      expect(screen.getByText('Active Model Synthetic Evaluation')).toBeInTheDocument();
      expect(screen.getByText(/Note: Evaluated on synthetic holdout set/)).toBeInTheDocument();
      
      // Accuracies formatted consistently
      expect(screen.getByText('95.0%')).toBeInTheDocument(); // Acc
      expect(screen.getByText('94.0%')).toBeInTheDocument(); // F1
    });
  });

  it('handles unavailable metrics explicitly', async () => {
    vi.mocked(api.get).mockResolvedValue({ 
      data: { ...mockStatus, metrics: null } 
    });
    render(<AdaptiveLearningMetrics />);
    
    await waitFor(() => {
      expect(screen.getByText('Metrics unavailable for current model')).toBeInTheDocument();
    });
  });

  it('triggers training API successfully', async () => {
    vi.mocked(api.get).mockResolvedValue({ data: mockStatus });
    vi.mocked(api.post).mockResolvedValue({ data: {} });
    
    render(<AdaptiveLearningMetrics />);
    
    await waitFor(() => expect(screen.getByText('v_20261009105900_abcd')).toBeInTheDocument());
    
    // Trigger training
    const trainBtn = screen.getByRole('button', { name: /Train & Evaluate Candidate/i });
    fireEvent.click(trainBtn);
    
    await waitFor(() => {
      expect(api.post).toHaveBeenCalledWith('/api/ml/train', { task_name: 'port_scan' });
    });
  });

  it('disables Train button when total_examples < 10 or no new examples', async () => {
    vi.mocked(api.get).mockResolvedValue({ 
      data: { ...mockStatus, total_examples: 9, new_examples: 9, status: 'NOT_READY' } 
    });
    render(<AdaptiveLearningMetrics />);
    
    await waitFor(() => {
      const trainBtn = screen.getByRole('button', { name: /Train & Evaluate Candidate/i });
      expect(trainBtn).toBeDisabled();
      expect(screen.getByText('Need at least 10 total examples to train.')).toBeInTheDocument();
    });
  });
});
