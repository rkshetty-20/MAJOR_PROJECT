import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import api from '../../api';
import { PhishingDetectionPage } from '../PhishingDetectionPage';

vi.mock('../../api', () => ({
  default: { post: vi.fn() },
}));

const benignResult = {
  url: 'https://example.com/login',
  is_phishing: false,
  heuristic_confidence: 0.12,
  explanation: 'No suspicious indicators found.',
  features: {
    url_length: 26,
    hostname_length: 11,
    num_subdomains: 1,
    special_chars: 2,
    is_ip: false,
    is_https: true,
    keyword_count: 0,
  },
};

describe('PhishingDetectionPage (Phase 6)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders the header and keeps Analyze disabled until a URL is entered', () => {
    render(<PhishingDetectionPage onVisualize={vi.fn()} />);
    expect(screen.getByRole('heading', { name: 'Phishing Detection' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /analyze url/i })).toBeDisabled();
  });

  it('submits the URL and renders the honest heuristic + ML-unavailable states', async () => {
    (api.post as ReturnType<typeof vi.fn>).mockResolvedValue({ data: benignResult });
    render(<PhishingDetectionPage onVisualize={vi.fn()} />);

    fireEvent.change(screen.getByLabelText('URL to analyze'), { target: { value: 'https://example.com/login' } });
    fireEvent.click(screen.getByRole('button', { name: /analyze url/i }));

    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith('/api/detect/phishing', { url: 'https://example.com/login' }),
    );
    expect(await screen.findByText('Benign (No Immediate Threats)')).toBeInTheDocument();
    expect(screen.getByText('Threshold: 65%')).toBeInTheDocument();
    // Honest degraded ML state, never a fabricated model result.
    expect(screen.getByText('Model Unavailable')).toBeInTheDocument();
  });

  it('surfaces a failed analysis as an error state', async () => {
    (api.post as ReturnType<typeof vi.fn>).mockRejectedValue({
      response: { data: { detail: 'Backend unreachable' } },
    });
    render(<PhishingDetectionPage onVisualize={vi.fn()} />);

    fireEvent.change(screen.getByLabelText('URL to analyze'), { target: { value: 'http://bad' } });
    fireEvent.click(screen.getByRole('button', { name: /analyze url/i }));

    expect(await screen.findByRole('alert')).toBeInTheDocument();
    expect(screen.getByText('Backend unreachable')).toBeInTheDocument();
  });
});
