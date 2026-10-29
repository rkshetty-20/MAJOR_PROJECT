import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import api from '../../api';
import { PhishingDetectionPage } from '../PhishingDetectionPage';

vi.mock('../../api', () => ({
  default: { post: vi.fn(), get: vi.fn() },
}));

/**
 * Registry fixture shaped like GET /api/detect/phishing/indicators. The counts
 * and weights are read by the page and rendered as-is; the test only needs the
 * fields the contract card touches.
 */
const registryFixture = {
  scorer: 'lexical-phishing-scorer',
  version: '2.0.0',
  core_indicators: 10,
  extended_indicators: 2,
  declared_features: 14,
  required_features: 11,
  evidence_only_features: 3,
  features_produced_by_extractor: 14,
  confidence_cap: 0.99,
  max_single_indicator_contribution: 0.6,
  thresholds: { phishing: 0.65, suspicious: 0.35 },
  keyword_vocabulary_size: 12,
  categories: { 'host-shape': 4, protocol: 1, content: 3, structure: 4 },
  indicators: [
    {
      id: 'rule_ip_host',
      name: 'IP Address Hostname',
      category: 'host-shape',
      version: '2.0.0',
      weight: 0.4,
      weight_kind: 'flat',
      inputs: ['is_ip'],
      matching: 'host is an IPv4/IPv6 literal',
      severity: 'high',
      explanation: 'Uses an IP address instead of a hostname.',
      mitre: 'T1566.002',
      core: true,
      extended: false,
    },
  ],
  provenance: {
    scorer: 'lexical-phishing-scorer',
    version: '2.0.0',
    model_family: 'deterministic lexical and structural scorer',
    trained_model: false,
    fitted_on_data: false,
    calibration: 'uncalibrated',
    calibration_note:
      'Weights are hand-set heuristics, not fitted parameters. No labelled evaluation corpus was used.',
    network_access: false,
    submits_url: false,
    resolves_dns: false,
    domain_suffix_list: 'bundled offline snapshot only (no publicsuffix.org fetch)',
    external_reputation: { implemented: false, providers: [], note: 'No reputation integration exists.' },
    core_indicators: 10,
    extended_indicators: 2,
    confidence_cap: 0.99,
    max_single_indicator_contribution: 0.6,
    thresholds: { phishing: 0.65, suspicious: 0.35, legitimate_below: 0.35 },
    deterministic: true,
  },
};

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
  // Exactly what the backend returns: a fixed statement that reputation is not
  // implemented, never a fake "clean" lookup result.
  reputation: {
    implemented: false,
    provider: null,
    status: 'unavailable',
    details:
      'No external reputation integration (VirusTotal, Google Safe Browsing or any other feed) exists in this project, and no URL is ever fetched or resolved.',
  },
  scorer: { name: 'lexical-phishing-scorer', version: '2.0.0' },
  confidence_cap: 0.99,
  max_single_indicator_contribution: 0.6,
  provenance: registryFixture.provenance,
};

describe('PhishingDetectionPage (Phase 6)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    (api.get as ReturnType<typeof vi.fn>).mockResolvedValue({ data: registryFixture });
  });

  /**
   * The page reads the indicator registry on mount, so the mount effect settles
   * an async state update. Rendering inside `act` flushes it instead of leaving
   * an "update not wrapped in act(...)" warning behind.
   */
  const mount = async () => {
    await act(async () => {
      render(<PhishingDetectionPage onVisualize={vi.fn()} />);
    });
  };

  it('renders the header and keeps Analyze disabled until a URL is entered', async () => {
    await mount();
    expect(screen.getByRole('heading', { name: 'Phishing Detection' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /analyze url/i })).toBeDisabled();
  });

  it('submits the URL and renders the honest lexical verdict, contract and limits', async () => {
    (api.post as ReturnType<typeof vi.fn>).mockResolvedValue({ data: benignResult });
    await mount();

    fireEvent.change(screen.getByLabelText('URL to analyze'), { target: { value: 'https://example.com/login' } });
    fireEvent.click(screen.getByRole('button', { name: /analyze url/i }));

    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith('/api/detect/phishing', { url: 'https://example.com/login' }),
    );
    expect(await screen.findByText('Below the phishing threshold - not a safety verdict')).toBeInTheDocument();
    // Threshold and cap come from the backend response, not from a hardcoded label.
    expect(screen.getByText('Phishing threshold: 65%')).toBeInTheDocument();
    expect(screen.getByText('Reported cap: 99%')).toBeInTheDocument();
    // No ML is claimed for phishing, and no reputation lookup is faked.
    expect(screen.getByText('No machine-learning model is used here')).toBeInTheDocument();
    expect(screen.getByText('Not implemented - no lookup was performed')).toBeInTheDocument();
    expect(screen.queryByText(/VirusTotal API key/i)).not.toBeInTheDocument();
    expect(screen.queryByText('Model Unavailable')).not.toBeInTheDocument();
    // The uncalibrated limitation is visible next to the verdict.
    expect(screen.getByText(/not a fitted model/i)).toBeInTheDocument();
  });

  it('renders the indicator registry served by the backend', async () => {
    (api.post as ReturnType<typeof vi.fn>).mockResolvedValue({ data: benignResult });
    await mount();

    fireEvent.change(screen.getByLabelText('URL to analyze'), { target: { value: 'https://example.com/login' } });
    fireEvent.click(screen.getByRole('button', { name: /analyze url/i }));

    expect(await screen.findByText('Scorer Contract')).toBeInTheDocument();
    await waitFor(() => expect(api.get).toHaveBeenCalledWith('/api/detect/phishing/indicators'));
    expect(screen.getByText('IP Address Hostname')).toBeInTheDocument();
    expect(screen.getByText('host is an IPv4/IPv6 literal')).toBeInTheDocument();
    expect(screen.getByText('Fetches the URL')).toBeInTheDocument();
    expect(screen.getByText('Trained model')).toBeInTheDocument();
    expect(screen.getByText('none integrated')).toBeInTheDocument();
    expect(screen.getByText('bundled offline snapshot only (no publicsuffix.org fetch)')).toBeInTheDocument();
    expect(screen.getByText(/Weights are hand-set heuristics, not fitted parameters/)).toBeInTheDocument();
  });

  it('states plainly that the registry could not be read, without inventing weights', async () => {
    (api.get as ReturnType<typeof vi.fn>).mockRejectedValue(new Error('offline'));
    (api.post as ReturnType<typeof vi.fn>).mockResolvedValue({ data: benignResult });
    await mount();

    fireEvent.change(screen.getByLabelText('URL to analyze'), { target: { value: 'https://example.com/login' } });
    fireEvent.click(screen.getByRole('button', { name: /analyze url/i }));

    expect(await screen.findByText(/indicator registry could not be read/i)).toBeInTheDocument();
    expect(screen.queryByText('IP Address Hostname')).not.toBeInTheDocument();
  });

  it('surfaces a failed analysis as an error state', async () => {
    (api.post as ReturnType<typeof vi.fn>).mockRejectedValue({
      response: { data: { detail: 'Backend unreachable' } },
    });
    await mount();

    fireEvent.change(screen.getByLabelText('URL to analyze'), { target: { value: 'http://bad' } });
    fireEvent.click(screen.getByRole('button', { name: /analyze url/i }));

    expect(await screen.findByRole('alert')).toBeInTheDocument();
    expect(screen.getByText('Backend unreachable')).toBeInTheDocument();
  });
});
