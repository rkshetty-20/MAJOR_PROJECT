import { render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import api from '../../api';
import { isCoreHealthy, SystemHealthProvider, useSystemHealth } from '../useSystemHealth';

vi.mock('../../api', () => ({
  default: { get: vi.fn() },
}));

/**
 * The payload `GET /api/system/config` really returns on a healthy core. Captured
 * from a running `uvicorn app.main:app` instance, not invented: the badge used to
 * read `api === 'ok' && database === 'ok'`, but the backend emits `"online"` and
 * `"connected"`, so every screen showed "Degraded" while all requests returned 200.
 */
const LIVE_HEALTHY_CONFIG = {
  health: { database: 'connected', api: 'online' },
  detection: {
    phishing_threshold: 0.65,
    supported_rules: ['brute_force'],
    ml_model_version: 'base_model',
    ml_training_ready: false,
  },
  integrity: { hmac_configured: true },
  data: { event_count: 852, detection_count: 43, retention_policy: 'No automated deletion' },
};

function Probe() {
  const health = useSystemHealth();
  return (
    <div>
      <span data-testid="status">{health.status}</span>
      <span data-testid="ml">{health.ml.status}</span>
      <span data-testid="integrity">{health.integrity.status}</span>
      <span data-testid="model">{health.ml.modelVersion ?? 'none'}</span>
    </div>
  );
}

function renderProbe() {
  return render(
    <SystemHealthProvider>
      <Probe />
    </SystemHealthProvider>,
  );
}

describe('isCoreHealthy', () => {
  it('accepts the vocabulary the backend actually emits', () => {
    expect(isCoreHealthy({ health: { database: 'connected', api: 'online' } })).toBe(true);
  });

  it('still accepts the older "ok" fixtures', () => {
    expect(isCoreHealthy({ health: { database: 'ok', api: 'ok' } })).toBe(true);
  });

  it('treats a failed database probe as degraded, not connected', () => {
    expect(isCoreHealthy({ health: { database: 'error', api: 'online' } })).toBe(false);
  });

  it('refuses to claim health when the payload is missing', () => {
    expect(isCoreHealthy(null)).toBe(false);
    expect(isCoreHealthy(undefined)).toBe(false);
    expect(isCoreHealthy({ health: { database: '', api: '' } })).toBe(false);
  });
});

describe('SystemHealthProvider', () => {
  beforeEach(() => {
    vi.mocked(api.get).mockReset();
  });

  it('reports connected against the real /api/system/config payload', async () => {
    vi.mocked(api.get).mockImplementation(async (url: string) => {
      if (url === '/health') return { data: { status: 'ok' } } as never;
      return { data: LIVE_HEALTHY_CONFIG } as never;
    });

    renderProbe();

    await waitFor(() => expect(screen.getByTestId('status')).toHaveTextContent('connected'));
    expect(screen.getByTestId('status')).not.toHaveTextContent('degraded');
    expect(screen.getByTestId('integrity')).toHaveTextContent('ready');
    // An untrained model is "unavailable", never "degraded" and never invented.
    expect(screen.getByTestId('ml')).toHaveTextContent('unavailable');
    expect(screen.getByTestId('model')).not.toHaveTextContent('none');
  });

  it('reports degraded when the database probe fails', async () => {
    vi.mocked(api.get).mockImplementation(async (url: string) => {
      if (url === '/health') return { data: { status: 'ok' } } as never;
      return { data: { ...LIVE_HEALTHY_CONFIG, health: { database: 'error', api: 'online' } } } as never;
    });

    renderProbe();

    await waitFor(() => expect(screen.getByTestId('status')).toHaveTextContent('degraded'));
  });

  it('reports disconnected when the backend is unreachable', async () => {
    vi.mocked(api.get).mockRejectedValue(new Error('Network Error'));

    renderProbe();

    await waitFor(() => expect(screen.getByTestId('status')).toHaveTextContent('disconnected'));
  });
});
