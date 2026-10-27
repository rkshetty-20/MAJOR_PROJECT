import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { expect, test, vi, beforeEach } from 'vitest';
import { SettingsPage } from '../SettingsPage';
import { getSystemConfig } from '../../api';

// Mock the API
vi.mock('../../api', () => ({
  getSystemConfig: vi.fn(),
}));

beforeEach(() => {
  vi.clearAllMocks();
  localStorage.clear();
});

test('SettingsPage fetches and renders system config', async () => {
  const mockConfig = {
    health: { database: 'connected', api: 'online' },
    detection: {
      phishing_threshold: 0.75,
      supported_rules: ['brute_force', 'sql_injection'],
      ml_model_version: 'v2.0 (Deep Learning)',
      ml_training_ready: true,
    },
    integrity: { hmac_configured: true },
    data: { event_count: 1500, detection_count: 42, retention_policy: '30 days' },
  };

  (getSystemConfig as any).mockResolvedValueOnce({ data: mockConfig });

  render(<SettingsPage />);

  // Should show loading state initially
  expect(screen.getByText('Loading system configuration...')).toBeInTheDocument();

  // Wait for the config to load and render
  await waitFor(() => {
    expect(screen.queryByText('Loading system configuration...')).not.toBeInTheDocument();
  });

  // Verify elements are rendered
  expect(screen.getByText('System Configuration & Health')).toBeInTheDocument();
  expect(screen.getByText('FastAPI Connectivity')).toBeInTheDocument();
  expect(screen.getByText('SQLite Connectivity')).toBeInTheDocument();
  expect(screen.getByText('75%')).toBeInTheDocument();
  expect(screen.getByText('brute force')).toBeInTheDocument();
  expect(screen.getByText('sql injection')).toBeInTheDocument();
  expect(screen.getByText('v2.0 (Deep Learning)')).toBeInTheDocument();
  expect(screen.getByText('Ready for Training')).toBeInTheDocument();
  expect(screen.getByText('Configured & Active')).toBeInTheDocument();
  expect(screen.getByText('1,500')).toBeInTheDocument();
  expect(screen.getByText('42')).toBeInTheDocument();
  expect(screen.getByText('30 days')).toBeInTheDocument();
});

test('SettingsPage handles error state', async () => {
  (getSystemConfig as any).mockRejectedValueOnce(new Error('Network error'));

  render(<SettingsPage />);

  await waitFor(() => {
    expect(screen.getByText('Configuration Unavailable')).toBeInTheDocument();
    expect(screen.getByText('Network error')).toBeInTheDocument();
  });
});

test('SettingsPage saves preferences to local storage', async () => {
  const mockConfig = {
    health: { database: 'connected', api: 'online' },
    detection: {
      phishing_threshold: 0.75,
      supported_rules: [],
      ml_model_version: 'v1.0',
      ml_training_ready: false,
    },
    integrity: { hmac_configured: false },
    data: { event_count: 0, detection_count: 0, retention_policy: 'None' },
  };

  (getSystemConfig as any).mockResolvedValueOnce({ data: mockConfig });
  
  // Mock window.alert
  const alertMock = vi.spyOn(window, 'alert').mockImplementation(() => {});

  render(<SettingsPage />);

  await waitFor(() => {
    expect(screen.getByText('Save Preferences')).toBeInTheDocument();
  });

  // Change theme
  const themeSelect = screen.getByLabelText('UI Theme') as HTMLSelectElement;
  fireEvent.change(themeSelect, { target: { value: 'light' } });
  
  // Change landing page
  const landingPageSelect = screen.getByLabelText('Default Landing Page') as HTMLSelectElement;
  fireEvent.change(landingPageSelect, { target: { value: 'logs' } });

  // Click save
  fireEvent.click(screen.getByText('Save Preferences'));

  expect(localStorage.getItem('theme')).toBe('light');
  expect(localStorage.getItem('landingPage')).toBe('logs');
  expect(alertMock).toHaveBeenCalled();
  
  alertMock.mockRestore();
});
