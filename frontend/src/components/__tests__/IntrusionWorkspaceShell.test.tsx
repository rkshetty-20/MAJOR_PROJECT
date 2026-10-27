import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, within } from '@testing-library/react';

vi.mock('../ids/api', () => ({
  fetchCatalog: vi.fn().mockResolvedValue([]),
  fetchPresets: vi.fn().mockResolvedValue([]),
  fetchRules: vi.fn().mockResolvedValue([]),
  analyzePayload: vi.fn(),
  runPreset: vi.fn(),
  extractError: (_err: unknown, fallback: string) => fallback,
}));

import { IntrusionDetectionWorkspace } from '../ids/IntrusionDetectionWorkspace';

describe('IntrusionDetectionWorkspace shell (Phase 5)', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it('renders the page header and an accessible tablist once reference data loads', async () => {
    render(<IntrusionDetectionWorkspace />);

    expect(screen.getByRole('heading', { name: 'Intrusion Detection' })).toBeInTheDocument();

    // Loading resolves to the main shell (empty catalog is a legitimate, honest state).
    const tablist = await screen.findByRole('tablist', { name: 'IDS views' });
    const tabs = within(tablist).getAllByRole('tab');
    expect(tabs).toHaveLength(3);
    expect(screen.getByRole('tab', { name: /payload lab/i })).toHaveAttribute('aria-selected', 'true');
  });

  it('moves tab selection when another tab is activated', async () => {
    render(<IntrusionDetectionWorkspace />);
    await screen.findByRole('tablist', { name: 'IDS views' });

    fireEvent.click(screen.getByRole('tab', { name: /rules/i }));
    expect(screen.getByRole('tab', { name: /rules/i })).toHaveAttribute('aria-selected', 'true');
    expect(screen.getByRole('tab', { name: /payload lab/i })).toHaveAttribute('aria-selected', 'false');
  });
});
