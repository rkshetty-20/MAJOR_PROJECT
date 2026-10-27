import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { studioListCategories, studioPropose } from '../../api';
import { ScenarioStudioPage } from '../ScenarioStudioPage';

vi.mock('../../api', () => ({
  studioListCategories: vi.fn(),
  studioPropose: vi.fn(),
  studioValidate: vi.fn(),
  studioCompile: vi.fn(),
  studioReplay: vi.fn(),
  studioLifecycle: vi.fn(),
  studioLearningEligibility: vi.fn(),
  studioImportLearning: vi.fn(),
}));

describe('ScenarioStudioPage (Phase 7)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    (studioListCategories as ReturnType<typeof vi.fn>).mockResolvedValue({ data: [] });
  });

  it('renders the PageHeader and Step 1, keeping Propose disabled until a request is typed', async () => {
    render(<ScenarioStudioPage />);
    expect(screen.getByRole('heading', { name: 'Attack Scenario Studio' })).toBeInTheDocument();
    expect(screen.getByText(/Describe the scenario/)).toBeInTheDocument();

    const proposeBtn = screen.getByRole('button', { name: /propose scenario/i });
    expect(proposeBtn).toBeDisabled();

    await waitFor(() => expect(studioListCategories).toHaveBeenCalled());
  });

  it('enables Propose once text is entered and shows the honest 503 message without a fabricated proposal', async () => {
    (studioPropose as ReturnType<typeof vi.fn>).mockRejectedValue({ response: { status: 503 } });
    render(<ScenarioStudioPage />);

    fireEvent.change(screen.getByLabelText('Scenario request'), {
      target: { value: 'Simulate a synthetic port scan with a benign baseline.' },
    });
    const proposeBtn = screen.getByRole('button', { name: /propose scenario/i });
    expect(proposeBtn).toBeEnabled();
    fireEvent.click(proposeBtn);

    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent('AI provider unavailable (503). The deterministic simulator remains available');
    expect(screen.queryByText(/edit the proposal/)).not.toBeInTheDocument();
    expect(studioPropose).toHaveBeenCalled();
  });
});
