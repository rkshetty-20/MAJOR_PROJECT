import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { Sidebar } from '../Sidebar';

const base = {
  responseTime: 42,
  onPing: () => {},
  apiUrl: 'http://localhost:8000',
};

describe('Sidebar shell semantics', () => {
  it('marks the active destination with aria-current and routes clicks', () => {
    const onNavigate = vi.fn();
    render(<Sidebar {...base} activePage="adaptive" onNavigate={onNavigate} connectionState="connected" />);

    const active = screen.getByRole('button', { name: /Adaptive Learning/i });
    expect(active).toHaveAttribute('aria-current', 'page');

    const other = screen.getByRole('button', { name: /Dashboard/i });
    expect(other).not.toHaveAttribute('aria-current');

    fireEvent.click(other);
    expect(onNavigate).toHaveBeenCalledWith('dashboard');
  });

  it('distinguishes service health from raw connectivity when provided', () => {
    render(
      <Sidebar
        {...base}
        activePage="dashboard"
        onNavigate={() => {}}
        connectionState="degraded"
        mlStatus="unavailable"
        integrityStatus="ready"
      />,
    );
    expect(screen.getByText('Degraded')).toBeInTheDocument();
    expect(screen.getByText('ML Engine')).toBeInTheDocument();
    expect(screen.getByText('Evidence Integrity')).toBeInTheDocument();
    // Untrained ML is shown as a label, not a crash; integrity is ready.
    expect(screen.getByText('Unavailable')).toBeInTheDocument();
    expect(screen.getByText('Ready')).toBeInTheDocument();
  });

  it('hides service sub-indicators when they are not supplied', () => {
    render(<Sidebar {...base} activePage="dashboard" onNavigate={() => {}} connectionState="connected" />);
    expect(screen.queryByText('ML Engine')).not.toBeInTheDocument();
    expect(screen.queryByText('Evidence Integrity')).not.toBeInTheDocument();
  });
});
