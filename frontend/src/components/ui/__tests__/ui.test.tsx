import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import {
  Button,
  MetricCard,
  StatusBadge,
  RiskIndicator,
  EmptyState,
  ErrorState,
  SkeletonPanel,
  Tooltip,
  Card,
  PageHeader,
} from '../index';

describe('Shared UI kit (design system foundation)', () => {
  it('Button shows a loading state and prevents duplicate activation', () => {
    const onClick = vi.fn();
    render(
      <Button loading onClick={onClick}>
        Save
      </Button>,
    );
    const btn = screen.getByRole('button', { name: 'Save' });
    expect(btn).toBeDisabled();
    expect(btn).toHaveAttribute('aria-busy', 'true');
    fireEvent.click(btn);
    expect(onClick).not.toHaveBeenCalled();
  });

  it('MetricCard renders an explicit unavailable state instead of a fake zero', () => {
    render(<MetricCard label="Stored detections" value={null} />);
    expect(screen.getByText('Stored detections')).toBeInTheDocument();
    expect(screen.getByText('Unavailable')).toBeInTheDocument();
    expect(screen.queryByText('0')).not.toBeInTheDocument();
  });

  it('MetricCard renders a real value with unit', () => {
    render(<MetricCard label="F1" value={0.87} unit="" tone="success" />);
    expect(screen.getByText('0.87')).toBeInTheDocument();
  });

  it('StatusBadge and RiskIndicator expose a text label (not color alone)', () => {
    render(<RiskIndicator level="high" />);
    expect(screen.getByText('High')).toBeInTheDocument();
    render(<StatusBadge tone="success">Active</StatusBadge>);
    expect(screen.getByText('Active')).toBeInTheDocument();
  });

  it('EmptyState surfaces its next-action and ErrorState offers a working retry', () => {
    render(<EmptyState title="No datasets" description="Generate one" action={<button>Generate</button>} />);
    expect(screen.getByText('No datasets')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Generate' })).toBeInTheDocument();

    const onRetry = vi.fn();
    render(<ErrorState message="Request failed" onRetry={onRetry} />);
    expect(screen.getByRole('alert')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }));
    expect(onRetry).toHaveBeenCalledTimes(1);
  });

  it('SkeletonPanel announces a loading status for assistive tech', () => {
    render(<SkeletonPanel lines={3} />);
    expect(screen.getByRole('status')).toBeInTheDocument();
  });

  it('Tooltip renders its accessible label text', () => {
    render(
      <Tooltip label="Threshold explanation">
        <span>info</span>
      </Tooltip>,
    );
    expect(screen.getByRole('tooltip')).toHaveTextContent('Threshold explanation');
  });

  it('Card renders its title and PageHeader renders breadcrumb + actions', () => {
    render(<Card title="Detection">body</Card>);
    expect(screen.getByText('Detection')).toBeInTheDocument();

    render(
      <PageHeader
        title="Adaptive Learning"
        description="Model state"
        breadcrumb={['Intelligence', 'Adaptive Learning']}
        actions={<button>Train</button>}
      />,
    );
    expect(screen.getByRole('heading', { name: 'Adaptive Learning' })).toBeInTheDocument();
    expect(screen.getByRole('navigation', { name: 'Breadcrumb' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Train' })).toBeInTheDocument();
  });
});
