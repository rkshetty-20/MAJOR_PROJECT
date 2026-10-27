import React from 'react';
import {
  Activity,
  ShieldAlert,
  AlertTriangle,
  Radio,
  CheckCircle2,
  Cpu,
} from 'lucide-react';
import { MetricCard, SectionHeader, Skeleton } from './ui';

export interface OverviewMetrics {
  total_events: number;
  detected_threats: number;
  high_risk_events: number;
  active_simulations: number;
  detections_per_event_ratio: string;
  false_positive_rate: string;
  model_accuracy: string;
  model_accuracy_source?: string | null;
}

interface SecurityOverviewProps {
  metrics: OverviewMetrics | null;
  isLoading: boolean;
  onRefresh: () => void;
}

export const SecurityOverview: React.FC<SecurityOverviewProps> = ({
  metrics,
  isLoading,
}) => {
  const isDetectionRateNa = !metrics || metrics.detections_per_event_ratio === 'N/A';
  const isFpNa = !metrics || metrics.false_positive_rate === 'N/A';
  const isModelAccuracyNa = !metrics || metrics.model_accuracy === 'N/A';

  if (isLoading && !metrics) {
    return (
      <div className="w-full space-y-3">
        <SectionHeader title="Security Overview Metrics" />
        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-3">
          {Array.from({ length: 7 }).map((_, i) => (
            <Skeleton key={i} className="h-[92px] w-full" />
          ))}
        </div>
      </div>
    );
  }

  const accuracyHint = metrics?.model_accuracy_source
    ? `${metrics.model_accuracy_source} synthetic holdout - Controlled synthetic evaluation`
    : 'Controlled synthetic evaluation';

  return (
    <div className="w-full space-y-3">
      <SectionHeader title="Security Overview Metrics" />

      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-3">
        <MetricCard
          label="Total Events"
          value={metrics ? metrics.total_events.toLocaleString() : undefined}
          hint="All persisted security telemetry"
          icon={<Radio className="w-3.5 h-3.5" />}
        />
        <MetricCard
          label="Detected Threats"
          value={metrics ? metrics.detected_threats.toLocaleString() : undefined}
          hint="Events with detection signals"
          tone="warning"
          icon={<ShieldAlert className="w-3.5 h-3.5" />}
        />
        <MetricCard
          label="High/Crit Risk"
          value={metrics ? metrics.high_risk_events.toLocaleString() : undefined}
          hint="Events with risk score >= 60"
          tone="danger"
          icon={<AlertTriangle className="w-3.5 h-3.5" />}
        />
        <MetricCard
          label="Active Sims"
          value={metrics ? metrics.active_simulations : undefined}
          hint="Running sessions"
          tone="success"
          icon={<Activity className="w-3.5 h-3.5" />}
        />
        <MetricCard
          label="Detections / Event"
          value={isDetectionRateNa ? undefined : metrics!.detections_per_event_ratio}
          unavailable={isDetectionRateNa}
          hint={isDetectionRateNa ? 'No events evaluated' : 'Global detection volume'}
          tone="info"
          icon={<CheckCircle2 className="w-3.5 h-3.5" />}
        />
        <MetricCard
          label="False Positives"
          value={isFpNa ? undefined : metrics!.false_positive_rate}
          unavailable={isFpNa}
          hint={isFpNa ? 'Pending baseline' : 'Benchmark baseline'}
          tone="info"
          icon={<AlertTriangle className="w-3.5 h-3.5" />}
        />
        <MetricCard
          label="ML Synthetic Accuracy"
          value={isModelAccuracyNa ? undefined : metrics!.model_accuracy}
          unavailable={isModelAccuracyNa}
          hint={isModelAccuracyNa ? 'No evaluation data' : accuracyHint}
          tone="default"
          icon={<Cpu className="w-3.5 h-3.5" />}
        />
      </div>
    </div>
  );
};
