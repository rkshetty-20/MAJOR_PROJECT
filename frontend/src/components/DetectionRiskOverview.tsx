import React from 'react';
import {
  ShieldCheck,
  Layers,
} from 'lucide-react';
import { Card, MetricCard, StatusBadge, EmptyState, Mono } from './ui';

export interface RiskData {
  total_assessments: number;
  average_score: number;
  distribution: {
    LOW: number;
    MEDIUM: number;
    HIGH: number;
    CRITICAL: number;
  };
  latest_scores: Array<{
    id: number;
    session_id: number;
    score: number;
    band: string;
    timestamp: string;
  }>;
}

export interface DetectionItem {
  id: number;
  session_id: number;
  source: string;
  label: string;
  confidence: number;
  explanation?: string;
  timestamp: string;
}

interface DetectionRiskOverviewProps {
  riskData: RiskData | null;
  detections: DetectionItem[];
  isLoading?: boolean;
  onInvestigateDetection?: (id: number) => void;
}

const METERS = [
  { key: 'CRITICAL', label: 'CRITICAL (85 - 100)', dot: 'bg-danger', fill: 'bg-danger', text: 'text-danger' },
  { key: 'HIGH', label: 'HIGH (60 - 84)', dot: 'bg-warning', fill: 'bg-warning', text: 'text-warning' },
  { key: 'MEDIUM', label: 'MEDIUM (30 - 59)', dot: 'bg-info', fill: 'bg-info', text: 'text-info' },
  { key: 'LOW', label: 'LOW (0 - 29)', dot: 'bg-success', fill: 'bg-success', text: 'text-success' },
] as const;

export const DetectionRiskOverview: React.FC<DetectionRiskOverviewProps> = ({
  riskData,
  detections,
  onInvestigateDetection,
}) => {
  const distribution = riskData?.distribution || { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };
  const totalRisks = (distribution.LOW + distribution.MEDIUM + distribution.HIGH + distribution.CRITICAL) || 1;

  const ruleCount = detections.filter(d => d.source.toLowerCase() === 'rule').length;
  const mlCount = detections.filter(d => d.source.toLowerCase() === 'ml').length;
  const hybridCount = detections.filter(d => d.source.toLowerCase() === 'hybrid').length;

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 w-full">
      {/* Risk Distribution Card */}
      <Card
        title="Risk Level Distribution"
        icon={<ShieldCheck className="w-4 h-4" />}
        right={
          <span className="text-xs font-mono text-ink-muted">
            Avg Score: <strong className="text-ink">{riskData ? `${riskData.average_score}/100` : 'N/A'}</strong>
          </span>
        }
      >
        {riskData ? (
          <div className="space-y-2.5 text-xs">
            {METERS.map((meter) => {
              const count = distribution[meter.key];
              const pct = Math.round((count / totalRisks) * 100);
              return (
                <div key={meter.key}>
                  <div className="flex justify-between text-ink-soft mb-1">
                    <span className={`flex items-center gap-1.5 font-semibold ${meter.text}`}>
                      <span className={`w-2 h-2 rounded-full ${meter.dot}`} />
                      {meter.label}
                    </span>
                    <span className="font-mono text-ink-muted">{count} events ({pct}%)</span>
                  </div>
                  <div className="w-full bg-app h-2 rounded-full overflow-hidden">
                    <div
                      className={`${meter.fill} h-full transition-all duration-500 rounded-full`}
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        ) : (
          <EmptyState
            title="No risk data available"
            description="Risk assessments will appear here once the backend returns scored events."
          />
        )}
      </Card>

      {/* Detection Pipeline Breakdown Card */}
      <Card
        title="Detection Pipeline Source"
        icon={<Layers className="w-4 h-4" />}
        right={
          <span className="text-xs font-mono text-ink-muted">
            Total Detections: <strong className="text-ink">{detections.length}</strong>
          </span>
        }
      >
        <div className="grid grid-cols-3 gap-3">
          <MetricCard label="Rule Engine" value={ruleCount} hint="Sliding windows" tone="info" className="p-3" />
          <MetricCard label="ML Model" value={mlCount} hint="Random Forest" tone="default" className="p-3" />
          <MetricCard label="Consensus" value={hybridCount} hint="Hybrid boost" tone="success" className="p-3" />
        </div>

        {/* Recent Detections Preview */}
        <div className="mt-4 space-y-1.5">
          <span className="text-[11px] font-semibold text-ink-muted uppercase tracking-wider block">
            Recent Triggered Rules:
          </span>
          {detections.length === 0 ? (
            <EmptyState title="No threat detections triggered yet." />
          ) : (
            <div className="max-h-24 overflow-y-auto space-y-1 custom-scrollbar">
              {detections.slice(0, 3).map((d) => (
                <div
                  key={d.id}
                  role={onInvestigateDetection ? 'button' : undefined}
                  tabIndex={onInvestigateDetection ? 0 : undefined}
                  onClick={() => onInvestigateDetection && onInvestigateDetection(d.id)}
                  onKeyDown={(e) => {
                    if (onInvestigateDetection && (e.key === 'Enter' || e.key === ' ')) {
                      e.preventDefault();
                      onInvestigateDetection(d.id);
                    }
                  }}
                  className={`text-xs p-1.5 rounded-card bg-app/50 border border-line flex items-center justify-between gap-2 ${
                    onInvestigateDetection ? 'cursor-pointer hover:bg-elevated/60 hover:border-line-strong transition-colors focus-visible:ring-2 focus-visible:ring-accent/40' : ''
                  }`}
                >
                  <Mono className="truncate max-w-[240px]">{d.label}</Mono>
                  <StatusBadge tone="neutral">{d.source}</StatusBadge>
                </div>
              ))}
            </div>
          )}
        </div>
      </Card>
    </div>
  );
};
