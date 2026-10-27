import React from 'react';
import { SecurityOverview, OverviewMetrics } from './SecurityOverview';
import { AttackCoverage } from './AttackCoverage';
import { DetectionRiskOverview, RiskData, DetectionItem } from './DetectionRiskOverview';
import { Activity, RefreshCw } from 'lucide-react';
import { PageHeader, SectionHeader, Button } from './ui';

interface DashboardPageProps {
  overviewMetrics: OverviewMetrics | null;
  riskData: RiskData | null;
  detections: DetectionItem[];
  isTelemetryLoading: boolean;
  onRefresh: () => void;
  onInvestigateDetection: (id: number) => void;
}

export const DashboardPage: React.FC<DashboardPageProps> = ({
  overviewMetrics,
  riskData,
  detections,
  isTelemetryLoading,
  onRefresh,
  onInvestigateDetection
}) => {
  return (
    <div className="w-full max-w-[1400px] mx-auto space-y-8">
      <PageHeader
        title="Security Operations Overview"
        description="Live telemetry across network intrusion and phishing detection."
        icon={<Activity className="w-5 h-5" />}
        actions={
          <Button
            variant="secondary"
            size="sm"
            onClick={onRefresh}
            loading={isTelemetryLoading}
            leftIcon={<RefreshCw className="w-3.5 h-3.5" />}
          >
            Refresh
          </Button>
        }
      />

      {/* SECTION 2: Security Overview Cards */}
      <SecurityOverview
        metrics={overviewMetrics}
        isLoading={isTelemetryLoading}
        onRefresh={onRefresh}
      />

      {/* TWO-TRACK ARCHITECTURE (INTRUSION vs PHISHING) */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        
        {/* LEFT TRACK: NETWORK INTRUSION */}
        <div className="flex flex-col gap-4">
          <SectionHeader
            title="Network Intrusion Detection"
            className="[&_h2]:text-success"
          />
          <div className="h-64">
            <AttackCoverage domain="intrusion" />
          </div>
        </div>

        {/* RIGHT TRACK: PHISHING */}
        <div className="flex flex-col gap-4">
          <SectionHeader
            title="Phishing Detection"
            className="[&_h2]:text-warning"
          />
          <div className="h-64">
            <AttackCoverage domain="phishing" />
          </div>
        </div>
      </div>

      {/* SECTION 4: Detection Overview & Risk Distribution */}
      <DetectionRiskOverview
        riskData={riskData}
        detections={detections}
        isLoading={isTelemetryLoading}
        onInvestigateDetection={onInvestigateDetection}
      />
    </div>
  );
};
