import React from 'react';
import { Shield, ShieldAlert, Zap, Globe, Key, Database, Activity, Link2, Search } from 'lucide-react';
import { Card, StatusBadge, type BadgeTone } from './ui';

interface AttackCoverageProps {
  domain: 'intrusion' | 'phishing';
}

export const AttackCoverage: React.FC<AttackCoverageProps> = ({ domain }) => {
  const isIntrusion = domain === 'intrusion';
  const tone: BadgeTone = isIntrusion ? 'success' : 'warning';
  const iconColor = isIntrusion ? 'text-success' : 'text-warning';

  const intrusionItems = [
    { name: "Brute Force", desc: "Telemetry-driven threshold logic", icon: Key },
    { name: "Credential Stuffing", desc: "Distinct user targeting velocity", icon: Database },
    { name: "Suspicious Login", desc: "Geo-velocity & Impossible Travel", icon: Globe },
    { name: "Port Scanning", desc: "Adaptive Random Forest ML", icon: Activity },
  ];

  const phishingItems = [
    { name: "Phishing URLs", desc: "Domain heuristics & Keyword scoring", icon: Link2 },
    { name: "Deceptive Domains", desc: "URL length & structure analysis", icon: ShieldAlert },
    { name: "Suspicious Content", desc: "Keyword harvesting & risk patterns", icon: Search },
  ];

  const coverageItems = isIntrusion ? intrusionItems : phishingItems;
  const HeaderIcon = isIntrusion ? Shield : ShieldAlert;
  const title = isIntrusion ? "Network Intrusion Coverage" : "Phishing Detection Coverage";

  return (
    <Card
      title={title}
      icon={<HeaderIcon className="w-4 h-4" />}
      className="h-full flex flex-col"
      bodyClassName="flex-1 min-h-0 p-4"
      right={
        <StatusBadge tone={tone} glyph={<Zap className="w-3 h-3" />}>
          Data-Driven
        </StatusBadge>
      }
    >
      <div className="h-full overflow-y-auto pr-1 custom-scrollbar">
        <div className="grid grid-cols-1 gap-2.5">
          {coverageItems.map((item) => {
            const ItemIcon = item.icon;
            return (
              <div
                key={item.name}
                className="bg-app/40 p-3 rounded-card border border-line flex items-center gap-4"
              >
                <div className={`bg-elevated/60 p-2 rounded border border-line ${iconColor}`}>
                  <ItemIcon className="w-4 h-4" />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="text-sm font-medium text-ink">{item.name}</div>
                  <div className="text-xs text-ink-muted mt-0.5">{item.desc}</div>
                </div>
                <StatusBadge tone={tone}>Active</StatusBadge>
              </div>
            );
          })}
        </div>
      </div>
    </Card>
  );
};
