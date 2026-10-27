// Threat intelligence panel: CVEs, actors, NIST/OWASP refs, mitigations and
// a one-click JSON export of the full analysis.
import React from 'react';
import { BookOpen, Download, Bug, Users, ShieldCheck, Lightbulb, ListChecks } from 'lucide-react';
import type { IdsAnalysis } from './types';
import { Card } from './primitives';
import { Button } from '../ui';

export const ThreatIntelPanel: React.FC<{ analysis: IdsAnalysis }> = ({ analysis }) => {
  const { threat_intel } = analysis;

  const handleExport = () => {
    const blob = new Blob([JSON.stringify(analysis, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${analysis.analysis_id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <Card
      title="Threat Intelligence"
      icon={<BookOpen className="w-4 h-4" />}
      right={
        <Button variant="secondary" size="sm" onClick={handleExport} leftIcon={<Download className="w-3.5 h-3.5" />}>
          Export JSON
        </Button>
      }
    >
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        <IntelGroup icon={<Bug className="w-3.5 h-3.5" />} label="Related CVEs" items={threat_intel.cves} empty="No CVE references." pill="rose" />
        <IntelGroup icon={<Users className="w-3.5 h-3.5" />} label="Threat Actors" items={threat_intel.actors} empty="No actor attribution." pill="orange" />
        <IntelGroup icon={<ShieldCheck className="w-3.5 h-3.5" />} label="NIST References" items={threat_intel.nist} empty="No NIST controls mapped." pill="sky" />
        <IntelGroup icon={<ListChecks className="w-3.5 h-3.5" />} label="OWASP References" items={threat_intel.owasp} empty="No OWASP mapping." pill="indigo" />
      </div>

      {threat_intel.mitigations.length > 0 && (
        <div className="mt-5">
          <div className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-emerald-300 mb-2">
            <Lightbulb className="w-4 h-4" /> Recommended Mitigations
          </div>
          <ul className="space-y-1.5">
            {threat_intel.mitigations.map((m, i) => (
              <li key={i} className="flex items-start gap-2 text-xs text-ink-soft">
                <span className="mt-1 w-1.5 h-1.5 rounded-full bg-emerald-400 shrink-0" />
                <span>{m}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {threat_intel.frequency_note && (
        <p className="mt-4 text-[11px] text-ink-muted italic border-t border-line pt-3">{threat_intel.frequency_note}</p>
      )}
    </Card>
  );
};

const PILL: Record<string, string> = {
  rose: 'bg-rose-500/10 text-rose-300 border-rose-500/25',
  orange: 'bg-orange-500/10 text-orange-300 border-orange-500/25',
  sky: 'bg-sky-500/10 text-sky-300 border-sky-500/25',
  indigo: 'bg-indigo-500/10 text-indigo-300 border-indigo-500/25',
};

const IntelGroup: React.FC<{
  icon: React.ReactNode;
  label: string;
  items: string[];
  empty: string;
  pill: keyof typeof PILL;
}> = ({ icon, label, items, empty, pill }) => (
  <div>
    <div className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-ink-muted mb-2">
      <span className="text-ink-faint">{icon}</span>
      {label}
    </div>
    {items.length === 0 ? (
      <div className="text-[11px] text-ink-muted italic">{empty}</div>
    ) : (
      <div className="flex flex-wrap gap-1.5">
        {items.map((it, i) => (
          <span key={i} className={`px-2 py-0.5 rounded-md text-[11px] font-mono border ${PILL[pill]}`}>
            {it}
          </span>
        ))}
      </div>
    )}
  </div>
);
