import React, { useState } from 'react';
import {
  Search,
  MessageSquare,
  Radio,
  RefreshCw,
} from 'lucide-react';
import {
  PageHeader,
  Card,
  Button,
  StatusBadge,
  EmptyState,
  SkeletonPanel,
  Mono,
  type BadgeTone,
} from './ui';

export interface SecurityEventItem {
  id: number;
  session_id?: number;
  simulation_id?: string;
  scenario: string;
  event_type: string;
  timestamp: string;
  source: string;
  target: string;
  device?: string;
  location?: string;
  risk_score?: number;
  risk_level?: string;
  detection_status: string;
  payload?: Record<string, unknown>;
  evidence_hash?: string;
}

interface RecentEventsTableProps {
  events: SecurityEventItem[];
  isLoading: boolean;
  onSelectEvent: (event: SecurityEventItem) => void;
  onAskChatbot: (telemetryContext: Record<string, unknown>, promptMessage: string) => void;
  onRefresh: () => void;
}

const RISK_TONE: Record<string, BadgeTone> = {
  CRITICAL: 'danger',
  HIGH: 'warning',
  MEDIUM: 'info',
  LOW: 'success',
};

export const RecentEventsTable: React.FC<RecentEventsTableProps> = ({
  events,
  isLoading,
  onSelectEvent,
  onAskChatbot,
  onRefresh,
}) => {
  const [filterQuery, setFilterQuery] = useState('');
  const [riskFilter, setRiskFilter] = useState<'ALL' | 'HIGH' | 'MEDIUM' | 'LOW'>('ALL');

  const filteredEvents = events.filter((ev) => {
    const matchesSearch =
      ev.scenario.toLowerCase().includes(filterQuery.toLowerCase()) ||
      ev.event_type.toLowerCase().includes(filterQuery.toLowerCase()) ||
      ev.source.toLowerCase().includes(filterQuery.toLowerCase()) ||
      ev.target.toLowerCase().includes(filterQuery.toLowerCase());

    const matchesRisk =
      riskFilter === 'ALL'
        ? true
        : riskFilter === 'HIGH'
        ? ev.risk_level?.toUpperCase() === 'HIGH' || ev.risk_level?.toUpperCase() === 'CRITICAL'
        : ev.risk_level?.toUpperCase() === riskFilter;

    return matchesSearch && matchesRisk;
  });

  const formatTimestamp = (raw: string) => {
    try {
      const d = new Date(raw);
      return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    } catch {
      return raw;
    }
  };

  return (
    <div className="w-full space-y-6">
      <PageHeader
        title="Event Logs"
        description="Real-time telemetry captured by the detection engine."
        icon={<Radio className="w-5 h-5" />}
        actions={
          <Button
            variant="secondary"
            size="sm"
            onClick={onRefresh}
            loading={isLoading}
            leftIcon={<RefreshCw className="w-3.5 h-3.5" />}
          >
            Refresh
          </Button>
        }
      />

      <Card bodyClassName="p-0">
        {/* Filter Toolbar */}
        <div className="px-5 py-3 border-b border-line bg-app/40 flex items-center justify-between flex-wrap gap-3">
          <p className="text-xs text-ink-muted">
            {events.length} total event{events.length === 1 ? '' : 's'}
          </p>

          <div className="flex items-center gap-2 flex-wrap">
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-ink-faint absolute left-2.5 top-1/2 -translate-y-1/2" aria-hidden />
              <input
                type="text"
                value={filterQuery}
                onChange={(e) => setFilterQuery(e.target.value)}
                placeholder="Filter by IP, target, scenario..."
                aria-label="Filter events by IP, target, or scenario"
                className="bg-app border border-line-strong rounded-lg pl-8 pr-3 py-1.5 text-xs text-ink placeholder:text-ink-faint focus:outline-none focus-visible:ring-2 focus-visible:ring-accent/40 w-44 sm:w-56"
              />
            </div>

            <div role="group" aria-label="Filter by risk level" className="flex bg-app p-0.5 rounded-lg border border-line text-[11px]">
              {(['ALL', 'HIGH', 'MEDIUM', 'LOW'] as const).map((lvl) => (
                <button
                  key={lvl}
                  type="button"
                  onClick={() => setRiskFilter(lvl)}
                  aria-pressed={riskFilter === lvl}
                  className={`px-2 py-0.5 rounded-md font-medium capitalize transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/40 ${
                    riskFilter === lvl ? 'bg-accent text-white' : 'text-ink-muted hover:text-ink'
                  }`}
                >
                  {lvl}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Table Container */}
        <div className="overflow-x-auto max-h-[420px] custom-scrollbar">
          <table className="w-full text-left border-collapse text-xs">
            <caption className="sr-only">
              Recent security events with risk level, source, target, and detection status.
            </caption>
            <thead className="bg-app/60 sticky top-0 border-b border-line text-ink-muted font-semibold uppercase tracking-wider">
              <tr>
                <th className="w-1.5 p-0" aria-hidden />
                <th scope="col" className="py-3 px-4">Time</th>
                <th scope="col" className="py-3 px-4">Scenario / Type</th>
                <th scope="col" className="py-3 px-4">Source</th>
                <th scope="col" className="py-3 px-4">Target</th>
                <th scope="col" className="py-3 px-4">Risk Level</th>
                <th scope="col" className="py-3 px-4">Status</th>
                <th scope="col" className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line/60">
              {isLoading && events.length === 0 ? (
                <tr>
                  <td colSpan={8} className="p-6">
                    <SkeletonPanel lines={5} />
                  </td>
                </tr>
              ) : filteredEvents.length === 0 ? (
                <tr>
                  <td colSpan={8}>
                    <EmptyState
                      title={events.length === 0
                        ? "No security telemetry events yet"
                        : "No events match your filters"}
                      description={events.length === 0
                        ? "Events will appear here as the detection engine records them."
                        : "Try adjusting the search text or risk filter."}
                    />
                  </td>
                </tr>
              ) : (
                filteredEvents.map((ev) => {
                  const isPhishing = ev.scenario.toLowerCase().includes('phishing');
                  const accentColor = isPhishing ? 'bg-warning' : 'bg-success';
                  const level = (ev.risk_level || 'LOW').toUpperCase();

                  return (
                    <tr
                      key={ev.id}
                      className="hover:bg-elevated/40 transition-colors cursor-pointer"
                      onClick={() => onSelectEvent(ev)}
                    >
                      <td className={`w-1.5 p-0 ${accentColor}`} aria-hidden />
                      <td className="py-3 px-4 text-ink-muted whitespace-nowrap font-mono">
                        {formatTimestamp(ev.timestamp)}
                      </td>
                      <td className="py-3 px-4 whitespace-nowrap">
                        <div className="font-sans font-semibold text-ink">
                          {ev.scenario.replace(/_/g, ' ')}
                        </div>
                        <div className="text-[11px] text-ink-faint font-mono">
                          {ev.event_type}
                        </div>
                      </td>
                      <td className="py-3 px-4 whitespace-nowrap">
                        <Mono>{ev.source}</Mono>
                      </td>
                      <td className="py-3 px-4 whitespace-nowrap truncate max-w-[140px]">
                        <Mono title={ev.target}>{ev.target}</Mono>
                      </td>
                      <td className="py-3 px-4 whitespace-nowrap">
                        <StatusBadge tone={RISK_TONE[level] || 'neutral'}>
                          {level} ({ev.risk_score !== null && ev.risk_score !== undefined ? ev.risk_score : '—'})
                        </StatusBadge>
                      </td>
                      <td className="py-3 px-4 whitespace-nowrap">
                        <span className="text-[11px] font-sans px-2 py-0.5 rounded bg-elevated/60 text-ink-soft border border-line">
                          {ev.detection_status}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-right whitespace-nowrap">
                        <div className="inline-flex items-center gap-1.5" onClick={(e) => e.stopPropagation()}>
                          <Button variant="ghost" size="sm" onClick={() => onSelectEvent(ev)} title="View event details">
                            Details
                          </Button>
                          <Button
                            variant="primary"
                            size="sm"
                            leftIcon={<MessageSquare className="w-3 h-3" />}
                            title="Ask Security Assistant about this event"
                            onClick={() => {
                              const prompt = `Why was this ${ev.event_type} event on target ${ev.target} from ${ev.source} detected and what is the recommended response?`;
                              onAskChatbot(ev as unknown as Record<string, unknown>, prompt);
                            }}
                          >
                            Ask AI
                          </Button>
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
};
