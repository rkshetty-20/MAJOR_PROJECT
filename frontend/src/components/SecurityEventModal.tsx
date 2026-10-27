import React, { useEffect } from 'react';
import {
  X,
  ShieldAlert,
  MessageSquare,
  MapPin,
  Laptop,
} from 'lucide-react';
import { SecurityEventItem } from './RecentEventsTable';
import { DetectionItem } from './DetectionRiskOverview';
import { Button, StatusBadge, Mono, type BadgeTone } from './ui';

interface SecurityEventModalProps {
  event: SecurityEventItem | null;
  detections: DetectionItem[];
  onClose: () => void;
  onAskChatbot: (telemetryContext: Record<string, unknown>, promptMessage: string) => void;
  onInvestigateDetection: (detectionId: number) => void;
}

const RISK_TONE: Record<string, BadgeTone> = {
  CRITICAL: 'danger',
  HIGH: 'warning',
  MEDIUM: 'info',
  LOW: 'success',
};

export const SecurityEventModal: React.FC<SecurityEventModalProps> = ({
  event,
  detections,
  onClose,
  onAskChatbot,
  onInvestigateDetection,
}) => {
  useEffect(() => {
    if (!event) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    document.addEventListener('keydown', onKeyDown);
    return () => document.removeEventListener('keydown', onKeyDown);
  }, [event, onClose]);

  if (!event) return null;

  const payload = event.payload || {};
  const failedAttempts = payload.failed_attempts ?? payload.attempt ?? payload.failure_attempt ?? 'Not available.';
  const telemetryCategory = payload.scan_type ? `Network Scan (${payload.scan_type})` : 'System Event';
  const recommendedAction =
    event.risk_level === 'CRITICAL'
      ? 'Isolate host immediately, revoke active tokens, and initiate Incident Response Playbook.'
      : event.risk_level === 'HIGH'
      ? 'Enforce MFA step-up authentication, temporarily block source IP, and alert account owner.'
      : 'Log telemetry for anomaly baselining and monitor subsequent authentication attempts.';

  const handleAskAssistant = () => {
    const question = `Why was this ${event.event_type} event on target ${event.target} from ${event.source} flagged with risk score ${event.risk_score}/100 and what actions should I take?`;
    onAskChatbot(event as unknown as Record<string, unknown>, question);
    onClose();
  };

  const relatedDetections = detections.filter(d => d.session_id === event.session_id);
  const level = (event.risk_level || 'LOW').toUpperCase();

  return (
    <div
      className="fixed inset-0 z-50 bg-app/80 backdrop-blur-md flex items-center justify-center p-4"
      onClick={onClose}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="security-event-title"
        className="bg-panel border border-line-strong rounded-panel max-w-2xl w-full max-h-[90vh] overflow-y-auto custom-scrollbar shadow-raised flex flex-col"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="p-5 border-b border-line bg-app/40 flex items-center justify-between gap-3 sticky top-0 z-10">
          <div className="flex items-center gap-3 min-w-0">
            <div className="p-2.5 rounded-card bg-accent/10 border border-accent/20 text-accent-soft shrink-0">
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div className="min-w-0">
              <h2 id="security-event-title" className="text-base font-bold text-ink">
                Security Telemetry Inspector
              </h2>
              <p className="text-xs text-ink-muted mt-0.5">
                Event ID: <Mono title={`Event #${event.id}`}>#{event.id}</Mono>{' '}
                • Scenario: <Mono title={event.scenario}>{event.scenario}</Mono>
              </p>
            </div>
          </div>
          <Button
            variant="ghost"
            size="sm"
            onClick={onClose}
            aria-label="Close inspector"
            autoFocus
            className="shrink-0"
          >
            <X className="w-5 h-5" />
          </Button>
        </div>

        {/* Body */}
        <div className="p-6 space-y-5 text-xs text-ink-soft">
          {/* Risk Summary Banner */}
          <div className="p-4 rounded-card bg-app/50 border border-line flex items-center justify-between">
            <div>
              <span className="text-[11px] text-ink-muted uppercase tracking-wider block mb-1">
                Evaluated Threat Level
              </span>
              <StatusBadge tone={RISK_TONE[level] || 'neutral'}>{level} RISK</StatusBadge>
            </div>
            <div className="text-right">
              <span className="text-[11px] text-ink-muted uppercase tracking-wider block mb-1">
                Calculated Risk Score
              </span>
              <span className="text-2xl font-extrabold font-mono text-accent-soft">
                {event.risk_score !== null && event.risk_score !== undefined ? `${event.risk_score}/100` : 'Not available.'}
              </span>
            </div>
          </div>

          {/* Details Grid */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5">
            <div className="p-3.5 rounded-card bg-app/50 border border-line">
              <span className="text-ink-muted block mb-1">Event Type</span>
              <Mono>{event.event_type}</Mono>
            </div>
            <div className="p-3.5 rounded-card bg-app/50 border border-line">
              <span className="text-ink-muted block mb-1">Timestamp</span>
              <Mono title={event.timestamp}>{event.timestamp}</Mono>
            </div>
            <div className="p-3.5 rounded-card bg-app/50 border border-line">
              <span className="text-ink-muted block mb-1">Source Host / IP</span>
              <Mono title={event.source}>{event.source}</Mono>
            </div>
            <div className="p-3.5 rounded-card bg-app/50 border border-line">
              <span className="text-ink-muted block mb-1">Target Account / Asset</span>
              <Mono title={event.target}>{event.target}</Mono>
            </div>
            <div className="p-3.5 rounded-card bg-app/50 border border-line">
              <span className="text-ink-muted block mb-1 flex items-center gap-1">
                <Laptop className="w-3.5 h-3.5" /> Device Fingerprint
              </span>
              <span className="font-mono text-ink">{event.device || 'Not available.'}</span>
            </div>
            <div className="p-3.5 rounded-card bg-app/50 border border-line">
              <span className="text-ink-muted block mb-1 flex items-center gap-1">
                <MapPin className="w-3.5 h-3.5" /> Geographic Location
              </span>
              <span className="font-mono text-ink">{event.location || 'Not available.'}</span>
            </div>
            <div className="p-3.5 rounded-card bg-app/50 border border-line">
              <span className="text-ink-muted block mb-1">Failed Attempts Recorded</span>
              <span className="font-mono font-bold text-warning">{String(failedAttempts)}</span>
            </div>
            <div className="p-3.5 rounded-card bg-app/50 border border-line">
              <span className="text-ink-muted block mb-1">Telemetry Category</span>
              <span className="font-mono text-info">{telemetryCategory}</span>
            </div>
          </div>

          {/* Recommended Mitigation Action */}
          <div className="p-4 rounded-card bg-accent/10 border border-accent/20 space-y-1">
            <span className="font-semibold text-accent-soft uppercase tracking-wider text-[11px] block">
              Recommended SOC Mitigation Action
            </span>
            <p className="text-ink text-xs leading-relaxed">{recommendedAction}</p>
          </div>

          {/* Related Detections */}
          <div className="p-4 rounded-card bg-app/50 border border-line space-y-3">
            <span className="font-semibold text-ink-muted uppercase tracking-wider text-[11px] block">
              Correlated Security Detections
            </span>
            {relatedDetections.length > 0 ? (
              <div className="space-y-2">
                {relatedDetections.map(d => (
                  <div key={d.id} className="flex items-center justify-between gap-3 p-3 rounded-card bg-panel border border-line">
                    <div className="space-y-0.5 min-w-0">
                      <div className="text-sm font-bold text-ink">{d.label}</div>
                      <div className="text-[11px] text-ink-faint font-mono">
                        Detection ID: <Mono title={`Detection #${d.id}`}>#{d.id}</Mono> • Confidence: {Math.round(d.confidence * 100)}%
                      </div>
                    </div>
                    <Button
                      variant="secondary"
                      size="sm"
                      onClick={() => {
                        onClose();
                        onInvestigateDetection(d.id);
                      }}
                    >
                      Investigate Detection
                    </Button>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-ink-faint text-xs">No detection signal associated with this event.</p>
            )}
          </div>

          {/* Raw Payload Telemetry */}
          {event.payload && (
            <div className="space-y-1.5">
              <span className="font-semibold text-ink-muted uppercase tracking-wider text-[11px] block">
                Raw Event Telemetry JSON:
              </span>
              <pre className="p-3 bg-app rounded-card border border-line font-mono text-[11px] text-ink-soft overflow-x-auto max-h-36 custom-scrollbar">
                {JSON.stringify(event.payload, null, 2)}
              </pre>
            </div>
          )}
        </div>

        {/* Footer Actions */}
        <div className="p-5 border-t border-line bg-app/40 flex items-center justify-between gap-3">
          <Button variant="secondary" onClick={onClose}>
            Close Inspector
          </Button>
          <Button variant="primary" leftIcon={<MessageSquare className="w-4 h-4" />} onClick={handleAskAssistant}>
            Ask Security Assistant
          </Button>
        </div>
      </div>
    </div>
  );
};
