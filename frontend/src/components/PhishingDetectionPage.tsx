import React, { useEffect, useState } from 'react';
import {
  Search,
  ShieldAlert,
  ShieldCheck,
  Info,
  Server,
  Type,
  Database,
  Activity,
  Globe,
  XCircle,
  CheckCircle,
  HelpCircle,
  Mail,
  UserCheck,
  Link2,
  Sparkles,
  Lock,
} from 'lucide-react';
import api from '../api';
import { InvestigationContext } from './VisualizationInvestigationPage';
import { PageHeader, Card, Button, StatusBadge, ErrorState, Mono } from './ui';

// ==========================================
// Types
// ==========================================

/** Provenance block the backend publishes with every verdict. */
interface ScorerProvenance {
  scorer: string;
  version: string;
  model_family: string;
  trained_model: boolean;
  fitted_on_data: boolean;
  calibration: string;
  calibration_note: string;
  network_access: boolean;
  submits_url: boolean;
  resolves_dns: boolean;
  domain_suffix_list: string;
  external_reputation: { implemented: boolean; providers: string[]; note: string };
  core_indicators: number;
  extended_indicators: number;
  confidence_cap: number;
  max_single_indicator_contribution: number;
  thresholds: { phishing: number; suspicious: number; legitimate_below: number };
  deterministic: boolean;
  categories?: Record<string, number>;
}

/** One indicator as the backend registry declares it. */
interface LexicalIndicator {
  id: string;
  name: string;
  category: string;
  version: string;
  weight: number;
  weight_kind: string;
  inputs: string[];
  matching: string;
  severity: string;
  explanation: string;
  mitre: string;
  core: boolean;
  extended: boolean;
}

/** Response of GET /api/detect/phishing/indicators. */
interface IndicatorRegistry {
  scorer: string;
  version: string;
  core_indicators: number;
  extended_indicators: number;
  declared_features: number;
  required_features: number;
  evidence_only_features: number;
  features_produced_by_extractor: number;
  confidence_cap: number;
  max_single_indicator_contribution: number;
  thresholds: { phishing: number; suspicious: number };
  keyword_vocabulary_size: number;
  categories: Record<string, number>;
  indicators: LexicalIndicator[];
  provenance: ScorerProvenance;
}

interface UrlPhishingResult {
  url: string;
  is_phishing: boolean;
  heuristic_confidence: number;
  explanation: string;
  features: {
    url_length: number;
    hostname_length: number;
    num_subdomains: number;
    special_chars: number;
    is_ip: boolean;
    is_https: boolean;
    keyword_count: number;
    is_punycode?: boolean;
    has_misleading_subdomain?: boolean;
    has_credentials?: boolean;
    unusual_port?: boolean;
    domain?: string;
    open_redirect_detected?: boolean;
    redirect_targets?: Array<{ param: string; target: string }>;
    suspicious_tld?: boolean;
  };
  triggered_rules?: Array<{
    id: string;
    name: string;
    explanation: string;
    contribution: number;
    feature_values: Record<string, any>;
  }>;
  reputation?: {
    /**
     * False in this project: no reputation provider is integrated anywhere.
     * The UI must render that fact instead of implying a degraded lookup.
     */
    implemented?: boolean;
    provider?: string | null;
    status?: 'match' | 'no_match' | 'unavailable';
    details?: string;
  };
  scorer?: { name: string; version: string };
  provenance?: ScorerProvenance;
  confidence_cap?: number;
  max_single_indicator_contribution?: number;
}

interface EmailPhishingResult {
  classification: 'legitimate' | 'suspicious' | 'phishing';
  is_phishing: boolean;
  confidence: number;
  risk_score: number;
  risk_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  explanation: string;
  sender_analysis: {
    display_name: string;
    address: string;
    domain: string;
    is_free_webmail: boolean;
    impersonated_brand?: string | null;
  };
  links_analysis: {
    total_links: number;
    analyzed_links_count?: number;
    flagged_links: any[];
    all_links: any[];
    /** Links found in the body that could not be parsed. Reported, never dropped. */
    skipped_links?: Array<{ url: string; reason: string }>;
    anchor_mismatches: Array<{ displayed: string; actual_destination: string }>;
  };
  provenance?: MessageScorerProvenance;
  triggered_rules: Array<{
    id: string;
    name: string;
    explanation: string;
    contribution: number;
    feature_values: Record<string, any>;
  }>;
}

/** Provenance published with the email and spear verdicts. */
interface MessageScorerProvenance {
  model_family: string;
  trained_model: boolean;
  calibration: string;
  network_access: boolean;
  note: string;
}

interface SpearPhishingResult {
  classification: 'legitimate' | 'suspicious' | 'phishing';
  is_phishing: boolean;
  confidence: number;
  risk_score: number;
  risk_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  attack_vector: string;
  personalization: {
    level: 'none' | 'moderate' | 'high';
    target_name_matched: boolean;
    role_matched: boolean;
    organization_matched: boolean;
    score: number;
  };
  impersonation: {
    claimed_leadership?: string | null;
    sender_domain: string;
    is_external: boolean;
  };
  explanation: string;
  triggered_rules: Array<{
    id: string;
    name: string;
    explanation: string;
    contribution: number;
    feature_values: Record<string, any>;
  }>;
  recommended_countermeasures: string[];
  link_analysis?: { evaluated: string | null; skipped: Array<{ url: string; reason: string }> };
  provenance?: MessageScorerProvenance;
}

interface PhishingDetectionPageProps {
  onVisualize: (context: InvestigationContext) => void;
}

export const PhishingDetectionPage: React.FC<PhishingDetectionPageProps> = ({ onVisualize }) => {
  const [activeTab, setActiveTab] = useState<'url' | 'email' | 'spear'>('url');

  // URL state
  const [url, setUrl] = useState('');
  const [isUrlLoading, setIsUrlLoading] = useState(false);
  const [urlResult, setUrlResult] = useState<UrlPhishingResult | null>(null);
  const [urlError, setUrlError] = useState<string | null>(null);

  // The indicator registry is read from the backend, never restated here as
  // prose: counts, weights and thresholds come from the registry the scorer
  // actually evaluates (validated at import time on the server).
  const [registry, setRegistry] = useState<IndicatorRegistry | null>(null);
  const [registryError, setRegistryError] = useState<string | null>(null);

  // Email state
  const [emailSender, setEmailSender] = useState('');
  const [emailSubject, setEmailSubject] = useState('');
  const [emailBody, setEmailBody] = useState('');
  const [emailReplyTo, setEmailReplyTo] = useState('');
  const [isEmailLoading, setIsEmailLoading] = useState(false);
  const [emailResult, setEmailResult] = useState<EmailPhishingResult | null>(null);
  const [emailError, setEmailError] = useState<string | null>(null);

  // Spear Phishing state
  const [spearSender, setSpearSender] = useState('');
  const [spearTargetName, setSpearTargetName] = useState('');
  const [spearTargetRole, setSpearTargetRole] = useState('');
  const [spearSubject, setSpearSubject] = useState('');
  const [spearBody, setSpearBody] = useState('');
  const [spearOrg, setSpearOrg] = useState('');
  const [spearClaimedIdentity, setSpearClaimedIdentity] = useState('');
  const [isSpearLoading, setIsSpearLoading] = useState(false);
  const [spearResult, setSpearResult] = useState<SpearPhishingResult | null>(null);
  const [spearError, setSpearError] = useState<string | null>(null);

  // ==========================================
  // Handlers
  // ==========================================

  useEffect(() => {
    let cancelled = false;
    api
      .get<IndicatorRegistry>('/api/detect/phishing/indicators')
      .then((res) => {
        if (!cancelled) {
          setRegistry(res.data);
          setRegistryError(null);
        }
      })
      .catch(() => {
        if (!cancelled) {
          setRegistry(null);
          setRegistryError(
            'The indicator registry could not be read from GET /api/detect/phishing/indicators. No fallback weights are shown, because inventing them here would misrepresent the scorer.',
          );
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const handleAnalyzeUrl = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url.trim()) return;

    setIsUrlLoading(true);
    setUrlError(null);
    setUrlResult(null);

    try {
      const res = await api.post<UrlPhishingResult>('/api/detect/phishing', { url: url.trim() });
      setUrlResult(res.data);
    } catch (err: any) {
      if (err.response?.data?.detail) {
        setUrlError(err.response.data.detail);
      } else {
        setUrlError('Failed to analyze URL. Please check backend connection.');
      }
    } finally {
      setIsUrlLoading(false);
    }
  };

  const handleAnalyzeEmail = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!emailSender.trim() || (!emailSubject.trim() && !emailBody.trim())) return;

    setIsEmailLoading(true);
    setEmailError(null);
    setEmailResult(null);

    try {
      const res = await api.post<EmailPhishingResult>('/api/detect/email', {
        sender: emailSender.trim(),
        subject: emailSubject.trim(),
        body: emailBody.trim(),
        reply_to: emailReplyTo.trim() || undefined,
      });
      setEmailResult(res.data);
    } catch (err: any) {
      if (err.response?.data?.detail) {
        setEmailError(err.response.data.detail);
      } else {
        setEmailError('Failed to analyze email. Please check backend connection.');
      }
    } finally {
      setIsEmailLoading(false);
    }
  };

  const handleAnalyzeSpear = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!spearSender.trim() || !spearTargetName.trim() || !spearBody.trim()) return;

    setIsSpearLoading(true);
    setSpearError(null);
    setSpearResult(null);

    try {
      const res = await api.post<SpearPhishingResult>('/api/detect/spear-phishing', {
        sender: spearSender.trim(),
        recipient_name: spearTargetName.trim(),
        recipient_role: spearTargetRole.trim() || 'Employee',
        subject: spearSubject.trim(),
        body: spearBody.trim(),
        organization_name: spearOrg.trim() || undefined,
        claimed_identity: spearClaimedIdentity.trim() || undefined,
      });
      setSpearResult(res.data);
    } catch (err: any) {
      if (err.response?.data?.detail) {
        setSpearError(err.response.data.detail);
      } else {
        setSpearError('Failed to analyze spear phishing. Please check backend connection.');
      }
    } finally {
      setIsSpearLoading(false);
    }
  };

  const getReputationIcon = (status: string) => {
    switch (status) {
      case 'match': return <XCircle className="w-5 h-5 text-danger" />;
      case 'no_match': return <CheckCircle className="w-5 h-5 text-success" />;
      default: return <HelpCircle className="w-5 h-5 text-ink-faint" />;
    }
  };

  const getReputationColor = (status: string) => {
    switch (status) {
      case 'match': return 'border-danger/30 bg-danger/10 text-danger';
      case 'no_match': return 'border-success/30 bg-success/10 text-success';
      default: return 'border-line bg-elevated/60 text-ink-muted';
    }
  };

  const getRiskTone = (level: string) => {
    switch (level) {
      case 'CRITICAL': return 'danger';
      case 'HIGH': return 'danger';
      case 'MEDIUM': return 'warning';
      default: return 'success';
    }
  };

  return (
    <div className="w-full max-w-4xl mx-auto space-y-6 pb-20">
      <PageHeader
        title="Phishing Detection"
        description="Offline lexical analysis of URLs, email messages and targeted messages. Nothing is fetched, resolved or sent to a third party."
        icon={<ShieldAlert className="w-5 h-5" />}
      />

      {/* Module Navigation Tabs */}
      <div className="flex border-b border-line bg-surface/50 rounded-t-lg p-1 gap-2" role="tablist">
        <button
          type="button"
          role="tab"
          aria-selected={activeTab === 'url'}
          onClick={() => setActiveTab('url')}
          className={`flex items-center gap-2 px-4 py-2.5 text-sm font-semibold rounded-lg transition-all ${
            activeTab === 'url'
              ? 'bg-accent text-accent-contrast shadow-sm'
              : 'text-ink-muted hover:text-ink hover:bg-elevated/50'
          }`}
        >
          <Link2 className="w-4 h-4" />
          URL Phishing Detection
        </button>

        <button
          type="button"
          role="tab"
          aria-selected={activeTab === 'email'}
          onClick={() => setActiveTab('email')}
          className={`flex items-center gap-2 px-4 py-2.5 text-sm font-semibold rounded-lg transition-all ${
            activeTab === 'email'
              ? 'bg-accent text-accent-contrast shadow-sm'
              : 'text-ink-muted hover:text-ink hover:bg-elevated/50'
          }`}
        >
          <Mail className="w-4 h-4" />
          Email Phishing Detection
        </button>

        <button
          type="button"
          role="tab"
          aria-selected={activeTab === 'spear'}
          onClick={() => setActiveTab('spear')}
          className={`flex items-center gap-2 px-4 py-2.5 text-sm font-semibold rounded-lg transition-all ${
            activeTab === 'spear'
              ? 'bg-accent text-accent-contrast shadow-sm'
              : 'text-ink-muted hover:text-ink hover:bg-elevated/50'
          }`}
        >
          <UserCheck className="w-4 h-4" />
          Spear Phishing Detection
        </button>
      </div>

      {/* =================================================================== */}
      {/* 1. URL PHISHING DETECTION TAB */}
      {/* =================================================================== */}
      {activeTab === 'url' && (
        <div className="space-y-6">
          <Card>
            <form onSubmit={handleAnalyzeUrl} className="space-y-4">
              <div>
                <div className="flex items-center justify-between mb-2">
                  <label htmlFor="phishing-url" className="block text-sm font-medium text-ink-soft">
                    Enter URL for Analysis
                  </label>
                  <div className="flex items-center gap-1.5 text-xs text-ink-muted">
                    <Sparkles className="w-3.5 h-3.5 text-accent" />
                    <span>Quick presets:</span>
                    <button
                      type="button"
                      onClick={() => setUrl('https://www.google.com/search?q=cybersecurity')}
                      className="text-accent-soft hover:underline"
                    >
                      Benign Google
                    </button>
                    <span>•</span>
                    <button
                      type="button"
                      onClick={() => setUrl('http://192.168.1.1/update-banking-account-login-verify')}
                      className="text-danger hover:underline"
                    >
                      IP Bank Phish
                    </button>
                    <span>•</span>
                    <button
                      type="button"
                      onClick={() => setUrl('https://login.paypal.com.scammer-verification.net/auth')}
                      className="text-warning hover:underline"
                    >
                      Lookalike Subdomain
                    </button>
                  </div>
                </div>

                <div className="flex gap-3">
                  <div className="relative flex-1">
                    <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                      <Search className="h-5 w-5 text-ink-faint" aria-hidden />
                    </div>
                    <input
                      id="phishing-url"
                      type="text"
                      value={url}
                      onChange={(e) => setUrl(e.target.value)}
                      placeholder="https://example.com/login"
                      aria-label="URL to analyze"
                      className="block w-full pl-10 pr-3 py-2.5 bg-app border border-line-strong rounded-lg text-ink placeholder:text-ink-faint focus:outline-none focus-visible:ring-2 focus-visible:ring-accent/40 transition-all sm:text-sm"
                    />
                  </div>
                  <Button type="submit" loading={isUrlLoading} disabled={!url.trim()}>
                    Analyze URL
                  </Button>
                </div>
                <p className="mt-2 text-[11px] text-ink-muted flex items-center gap-1">
                  <Info className="w-3 h-3" aria-hidden />
                  Deterministic lexical and structural indicators, open-redirect parameter inspection, and offline
                  RFC-domain feature parsing. The verdict is a triage signal, not a confirmed identification.
                </p>
              </div>
            </form>
          </Card>

          {urlError && <ErrorState title="Analysis Failed" message={urlError} />}

          {urlResult && (
            <div className="space-y-6">
              {/* 1. Heuristic Analysis */}
              <Card title="Heuristic Analysis" icon={<Activity className="w-4 h-4" />}>
                <div
                  className={`p-5 rounded-card border ${
                    urlResult.is_phishing ? 'bg-warning/10 border-warning/30' : 'bg-success/10 border-success/30'
                  } flex flex-col sm:flex-row sm:items-center justify-between gap-4`}
                >
                  <div className="flex items-center gap-4">
                    <div
                      className={`p-3 rounded-full ${
                        urlResult.is_phishing ? 'bg-warning/20 text-warning' : 'bg-success/20 text-success'
                      }`}
                    >
                      {urlResult.is_phishing ? <ShieldAlert className="w-6 h-6" /> : <ShieldCheck className="w-6 h-6" />}
                    </div>
                    <div>
                      <h3 className={`text-lg font-bold ${urlResult.is_phishing ? 'text-warning' : 'text-ink-soft'}`}>
                        {urlResult.is_phishing
                          ? 'Phishing indicators crossed the threshold'
                          : 'Below the phishing threshold - not a safety verdict'}
                      </h3>
                      <p className="text-sm text-ink-soft mt-1">{urlResult.explanation}</p>
                      <p className="text-xs text-ink-muted mt-2">
                        Analyzed URL: <Mono title={urlResult.url}>{urlResult.url}</Mono>
                      </p>
                    </div>
                  </div>
                  <div className="text-center sm:text-right p-3 bg-app/50 rounded-card border border-line shrink-0">
                    <div className="text-2xl font-black text-ink">
                      {(urlResult.heuristic_confidence * 100).toFixed(0)}%
                    </div>
                    <div className="text-[10px] text-ink-muted uppercase tracking-wider mt-1">Lexical Score</div>
                    <div className="text-[10px] text-ink-faint mt-1">
                      Phishing threshold: {Math.round((urlResult.provenance?.thresholds?.phishing ?? 0.65) * 100)}%
                    </div>
                    <div className="text-[10px] text-ink-faint">
                      Reported cap: {Math.round((urlResult.confidence_cap ?? 0.99) * 100)}%
                    </div>
                  </div>
                </div>

                {/* Uncalibrated limitation, straight from the backend provenance block. */}
                {urlResult.provenance && (
                  <p className="mt-3 text-[11px] leading-relaxed text-ink-muted bg-app/50 border border-line rounded-card p-3">
                    <span className="font-semibold text-warning">
                      {urlResult.provenance.calibration.replace(/_/g, ' ')}:
                    </span>{' '}
                    scores are hand-set indicator weights, not a fitted model. No precision, recall or accuracy
                    figure is published for this scorer, and a score below the threshold is not evidence that a URL
                    is safe.
                  </p>
                )}

                {urlResult.triggered_rules && urlResult.triggered_rules.length > 0 && (
                  <div className="mt-4 bg-app/50 p-4 rounded-card border border-line">
                    <h4 className="text-xs font-bold text-ink-faint uppercase tracking-wider mb-3">
                      Triggered Indicators
                    </h4>
                    <div className="space-y-3">
                      {urlResult.triggered_rules.map((rule, idx) => (
                        <div
                          key={idx}
                          className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 p-3 bg-panel rounded-card border border-line"
                        >
                          <div>
                            <span className="text-sm font-medium text-warning">{rule.name}</span>
                            <p className="text-xs text-ink-muted mt-0.5">{rule.explanation}</p>
                          </div>
                          <Mono>+{(rule.contribution * 100).toFixed(0)}%</Mono>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
                  <div className="bg-app/50 p-4 rounded-card border border-line">
                    <h4 className="text-xs font-bold text-ink-faint uppercase tracking-wider mb-4 flex items-center gap-2">
                      <Server className="w-3.5 h-3.5" aria-hidden /> Infrastructure
                    </h4>
                    <div className="space-y-3">
                      <div className="flex justify-between items-center">
                        <span className="text-sm text-ink-muted">Uses HTTPS</span>
                        <span
                          className={`text-sm font-medium ${
                            urlResult.features.is_https ? 'text-success' : 'text-warning'
                          }`}
                        >
                          {urlResult.features.is_https ? 'Yes' : 'No'}
                        </span>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-sm text-ink-muted">IP as Hostname</span>
                        <span className={`text-sm font-medium ${urlResult.features.is_ip ? 'text-danger' : 'text-ink'}`}>
                          {urlResult.features.is_ip ? 'Yes (Suspicious)' : 'No'}
                        </span>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-sm text-ink-muted">Subdomains</span>
                        <span
                          className={`text-sm font-medium ${
                            urlResult.features.num_subdomains >= 3 ? 'text-warning' : 'text-ink'
                          }`}
                        >
                          {urlResult.features.num_subdomains}{' '}
                          {urlResult.features.num_subdomains >= 3 ? '(High)' : ''}
                        </span>
                      </div>
                    </div>
                  </div>

                  <div className="bg-app/50 p-4 rounded-card border border-line">
                    <h4 className="text-xs font-bold text-ink-faint uppercase tracking-wider mb-4 flex items-center gap-2">
                      <Type className="w-3.5 h-3.5" aria-hidden /> Lexical Analysis
                    </h4>
                    <div className="space-y-3">
                      <div className="flex justify-between items-center">
                        <span className="text-sm text-ink-muted">Suspicious Keywords</span>
                        <span
                          className={`text-sm font-medium ${
                            urlResult.features.keyword_count > 0 ? 'text-danger' : 'text-success'
                          }`}
                        >
                          {urlResult.features.keyword_count} detected
                        </span>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-sm text-ink-muted">Special Characters</span>
                        <span
                          className={`text-sm font-medium ${
                            urlResult.features.special_chars > 5 ? 'text-warning' : 'text-ink'
                          }`}
                        >
                          {urlResult.features.special_chars}{' '}
                          {urlResult.features.special_chars > 5 ? '(High)' : ''}
                        </span>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-sm text-ink-muted">Total Length</span>
                        <span
                          className={`text-sm font-medium ${
                            urlResult.features.url_length > 75 ? 'text-warning' : 'text-ink'
                          }`}
                        >
                          {urlResult.features.url_length} chars
                        </span>
                      </div>
                    </div>
                  </div>
                </div>
              </Card>

              {/* 2. Detection method - stated, not implied */}
              <Card title="Detection Method" icon={<Activity className="w-4 h-4" />}>
                <div className="p-4 rounded-card border border-line bg-app/50 flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className="p-2 rounded-lg bg-elevated/60">
                      <Info className="w-5 h-5 text-ink-muted" />
                    </div>
                    <div>
                      <h4 className="text-sm font-medium text-ink-soft">No machine-learning model is used here</h4>
                      <p className="text-xs text-ink-muted mt-0.5">
                        This verdict is produced by a deterministic lexical scorer. There is no trained phishing
                        classifier in this project and no model output is being withheld - the ML models that do exist
                        are for network telemetry (port scan / authentication), not for URL phishing.
                      </p>
                    </div>
                  </div>
                  <StatusBadge tone="neutral">Deterministic</StatusBadge>
                </div>
              </Card>

              {/* 3. External reputation - not implemented in this project */}
              <Card title="External Reputation" icon={<Globe className="w-4 h-4" />}>
                {urlResult.reputation?.implemented === false ? (
                  <div className="p-4 rounded-card border border-line bg-app/50 flex items-start justify-between gap-4">
                    <div className="flex items-start gap-3">
                      <div className="p-2 rounded-lg bg-elevated/60">
                        <HelpCircle className="w-5 h-5 text-ink-faint" />
                      </div>
                      <div>
                        <h4 className="text-sm font-medium text-ink-soft">Not implemented - no lookup was performed</h4>
                        <p className="text-xs text-ink-muted mt-1 max-w-xl leading-relaxed">
                          {urlResult.reputation.details}
                        </p>
                      </div>
                    </div>
                    <Mono>provider: none</Mono>
                  </div>
                ) : (
                  <div
                    className={`p-4 rounded-card border ${getReputationColor(
                      urlResult.reputation?.status ?? 'unavailable'
                    )} flex items-center justify-between transition-colors`}
                  >
                    <div className="flex items-start sm:items-center gap-3 flex-col sm:flex-row">
                      <div className="p-2 rounded-lg bg-app/50">
                        {getReputationIcon(urlResult.reputation?.status ?? 'unavailable')}
                      </div>
                      <div>
                        <h4 className="text-sm font-medium">
                          {urlResult.reputation?.status === 'match' && 'Malicious URL Reported By Provider'}
                          {urlResult.reputation?.status === 'no_match' && 'No Records Reported By Provider'}
                          {urlResult.reputation?.status === 'unavailable' && 'Reputation Lookup Unavailable'}
                        </h4>
                        <p className="text-xs mt-1 opacity-80 max-w-xl">
                          {urlResult.reputation?.details}
                          {urlResult.reputation?.status === 'no_match' &&
                            ' (Note: Absence of records is not sufficient evidence to declare a URL safe)'}
                        </p>
                      </div>
                    </div>
                    <span className="hidden sm:inline-flex">
                      <Mono title={urlResult.reputation?.provider ?? 'unknown'}>
                        {urlResult.reputation?.provider ?? 'unknown'}
                      </Mono>
                    </span>
                  </div>
                )}
              </Card>

              {/* 4. The indicator registry the backend actually evaluates */}
              <Card
                title="Scorer Contract"
                icon={<Database className="w-4 h-4" />}
                right={
                  registry ? (
                    <Mono>{`${registry.scorer} v${registry.version}`}</Mono>
                  ) : undefined
                }
              >
                {registry ? (
                  <div className="space-y-4">
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                      <div className="p-3 bg-app/50 rounded-card border border-line">
                        <div className="text-lg font-black text-ink">{registry.core_indicators}</div>
                        <div className="text-[10px] uppercase tracking-wider text-ink-faint mt-0.5">
                          Core indicators
                        </div>
                      </div>
                      <div className="p-3 bg-app/50 rounded-card border border-line">
                        <div className="text-lg font-black text-ink">{registry.extended_indicators}</div>
                        <div className="text-[10px] uppercase tracking-wider text-ink-faint mt-0.5">
                          Extended indicators
                        </div>
                      </div>
                      <div className="p-3 bg-app/50 rounded-card border border-line">
                        <div className="text-lg font-black text-ink">
                          {Math.round(registry.max_single_indicator_contribution * 100)}%
                        </div>
                        <div className="text-[10px] uppercase tracking-wider text-ink-faint mt-0.5">
                          Per-indicator weight cap
                        </div>
                      </div>
                      <div className="p-3 bg-app/50 rounded-card border border-line">
                        <div className="text-lg font-black text-ink">{registry.keyword_vocabulary_size}</div>
                        <div className="text-[10px] uppercase tracking-wider text-ink-faint mt-0.5">
                          Keyword vocabulary
                        </div>
                      </div>
                    </div>

                    <div className="overflow-x-auto rounded-card border border-line">
                      <table className="w-full text-left text-xs">
                        <thead className="bg-app/60 text-ink-faint uppercase tracking-wider">
                          <tr>
                            <th className="px-3 py-2 font-semibold">Indicator</th>
                            <th className="px-3 py-2 font-semibold whitespace-nowrap">Weight</th>
                            <th className="px-3 py-2 font-semibold">When it fires</th>
                            <th className="px-3 py-2 font-semibold">Inputs read</th>
                          </tr>
                        </thead>
                        <tbody>
                          {registry.indicators.map((indicator) => (
                            <tr key={indicator.id} className="border-t border-line align-top">
                              <td className="px-3 py-2">
                                <span className="font-medium text-ink">{indicator.name}</span>
                                <span className="text-ink-faint"> ({indicator.category})</span>
                                {indicator.extended && (
                                  <span className="ml-2 text-[10px] uppercase tracking-wider text-accent-soft">
                                    tiered view only
                                  </span>
                                )}
                              </td>
                              <td className="px-3 py-2 whitespace-nowrap">
                                <Mono>
                                  {Math.round(indicator.weight * 100)}%
                                  {indicator.weight_kind === 'per_match' ? ' x matches' : ''}
                                </Mono>
                              </td>
                              <td className="px-3 py-2 text-ink-muted">{indicator.matching}</td>
                              <td className="px-3 py-2">
                                <Mono>{indicator.inputs.join(', ')}</Mono>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>

                    <dl className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px] text-ink-muted">
                      <div className="flex items-center justify-between gap-2 bg-app/50 border border-line rounded-card px-3 py-2">
                        <dt className="uppercase tracking-wider text-ink-faint">Fetches the URL</dt>
                        <dd className="font-semibold text-success">
                          {registry.provenance.network_access ? 'yes' : 'never'}
                        </dd>
                      </div>
                      <div className="flex items-center justify-between gap-2 bg-app/50 border border-line rounded-card px-3 py-2">
                        <dt className="uppercase tracking-wider text-ink-faint">Resolves DNS</dt>
                        <dd className="font-semibold text-success">
                          {registry.provenance.resolves_dns ? 'yes' : 'never'}
                        </dd>
                      </div>
                      <div className="flex items-center justify-between gap-2 bg-app/50 border border-line rounded-card px-3 py-2">
                        <dt className="uppercase tracking-wider text-ink-faint">Trained model</dt>
                        <dd className="font-semibold text-warning">
                          {registry.provenance.trained_model ? 'yes' : 'none'}
                        </dd>
                      </div>
                      <div className="flex items-center justify-between gap-2 bg-app/50 border border-line rounded-card px-3 py-2">
                        <dt className="uppercase tracking-wider text-ink-faint">Reputation provider</dt>
                        <dd className="font-semibold text-warning">
                          {registry.provenance.external_reputation.implemented
                            ? registry.provenance.external_reputation.providers.join(', ')
                            : 'none integrated'}
                        </dd>
                      </div>
                      <div className="sm:col-span-2 flex items-start justify-between gap-2 bg-app/50 border border-line rounded-card px-3 py-2">
                        <dt className="uppercase tracking-wider text-ink-faint shrink-0">Domain suffix data</dt>
                        <dd>
                          <Mono>{registry.provenance.domain_suffix_list}</Mono>
                        </dd>
                      </div>
                    </dl>

                    <p className="text-[11px] leading-relaxed text-ink-muted bg-app/50 border border-line rounded-card p-3">
                      {registry.provenance.calibration_note}
                    </p>
                  </div>
                ) : (
                  <p className="text-xs text-ink-muted">
                    {registryError ?? 'Reading the indicator registry from the backend …'}
                  </p>
                )}
              </Card>

              <div className="flex justify-end pt-4 border-t border-line">
                <Button
                  type="button"
                  leftIcon={<Activity className="w-4 h-4" />}
                  onClick={() =>
                    onVisualize({
                      type: 'phishing',
                      url: urlResult.url,
                      result: urlResult,
                    })
                  }
                >
                  Visualize
                </Button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* =================================================================== */}
      {/* 2. EMAIL PHISHING DETECTION TAB */}
      {/* =================================================================== */}
      {activeTab === 'email' && (
        <div className="space-y-6">
          <Card title="Email Phishing Inspection" icon={<Mail className="w-4 h-4" />}>
            <form onSubmit={handleAnalyzeEmail} className="space-y-4">
              <div className="flex items-center justify-between">
                <span className="text-xs text-ink-muted">Fill with demo scenario:</span>
                <div className="flex items-center gap-2 text-xs">
                  <button
                    type="button"
                    onClick={() => {
                      setEmailSender('Alice Smith <alice@company.com>');
                      setEmailSubject('Meeting Minutes for Review');
                      setEmailBody('Hi Bob,\nPlease review the attached notes from our product sync.\nThanks,\nAlice');
                      setEmailReplyTo('');
                    }}
                    className="text-accent-soft hover:underline"
                  >
                    Legitimate Email
                  </button>
                  <span>•</span>
                  <button
                    type="button"
                    onClick={() => {
                      setEmailSender('PayPal Security Team <security-alert@gmail.com>');
                      setEmailSubject('URGENT: Your PayPal account has been suspended!');
                      setEmailBody('Dear Customer,\nYour account was accessed from an unrecognized device. Click here to login and update billing credentials immediately: http://192.168.1.1/paypal/verify\nFailure to do so within 24 hours will result in permanent closure.');
                      setEmailReplyTo('scam-box@hacker-mailbox.net');
                    }}
                    className="text-danger hover:underline"
                  >
                    PayPal Spoof Phish
                  </button>
                  <span>•</span>
                  <button
                    type="button"
                    onClick={() => {
                      setEmailSender('Billing Department <invoicing@corp-pay.xyz>');
                      setEmailSubject('OVERDUE INVOICE #98214 - Action Required');
                      setEmailBody('Dear Client,\nYour invoice is past due. Review invoice.pdf.exe immediately and wire transfer funds to our overseas account.');
                      setEmailReplyTo('');
                    }}
                    className="text-warning hover:underline"
                  >
                    Invoice & Malware
                  </button>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-semibold text-ink-soft mb-1">
                    Sender (Name & Email Address) *
                  </label>
                  <input
                    type="text"
                    value={emailSender}
                    onChange={(e) => setEmailSender(e.target.value)}
                    placeholder="e.g. PayPal Support <support@paypal-security.net>"
                    className="w-full px-3 py-2 bg-app border border-line-strong rounded-lg text-ink text-sm"
                    required
                  />
                </div>

                <div>
                  <label className="block text-xs font-semibold text-ink-soft mb-1">
                    Reply-To Address (Optional)
                  </label>
                  <input
                    type="text"
                    value={emailReplyTo}
                    onChange={(e) => setEmailReplyTo(e.target.value)}
                    placeholder="e.g. reply@hacker-collector.net"
                    className="w-full px-3 py-2 bg-app border border-line-strong rounded-lg text-ink text-sm"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold text-ink-soft mb-1">
                  Subject Line *
                </label>
                <input
                  type="text"
                  value={emailSubject}
                  onChange={(e) => setEmailSubject(e.target.value)}
                  placeholder="e.g. Urgent: Account Verification Required"
                  className="w-full px-3 py-2 bg-app border border-line-strong rounded-lg text-ink text-sm"
                  required
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-ink-soft mb-1">
                  Email Body Content *
                </label>
                <textarea
                  rows={5}
                  value={emailBody}
                  onChange={(e) => setEmailBody(e.target.value)}
                  placeholder="Paste raw email body or HTML text here..."
                  className="w-full px-3 py-2 bg-app border border-line-strong rounded-lg text-ink text-sm font-mono"
                  required
                />
              </div>

              <div className="flex justify-end">
                <Button type="submit" loading={isEmailLoading} disabled={!emailSender.trim() || !emailBody.trim()}>
                  Inspect Email Telemetry
                </Button>
              </div>
            </form>
          </Card>

          {emailError && <ErrorState title="Email Analysis Error" message={emailError} />}

          {emailResult && (
            <div className="space-y-6">
              {/* Verdict Summary */}
              <Card title="Email Analysis Verdict" icon={<ShieldAlert className="w-4 h-4" />}>
                <div
                  className={`p-5 rounded-card border ${
                    emailResult.is_phishing
                      ? 'bg-danger/10 border-danger/30'
                      : emailResult.classification === 'suspicious'
                      ? 'bg-warning/10 border-warning/30'
                      : 'bg-success/10 border-success/30'
                  } flex flex-col sm:flex-row sm:items-center justify-between gap-4`}
                >
                  <div className="flex items-center gap-4">
                    <div
                      className={`p-3 rounded-full ${
                        emailResult.is_phishing
                          ? 'bg-danger/20 text-danger'
                          : emailResult.classification === 'suspicious'
                          ? 'bg-warning/20 text-warning'
                          : 'bg-success/20 text-success'
                      }`}
                    >
                      {emailResult.is_phishing ? <ShieldAlert className="w-6 h-6" /> : <ShieldCheck className="w-6 h-6" />}
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <h3 className="text-lg font-bold text-ink">
                          Classification: {emailResult.classification.toUpperCase()}
                        </h3>
                        <StatusBadge tone={getRiskTone(emailResult.risk_level)}>
                          {emailResult.risk_level} RISK
                        </StatusBadge>
                      </div>
                      <p className="text-sm text-ink-soft mt-1">{emailResult.explanation}</p>
                    </div>
                  </div>

                  <div className="text-center sm:text-right p-3 bg-app/50 rounded-card border border-line shrink-0">
                    <div className="text-2xl font-black text-ink">{emailResult.risk_score} / 100</div>
                    <div className="text-[10px] text-ink-muted uppercase tracking-wider mt-1">Risk Score</div>
                    <div className="text-[10px] text-ink-faint mt-1">Confidence: {(emailResult.confidence * 100).toFixed(0)}%</div>
                  </div>
                </div>

                {/* Sender Breakdown */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
                  <div className="bg-app/50 p-4 rounded-card border border-line">
                    <h4 className="text-xs font-bold text-ink-faint uppercase tracking-wider mb-3">Sender Identity Details</h4>
                    <div className="space-y-2 text-sm">
                      <div className="flex justify-between">
                        <span className="text-ink-muted">Display Name:</span>
                        <span className="font-medium text-ink">{emailResult.sender_analysis.display_name || '(None)'}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-ink-muted">Address:</span>
                        <Mono>{emailResult.sender_analysis.address}</Mono>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-ink-muted">Domain:</span>
                        <span className="font-medium text-ink">{emailResult.sender_analysis.domain}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-ink-muted">Free Webmail:</span>
                        <span className={emailResult.sender_analysis.is_free_webmail ? 'text-warning font-semibold' : 'text-success'}>
                          {emailResult.sender_analysis.is_free_webmail ? 'Yes (Flagged)' : 'No'}
                        </span>
                      </div>
                    </div>
                  </div>

                  <div className="bg-app/50 p-4 rounded-card border border-line">
                    <h4 className="text-xs font-bold text-ink-faint uppercase tracking-wider mb-3">Embedded Links Breakdown</h4>
                    <div className="space-y-2 text-sm">
                      <div className="flex justify-between">
                        <span className="text-ink-muted">Total Links Extracted:</span>
                        <span className="font-semibold text-ink">{emailResult.links_analysis.total_links}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-ink-muted">Flagged Phishing Links:</span>
                        <span className={emailResult.links_analysis.flagged_links.length > 0 ? 'text-danger font-semibold' : 'text-success'}>
                          {emailResult.links_analysis.flagged_links.length}
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-ink-muted">Anchor Text Deception:</span>
                        <span className={emailResult.links_analysis.anchor_mismatches.length > 0 ? 'text-danger font-semibold' : 'text-success'}>
                          {emailResult.links_analysis.anchor_mismatches.length > 0 ? 'Detected' : 'None'}
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-ink-muted">Unparseable Links (skipped):</span>
                        <span
                          className={(emailResult.links_analysis.skipped_links?.length ?? 0) > 0 ? 'text-warning font-semibold' : 'text-ink'}
                          title="Links that were found in the body but rejected by the URL validator. Their reasons are listed below - a skipped link is not a clean link."
                        >
                          {emailResult.links_analysis.skipped_links?.length ?? 0}
                        </span>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Triggered Rules */}
                {emailResult.triggered_rules.length > 0 && (
                  <div className="mt-4 bg-app/50 p-4 rounded-card border border-line">
                    <h4 className="text-xs font-bold text-ink-faint uppercase tracking-wider mb-3">
                      Triggered Rules & Forensic Indicators ({emailResult.triggered_rules.length})
                    </h4>
                    <div className="space-y-2">
                      {emailResult.triggered_rules.map((rule, idx) => (
                        <div key={idx} className="flex justify-between items-center p-3 bg-panel rounded border border-line">
                          <div>
                            <span className="text-sm font-semibold text-warning">{rule.name}</span>
                            <p className="text-xs text-ink-muted mt-0.5">{rule.explanation}</p>
                          </div>
                          <Mono className="text-warning font-bold">
                            +{(rule.contribution * 100).toFixed(0)}%
                          </Mono>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {(emailResult.links_analysis.skipped_links?.length ?? 0) > 0 && (
                  <div className="mt-4 bg-app/50 p-4 rounded-card border border-line">
                    <h4 className="text-xs font-bold text-ink-faint uppercase tracking-wider mb-2">
                      Links The Validator Rejected
                    </h4>
                    <ul className="space-y-1 text-xs text-ink-muted">
                      {emailResult.links_analysis.skipped_links!.map((link) => (
                        <li key={link.url} className="flex flex-col sm:flex-row sm:items-center gap-1 sm:gap-2">
                          <Mono className="shrink-0">{link.url}</Mono>
                          <span>- {link.reason}</span>
                        </li>
                      ))}
                    </ul>
                    <p className="text-[11px] text-ink-faint mt-2">
                      These links were not scored. The message analysis completed instead of failing, but the link
                      content remains unexamined.
                    </p>
                  </div>
                )}

                {emailResult.provenance && (
                  <p className="mt-4 text-[11px] leading-relaxed text-ink-muted bg-app/50 border border-line rounded-card p-3">
                    <span className="font-semibold text-warning">
                      {emailResult.provenance.calibration.replace(/_/g, ' ')}:
                    </span>{' '}
                    {emailResult.provenance.note}
                  </p>
                )}
              </Card>
            </div>
          )}
        </div>
      )}

      {/* =================================================================== */}
      {/* 3. SPEAR PHISHING DETECTION TAB */}
      {/* =================================================================== */}
      {activeTab === 'spear' && (
        <div className="space-y-6">
          <Card title="Spear Phishing & BEC Analyzer" icon={<UserCheck className="w-4 h-4" />}>
            <form onSubmit={handleAnalyzeSpear} className="space-y-4">
              <div className="flex items-center justify-between">
                <span className="text-xs text-ink-muted">Fill with spear phishing preset:</span>
                <div className="flex items-center gap-2 text-xs">
                  <button
                    type="button"
                    onClick={() => {
                      setSpearSender('David Miller <david.miller.ceo@gmail.com>');
                      setSpearClaimedIdentity('CEO');
                      setSpearOrg('Acme Global');
                      setSpearTargetName('Robert Langdon');
                      setSpearTargetRole('Chief Financial Officer');
                      setSpearSubject('CONFIDENTIAL: Urgent Wire Transfer Required Today');
                      setSpearBody('Robert,\nI am currently in an all-day confidential board meeting and cannot take calls. As per my instructions, we need to execute an urgent wire transfer of $78,500 to our overseas supplier before 3 PM. Bypass standard PO approval for now, I will sign paperwork later. Keep this strictly confidential.');
                    }}
                    className="text-danger hover:underline"
                  >
                    CEO BEC Wire Fraud
                  </button>
                  <span>•</span>
                  <button
                    type="button"
                    onClick={() => {
                      setSpearSender('Alex Mercer <alex.mercer.work@yahoo.com>');
                      setSpearClaimedIdentity('Senior Engineer');
                      setSpearOrg('Acme Global');
                      setSpearTargetName('Mary Watson');
                      setSpearTargetRole('Payroll Specialist');
                      setSpearSubject('URGENT: Change my direct deposit bank info');
                      setSpearBody('Hello Mary,\nPlease immediately update my direct deposit bank routing number for this upcoming payroll cycle before cutoff. Voided check attached.');
                    }}
                    className="text-warning hover:underline"
                  >
                    Payroll Diversion
                  </button>
                  <span>•</span>
                  <button
                    type="button"
                    onClick={() => {
                      setSpearSender('Marcus Vance <executive.office@gmail.com>');
                      setSpearClaimedIdentity('President');
                      setSpearOrg('Acme Global');
                      setSpearTargetName('Emily Davis');
                      setSpearTargetRole('Executive Assistant');
                      setSpearSubject('Quick task for you');
                      setSpearBody('Emily, are you at your desk? I need you to quickly purchase 10 Apple gift cards for a client presentation. Scratch the back and send me the codes. I am in a meeting, do not call.');
                    }}
                    className="text-danger hover:underline"
                  >
                    Gift Card Scam
                  </button>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div>
                  <label className="block text-xs font-semibold text-ink-soft mb-1">
                    Sender Identity / Address *
                  </label>
                  <input
                    type="text"
                    value={spearSender}
                    onChange={(e) => setSpearSender(e.target.value)}
                    placeholder="e.g. CEO John Smith <ceo@gmail.com>"
                    className="w-full px-3 py-2 bg-app border border-line-strong rounded-lg text-ink text-sm"
                    required
                  />
                </div>

                <div>
                  <label className="block text-xs font-semibold text-ink-soft mb-1">
                    Target Name *
                  </label>
                  <input
                    type="text"
                    value={spearTargetName}
                    onChange={(e) => setSpearTargetName(e.target.value)}
                    placeholder="e.g. Robert Langdon"
                    className="w-full px-3 py-2 bg-app border border-line-strong rounded-lg text-ink text-sm"
                    required
                  />
                </div>

                <div>
                  <label className="block text-xs font-semibold text-ink-soft mb-1">
                    Target Role / Dept *
                  </label>
                  <input
                    type="text"
                    value={spearTargetRole}
                    onChange={(e) => setSpearTargetRole(e.target.value)}
                    placeholder="e.g. CFO, Finance, HR"
                    className="w-full px-3 py-2 bg-app border border-line-strong rounded-lg text-ink text-sm"
                    required
                  />
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-semibold text-ink-soft mb-1">
                    Organization Name (Context)
                  </label>
                  <input
                    type="text"
                    value={spearOrg}
                    onChange={(e) => setSpearOrg(e.target.value)}
                    placeholder="e.g. Acme Corp"
                    className="w-full px-3 py-2 bg-app border border-line-strong rounded-lg text-ink text-sm"
                  />
                </div>

                <div>
                  <label className="block text-xs font-semibold text-ink-soft mb-1">
                    Subject Line
                  </label>
                  <input
                    type="text"
                    value={spearSubject}
                    onChange={(e) => setSpearSubject(e.target.value)}
                    placeholder="e.g. Confidential Wire Transfer Request"
                    className="w-full px-3 py-2 bg-app border border-line-strong rounded-lg text-ink text-sm"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold text-ink-soft mb-1">
                  Message Content *
                </label>
                <textarea
                  rows={4}
                  value={spearBody}
                  onChange={(e) => setSpearBody(e.target.value)}
                  placeholder="Paste targeted message body here..."
                  className="w-full px-3 py-2 bg-app border border-line-strong rounded-lg text-ink text-sm font-mono"
                  required
                />
              </div>

              <div className="flex justify-end">
                <Button
                  type="submit"
                  loading={isSpearLoading}
                  disabled={!spearSender.trim() || !spearTargetName.trim() || !spearBody.trim()}
                >
                  Evaluate Spear Phishing Threat
                </Button>
              </div>
            </form>
          </Card>

          {spearError && <ErrorState title="Spear Phishing Analysis Error" message={spearError} />}

          {spearResult && (
            <div className="space-y-6">
              <Card title="Spear Phishing Analysis Report" icon={<ShieldAlert className="w-4 h-4" />}>
                <div
                  className={`p-5 rounded-card border ${
                    spearResult.is_phishing
                      ? 'bg-danger/10 border-danger/30'
                      : spearResult.classification === 'suspicious'
                      ? 'bg-warning/10 border-warning/30'
                      : 'bg-success/10 border-success/30'
                  } flex flex-col sm:flex-row sm:items-center justify-between gap-4`}
                >
                  <div className="flex items-center gap-4">
                    <div
                      className={`p-3 rounded-full ${
                        spearResult.is_phishing
                          ? 'bg-danger/20 text-danger'
                          : spearResult.classification === 'suspicious'
                          ? 'bg-warning/20 text-warning'
                          : 'bg-success/20 text-success'
                      }`}
                    >
                      {spearResult.is_phishing ? <ShieldAlert className="w-6 h-6" /> : <ShieldCheck className="w-6 h-6" />}
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <h3 className="text-lg font-bold text-ink">
                          {spearResult.is_phishing
                            ? 'Spear-phishing pretext indicators crossed the threshold'
                            : 'No spear-phishing pretext crossed the threshold'}
                        </h3>
                        <StatusBadge tone={getRiskTone(spearResult.risk_level)}>
                          {spearResult.attack_vector.toUpperCase()}
                        </StatusBadge>
                      </div>
                      <p className="text-sm text-ink-soft mt-1">{spearResult.explanation}</p>
                    </div>
                  </div>

                  <div className="text-center sm:text-right p-3 bg-app/50 rounded-card border border-line shrink-0">
                    <div className="text-2xl font-black text-ink">{spearResult.risk_score} / 100</div>
                    <div className="text-[10px] text-ink-muted uppercase tracking-wider mt-1">Risk Score</div>
                    <div className="text-[10px] text-ink-faint mt-1">Confidence: {(spearResult.confidence * 100).toFixed(0)}%</div>
                  </div>
                </div>

                {/* Personalization & Impersonation Matrix */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
                  <div className="bg-app/50 p-4 rounded-card border border-line">
                    <h4 className="text-xs font-bold text-ink-faint uppercase tracking-wider mb-3">
                      Target Reconnaissance & Personalization
                    </h4>
                    <div className="space-y-2 text-sm">
                      <div className="flex justify-between">
                        <span className="text-ink-muted">Personalization Level:</span>
                        <span className="font-semibold text-ink uppercase">{spearResult.personalization.level}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-ink-muted">Recipient Name Matched:</span>
                        <span className={spearResult.personalization.target_name_matched ? 'text-warning font-semibold' : 'text-ink'}>
                          {spearResult.personalization.target_name_matched ? 'Yes (Targeted)' : 'No'}
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-ink-muted">Role & Dept Tailored:</span>
                        <span className={spearResult.personalization.role_matched ? 'text-warning font-semibold' : 'text-ink'}>
                          {spearResult.personalization.role_matched ? 'Yes (Tailored)' : 'No'}
                        </span>
                      </div>
                    </div>
                  </div>

                  <div className="bg-app/50 p-4 rounded-card border border-line">
                    <h4 className="text-xs font-bold text-ink-faint uppercase tracking-wider mb-3">
                      Executive Impersonation Metrics
                    </h4>
                    <div className="space-y-2 text-sm">
                      <div className="flex justify-between">
                        <span className="text-ink-muted">Claimed Role:</span>
                        <span className="font-semibold text-ink">{spearResult.impersonation.claimed_leadership || 'None'}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-ink-muted">External / Webmail Sender:</span>
                        <span className={spearResult.impersonation.is_external ? 'text-danger font-semibold' : 'text-success'}>
                          {spearResult.impersonation.is_external ? 'Yes (High Risk)' : 'No'}
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-ink-muted">Attack Vector Type:</span>
                        <Mono>{spearResult.attack_vector}</Mono>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Recommended Defensive Countermeasures */}
                {spearResult.recommended_countermeasures.length > 0 && (
                  <div className="mt-4 p-4 rounded-card border border-accent/30 bg-accent/5">
                    <h4 className="text-xs font-bold text-accent-soft uppercase tracking-wider mb-2 flex items-center gap-1.5">
                      <Lock className="w-3.5 h-3.5" /> Actionable Defensive Countermeasures
                    </h4>
                    <ul className="list-disc list-inside space-y-1 text-sm text-ink-soft">
                      {spearResult.recommended_countermeasures.map((cm, i) => (
                        <li key={i}>{cm}</li>
                      ))}
                    </ul>
                  </div>
                )}

                {(spearResult.link_analysis?.skipped.length ?? 0) > 0 && (
                  <div className="mt-4 bg-app/50 p-4 rounded-card border border-line">
                    <h4 className="text-xs font-bold text-ink-faint uppercase tracking-wider mb-2">
                      Embedded Links The Validator Rejected
                    </h4>
                    <ul className="space-y-1 text-xs text-ink-muted">
                      {spearResult.link_analysis!.skipped.map((link) => (
                        <li key={link.url} className="flex flex-col sm:flex-row sm:items-center gap-1 sm:gap-2">
                          <Mono className="shrink-0">{link.url}</Mono>
                          <span>- {link.reason}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {spearResult.provenance && (
                  <p className="mt-4 text-[11px] leading-relaxed text-ink-muted bg-app/50 border border-line rounded-card p-3">
                    <span className="font-semibold text-warning">
                      {spearResult.provenance.calibration.replace(/_/g, ' ')}:
                    </span>{' '}
                    {spearResult.provenance.note}
                  </p>
                )}
              </Card>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
