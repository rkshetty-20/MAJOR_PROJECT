import React, { useState } from 'react';
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
    provider: string;
    status: 'match' | 'no_match' | 'unavailable';
    details: string;
  };
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
    flagged_links: any[];
    all_links: any[];
    anchor_mismatches: Array<{ displayed: string; actual_destination: string }>;
  };
  triggered_rules: Array<{
    id: string;
    name: string;
    explanation: string;
    contribution: number;
    feature_values: Record<string, any>;
  }>;
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
        description="Unified Offensive-Defensive Phishing Analysis Suite (URL, Email, & Spear Phishing)"
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
                  Offline lexical heuristics, open-redirect parameter inspection, and RFC domain feature parsing.
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
                      <h3 className={`text-lg font-bold ${urlResult.is_phishing ? 'text-warning' : 'text-success'}`}>
                        {urlResult.is_phishing ? 'Suspicious (Phishing Likely)' : 'Benign (No Immediate Threats)'}
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
                    <div className="text-[10px] text-ink-muted uppercase tracking-wider mt-1">Heuristic Score</div>
                    <div className="text-[10px] text-ink-faint mt-1">Threshold: 65%</div>
                  </div>
                </div>

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

              {/* 2. ML Classification */}
              <Card title="ML Classification" icon={<Database className="w-4 h-4" />}>
                <div className="p-4 rounded-card border border-line bg-app/50 flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className="p-2 rounded-lg bg-elevated/60">
                      <Info className="w-5 h-5 text-ink-muted" />
                    </div>
                    <div>
                      <h4 className="text-sm font-medium text-ink-soft">Model Unavailable</h4>
                      <p className="text-xs text-ink-muted mt-0.5">
                        Phishing classification model has not been trained yet. Waiting for labeled dataset.
                      </p>
                    </div>
                  </div>
                  <StatusBadge tone="neutral">Not Configured</StatusBadge>
                </div>
              </Card>

              {/* 3. URL Reputation */}
              <Card title="URL Reputation (VirusTotal)" icon={<Globe className="w-4 h-4" />}>
                {urlResult.reputation ? (
                  <div
                    className={`p-4 rounded-card border ${getReputationColor(
                      urlResult.reputation.status
                    )} flex items-center justify-between transition-colors`}
                  >
                    <div className="flex items-start sm:items-center gap-3 flex-col sm:flex-row">
                      <div className="p-2 rounded-lg bg-app/50">
                        {getReputationIcon(urlResult.reputation.status)}
                      </div>
                      <div>
                        <h4 className="text-sm font-medium">
                          {urlResult.reputation.status === 'match' && 'Malicious URL Detected'}
                          {urlResult.reputation.status === 'no_match' && 'No Malicious Records Found'}
                          {urlResult.reputation.status === 'unavailable' && 'Reputation Lookup Unavailable'}
                        </h4>
                        <p className="text-xs mt-1 opacity-80 max-w-xl">
                          {urlResult.reputation.details}
                          {urlResult.reputation.status === 'no_match' &&
                            ' (Note: Absence of records is not sufficient evidence to declare a URL safe)'}
                        </p>
                      </div>
                    </div>
                    <span className="hidden sm:inline-flex">
                      <Mono title={urlResult.reputation.provider}>{urlResult.reputation.provider}</Mono>
                    </span>
                  </div>
                ) : (
                  <div className="p-4 rounded-card border border-line bg-app/50 flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <div className="p-2 rounded-lg bg-elevated/60">
                        <HelpCircle className="w-5 h-5 text-ink-muted" />
                      </div>
                      <div>
                        <h4 className="text-sm font-medium text-ink-soft">Reputation Lookup Disabled</h4>
                        <p className="text-xs text-ink-muted mt-0.5">VirusTotal API key is not configured.</p>
                      </div>
                    </div>
                  </div>
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
                    <div className="text-[10px] text-ink-muted uppercase tracking-wider mt-1">Threat Score</div>
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
                          {spearResult.is_phishing ? 'ATTACK DETECTED: SPEAR PHISHING' : 'BENIGN COMMUNICATION'}
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
                    <div className="text-[10px] text-ink-muted uppercase tracking-wider mt-1">Spear Likelihood</div>
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
              </Card>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
