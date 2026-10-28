// Shared TypeScript types mirroring the backend /api/ids contracts.

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export type Volume = 'low' | 'medium' | 'high';
export type VerdictLabel = 'Clean' | 'Suspicious' | 'Malicious';

export interface MitreMapping {
  technique_id: string;
  technique_name: string;
  tactic: string;
  source?: string;
}

export interface CatalogAttack {
  id: string;
  name: string;
  severity: Severity;
  description: string;
  kill_chain_stage: string;
  mitre: MitreMapping[];
}

export interface CatalogCategory {
  id: string;
  name: string;
  blurb: string;
  attacks: CatalogAttack[];
}

export interface DetectionEvidence {
  type: 'packet';
  packet_index: number;
  timestamp: string;
  src_ip: string;
  dst_ip: string;
  dst_port: number;
  protocol: string;
  flags: string;
  size: number;
  ttl: number;
  payload_preview: string;
}

export interface TriggeredRule {
  rule_id: string;
  name: string;
  layer: 'signature' | 'threshold' | 'stateful';
  category: 'signature' | 'threshold' | 'stateful';
  version: string;
  severity: Severity;
  weight: number;
  mitre?: string | null;
  confidence: number;
  detail: string;
  explanation: string;
  inputs_used: string[];
  matched_packets: number[];
  evidence: DetectionEvidence[];
}

export interface RuleMeta {
  rule_id: string;
  name: string;
  layer: 'signature' | 'threshold' | 'stateful';
  category: 'signature' | 'threshold' | 'stateful';
  version: string;
  severity: Severity;
  weight: number;
  mitre?: string | null;
  description: string;
  matching: string;
  explanation: string;
  inputs: string[];
  enabled: boolean;
  tunable: boolean;
  threshold?: Record<string, number> | null;
}

// Counts reported by GET /api/ids/rules/summary; derived from the registry code,
// never hardcoded in the UI.
export interface RegistrySummary {
  ruleset_version: string;
  total: number;
  layers: Record<'signature' | 'threshold' | 'stateful', number>;
  enabled: number;
  tunable: number;
  with_mitre_mapping: number;
  severities: Record<Severity, number>;
  input_scope: string;
}

export interface SkippedPacket {
  position: number;
  index: number | null;
  reason: string;
}

// Machine-readable statement of where the analysed bytes came from. The project
// has no authorized live capture path, so this must stay visible in the UI.
export interface PipelineProvenance {
  input_source: string;
  live_traffic_capture: false;
  live_traffic_claim: string;
}

export interface MlFeatureContribution {
  feature: string;
  label: string;
  value: number;
  anomaly: number;
}

export interface MlBreakdown {
  overall_score: number;
  models: Record<string, number>;
  ensemble_weights?: Record<string, number>;
  features: MlFeatureContribution[];
  top_contributors: MlFeatureContribution[];
  confidence: number;
  false_positive_probability: number;
  explanation: string;
  // These four scorers are deterministic statistical proxies, NOT trained
  // models; the text is emitted by the backend and must be shown verbatim.
  model_status?: string;
  feature_count?: number;
  scorers?: string[];
}

export interface PacketRecord {
  index: number;
  timestamp: string;
  unix_ts: number;
  protocol: string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  flags: string;
  ttl: number;
  size: number;
  payload_text: string;
  payload_sample_hex: string;
  hex: string;
}

export interface KillChainStage {
  key: string;
  label: string;
  reached: boolean;
}

export interface ThreatIntel {
  cves: string[];
  actors: string[];
  nist: string[];
  owasp: string[];
  mitigations: string[];
  frequency_note?: string;
}

export interface PacketAnalysis {
  protocol_breakdown: Record<string, number>;
  port_breakdown: Record<string, number>;
  flag_breakdown: Record<string, number>;
  size_stats: { min?: number; max?: number; mean?: number; total_bytes?: number };
  suspicious_indices: number[];
  total_bytes: number;
}

export interface IdsAnalysis {
  analysis_id: string;
  attack: { id: string; name: string; category: string; description: string; severity: Severity };
  generation: { volume: Volume; seed: number | null; packet_count: number };
  verdict: { label: VerdictLabel; threat_score: number; rule_score: number; ml_score: number };
  rules: {
    triggered_count: number;
    triggered: TriggeredRule[];
    evaluated: string[];
    evaluated_count?: number;
    registry_size?: number;
    registry?: RegistrySummary;
    ruleset_version?: string;
    accepted_packets?: number;
    skipped_packets?: SkippedPacket[];
  };
  ml: MlBreakdown;
  pipeline?: PipelineProvenance;
  kill_chain: { current: string; current_label: string; index: number; stages: KillChainStage[] };
  mitre: MitreMapping[];
  packets: PacketRecord[];
  packet_analysis: PacketAnalysis;
  threat_intel: ThreatIntel;
}

export interface PresetStage {
  attack_id: string;
  beat: string;
}

export interface Preset {
  id: string;
  name: string;
  tagline: string;
  narrative: string;
  stages: PresetStage[];
}

export interface PresetStepResult {
  beat: string;
  stage_index: number;
  attack_name: string;
  result: IdsAnalysis;
}

export interface PresetRunResult {
  preset_id: string;
  name: string;
  tagline: string;
  narrative: string;
  overall_threat_score: number;
  steps: PresetStepResult[];
}

export interface AnalyzeRequest {
  attack_id: string;
  volume: Volume;
  packet_count: number;
  seed?: number | null;
  sensitivity: number;
  rule_enabled?: Record<string, boolean>;
  rule_overrides?: Record<string, { enabled?: boolean; threshold?: Record<string, number> }>;
}
