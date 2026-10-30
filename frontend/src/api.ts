import axios from 'axios';
import { API_BASE_URL } from './apiBase';

// Backend base URL configured via VITE_API_URL environment variable
const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 15000,
  headers: {
    'Content-Type': 'application/json',
  },
});

export default api;

export interface SystemConfig {
  health: {
    database: string;
    api: string;
  };
  detection: {
    phishing_threshold: number;
    supported_rules: string[];
    ml_model_version: string;
    ml_training_ready: boolean;
  };
  integrity: {
    hmac_configured: boolean;
  };
  data: {
    event_count: number;
    detection_count: number;
    retention_policy: string;
  };
}

export const getSystemConfig = () => api.get<SystemConfig>('/api/system/config');

// ==========================================
// Attack Scenario Studio
// ==========================================

export interface StudioCategory {
  attack_category: string;
  detector_route: {
    rule_engine: boolean;
    ml_supported: boolean;
    heuristic_only: boolean;
    ml_task_name: string | null;
    feature_schema: string;
  };
}

export interface StudioControls {
  attack_category?: string;
  intensity?: string;
  event_count?: number;
  duration_seconds?: number;
  benign_to_malicious_ratio?: number;
  seed?: number;
  evaluation_objective?: string;
  dataset_role?: string;
}

export interface ValidationReport {
  ok: boolean;
  violations: Array<{ code: string; message: string; location: string | null }>;
  warnings: Array<{ code: string; message: string; location: string | null }>;
}

export interface ProposeResponse {
  status: 'ready' | 'invalid' | 'unsafe_request';
  spec: Record<string, unknown> | null;
  validation: ValidationReport | null;
  model: string | null;
  correlation_id: string | null;
  attempts: number;
  fallback_available: boolean;
}

export interface ValidateResponse {
  valid: boolean;
  spec: Record<string, unknown> | null;
  validation: ValidationReport;
}

export interface CompileResponse {
  dataset_id: string;
  scenario_id: string;
  scenario_category: string;
  events_count: number;
  dataset_role: string;
  generator_version: string | null;
  llm_input_sha256: string | null;
  is_training_eligible: boolean;
  ground_truth_available: boolean;
  provenance: Record<string, unknown>;
}

export interface ReplayResponse {
  eval_run_id: string;
  dataset_id: string;
  scenario_id: string;
  detector_type: string;
  model_version: string;
  session_id: number;
  expected_labels: string[];
  actual_labels: string[];
  true_positive_labels: string[];
  false_negative_labels: string[];
  false_positive_labels: string[];
  metrics: { precision: number; recall: number; f1_score: number };
}

export interface LifecycleResponse {
  provenance: Record<string, any>;
  layer_plan: Record<string, any>;
  layer_telemetry: { events_count: number; events: any[] };
  layer_ground_truth: Record<string, any>;
  layer_detections: Array<Record<string, any>>;
  layer_evaluation: Record<string, any>;
}

export const studioListCategories = () =>
  api.get<StudioCategory[]>('/api/scenario-studio/categories');

export const studioPropose = (request: string, controls?: StudioControls, model?: string) =>
  api.post<ProposeResponse>('/api/scenario-studio/propose', { request, controls, model });

export const studioValidate = (spec: Record<string, unknown>) =>
  api.post<ValidateResponse>('/api/scenario-studio/validate', { spec });

export const studioCompile = (spec: Record<string, unknown>) =>
  api.post<CompileResponse>('/api/scenario-studio/compile', { spec });

export const studioReplay = (datasetId: string) =>
  api.post<ReplayResponse>(`/api/scenario-studio/datasets/${datasetId}/replay`);

export const studioLifecycle = (datasetId: string) =>
  api.get<LifecycleResponse>(`/api/scenario-studio/datasets/${datasetId}/lifecycle`);

// ==========================================
// Adaptive Simulation & History
// ==========================================

export interface AdaptiveRecommendation {
  operator_id: string;
  recommended_scenario: string;
  scenario_name: string;
  recommended_intensity: 'low' | 'medium' | 'high';
  rationale: string;
  coverage_summary: {
    total_scenarios: number;
    tested_scenarios: number;
    untested_scenarios: string[];
  };
  recent_sessions_evaluated: number;
  last_session: {
    session_id: number;
    scenario: string;
    detections_count: number;
    risk_score: number;
    risk_band: string;
  } | null;
}

export interface SimulationHistoryItem {
  session_id: number;
  operator_id: string;
  scenario: string;
  scenario_name: string;
  status: string;
  started_at: string | null;
  ended_at: string | null;
  events_count: number;
  detections_count: number;
  risk_score: number | null;
  risk_band: string | null;
}

export interface SimulationHistoryResponse {
  total: number;
  limit: number;
  offset: number;
  items: SimulationHistoryItem[];
}

export const getSimulationRecommendation = (operatorId: string = 'simulation_operator') =>
  api.get<AdaptiveRecommendation>('/api/simulation/next-recommendation', {
    params: { operator_id: operatorId },
  });

export const getSimulationHistory = (operatorId?: string, limit: number = 20, offset: number = 0) =>
  api.get<SimulationHistoryResponse>('/api/simulation/history', {
    params: { operator_id: operatorId, limit, offset },
  });

export interface LearningEligibilityResponse {
  dataset_id: string;
  scenario_id: string | null;
  attack_category: string;
  task_name: string | null;
  dataset_role: string | null;
  ground_truth_available: boolean;
  is_evaluated: boolean;
  already_imported: number;
  eligible: boolean;
  can_reimport: boolean;
  reasons: string[];
}

export interface LearningImportResponse extends LearningEligibilityResponse {
  imported: number;
  status: 'IMPORTED' | 'ALREADY_IMPORTED';
}

export const studioLearningEligibility = (datasetId: string) =>
  api.get<LearningEligibilityResponse>(`/api/scenario-studio/datasets/${datasetId}/learning-eligibility`);

export const studioImportLearning = (datasetId: string) =>
  api.post<LearningImportResponse>(`/api/scenario-studio/datasets/${datasetId}/import-learning`);


// ==========================================
// Adaptive Learning — LLM Analyst (Milestone 1)
// ==========================================

export type AnalysisMode =
  | 'MISSED_DETECTION'
  | 'FALSE_POSITIVE'
  | 'DATASET_QUALITY'
  | 'FEATURE_IMPROVEMENT'
  | 'MODEL_EVALUATION'
  | 'NEXT_EXPERIMENT';

export interface EvidenceRef {
  kind: 'evaluation_run' | 'dataset' | 'event' | 'model_version' | 'learning_example';
  id: string;
  detail?: string | null;
}

export interface AnalystRecommendation {
  recommendation_id: string;
  analysis_run_id: string;
  attack_category: string;
  recommendation_type: string;
  summary: string;
  evidence_refs: EvidenceRef[];
  hypothesis?: string | null;
  confidence: 'low' | 'medium' | 'high';
  proposed_change?: string | null;
  required_features: string[];
  required_data?: string | null;
  expected_benefit?: string | null;
  potential_risks?: string | null;
  validation_plan?: string | null;
  status: string;
  created_at?: string;
}

export interface AnalysisReport {
  analysis_run_id: string;
  evaluation_run_id: string;
  mode: AnalysisMode;
  summary: string;
  findings: string[];
  recommendations: AnalystRecommendation[];
  model?: string | null;
  correlation_id?: string | null;
  provider_status: 'ok' | 'unavailable' | 'invalid';
}

export interface EvalRunSummary {
  id: string;
  dataset_id: string;
  attack_category?: string | null;
  detector_type?: string | null;
  model_version?: string | null;
  true_positives?: number | null;
  false_positives?: number | null;
  false_negatives?: number | null;
  precision?: number | null;
  recall?: number | null;
  f1_score?: number | null;
  started_at?: string | null;
}

export interface AnalystCapabilities {
  supported_modes: AnalysisMode[];
  recommendation_types: string[];
  categories: Array<{
    attack_category: string;
    ml_task: string | null;
    ml_supported: boolean;
    heuristic_only: boolean;
    feature_schema_version: string | null;
    registered_features: string[];
  }>;
  milestone: number;
}

export interface PersistedAnalysisRun {
  id: string;
  evaluation_run_id: string;
  dataset_id?: string | null;
  attack_category?: string | null;
  mode: string;
  status: string;
  summary?: string | null;
  findings: string[];
  model?: string | null;
  correlation_id?: string | null;
  context_sha256?: string | null;
  provider_status?: string | null;
  created_at?: string | null;
  completed_at?: string | null;
  recommendations?: Array<Record<string, any>>;
}

export const analystCapabilities = () =>
  api.get<AnalystCapabilities>('/api/adaptive-learning/capabilities');

export const analystEvaluationRuns = (limit = 50) =>
  api.get<{ evaluation_runs: EvalRunSummary[] }>(`/api/adaptive-learning/evaluation-runs?limit=${limit}`);

export const analystAnalyze = (evaluation_run_id: string, mode: AnalysisMode) =>
  api.post<AnalysisReport>('/api/adaptive-learning/analyze', { evaluation_run_id, mode });

export const analystAnalysisRuns = (params?: { evaluation_run_id?: string; limit?: number }) => {
  const qs = new URLSearchParams();
  if (params?.evaluation_run_id) qs.set('evaluation_run_id', params.evaluation_run_id);
  if (params?.limit) qs.set('limit', String(params.limit));
  const suffix = qs.toString() ? `?${qs.toString()}` : '';
  return api.get<{ analysis_runs: PersistedAnalysisRun[] }>(`/api/adaptive-learning/analysis-runs${suffix}`);
};

export const analystAnalysisRun = (id: string) =>
  api.get<PersistedAnalysisRun>(`/api/adaptive-learning/analysis-runs/${id}`);



export interface ChatStreamPayload {
  message: string;
  conversation_history: Array<{ role: string; content: string }>;
  security_context: any;
  session_id?: number;
}

export async function streamChat(
  payload: ChatStreamPayload,
  handlers: {
    onMeta: (meta: any) => void;
    onDelta: (text: string) => void;
    onError: (error: string) => void;
    onDone: () => void;
  },
  abortSignal?: AbortSignal
) {
  const url = `${API_BASE_URL}/api/chat/stream`;

  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payload),
      signal: abortSignal,
    });

    if (!response.ok) {
      let errorText = `Server error ${response.status}`;
      try {
        const errorJson = await response.json();
        if (errorJson.error) errorText = errorJson.error;
      } catch (e) {
        // Ignore JSON parse error on non-JSON response
      }
      handlers.onError(errorText);
      handlers.onDone();
      return;
    }

    if (!response.body) {
      handlers.onError('No response body received.');
      handlers.onDone();
      return;
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder('utf-8');
    let buffer = '';
    let receivedDoneEvent = false;

    const processPart = (part: string) => {
      const lines = part.split('\n');
      let eventType = 'message';
      let eventData = '';
      
      for (const line of lines) {
        if (line.startsWith('event:')) {
          eventType = line.slice(6).trim();
        } else if (line.startsWith('data:')) {
          eventData += line.slice(5).trim();
        }
      }

      if (eventType === 'meta') {
        try { handlers.onMeta(JSON.parse(eventData)); } catch (e) {}
      } else if (eventType === 'delta') {
        try { 
          const parsed = JSON.parse(eventData);
          if (parsed.text) handlers.onDelta(parsed.text);
        } catch (e) {}
      } else if (eventType === 'error') {
        try {
          const parsed = JSON.parse(eventData);
          handlers.onError(parsed.error || 'Unknown error received.');
        } catch (e) {
          handlers.onError(eventData);
        }
      } else if (eventType === 'done') {
        receivedDoneEvent = true;
        handlers.onDone();
      }
    };

    while (true) {
      const { done, value } = await reader.read();
      
      if (value) {
        buffer += decoder.decode(value, { stream: !done });
        
        // SSE blocks are separated by double newlines (\n\n)
        const parts = buffer.split('\n\n');
        // The last element is the incomplete buffer
        buffer = parts.pop() || '';

        for (const part of parts) {
          processPart(part);
        }
      }

      if (done) {
        if (buffer.trim().length > 0) {
          processPart(buffer.trim());
        }
        if (!receivedDoneEvent) {
          handlers.onError('Stream ended prematurely without completion event.');
          handlers.onDone();
        }
        break;
      }
    }
  } catch (err: any) {
    if (err.name === 'AbortError') {
      // Abort is a normal cancellation, not necessarily an error to show, but we can call onError
      handlers.onError('Request cancelled.');
    } else {
      handlers.onError(err.message || 'Failed to communicate with stream server.');
    }
    handlers.onDone();
  }
}
