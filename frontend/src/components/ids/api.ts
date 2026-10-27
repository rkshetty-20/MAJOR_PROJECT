// API client for the expanded Intrusion Detection (IDS) module.
// All endpoints are DB-free and deterministic given a seed.
import api from '../../api';
import type {
  AnalyzeRequest,
  CatalogCategory,
  IdsAnalysis,
  Preset,
  PresetRunResult,
  RuleMeta,
} from './types';

export const fetchCatalog = async (): Promise<CatalogCategory[]> => {
  const { data } = await api.get<CatalogCategory[]>('/api/ids/catalog');
  return data;
};

export const fetchPresets = async (): Promise<Preset[]> => {
  const { data } = await api.get<Preset[]>('/api/ids/presets');
  return data;
};

export const fetchRules = async (): Promise<RuleMeta[]> => {
  const { data } = await api.get<RuleMeta[]>('/api/ids/rules');
  return data;
};

export const analyzePayload = async (
  req: AnalyzeRequest,
  ruleEnabled?: Record<string, boolean>,
): Promise<IdsAnalysis> => {
  const { data } = await api.post<IdsAnalysis>('/api/ids/analyze', {
    ...req,
    rule_enabled: ruleEnabled,
  });
  return data;
};

export const runPreset = async (
  presetId: string,
  volume: AnalyzeRequest['volume'],
  packetCount: number,
  sensitivity: number,
): Promise<PresetRunResult> => {
  const { data } = await api.post<PresetRunResult>('/api/ids/preset/run', {
    preset_id: presetId,
    volume,
    packet_count: packetCount,
    sensitivity,
  });
  return data;
};

// Normalize an unknown thrown value into a human-readable message.
export function extractError(err: unknown, fallback: string): string {
  if (err && typeof err === 'object' && 'response' in err) {
    const resp = (err as { response?: { data?: { detail?: string } } }).response;
    if (resp?.data?.detail) return resp.data.detail;
  }
  if (err instanceof Error) return err.message;
  return fallback;
}
