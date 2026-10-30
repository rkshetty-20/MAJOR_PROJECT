import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import api, { type SystemConfig } from '../api';

export type ServiceStatus = 'checking' | 'connected' | 'degraded' | 'disconnected';
export type SubsystemStatus = 'ready' | 'unavailable' | 'unknown';

/**
 * The values ``GET /api/system/config`` actually returns for a healthy core.
 *
 * ``app/routers/system.py`` reports ``{"database": "connected", "api": "online"}``
 * and ``{"database": "error", "api": "online"}`` when the DB probe fails. This
 * used to be compared against ``'ok'``, which the backend never emits, so the
 * sidebar badge reported "Degraded" permanently while every request returned 200.
 * ``'ok'`` is still accepted so older fixtures keep working.
 */
const HEALTHY_API = ['online', 'ok'];
const HEALTHY_DATABASE = ['connected', 'ok'];

export function isCoreHealthy(cfg?: Pick<SystemConfig, 'health'> | null): boolean {
  const api = String(cfg?.health?.api ?? '').toLowerCase();
  const database = String(cfg?.health?.database ?? '').toLowerCase();
  return HEALTHY_API.includes(api) && HEALTHY_DATABASE.includes(database);
}

export interface SystemHealthValue {
  /** Overall connectivity + service health, derived from real responses only. */
  status: ServiceStatus;
  /** HTTP round-trip latency in ms from /health, or null if not yet measured. */
  latency: number | null;
  /** ML engine readiness, distinguished from backend connectivity. */
  ml: { status: SubsystemStatus; trainingReady: boolean | null; modelVersion: string | null };
  /** Evidence-integrity (HMAC) configuration status. */
  integrity: { status: SubsystemStatus; hmacConfigured: boolean | null };
  /** True while the initial / first refresh fetch is in flight. */
  refreshing: boolean;
  /** Manual re-check. No automatic polling is scheduled. */
  refresh: () => void;
  error: string | null;
}

const HealthContext = createContext<SystemHealthValue | null>(null);

interface HealthResponse {
  status: string;
}

export const SystemHealthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [status, setStatus] = useState<ServiceStatus>('checking');
  const [latency, setLatency] = useState<number | null>(null);
  const [ml, setMl] = useState<SystemHealthValue['ml']>({ status: 'unknown', trainingReady: null, modelVersion: null });
  const [integrity, setIntegrity] = useState<SystemHealthValue['integrity']>({ status: 'unknown', hmacConfigured: null });
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const runCheck = useCallback(async () => {
    setRefreshing(true);
    setError(null);
    const started =
      typeof performance !== 'undefined' && typeof performance.now === 'function' ? performance.now() : Date.now();

    // 1) Connectivity probe. If this fails the backend is unreachable.
    let reachable = false;
    try {
      await api.get<HealthResponse>('/health');
      reachable = true;
      const ended =
        typeof performance !== 'undefined' && typeof performance.now === 'function' ? performance.now() : Date.now();
      setLatency(Math.round(ended - started));
    } catch {
      const ended =
        typeof performance !== 'undefined' && typeof performance.now === 'function' ? performance.now() : Date.now();
      setLatency(Math.round(ended - started));
    }

    if (!reachable) {
      setStatus('disconnected');
      setMl({ status: 'unknown', trainingReady: null, modelVersion: null });
      setIntegrity({ status: 'unknown', hmacConfigured: null });
      setRefreshing(false);
      return;
    }

    // 2) Service-level health. Connectivity is up, so probe per-service signals.
    try {
      const res = await api.get<SystemConfig>('/api/system/config');
      const cfg = res.data;
      setMl({
        status: cfg?.detection?.ml_training_ready ? 'ready' : 'unavailable',
        trainingReady: cfg?.detection?.ml_training_ready ?? null,
        modelVersion: cfg?.detection?.ml_model_version ?? null,
      });
      setIntegrity({
        status: cfg?.integrity?.hmac_configured ? 'ready' : 'unavailable',
        hmacConfigured: cfg?.integrity?.hmac_configured ?? null,
      });

      const coreHealthy = isCoreHealthy(cfg);
      // An untrained model (ml unavailable) is a valid state, not degraded — only
      // a broken core (api/database not ok) or a failed integrity service degrades.
      setStatus(coreHealthy ? 'connected' : 'degraded');
    } catch (err: any) {
      // Reachable root but config failed: degraded (do not claim all modules healthy).
      setStatus('degraded');
      setMl({ status: 'unknown', trainingReady: null, modelVersion: null });
      setIntegrity({ status: 'unknown', hmacConfigured: null });
      setError(err?.message || 'Failed to load system configuration');
    } finally {
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    runCheck();
  }, [runCheck]);

  const value = useMemo<SystemHealthValue>(
    () => ({ status, latency, ml, integrity, refreshing, refresh: runCheck, error }),
    [status, latency, ml, integrity, refreshing, error, runCheck],
  );

  return <HealthContext.Provider value={value}>{children}</HealthContext.Provider>;
};

export function useSystemHealth(): SystemHealthValue {
  const ctx = useContext(HealthContext);
  if (!ctx) throw new Error('useSystemHealth must be used within a SystemHealthProvider');
  return ctx;
}
