import { useEffect, useState } from 'react';
import { whoAmI } from '../api';
import { updateInstanceRole } from '../agentInstances';
import type { WhoAmI } from '../types';

/** Fetched once per authenticated session against the currently active instance — refetches
 * when the operator switches instances (agentInstances.ts) since each instance has its own
 * fixed role. A single instance's role never changes at runtime otherwise (see types.ts's
 * WhoAmI doc comment). */
export function useWhoAmI(enabled: boolean, activeBaseUrl: string) {
  const [identity, setIdentity] = useState<WhoAmI | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!enabled) {
      setIdentity(null);
      return;
    }
    let cancelled = false;
    whoAmI()
      .then((result) => {
        if (cancelled) return;
        setIdentity(result);
        updateInstanceRole(activeBaseUrl, result.role);
      })
      .catch((err) => {
        if (!cancelled) setError((err as Error).message);
      });
    return () => {
      cancelled = true;
    };
  }, [enabled, activeBaseUrl]);

  return { identity, error };
}
