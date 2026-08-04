/**
 * Brute-force guard for the dashboard login endpoint.
 *
 * The login page is served unauthenticated by design (a browser cannot
 * attach a bearer to a navigation), so the password field is reachable by
 * anyone who can reach the host. Without a limiter an attacker gets
 * unlimited offline-speed guesses against a single short secret.
 *
 * Deliberately in-memory: one process owns the HTTP surface, and a
 * restart clearing the counters is acceptable (an attacker cannot force
 * a restart). Entries are pruned lazily plus hard-capped so a spray from
 * rotating source addresses cannot grow the map without bound.
 */

const DEFAULT_MAX_ATTEMPTS = 5;
const DEFAULT_WINDOW_MINUTES = 15;
const MAX_TRACKED_CLIENTS = 10_000;

type Attempt = { count: number; firstAt: number; blockedUntil: number };

const attempts = new Map<string, Attempt>();

function maxAttempts(): number {
  const raw = process.env.AGENTMEMORY_DASHBOARD_MAX_ATTEMPTS?.trim();
  const parsed = raw ? Number(raw) : NaN;
  if (!Number.isFinite(parsed) || parsed < 1) return DEFAULT_MAX_ATTEMPTS;
  return Math.floor(parsed);
}

function windowMs(): number {
  const raw = process.env.AGENTMEMORY_DASHBOARD_LOCKOUT_MINUTES?.trim();
  const parsed = raw ? Number(raw) : NaN;
  if (!Number.isFinite(parsed) || parsed < 1)
    return DEFAULT_WINDOW_MINUTES * 60_000;
  return Math.floor(parsed) * 60_000;
}

/**
 * Identify the caller. Behind a reverse proxy the socket address is always
 * the proxy, so X-Forwarded-For's first hop is the only usable signal. It
 * is client-controlled and therefore spoofable — this limiter raises the
 * cost of a naive brute force, it is not an access control. Pair it with a
 * long password.
 */
export function clientKey(
  headers: Record<string, string | string[]> | undefined,
): string {
  const pick = (name: string): string | null => {
    const raw = headers?.[name] ?? headers?.[name.toLowerCase()];
    if (!raw) return null;
    const value = Array.isArray(raw) ? raw[0] : raw;
    const first = value.split(",")[0]?.trim();
    return first || null;
  };
  return pick("x-forwarded-for") || pick("x-real-ip") || "unknown";
}

function prune(now: number): void {
  for (const [key, entry] of attempts) {
    if (entry.blockedUntil <= now && now - entry.firstAt > windowMs()) {
      attempts.delete(key);
    }
  }
  if (attempts.size <= MAX_TRACKED_CLIENTS) return;
  // Still over cap after pruning expired entries: drop oldest-first.
  const ordered = [...attempts.entries()].sort(
    (a, b) => a[1].firstAt - b[1].firstAt,
  );
  for (const [key] of ordered.slice(0, attempts.size - MAX_TRACKED_CLIENTS)) {
    attempts.delete(key);
  }
}

export function checkRateLimit(
  key: string,
  now: number = Date.now(),
): { allowed: true } | { allowed: false; retryAfterSeconds: number } {
  const entry = attempts.get(key);
  if (!entry) return { allowed: true };
  if (entry.blockedUntil > now) {
    return {
      allowed: false,
      retryAfterSeconds: Math.ceil((entry.blockedUntil - now) / 1000),
    };
  }
  return { allowed: true };
}

export function recordFailure(key: string, now: number = Date.now()): void {
  prune(now);
  const entry = attempts.get(key);
  if (!entry || now - entry.firstAt > windowMs()) {
    attempts.set(key, { count: 1, firstAt: now, blockedUntil: 0 });
    return;
  }
  entry.count += 1;
  if (entry.count >= maxAttempts()) {
    entry.blockedUntil = now + windowMs();
    // Reset the counter alongside the block so the next window starts
    // clean rather than re-blocking on the very next failed attempt.
    entry.count = 0;
    entry.firstAt = now;
  }
}

export function recordSuccess(key: string): void {
  attempts.delete(key);
}

/** Test seam — production code has no reason to call this. */
export function resetRateLimit(): void {
  attempts.clear();
}
