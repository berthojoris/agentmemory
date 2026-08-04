import { createHmac, randomBytes } from "node:crypto";
import { timingSafeCompare } from "../auth.js";

// Session signing key. Generated per process on purpose: sessions are
// meant to be short-lived, and tying them to process lifetime means a
// restart logs everyone out without needing anywhere to persist the key.
// Rotating the key is therefore just a restart.
const sessionKey = randomBytes(32);

export const DASHBOARD_COOKIE_NAME = "agentmemory_dashboard";

const DEFAULT_SESSION_TTL_MINUTES = 120;
const MIN_SESSION_TTL_MINUTES = 5;
const MAX_SESSION_TTL_MINUTES = 1440;

/**
 * The dashboard password. Deliberately a separate key from
 * AGENTMEMORY_SECRET with no fallback: the secret authorizes MCP clients
 * and the full REST surface, so reusing it here would mean a leaked
 * dashboard password also compromises every wired agent. Returns null
 * when unset, which disables the dashboard entirely.
 */
export function getDashboardPassword(): string | null {
  const raw = process.env.AGENTMEMORY_PASSWORD?.trim();
  return raw ? raw : null;
}

export function isDashboardEnabled(): boolean {
  return getDashboardPassword() !== null;
}

export function getSessionTtlMinutes(): number {
  const raw = process.env.AGENTMEMORY_DASHBOARD_SESSION_TTL?.trim();
  if (!raw) return DEFAULT_SESSION_TTL_MINUTES;
  const parsed = Number(raw);
  if (!Number.isFinite(parsed)) return DEFAULT_SESSION_TTL_MINUTES;
  return Math.min(
    MAX_SESSION_TTL_MINUTES,
    Math.max(MIN_SESSION_TTL_MINUTES, Math.floor(parsed)),
  );
}

function sign(payload: string): string {
  return createHmac("sha256", sessionKey).update(payload).digest("base64url");
}

/**
 * Stateless signed token: `<expiryMs>.<nonce>.<signature>`. No server-side
 * session store to keep in sync, and forging one requires the in-memory
 * key. The nonce keeps two tokens minted in the same millisecond distinct.
 */
export function issueSessionToken(now: number = Date.now()): string {
  const exp = now + getSessionTtlMinutes() * 60_000;
  const nonce = randomBytes(12).toString("base64url");
  const payload = `${exp}.${nonce}`;
  return `${payload}.${sign(payload)}`;
}

export function verifySessionToken(
  token: string | undefined | null,
  now: number = Date.now(),
): boolean {
  if (!token) return false;
  const parts = token.split(".");
  if (parts.length !== 3) return false;
  const [expRaw, nonce, signature] = parts;
  if (!expRaw || !nonce || !signature) return false;

  // Verify the signature before trusting any field inside the token.
  if (!timingSafeCompare(signature, sign(`${expRaw}.${nonce}`))) return false;

  const exp = Number(expRaw);
  if (!Number.isFinite(exp)) return false;
  return exp > now;
}

export function parseCookies(
  header: string | string[] | undefined,
): Record<string, string> {
  const out: Record<string, string> = {};
  if (!header) return out;
  const raw = Array.isArray(header) ? header.join("; ") : header;
  for (const pair of raw.split(";")) {
    const eq = pair.indexOf("=");
    if (eq < 0) continue;
    const name = pair.slice(0, eq).trim();
    if (!name) continue;
    // Only the first occurrence wins: a client that sends the cookie
    // twice must not be able to smuggle a second value past the first.
    if (name in out) continue;
    out[name] = pair.slice(eq + 1).trim();
  }
  return out;
}

export function readSessionCookie(
  headers: Record<string, string | string[]> | undefined,
): string | null {
  const raw = headers?.["cookie"] ?? headers?.["Cookie"];
  const cookies = parseCookies(raw);
  return cookies[DASHBOARD_COOKIE_NAME] || null;
}

export function hasValidDashboardSession(
  headers: Record<string, string | string[]> | undefined,
  now: number = Date.now(),
): boolean {
  if (!isDashboardEnabled()) return false;
  return verifySessionToken(readSessionCookie(headers), now);
}

/**
 * `Secure` is on by default because the dashboard is meant to sit behind
 * HTTPS. AGENTMEMORY_DASHBOARD_COOKIE_INSECURE exists only so plain-HTTP
 * localhost testing works — a browser silently drops a `Secure` cookie
 * over http://, which looks like "login succeeds but nothing happens".
 */
export function buildSessionCookie(token: string): string {
  const insecure =
    process.env.AGENTMEMORY_DASHBOARD_COOKIE_INSECURE?.trim().toLowerCase() ===
    "true";
  const attrs = [
    `${DASHBOARD_COOKIE_NAME}=${token}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Strict",
    `Max-Age=${getSessionTtlMinutes() * 60}`,
  ];
  if (!insecure) attrs.push("Secure");
  return attrs.join("; ");
}

export function buildClearedSessionCookie(): string {
  const insecure =
    process.env.AGENTMEMORY_DASHBOARD_COOKIE_INSECURE?.trim().toLowerCase() ===
    "true";
  const attrs = [
    `${DASHBOARD_COOKIE_NAME}=`,
    "Path=/",
    "HttpOnly",
    "SameSite=Strict",
    "Max-Age=0",
  ];
  if (!insecure) attrs.push("Secure");
  return attrs.join("; ");
}

export function verifyDashboardPassword(candidate: unknown): boolean {
  const expected = getDashboardPassword();
  if (!expected) return false;
  if (typeof candidate !== "string" || !candidate) return false;
  return timingSafeCompare(candidate, expected);
}
