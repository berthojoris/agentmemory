import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  DASHBOARD_COOKIE_NAME,
  buildClearedSessionCookie,
  buildSessionCookie,
  getDashboardPassword,
  getSessionTtlMinutes,
  hasValidDashboardSession,
  isDashboardEnabled,
  issueSessionToken,
  parseCookies,
  readSessionCookie,
  verifyDashboardPassword,
  verifySessionToken,
} from "../src/dashboard/session.js";

const ENV_KEYS = [
  "AGENTMEMORY_PASSWORD",
  "AGENTMEMORY_SECRET",
  "AGENTMEMORY_DASHBOARD_SESSION_TTL",
  "AGENTMEMORY_DASHBOARD_COOKIE_INSECURE",
] as const;

let saved: Record<string, string | undefined> = {};

beforeEach(() => {
  saved = {};
  for (const key of ENV_KEYS) {
    saved[key] = process.env[key];
    delete process.env[key];
  }
});

afterEach(() => {
  for (const key of ENV_KEYS) {
    if (saved[key] === undefined) delete process.env[key];
    else process.env[key] = saved[key];
  }
});

describe("getDashboardPassword", () => {
  it("returns null when AGENTMEMORY_PASSWORD is unset", () => {
    expect(getDashboardPassword()).toBeNull();
    expect(isDashboardEnabled()).toBe(false);
  });

  it("returns null for a whitespace-only password", () => {
    process.env.AGENTMEMORY_PASSWORD = "   ";
    expect(getDashboardPassword()).toBeNull();
  });

  it("never falls back to AGENTMEMORY_SECRET", () => {
    process.env.AGENTMEMORY_SECRET = "the-mcp-secret";
    expect(getDashboardPassword()).toBeNull();
    expect(isDashboardEnabled()).toBe(false);
  });

  it("trims the configured password", () => {
    process.env.AGENTMEMORY_PASSWORD = "  hunter2  ";
    expect(getDashboardPassword()).toBe("hunter2");
  });
});

describe("verifyDashboardPassword", () => {
  beforeEach(() => {
    process.env.AGENTMEMORY_PASSWORD = "correct-horse-battery-staple";
  });

  it("accepts the configured password", () => {
    expect(verifyDashboardPassword("correct-horse-battery-staple")).toBe(true);
  });

  it("rejects a wrong password", () => {
    expect(verifyDashboardPassword("wrong")).toBe(false);
  });

  it("rejects empty, non-string, and null candidates", () => {
    expect(verifyDashboardPassword("")).toBe(false);
    expect(verifyDashboardPassword(undefined)).toBe(false);
    expect(verifyDashboardPassword(null)).toBe(false);
    expect(verifyDashboardPassword(12345)).toBe(false);
    expect(verifyDashboardPassword({})).toBe(false);
  });

  it("rejects everything when no password is configured", () => {
    delete process.env.AGENTMEMORY_PASSWORD;
    expect(verifyDashboardPassword("anything")).toBe(false);
    expect(verifyDashboardPassword("")).toBe(false);
  });
});

describe("getSessionTtlMinutes", () => {
  it("defaults to 120 minutes", () => {
    expect(getSessionTtlMinutes()).toBe(120);
  });

  it("clamps below the 5 minute floor", () => {
    process.env.AGENTMEMORY_DASHBOARD_SESSION_TTL = "1";
    expect(getSessionTtlMinutes()).toBe(5);
  });

  it("clamps above the 1440 minute ceiling", () => {
    process.env.AGENTMEMORY_DASHBOARD_SESSION_TTL = "99999";
    expect(getSessionTtlMinutes()).toBe(1440);
  });

  it("falls back to the default on non-numeric input", () => {
    process.env.AGENTMEMORY_DASHBOARD_SESSION_TTL = "soon";
    expect(getSessionTtlMinutes()).toBe(120);
  });
});

describe("session tokens", () => {
  it("issues a token that verifies immediately", () => {
    const token = issueSessionToken();
    expect(verifySessionToken(token)).toBe(true);
  });

  it("rejects a token past its expiry", () => {
    const now = Date.now();
    const token = issueSessionToken(now);
    // Default TTL is 120 minutes; jump past it.
    expect(verifySessionToken(token, now + 121 * 60_000)).toBe(false);
  });

  it("still accepts a token one minute before expiry", () => {
    const now = Date.now();
    const token = issueSessionToken(now);
    expect(verifySessionToken(token, now + 119 * 60_000)).toBe(true);
  });

  it("rejects a token whose expiry was tampered with", () => {
    const token = issueSessionToken();
    const [, nonce, sig] = token.split(".");
    const forged = `${Date.now() + 10_000_000}.${nonce}.${sig}`;
    expect(verifySessionToken(forged)).toBe(false);
  });

  it("rejects a token with a tampered signature", () => {
    const [exp, nonce] = issueSessionToken().split(".");
    expect(verifySessionToken(`${exp}.${nonce}.deadbeef`)).toBe(false);
  });

  it("rejects malformed and empty tokens", () => {
    expect(verifySessionToken("")).toBe(false);
    expect(verifySessionToken(null)).toBe(false);
    expect(verifySessionToken(undefined)).toBe(false);
    expect(verifySessionToken("a.b")).toBe(false);
    expect(verifySessionToken("a.b.c.d")).toBe(false);
    expect(verifySessionToken("..")).toBe(false);
  });

  it("issues distinct tokens within the same millisecond", () => {
    const now = Date.now();
    expect(issueSessionToken(now)).not.toBe(issueSessionToken(now));
  });
});

describe("parseCookies", () => {
  it("parses a multi-cookie header", () => {
    expect(parseCookies("a=1; b=2; c=3")).toEqual({ a: "1", b: "2", c: "3" });
  });

  it("returns an empty object for missing or malformed input", () => {
    expect(parseCookies(undefined)).toEqual({});
    expect(parseCookies("")).toEqual({});
    expect(parseCookies("novalue")).toEqual({});
  });

  it("keeps the first occurrence when a cookie name repeats", () => {
    // A client sending the cookie twice must not be able to smuggle a
    // second value past the one that was validated.
    expect(parseCookies("s=first; s=second")).toEqual({ s: "first" });
  });

  it("preserves base64url token characters and joins array headers", () => {
    expect(parseCookies("t=aB-_9.x")).toEqual({ t: "aB-_9.x" });
    expect(parseCookies(["a=1", "b=2"])).toEqual({ a: "1", b: "2" });
  });
});

describe("readSessionCookie", () => {
  it("reads the dashboard cookie under either header casing", () => {
    const token = "tok123";
    expect(readSessionCookie({ cookie: `${DASHBOARD_COOKIE_NAME}=${token}` })).toBe(token);
    expect(readSessionCookie({ Cookie: `${DASHBOARD_COOKIE_NAME}=${token}` })).toBe(token);
  });

  it("returns null when absent", () => {
    expect(readSessionCookie(undefined)).toBeNull();
    expect(readSessionCookie({ cookie: "other=1" })).toBeNull();
  });
});

describe("hasValidDashboardSession", () => {
  it("is false while the dashboard is disabled, even with a valid token", () => {
    process.env.AGENTMEMORY_PASSWORD = "pw";
    const token = issueSessionToken();
    delete process.env.AGENTMEMORY_PASSWORD;
    expect(
      hasValidDashboardSession({ cookie: `${DASHBOARD_COOKIE_NAME}=${token}` }),
    ).toBe(false);
  });

  it("is true for a valid cookie while enabled", () => {
    process.env.AGENTMEMORY_PASSWORD = "pw";
    const token = issueSessionToken();
    expect(
      hasValidDashboardSession({ cookie: `${DASHBOARD_COOKIE_NAME}=${token}` }),
    ).toBe(true);
  });

  it("is false for a garbage cookie value", () => {
    process.env.AGENTMEMORY_PASSWORD = "pw";
    expect(
      hasValidDashboardSession({ cookie: `${DASHBOARD_COOKIE_NAME}=nope` }),
    ).toBe(false);
  });
});

describe("cookie attributes", () => {
  it("is HttpOnly, SameSite=Strict, Secure, and path-wide by default", () => {
    const cookie = buildSessionCookie("tok");
    expect(cookie).toContain(`${DASHBOARD_COOKIE_NAME}=tok`);
    expect(cookie).toContain("HttpOnly");
    expect(cookie).toContain("SameSite=Strict");
    expect(cookie).toContain("Secure");
    // Path=/ is required: the viewer calls /agentmemory/* from a page
    // served at /dashboard/view, so a narrower path would drop the cookie.
    expect(cookie).toContain("Path=/");
    expect(cookie).toContain("Max-Age=7200");
  });

  it("drops Secure only when explicitly opted out", () => {
    process.env.AGENTMEMORY_DASHBOARD_COOKIE_INSECURE = "true";
    expect(buildSessionCookie("tok")).not.toContain("Secure");
    expect(buildClearedSessionCookie()).not.toContain("Secure");
  });

  it("keeps Secure for any value other than the literal 'true'", () => {
    process.env.AGENTMEMORY_DASHBOARD_COOKIE_INSECURE = "yes";
    expect(buildSessionCookie("tok")).toContain("Secure");
  });

  it("expires the cookie on logout", () => {
    const cookie = buildClearedSessionCookie();
    expect(cookie).toContain(`${DASHBOARD_COOKIE_NAME}=`);
    expect(cookie).toContain("Max-Age=0");
    expect(cookie).toContain("HttpOnly");
  });
});
