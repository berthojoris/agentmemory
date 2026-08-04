import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  checkRateLimit,
  clientKey,
  recordFailure,
  recordSuccess,
  resetRateLimit,
} from "../src/dashboard/rate-limit.js";

const ENV_KEYS = [
  "AGENTMEMORY_DASHBOARD_MAX_ATTEMPTS",
  "AGENTMEMORY_DASHBOARD_LOCKOUT_MINUTES",
] as const;

let saved: Record<string, string | undefined> = {};

beforeEach(() => {
  resetRateLimit();
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
  resetRateLimit();
});

describe("clientKey", () => {
  it("prefers the first hop of X-Forwarded-For", () => {
    expect(clientKey({ "x-forwarded-for": "203.0.113.7, 10.0.0.1" })).toBe(
      "203.0.113.7",
    );
  });

  it("falls back to X-Real-IP", () => {
    expect(clientKey({ "x-real-ip": "198.51.100.4" })).toBe("198.51.100.4");
  });

  it("handles array-valued headers", () => {
    expect(clientKey({ "x-forwarded-for": ["203.0.113.9", "x"] })).toBe(
      "203.0.113.9",
    );
  });

  it("returns 'unknown' with no proxy headers", () => {
    expect(clientKey({})).toBe("unknown");
    expect(clientKey(undefined)).toBe("unknown");
  });
});

describe("checkRateLimit", () => {
  it("allows a client with no recorded failures", () => {
    expect(checkRateLimit("1.1.1.1")).toEqual({ allowed: true });
  });

  it("allows attempts below the threshold", () => {
    const now = Date.now();
    for (let i = 0; i < 4; i++) recordFailure("1.1.1.1", now);
    expect(checkRateLimit("1.1.1.1", now).allowed).toBe(true);
  });

  it("blocks once the failure threshold is reached", () => {
    const now = Date.now();
    for (let i = 0; i < 5; i++) recordFailure("1.1.1.1", now);
    const result = checkRateLimit("1.1.1.1", now);
    expect(result.allowed).toBe(false);
    if (!result.allowed) {
      expect(result.retryAfterSeconds).toBeGreaterThan(0);
      expect(result.retryAfterSeconds).toBeLessThanOrEqual(15 * 60);
    }
  });

  it("releases the block after the lockout window", () => {
    const now = Date.now();
    for (let i = 0; i < 5; i++) recordFailure("1.1.1.1", now);
    expect(checkRateLimit("1.1.1.1", now).allowed).toBe(false);
    expect(checkRateLimit("1.1.1.1", now + 15 * 60_000 + 1).allowed).toBe(true);
  });

  it("tracks clients independently", () => {
    const now = Date.now();
    for (let i = 0; i < 5; i++) recordFailure("1.1.1.1", now);
    expect(checkRateLimit("1.1.1.1", now).allowed).toBe(false);
    expect(checkRateLimit("2.2.2.2", now).allowed).toBe(true);
  });

  it("does not block when failures are spread beyond the window", () => {
    let now = Date.now();
    for (let i = 0; i < 10; i++) {
      recordFailure("1.1.1.1", now);
      now += 16 * 60_000;
    }
    expect(checkRateLimit("1.1.1.1", now).allowed).toBe(true);
  });

  it("clears the counter on a successful login", () => {
    const now = Date.now();
    for (let i = 0; i < 4; i++) recordFailure("1.1.1.1", now);
    recordSuccess("1.1.1.1");
    for (let i = 0; i < 4; i++) recordFailure("1.1.1.1", now);
    expect(checkRateLimit("1.1.1.1", now).allowed).toBe(true);
  });

  it("honours a configured attempt threshold", () => {
    process.env.AGENTMEMORY_DASHBOARD_MAX_ATTEMPTS = "2";
    const now = Date.now();
    recordFailure("1.1.1.1", now);
    expect(checkRateLimit("1.1.1.1", now).allowed).toBe(true);
    recordFailure("1.1.1.1", now);
    expect(checkRateLimit("1.1.1.1", now).allowed).toBe(false);
  });

  it("honours a configured lockout duration", () => {
    process.env.AGENTMEMORY_DASHBOARD_LOCKOUT_MINUTES = "60";
    const now = Date.now();
    for (let i = 0; i < 5; i++) recordFailure("1.1.1.1", now);
    expect(checkRateLimit("1.1.1.1", now + 30 * 60_000).allowed).toBe(false);
    expect(checkRateLimit("1.1.1.1", now + 61 * 60_000).allowed).toBe(true);
  });

  it("falls back to defaults on invalid configuration", () => {
    process.env.AGENTMEMORY_DASHBOARD_MAX_ATTEMPTS = "not-a-number";
    const now = Date.now();
    for (let i = 0; i < 4; i++) recordFailure("1.1.1.1", now);
    expect(checkRateLimit("1.1.1.1", now).allowed).toBe(true);
    recordFailure("1.1.1.1", now);
    expect(checkRateLimit("1.1.1.1", now).allowed).toBe(false);
  });

  it("re-blocks a client that keeps failing after a lockout expires", () => {
    const now = Date.now();
    for (let i = 0; i < 5; i++) recordFailure("1.1.1.1", now);
    const after = now + 15 * 60_000 + 1;
    expect(checkRateLimit("1.1.1.1", after).allowed).toBe(true);
    for (let i = 0; i < 5; i++) recordFailure("1.1.1.1", after);
    expect(checkRateLimit("1.1.1.1", after).allowed).toBe(false);
  });
});
