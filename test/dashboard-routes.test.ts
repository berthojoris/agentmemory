import { describe, it, expect, beforeEach, afterEach } from "vitest";
import type { ISdk } from "iii-sdk";
import { registerDashboardTriggers } from "../src/dashboard/routes.js";
import {
  DASHBOARD_COOKIE_NAME,
  issueSessionToken,
} from "../src/dashboard/session.js";
import { resetRateLimit } from "../src/dashboard/rate-limit.js";

type Handler = (req: unknown) => Promise<{
  status_code: number;
  headers?: Record<string, string>;
  body: unknown;
}>;

type Registered = {
  handlers: Map<string, Handler>;
  routes: Array<{ path: string; method: string; functionId: string }>;
};

function fakeSdk(): { sdk: ISdk; registered: Registered } {
  const registered: Registered = { handlers: new Map(), routes: [] };
  const sdk = {
    registerFunction(id: string, fn: Handler) {
      registered.handlers.set(id, fn);
    },
    registerTrigger(input: {
      function_id: string;
      config: { api_path: string; http_method: string };
    }) {
      registered.routes.push({
        path: input.config.api_path,
        method: input.config.http_method,
        functionId: input.function_id,
      });
    },
  } as unknown as ISdk;
  return { sdk, registered };
}

const ENV_KEYS = [
  "AGENTMEMORY_PASSWORD",
  "AGENTMEMORY_DASHBOARD_COOKIE_INSECURE",
] as const;

let saved: Record<string, string | undefined> = {};
let registered: Registered;

async function call(
  functionId: string,
  req: unknown = { headers: {}, body: {} },
) {
  const handler = registered.handlers.get(functionId);
  if (!handler) throw new Error(`no handler for ${functionId}`);
  return handler(req);
}

beforeEach(() => {
  resetRateLimit();
  saved = {};
  for (const key of ENV_KEYS) {
    saved[key] = process.env[key];
    delete process.env[key];
  }
  const fake = fakeSdk();
  registered = fake.registered;
  registerDashboardTriggers(fake.sdk);
});

afterEach(() => {
  for (const key of ENV_KEYS) {
    if (saved[key] === undefined) delete process.env[key];
    else process.env[key] = saved[key];
  }
  resetRateLimit();
});

describe("route registration", () => {
  it("mounts every route under both /dashboard and /agentmemory/dashboard", () => {
    // The top-level prefix is the URL the operator wants; the
    // /agentmemory twin is the guaranteed-routable fallback.
    for (const leaf of ["ping", "view", "login", "logout"]) {
      expect(registered.routes.some((r) => r.path === `/dashboard/${leaf}`)).toBe(true);
      expect(
        registered.routes.some((r) => r.path === `/agentmemory/dashboard/${leaf}`),
      ).toBe(true);
    }
  });

  it("uses GET for view/ping and POST for login/logout", () => {
    const byPath = (p: string) => registered.routes.find((r) => r.path === p);
    expect(byPath("/dashboard/view")?.method).toBe("GET");
    expect(byPath("/dashboard/ping")?.method).toBe("GET");
    expect(byPath("/dashboard/login")?.method).toBe("POST");
    expect(byPath("/dashboard/logout")?.method).toBe("POST");
  });
});

describe("GET /dashboard/ping", () => {
  it("answers 200 without auth so the mount can be probed", async () => {
    const res = await call("dashboard::ping");
    expect(res.status_code).toBe(200);
    expect((res.body as { ok: boolean }).ok).toBe(true);
  });

  it("reports whether a password is configured", async () => {
    expect((await call("dashboard::ping")).body).toMatchObject({ enabled: false });
    process.env.AGENTMEMORY_PASSWORD = "pw";
    expect((await call("dashboard::ping")).body).toMatchObject({ enabled: true });
  });
});

describe("GET /dashboard/view", () => {
  it("returns 503 when AGENTMEMORY_PASSWORD is unset", async () => {
    const res = await call("dashboard::view");
    expect(res.status_code).toBe(503);
    expect(String(res.body)).toContain("AGENTMEMORY_PASSWORD");
  });

  it("serves the login shell — not memory data — without a session", async () => {
    process.env.AGENTMEMORY_PASSWORD = "pw";
    const res = await call("dashboard::view");
    expect(res.status_code).toBe(200);
    const html = String(res.body);
    expect(html).toContain("Enter the dashboard password");
    expect(html).toContain('type="password"');
    // The shell must not leak the viewer application itself.
    expect(html).not.toContain("data-tab=\"memories\"");
  });

  it("serves the full viewer once a valid session cookie is present", async () => {
    process.env.AGENTMEMORY_PASSWORD = "pw";
    const token = issueSessionToken();
    const res = await call("dashboard::view", {
      headers: { cookie: `${DASHBOARD_COOKIE_NAME}=${token}` },
      body: {},
    });
    expect(res.status_code).toBe(200);
    const html = String(res.body);
    expect(html).toContain('data-tab="memories"');
    expect(html).not.toContain("Enter the dashboard password");
  });

  it("falls back to the login shell for an invalid cookie", async () => {
    process.env.AGENTMEMORY_PASSWORD = "pw";
    const res = await call("dashboard::view", {
      headers: { cookie: `${DASHBOARD_COOKIE_NAME}=forged` },
      body: {},
    });
    expect(String(res.body)).toContain("Enter the dashboard password");
  });

  it("sets no-store and anti-framing headers", async () => {
    process.env.AGENTMEMORY_PASSWORD = "pw";
    const res = await call("dashboard::view");
    expect(res.headers?.["Cache-Control"]).toContain("no-store");
    expect(res.headers?.["X-Frame-Options"]).toBe("DENY");
    expect(res.headers?.["Referrer-Policy"]).toBe("no-referrer");
    expect(res.headers?.["Content-Security-Policy"]).toContain("frame-ancestors 'none'");
  });

  it("never sets a session cookie on the view route", async () => {
    process.env.AGENTMEMORY_PASSWORD = "pw";
    const res = await call("dashboard::view");
    expect(res.headers?.["Set-Cookie"]).toBeUndefined();
  });
});

describe("POST /dashboard/login", () => {
  beforeEach(() => {
    process.env.AGENTMEMORY_PASSWORD = "correct-horse";
  });

  it("returns 503 when the dashboard is not configured", async () => {
    delete process.env.AGENTMEMORY_PASSWORD;
    const res = await call("dashboard::login", {
      headers: {},
      body: { password: "correct-horse" },
    });
    expect(res.status_code).toBe(503);
    expect(res.headers?.["Set-Cookie"]).toBeUndefined();
  });

  it("issues a hardened session cookie on the right password", async () => {
    const res = await call("dashboard::login", {
      headers: {},
      body: { password: "correct-horse" },
    });
    expect(res.status_code).toBe(200);
    const cookie = res.headers?.["Set-Cookie"] || "";
    expect(cookie).toContain(`${DASHBOARD_COOKIE_NAME}=`);
    expect(cookie).toContain("HttpOnly");
    expect(cookie).toContain("Secure");
    expect(cookie).toContain("SameSite=Strict");
  });

  it("mints a cookie that the view route accepts", async () => {
    const login = await call("dashboard::login", {
      headers: {},
      body: { password: "correct-horse" },
    });
    const token = (login.headers?.["Set-Cookie"] || "")
      .split(";")[0]
      .split("=")[1];
    const view = await call("dashboard::view", {
      headers: { cookie: `${DASHBOARD_COOKIE_NAME}=${token}` },
      body: {},
    });
    expect(String(view.body)).toContain('data-tab="memories"');
  });

  it("rejects a wrong password with 401 and no cookie", async () => {
    const res = await call("dashboard::login", {
      headers: {},
      body: { password: "nope" },
    });
    expect(res.status_code).toBe(401);
    expect(res.headers?.["Set-Cookie"]).toBeUndefined();
  });

  it("rejects a missing or non-string password", async () => {
    expect((await call("dashboard::login", { headers: {}, body: {} })).status_code).toBe(401);
    expect(
      (await call("dashboard::login", { headers: {}, body: { password: 1 } })).status_code,
    ).toBe(401);
  });

  it("locks out after repeated failures and reports Retry-After", async () => {
    const headers = { "x-forwarded-for": "203.0.113.10" };
    for (let i = 0; i < 5; i++) {
      await call("dashboard::login", { headers, body: { password: "bad" } });
    }
    const res = await call("dashboard::login", {
      headers,
      body: { password: "correct-horse" },
    });
    // Even the correct password is refused while locked out.
    expect(res.status_code).toBe(429);
    expect(res.headers?.["Retry-After"]).toBeDefined();
    expect(res.headers?.["Set-Cookie"]).toBeUndefined();
  });

  it("does not let one client's lockout affect another", async () => {
    for (let i = 0; i < 5; i++) {
      await call("dashboard::login", {
        headers: { "x-forwarded-for": "203.0.113.10" },
        body: { password: "bad" },
      });
    }
    const res = await call("dashboard::login", {
      headers: { "x-forwarded-for": "198.51.100.20" },
      body: { password: "correct-horse" },
    });
    expect(res.status_code).toBe(200);
  });

  it("resets the failure counter after a success", async () => {
    const headers = { "x-forwarded-for": "203.0.113.30" };
    for (let i = 0; i < 4; i++) {
      await call("dashboard::login", { headers, body: { password: "bad" } });
    }
    expect(
      (await call("dashboard::login", { headers, body: { password: "correct-horse" } }))
        .status_code,
    ).toBe(200);
    for (let i = 0; i < 4; i++) {
      await call("dashboard::login", { headers, body: { password: "bad" } });
    }
    expect(
      (await call("dashboard::login", { headers, body: { password: "correct-horse" } }))
        .status_code,
    ).toBe(200);
  });

  it("tolerates a missing body", async () => {
    const res = await call("dashboard::login", { headers: {} });
    expect(res.status_code).toBe(401);
  });
});

describe("POST /dashboard/logout", () => {
  it("expires the session cookie", async () => {
    const res = await call("dashboard::logout");
    expect(res.status_code).toBe(200);
    const cookie = res.headers?.["Set-Cookie"] || "";
    expect(cookie).toContain("Max-Age=0");
    expect(cookie).toContain("HttpOnly");
  });
});
