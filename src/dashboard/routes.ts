import type { ISdk, ApiRequest } from "iii-sdk";
import { renderViewerDocument } from "../viewer/document.js";
import { renderLoginPage } from "./login-page.js";
import {
  buildClearedSessionCookie,
  buildSessionCookie,
  getSessionTtlMinutes,
  hasValidDashboardSession,
  isDashboardEnabled,
  issueSessionToken,
  verifyDashboardPassword,
} from "./session.js";
import { checkRateLimit, clientKey, recordFailure, recordSuccess } from "./rate-limit.js";
import { logger } from "../logger.js";

type Response = {
  status_code: number;
  headers?: Record<string, string>;
  body: unknown;
};

/**
 * Every dashboard route is mounted twice. The engine's HTTP router is a
 * flat exact-path registry, but every other path in this codebase lives
 * under /agentmemory — so whether a top-level /dashboard prefix routes at
 * all is unproven. Registering both means the operator-facing URL works
 * if the engine allows it, and the /agentmemory-prefixed twin is there as
 * a guaranteed fallback either way. GET /dashboard/ping tells you which.
 */
const MOUNTS = ["/dashboard", "/agentmemory/dashboard"] as const;

function htmlResponse(
  status: number,
  html: string,
  csp?: string,
  extraHeaders?: Record<string, string>,
): Response {
  const headers: Record<string, string> = {
    "Content-Type": "text/html; charset=utf-8",
    // The login shell and the viewer both reflect session state, so they
    // must never be cached by a proxy and replayed to another visitor.
    "Cache-Control": "no-store, must-revalidate",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    ...(extraHeaders || {}),
  };
  if (csp) headers["Content-Security-Policy"] = csp;
  return { status_code: status, headers, body: html };
}

function dashboardDisabledHtml(): string {
  return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8" />
<title>agentmemory dashboard</title></head><body>
<h1>Dashboard not configured</h1>
<p>Set <code>AGENTMEMORY_PASSWORD</code> in the environment and restart to enable
the dashboard at this URL.</p></body></html>`;
}

export function registerDashboardTriggers(sdk: ISdk): void {
  // --- GET /dashboard/ping ------------------------------------------------
  // Unauthenticated liveness probe whose only job is to answer the routing
  // question: hit both mounts and see which returns 200 instead of 404.
  sdk.registerFunction(
    "dashboard::ping",
    async (): Promise<Response> => ({
      status_code: 200,
      headers: { "Cache-Control": "no-store" },
      body: {
        ok: true,
        service: "agentmemory-dashboard",
        enabled: isDashboardEnabled(),
        mounts: MOUNTS.map((m) => `${m}/view`),
      },
    }),
  );

  // --- GET /dashboard/view ------------------------------------------------
  // Served without auth on purpose: a browser cannot attach a bearer to a
  // navigation. With no valid session this returns the login shell, which
  // carries no memory data — the viewer is only rendered once the session
  // cookie verifies.
  sdk.registerFunction(
    "dashboard::view",
    async (req: ApiRequest): Promise<Response> => {
      if (!isDashboardEnabled()) {
        return htmlResponse(503, dashboardDisabledHtml());
      }

      if (!hasValidDashboardSession(req.headers)) {
        const login = renderLoginPage();
        return htmlResponse(200, login.html, login.csp);
      }

      const rendered = renderViewerDocument();
      if (!rendered.found) {
        return htmlResponse(
          404,
          `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8" /><title>agentmemory</title></head><body><h1>agentmemory</h1><p>viewer not found</p></body></html>`,
        );
      }
      return htmlResponse(200, rendered.html, rendered.csp);
    },
  );

  // --- POST /dashboard/login ----------------------------------------------
  sdk.registerFunction(
    "dashboard::login",
    async (req: ApiRequest): Promise<Response> => {
      if (!isDashboardEnabled()) {
        return {
          status_code: 503,
          headers: { "Cache-Control": "no-store" },
          body: { error: "Dashboard is not configured (AGENTMEMORY_PASSWORD unset)" },
        };
      }

      const key = clientKey(req.headers);
      const limit = checkRateLimit(key);
      if (!limit.allowed) {
        logger.warn(
          `[dashboard] login rate-limited for ${key} (${limit.retryAfterSeconds}s remaining)`,
        );
        return {
          status_code: 429,
          headers: {
            "Cache-Control": "no-store",
            "Retry-After": String(limit.retryAfterSeconds),
          },
          body: {
            error: `Too many attempts. Try again in ${Math.ceil(limit.retryAfterSeconds / 60)} minute(s).`,
          },
        };
      }

      const body = (req.body || {}) as Record<string, unknown>;
      if (!verifyDashboardPassword(body.password)) {
        recordFailure(key);
        logger.warn(`[dashboard] failed login attempt from ${key}`);
        return {
          status_code: 401,
          headers: { "Cache-Control": "no-store" },
          body: { error: "invalid password" },
        };
      }

      recordSuccess(key);
      const token = issueSessionToken();
      logger.info(`[dashboard] login succeeded for ${key}`);
      return {
        status_code: 200,
        headers: {
          "Cache-Control": "no-store",
          "Set-Cookie": buildSessionCookie(token),
        },
        body: { ok: true, expiresInMinutes: getSessionTtlMinutes() },
      };
    },
  );

  // --- POST /dashboard/logout ---------------------------------------------
  sdk.registerFunction(
    "dashboard::logout",
    async (): Promise<Response> => ({
      status_code: 200,
      headers: {
        "Cache-Control": "no-store",
        "Set-Cookie": buildClearedSessionCookie(),
      },
      body: { ok: true },
    }),
  );

  for (const mount of MOUNTS) {
    sdk.registerTrigger({
      type: "http",
      function_id: "dashboard::ping",
      config: { api_path: `${mount}/ping`, http_method: "GET" },
    });
    sdk.registerTrigger({
      type: "http",
      function_id: "dashboard::view",
      config: { api_path: `${mount}/view`, http_method: "GET" },
    });
    sdk.registerTrigger({
      type: "http",
      function_id: "dashboard::login",
      config: { api_path: `${mount}/login`, http_method: "POST" },
    });
    sdk.registerTrigger({
      type: "http",
      function_id: "dashboard::logout",
      config: { api_path: `${mount}/logout`, http_method: "POST" },
    });
  }
}
