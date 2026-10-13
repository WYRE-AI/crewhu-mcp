#!/usr/bin/env node
/**
 * Crewhu MCP Server
 *
 * Transports:
 *   - stdio (default): For local Claude Desktop / CLI usage
 *   - http: For hosted deployment via the WYRE MCP Gateway
 *
 * Auth modes:
 *   - env (default): Credentials from CREWHU_API_TOKEN
 *   - gateway: Credentials injected from X-Crewhu-Api-Token header per request
 *     (isolated via AsyncLocalStorage so concurrent tenants never see each other's tokens).
 *     Gateway mode never falls back to CREWHU_API_TOKEN.
 *
 * HTTP transport refuses to start unless CONDUIT_S2S_SECRET is a real secret.
 * Known placeholders are rejected. MCP_ALLOW_INSECURE_DEV=1 is a local-only
 * escape hatch: it logs a warning and forces the listener onto 127.0.0.1.
 * A configured secret keeps honoring MCP_HTTP_HOST. The secret is never logged.
 * /health stays unauthenticated. stdio does not use S2S auth.
 */

import { createServer as createHttpServer, IncomingMessage, Server as HttpServer, ServerResponse } from "node:http";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { logger } from "./utils/logger.js";
import { credentialStore } from "./utils/credential-store.js";
import { createMcpServer } from "./server.js";
import { verifyS2sHeader, S2S_HEADER } from "./s2s-verify.js";

const VERSION = "1.0.0";
const LOOPBACK_HOST = "127.0.0.1";

/**
 * Public example values. A copied placeholder must not verify as a real secret
 * and must not be treated as the insecure-dev bypass.
 */
const KNOWN_PLACEHOLDER_SECRETS = new Set([
  "replace-with-a-real-secret",
  "your-s2s-secret",
  "your-secret",
  "changeme",
  "change-me",
  "placeholder",
  "secret",
  "example",
  "replace-me",
  "s2s-secret",
]);

/** Hosts that count as loopback when deciding whether the dev bypass must override. */
function isLoopbackBindHost(host: string): boolean {
  const normalized = host.trim().toLowerCase().replace(/^\[(.+)\]$/, "$1");
  return normalized === "127.0.0.1" || normalized === "localhost" || normalized === "::1";
}

/**
 * Secret for X-Gateway-S2S on /mcp. Read at HTTP startup, not module load.
 * Empty or a known placeholder is fail-closed: the process exits unless the
 * value is empty and MCP_ALLOW_INSECURE_DEV=1. The secret value is never logged.
 */
function resolveHttpS2sSecret(): string {
  const secret = (process.env.CONDUIT_S2S_SECRET ?? "").trim();
  if (KNOWN_PLACEHOLDER_SECRETS.has(secret.toLowerCase())) {
    logger.error(
      "Refusing to start HTTP transport: CONDUIT_S2S_SECRET is a known placeholder. " +
        "Generate a secret with `openssl rand -hex 32` and set CONDUIT_S2S_SECRET to that value."
    );
    process.exit(1);
  }

  if (secret) return secret;

  if (process.env.MCP_ALLOW_INSECURE_DEV === "1") {
    logger.error(
      "SECURITY WARNING: CONDUIT_S2S_SECRET is empty and MCP_ALLOW_INSECURE_DEV=1. " +
        "HTTP /mcp is not enforcing X-Gateway-S2S and is limited to 127.0.0.1. " +
        "Do not use this outside local development."
    );
    return "";
  }

  logger.error(
    "Refusing to start HTTP transport: CONDUIT_S2S_SECRET is empty. " +
      "An empty secret would accept unauthenticated /mcp requests (CWE-306). " +
      "Set CONDUIT_S2S_SECRET to the gateway-provisioned service-to-service secret, " +
      "or set MCP_ALLOW_INSECURE_DEV=1 to bypass this check for local development only."
  );
  process.exit(1);
}

/**
 * No secret (insecure-dev bypass only) always binds 127.0.0.1, even when
 * MCP_HTTP_HOST is a wider address such as the image default 0.0.0.0.
 * A configured secret honors MCP_HTTP_HOST. Unset host defaults to 127.0.0.1.
 */
function resolveListenHost(s2sSecret: string): string {
  const configured = (process.env.MCP_HTTP_HOST ?? "").trim();
  if (!s2sSecret) {
    if (configured && !isLoopbackBindHost(configured)) {
      logger.error(
        `WARNING: MCP_HTTP_HOST=${configured} is not a loopback address. ` +
          "MCP_ALLOW_INSECURE_DEV=1 without CONDUIT_S2S_SECRET cannot listen there. " +
          `Binding ${LOOPBACK_HOST} only.`
      );
    }
    return LOOPBACK_HOST;
  }
  return configured || LOOPBACK_HOST;
}

function headerValue(value: string | string[] | undefined): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

async function startStdioTransport(): Promise<void> {
  const server = createMcpServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
  logger.info("Crewhu MCP running on stdio");
}

export async function startHttpTransport(): Promise<HttpServer> {
  const port = parseInt(process.env.MCP_HTTP_PORT || "8080", 10);
  const isGatewayMode = process.env.AUTH_MODE === "gateway";
  const s2sSecret = resolveHttpS2sSecret();
  const host = resolveListenHost(s2sSecret);

  const httpServer = createHttpServer((req: IncomingMessage, res: ServerResponse) => {
    const url = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);

    if (url.pathname === "/health") {
      // Liveness: HTTP server is bound. Always 200. In gateway mode the
      // upstream token arrives per-request via header, so process-env creds
      // being absent is normal — gating liveness on them caused a crash-loop
      // on ACA (probe → 503 → kill → restart → repeat). Diagnostic preserved
      // in the body as a non-load-bearing field. This route is unauthenticated
      // and must not require X-Gateway-S2S.
      const hasEnvCreds = !!process.env.CREWHU_API_TOKEN;
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          status: "ok",
          transport: "http",
          authMode: isGatewayMode ? "gateway" : "env",
          envCredentialsConfigured: hasEnvCreds,
          version: VERSION,
          timestamp: new Date().toISOString(),
        })
      );
      return;
    }

    if (url.pathname === "/mcp") {
      // Empty s2sSecret is only reachable when MCP_ALLOW_INSECURE_DEV=1.
      // A configured secret is always enforced, before credential extraction.
      if (s2sSecret && !verifyS2sHeader(headerValue(req.headers[S2S_HEADER]), s2sSecret)) {
        res.writeHead(401, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            error: "Missing or invalid X-Gateway-S2S header: this endpoint only accepts requests signed by the gateway.",
          })
        );
        return;
      }

      let gatewayCreds: { apiToken: string } | null = null;

      if (isGatewayMode) {
        // Gateway mode: the token must arrive on this request. Falling through
        // would resolve CREWHU_API_TOKEN from the process environment, which
        // is not request-scoped (CWE-306).
        const apiToken = headerValue(req.headers["x-crewhu-api-token"])?.trim();
        if (!apiToken) {
          res.writeHead(401, { "Content-Type": "application/json" });
          res.end(
            JSON.stringify({
              error: "Missing credentials",
              required: ["X-Crewhu-Api-Token"],
            })
          );
          return;
        }
        gatewayCreds = { apiToken };
      }

      const handleMcp = (): void => {
        const server = createMcpServer();
        const transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: undefined,
          enableJsonResponse: true,
        });

        res.on("close", () => {
          transport.close();
          server.close();
        });

        server
          .connect(transport)
          .then(() => transport.handleRequest(req, res))
          .catch((err) => {
            logger.error("MCP request error", { error: err });
            if (!res.headersSent) {
              res.writeHead(500, { "Content-Type": "application/json" });
              res.end(
                JSON.stringify({
                  jsonrpc: "2.0",
                  error: { code: -32603, message: "Internal error" },
                  id: null,
                })
              );
            }
          });
      };

      if (gatewayCreds) {
        credentialStore.run(gatewayCreds, handleMcp);
      } else {
        handleMcp();
      }
      return;
    }

    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Not found", endpoints: ["/mcp", "/health"] }));
  });

  await new Promise<void>((resolve, reject) => {
    const onError = (err: Error): void => reject(err);
    httpServer.once("error", onError);
    httpServer.listen(port, host, () => {
      httpServer.removeListener("error", onError);
      logger.info(`Crewhu MCP listening on http://${host}:${port}/mcp`);
      logger.info(`Auth mode: ${isGatewayMode ? "gateway" : "env"}`);
      resolve();
    });
  });

  return httpServer;
}

async function main(): Promise<void> {
  const transport = process.env.MCP_TRANSPORT || "stdio";
  logger.info("Starting Crewhu MCP", { transport });
  if (transport === "http") {
    const httpServer = await startHttpTransport();
    const shutdown = async (): Promise<void> => {
      logger.info("Shutting down...");
      await new Promise<void>((resolve, reject) => {
        httpServer.close((err) => (err ? reject(err) : resolve()));
      });
      process.exit(0);
    };
    process.on("SIGINT", shutdown);
    process.on("SIGTERM", shutdown);
  } else {
    await startStdioTransport();
  }
}

// Vitest imports this module to call startHttpTransport. Skip the CLI
// entrypoint there. `node dist/index.js` still starts stdio or HTTP.
if (process.env.VITEST !== "true") {
  main().catch((error) => {
    logger.error("Fatal startup error", { error });
    process.exit(1);
  });
}
