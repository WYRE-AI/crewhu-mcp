/**
 * HTTP transport fail-closed auth (CWE-306).
 *
 * Startup requires a real CONDUIT_S2S_SECRET unless MCP_ALLOW_INSECURE_DEV=1.
 * Known placeholders are refused even with that flag. The flag binds 127.0.0.1
 * only. /mcp rejects a missing or invalid X-Gateway-S2S header. AUTH_MODE=gateway
 * rejects requests that omit X-Crewhu-Api-Token and must not fall back to
 * CREWHU_API_TOKEN.
 */

import { createHmac } from "node:crypto";
import { request as httpRequest, type Server as HttpServer } from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { credentialStore } from "./utils/credential-store.js";
import { startHttpTransport } from "./index.js";

const S2S_SECRET = "s2s-do-not-log-7f3a";
const ENV_API_TOKEN = "env-token-must-not-be-used";
const PLACEHOLDER = "replace-with-a-real-secret";

const ENV_KEYS = [
  "CONDUIT_S2S_SECRET",
  "MCP_ALLOW_INSECURE_DEV",
  "MCP_HTTP_PORT",
  "MCP_HTTP_HOST",
  "AUTH_MODE",
  "CREWHU_API_TOKEN",
  "LOG_LEVEL",
  "MCP_TRANSPORT",
] as const;

const savedEnv = new Map<string, string | undefined>();
const servers: HttpServer[] = [];

function mintS2sHeader(secret: string, unixSeconds = Math.floor(Date.now() / 1000)): string {
  const message = `t=${unixSeconds}`;
  const hex = createHmac("sha256", secret).update(message).digest("hex");
  return `${message},v1=${hex}`;
}

function captureStderr(): { text: () => string; restore: () => void } {
  const lines: string[] = [];
  const spy = vi.spyOn(process.stderr, "write").mockImplementation((chunk: string | Uint8Array) => {
    lines.push(typeof chunk === "string" ? chunk : Buffer.from(chunk).toString("utf8"));
    return true;
  });
  return {
    text: () => lines.join(""),
    restore: () => spy.mockRestore(),
  };
}

function exitSpy() {
  return vi.spyOn(process, "exit").mockImplementation(((code?: number) => {
    throw new Error(`process.exit:${String(code)}`);
  }) as typeof process.exit);
}

interface HttpResult {
  status: number;
  body: string;
}

function sendHttp(options: {
  port: number;
  method: string;
  path: string;
  headers?: Record<string, string>;
  body?: string;
}): Promise<HttpResult> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      {
        hostname: "127.0.0.1",
        port: options.port,
        method: options.method,
        path: options.path,
        headers: options.headers,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (chunk: Buffer) => chunks.push(chunk));
        res.on("end", () => {
          resolve({
            status: res.statusCode ?? 0,
            body: Buffer.concat(chunks).toString("utf8"),
          });
        });
      }
    );
    req.setTimeout(5000, () => {
      req.destroy(new Error(`timeout ${options.method} ${options.path}`));
    });
    req.on("error", reject);
    if (options.body !== undefined) req.write(options.body);
    req.end();
  });
}

async function listen(): Promise<{ port: number; address: string }> {
  const server = await startHttpTransport();
  servers.push(server);
  const bound = server.address() as AddressInfo | null;
  if (!bound || typeof bound === "string") {
    throw new Error("HTTP server did not bind a TCP port");
  }
  return { port: bound.port, address: bound.address };
}

function mcpHeaders(extra?: Record<string, string>): Record<string, string> {
  return {
    "content-type": "application/json",
    accept: "application/json, text/event-stream",
    ...extra,
  };
}

const toolsList = JSON.stringify({
  jsonrpc: "2.0",
  id: 1,
  method: "tools/list",
  params: {},
});

function assertNoSecrets(text: string): void {
  expect(text).not.toContain(S2S_SECRET);
  expect(text).not.toContain(ENV_API_TOKEN);
  expect(text).not.toContain(PLACEHOLDER);
  expect(text).not.toContain("Your-S2S-Secret");
}

beforeAll(() => {
  for (const key of ENV_KEYS) savedEnv.set(key, process.env[key]);
});

afterAll(() => {
  for (const key of ENV_KEYS) {
    const value = savedEnv.get(key);
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
});

beforeEach(() => {
  process.env.MCP_HTTP_PORT = "0";
  delete process.env.MCP_HTTP_HOST;
  process.env.LOG_LEVEL = "error";
  delete process.env.CONDUIT_S2S_SECRET;
  delete process.env.MCP_ALLOW_INSECURE_DEV;
  delete process.env.AUTH_MODE;
  delete process.env.CREWHU_API_TOKEN;
  delete process.env.MCP_TRANSPORT;
});

afterEach(async () => {
  vi.restoreAllMocks();
  while (servers.length > 0) {
    const server = servers.pop();
    if (!server?.listening) continue;
    await new Promise<void>((resolve, reject) => {
      server.close((err) => (err ? reject(err) : resolve()));
    });
  }
});

describe("HTTP startup", () => {
  it("refuses to start when CONDUIT_S2S_SECRET is empty", async () => {
    process.env.CREWHU_API_TOKEN = ENV_API_TOKEN;
    const logs = captureStderr();
    const exit = exitSpy();

    try {
      await expect(startHttpTransport()).rejects.toThrow("process.exit:1");
      expect(exit).toHaveBeenCalledWith(1);
      const text = logs.text();
      expect(text).toContain("Refusing to start HTTP transport");
      expect(text).toContain("CONDUIT_S2S_SECRET is empty");
      expect(text).toContain("CWE-306");
      assertNoSecrets(text);
    } finally {
      exit.mockRestore();
      logs.restore();
    }
  });

  it("still refuses when MCP_ALLOW_INSECURE_DEV is not exactly 1", async () => {
    process.env.CONDUIT_S2S_SECRET = "";
    process.env.MCP_ALLOW_INSECURE_DEV = "true";
    const logs = captureStderr();
    const exit = exitSpy();

    try {
      await expect(startHttpTransport()).rejects.toThrow("process.exit:1");
      expect(exit).toHaveBeenCalledWith(1);
      expect(logs.text()).toContain("Refusing to start HTTP transport");
    } finally {
      exit.mockRestore();
      logs.restore();
    }
  });

  it("refuses a known placeholder secret and does not log it", async () => {
    process.env.CONDUIT_S2S_SECRET = PLACEHOLDER;
    const logs = captureStderr();
    const exit = exitSpy();

    try {
      await expect(startHttpTransport()).rejects.toThrow("process.exit:1");
      expect(exit).toHaveBeenCalledWith(1);
      const text = logs.text();
      expect(text).toContain("known placeholder");
      expect(text).toContain("openssl rand -hex 32");
      assertNoSecrets(text);
    } finally {
      exit.mockRestore();
      logs.restore();
    }
  });

  it("refuses a placeholder even when MCP_ALLOW_INSECURE_DEV=1", async () => {
    process.env.CONDUIT_S2S_SECRET = "  Your-S2S-Secret  ";
    process.env.MCP_ALLOW_INSECURE_DEV = "1";
    const logs = captureStderr();
    const exit = exitSpy();

    try {
      await expect(startHttpTransport()).rejects.toThrow("process.exit:1");
      expect(exit).toHaveBeenCalledWith(1);
      const text = logs.text();
      expect(text).toContain("known placeholder");
      assertNoSecrets(text);
    } finally {
      exit.mockRestore();
      logs.restore();
    }
  });

  it("allows startup with a warning when MCP_ALLOW_INSECURE_DEV=1", async () => {
    process.env.MCP_ALLOW_INSECURE_DEV = "1";
    process.env.CREWHU_API_TOKEN = ENV_API_TOKEN;
    const logs = captureStderr();
    try {
      const server = await listen();
      expect(server.address).toBe("127.0.0.1");
      const text = logs.text();
      expect(text).toContain("SECURITY WARNING");
      expect(text).toContain("CONDUIT_S2S_SECRET");
      expect(text).toContain("MCP_ALLOW_INSECURE_DEV=1");
      expect(text).toContain("127.0.0.1");
      expect(text).not.toContain("not a loopback address");
      assertNoSecrets(text);
    } finally {
      logs.restore();
    }
  });

  it("forces 127.0.0.1 when the dev bypass host is not loopback", async () => {
    process.env.MCP_ALLOW_INSECURE_DEV = "1";
    process.env.MCP_HTTP_HOST = "0.0.0.0";
    const logs = captureStderr();
    const exit = exitSpy();
    try {
      const server = await listen();
      expect(exit).not.toHaveBeenCalled();
      expect(server.address).toBe("127.0.0.1");
      const text = logs.text();
      expect(text).toContain("MCP_HTTP_HOST=0.0.0.0 is not a loopback address");
      expect(text).toContain("Binding 127.0.0.1 only");
      assertNoSecrets(text);
    } finally {
      exit.mockRestore();
      logs.restore();
    }
  });

  it("binds 127.0.0.1 when the dev bypass host is localhost", async () => {
    process.env.MCP_ALLOW_INSECURE_DEV = "1";
    process.env.MCP_HTTP_HOST = "localhost";
    const logs = captureStderr();
    try {
      const server = await listen();
      expect(server.address).toBe("127.0.0.1");
      expect(logs.text()).not.toContain("not a loopback address");
    } finally {
      logs.restore();
    }
  });

  it("honors a non-loopback MCP_HTTP_HOST when CONDUIT_S2S_SECRET is set", async () => {
    process.env.CONDUIT_S2S_SECRET = S2S_SECRET;
    process.env.MCP_HTTP_HOST = "0.0.0.0";
    const logs = captureStderr();
    try {
      const server = await listen();
      expect(server.address).toBe("0.0.0.0");
      expect(logs.text()).not.toContain("not a loopback address");
      assertNoSecrets(logs.text());
    } finally {
      logs.restore();
    }
  });

  it("binds 127.0.0.1 when MCP_HTTP_HOST is unset and a secret is set", async () => {
    delete process.env.MCP_HTTP_HOST;
    process.env.CONDUIT_S2S_SECRET = S2S_SECRET;
    const server = await listen();
    expect(server.address).toBe("127.0.0.1");
  });
});

describe("HTTP /mcp authentication", () => {
  beforeEach(() => {
    process.env.CONDUIT_S2S_SECRET = S2S_SECRET;
    process.env.AUTH_MODE = "gateway";
    process.env.MCP_HTTP_HOST = "127.0.0.1";
    process.env.CREWHU_API_TOKEN = ENV_API_TOKEN;
  });

  it("returns 401 when the S2S header is missing or invalid and does not log the secret", async () => {
    const logs = captureStderr();
    const runSpy = vi.spyOn(credentialStore, "run");
    try {
      const server = await listen();
      const missing = await sendHttp({
        port: server.port,
        method: "POST",
        path: "/mcp",
        headers: mcpHeaders({ "x-crewhu-api-token": "header-token" }),
        body: toolsList,
      });
      const invalid = await sendHttp({
        port: server.port,
        method: "POST",
        path: "/mcp",
        headers: mcpHeaders({
          "x-gateway-s2s": mintS2sHeader("wrong-secret"),
          "x-crewhu-api-token": "header-token",
        }),
        body: toolsList,
      });

      expect(missing.status).toBe(401);
      expect(invalid.status).toBe(401);
      expect(missing.body).toContain("X-Gateway-S2S");
      expect(invalid.body).toContain("X-Gateway-S2S");
      assertNoSecrets(missing.body);
      assertNoSecrets(invalid.body);
      assertNoSecrets(logs.text());
      expect(runSpy).not.toHaveBeenCalled();
    } finally {
      logs.restore();
    }
  });

  it("returns 401 in gateway mode without credential headers and does not use env credentials", async () => {
    const runSpy = vi.spyOn(credentialStore, "run");
    const server = await listen();
    const missing = await sendHttp({
      port: server.port,
      method: "POST",
      path: "/mcp",
      headers: mcpHeaders({ "x-gateway-s2s": mintS2sHeader(S2S_SECRET) }),
      body: toolsList,
    });
    const blank = await sendHttp({
      port: server.port,
      method: "POST",
      path: "/mcp",
      headers: mcpHeaders({
        "x-gateway-s2s": mintS2sHeader(S2S_SECRET),
        "x-crewhu-api-token": "   ",
      }),
      body: toolsList,
    });

    expect(missing.status).toBe(401);
    expect(blank.status).toBe(401);
    expect(missing.body).toContain("Missing credentials");
    expect(missing.body).toContain("X-Crewhu-Api-Token");
    expect(blank.body).toContain("Missing credentials");
    assertNoSecrets(missing.body);
    assertNoSecrets(blank.body);
    expect(runSpy).not.toHaveBeenCalled();
  });

  it("accepts a valid S2S header plus the credential header and uses that token", async () => {
    const logs = captureStderr();
    const runSpy = vi.spyOn(credentialStore, "run");
    try {
      const server = await listen();
      const response = await sendHttp({
        port: server.port,
        method: "POST",
        path: "/mcp",
        headers: mcpHeaders({
          "x-gateway-s2s": mintS2sHeader(S2S_SECRET),
          "x-crewhu-api-token": "header-token",
        }),
        body: toolsList,
      });

      expect(response.status).toBe(200);
      const payload = JSON.parse(response.body) as { result?: { tools?: unknown[] } };
      expect(Array.isArray(payload.result?.tools)).toBe(true);
      expect((payload.result?.tools ?? []).length).toBeGreaterThan(0);
      assertNoSecrets(response.body);
      assertNoSecrets(logs.text());
      expect(runSpy).toHaveBeenCalledWith({ apiToken: "header-token" }, expect.any(Function));
    } finally {
      logs.restore();
    }
  });

  it("serves /health without authentication and without revealing credentials", async () => {
    const runSpy = vi.spyOn(credentialStore, "run");
    const server = await listen();
    const response = await sendHttp({
      port: server.port,
      method: "GET",
      path: "/health",
    });

    expect(response.status).toBe(200);
    const body = JSON.parse(response.body) as { status?: string; authMode?: string };
    expect(body.status).toBe("ok");
    expect(body.authMode).toBe("gateway");
    assertNoSecrets(response.body);
    expect(runSpy).not.toHaveBeenCalled();
  });

  it("still requires credential headers in gateway mode when S2S is bypassed", async () => {
    delete process.env.CONDUIT_S2S_SECRET;
    process.env.MCP_ALLOW_INSECURE_DEV = "1";
    const runSpy = vi.spyOn(credentialStore, "run");
    const server = await listen();
    expect(server.address).toBe("127.0.0.1");

    const response = await sendHttp({
      port: server.port,
      method: "POST",
      path: "/mcp",
      headers: mcpHeaders(),
      body: toolsList,
    });

    expect(response.status).toBe(401);
    expect(response.body).toContain("Missing credentials");
    assertNoSecrets(response.body);
    expect(runSpy).not.toHaveBeenCalled();
  });
});
