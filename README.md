# Crewhu MCP Server

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Node.js](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen.svg)](https://nodejs.org/)

A Model Context Protocol (MCP) server for Crewhu — customer feedback, employee engagement, and gamification platform. Enables AI assistants to manage surveys, badges, prizes, and user engagement data.

This is a [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server that connects Claude (or any MCP-compatible AI) to your Crewhu environment.

> **Part of the [MSP Claude Plugins](https://github.com/WYRE-AI) ecosystem** — a growing suite of AI integrations for the MSP stack. Built by MSPs, for MSPs.

## Installation

```bash
npm install @wyre-ai/crewhu-mcp
```

## Configuration

Copy [`.env.example`](.env.example) and set the variables below. Leave `CONDUIT_S2S_SECRET` empty in that file.

| Variable | Required | Description |
|----------|----------|-------------|
| `CREWHU_API_TOKEN` | For stdio and `AUTH_MODE=env` | Crewhu API token. Not read in gateway mode. |
| `MCP_TRANSPORT` | No | `stdio` (default) or `http` |
| `AUTH_MODE` | No | `gateway` (Docker image and Compose default) or `env`. Gateway mode requires `X-Crewhu-Api-Token` on each `/mcp` request and never falls back to `CREWHU_API_TOKEN`. `env` uses that variable only after S2S auth succeeds. |
| `CONDUIT_S2S_SECRET` | Yes for HTTP | Service-to-service HMAC secret. The HTTP server logs an error and exits non-zero when this is empty or a known placeholder (`changeme`, `replace-with-a-real-secret`, and similar). Compose will not start without it. Generate with `openssl rand -hex 32`. Never commit a real value. The value is never logged. |
| `MCP_ALLOW_INSECURE_DEV` | No | Set to exactly `1` only for local development to start HTTP without `CONDUIT_S2S_SECRET`. The process logs a warning and does not enforce `X-Gateway-S2S`. The listener is forced to `127.0.0.1` even if `MCP_HTTP_HOST` is a wider address. A placeholder secret is still refused. |
| `MCP_HTTP_HOST` | No | Bind address when `MCP_TRANSPORT=http`. Defaults to `127.0.0.1`. Honored when `CONDUIT_S2S_SECRET` is set. The container image sets `0.0.0.0`. |
| `MCP_HTTP_PORT` | No | HTTP port. Defaults to `8080`. |

`/health` stays unauthenticated and does not require `X-Gateway-S2S`. The stdio transport does not use `CONDUIT_S2S_SECRET`.

### HTTP authentication

With `MCP_TRANSPORT=http` and a real `CONDUIT_S2S_SECRET`, every `/mcp` request must include `X-Gateway-S2S`. A missing or invalid header returns 401 before any vendor credential is read.

The header is an HMAC proof:

```text
X-Gateway-S2S: t=<unix seconds>,v1=<hex hmac-sha256>
```

`v1` is the hex-encoded HMAC-SHA256 of the ASCII string `t=<unix seconds>` (the same `t=` prefix and value), keyed with `CONDUIT_S2S_SECRET`. The timestamp must be within 300 seconds of the server clock.

```bash
t=$(date +%s)
sig=$(printf 't=%s' "$t" | openssl dgst -sha256 -hmac "$CONDUIT_S2S_SECRET" -hex | awk '{print $NF}')
curl -sS "http://127.0.0.1:8080/mcp" \
  -H "X-Gateway-S2S: t=${t},v1=${sig}" \
  -H "X-Crewhu-Api-Token: $CREWHU_API_TOKEN" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

In `AUTH_MODE=gateway`, `/mcp` also requires `X-Crewhu-Api-Token`. A missing or blank header returns 401 and does not fall back to `CREWHU_API_TOKEN`.

## Usage

### Running with Claude Desktop

Add to your Claude Desktop `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "crewhu-mcp": {
      "command": "npx",
      "args": ["@wyre-ai/crewhu-mcp"],
      "env": {
        "CREWHU_API_TOKEN": "your-crewhu-api-token"
      }
    }
  }
}
```

### Running with Claude Code (CLI)

```bash
claude mcp add crewhu-mcp \
  -e CREWHU_API_TOKEN=your-value \
  -- npx -y @wyre-ai/crewhu-mcp
```

### Docker

The image listens on `0.0.0.0` inside the container (`MCP_HTTP_HOST`) and defaults to `AUTH_MODE=gateway`. Publish the port on loopback and pass a real S2S secret. In gateway mode, the Crewhu token arrives on each request as `X-Crewhu-Api-Token`; it is not read from the environment. Startup exits if `CONDUIT_S2S_SECRET` is empty or a known placeholder.

```bash
docker build -t crewhu-mcp .
docker run \
  -e CONDUIT_S2S_SECRET="$CONDUIT_S2S_SECRET" \
  -p 127.0.0.1:8080:8080 \
  crewhu-mcp
```

Compose refuses to start when `CONDUIT_S2S_SECRET` is unset, defaults `AUTH_MODE` to `gateway`, publishes `127.0.0.1:8080:8080`, and does not set `CREWHU_API_TOKEN`:

```bash
CONDUIT_S2S_SECRET="$CONDUIT_S2S_SECRET" docker compose up
```

Single-tenant HTTP (`AUTH_MODE=env`) still requires the S2S secret, then uses `CREWHU_API_TOKEN`:

```bash
docker run \
  -e CONDUIT_S2S_SECRET="$CONDUIT_S2S_SECRET" \
  -e AUTH_MODE=env \
  -e CREWHU_API_TOKEN=your-value \
  -p 127.0.0.1:8080:8080 \
  crewhu-mcp
```

Local HTTP without a secret is development-only. It binds `127.0.0.1` only and logs a warning. A non-loopback `MCP_HTTP_HOST` is ignored:

```bash
MCP_TRANSPORT=http MCP_ALLOW_INSECURE_DEV=1 npm start
```

## Available Domains

### Badges
Manage and award employee badges

### Prizes
Manage prize catalog and redemptions

### Surveys
Create and manage customer satisfaction surveys

### Users
User management and engagement data


## Development

```bash
# Clone the repository
git clone https://github.com/WYRE-AI/crewhu-mcp.git
cd crewhu-mcp

# Install dependencies
npm install

# Build
npm run build

# Run tests
npm test
```

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) if present, or open an issue to discuss changes.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
