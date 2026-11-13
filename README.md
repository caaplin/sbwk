# SBWK (Sleepy Bot with Keys)

> *"I tell you where the problem is in the server, and suggest you fixes. I am the all-seeing eye."*

SBWK is a **zero-dependency, self-hosted observability + AI-assisted incident diagnosis** stack written in pure Node.js (`>=20`, native `node:http` / `node:net` / `node:tls` / `node:crypto` — zero npm packages).

An edge reverse-proxy sits in front of your application, detects anomalies (`5xx`, optional `4xx`, slow responses, upstream timeouts/connection failures), and dispatches redacted incidents to **Agent Core**. Agent Core queries read-only dependency diagnostics (**Agent Connector**), inspects your mounted source tree and recent GitHub commits, produces an auditable root-cause diagnosis (`evidenceGraph` + suggested fixes), and escalates to a human engineer when confidence falls below threshold (`80%` by default).

---

## Services

| Service | Default Port | Role |
| --- | --- | --- |
| `services/middleware` | `8080` | Reverse proxy + anomaly detector + PII-redacting resilient dispatcher |
| `services/agent-core` | `4200` | Investigation orchestrator, codebase inspector, heuristic + Groq LLM reasoner, context store |
| `services/agent-connector` | `4100` | Read-only HTTP & TCP/TLS diagnostics for `database`, `auth`, and `external_api` |
| `services/control-plane` | `4300` | Developer onboarding UI + configuration API (CSRF-protected, SSRF-guarded, AES-256-GCM at-rest secrets) |
| `services/dummy-server` | `8000` | Zero-dependency target backend with `/_control` failure injection (`/users`, `/external`, `/status/:code`, `/delay/:s`) |

---

## Quick Start

### Local (no Docker)

```bash
npm test          # run all unit + HTTP integration suites across services
npm run check     # syntax-check all entrypoints
npm run demo      # run end-to-end 5-service live smoke test
npm run stack     # launch all 5 services locally (:8000, :8080, :4100, :4200, :4300)
```

### Docker Compose

1. Copy `.env.example` to `.env` and generate strong `>=32`-character secrets (`openssl rand -hex 32`):
   - `AGENT_CORE_TOKEN`
   - `MIDDLEWARE_ADMIN_TOKEN`
   - `CONNECTOR_API_TOKEN`
   - Optional: `CONTROL_PLANE_TOKEN` & `CONTROL_PLANE_SECRET` (recommended if exposing `:4300` beyond `localhost`)
2. Set `TARGET_CODEBASE_PATH` in `.env` to your target application's source path (defaults to `./services/dummy-server` so SBWK inspects the target app rather than its own middleware code).
3. Launch the stack:

```bash
docker compose up --build
```

Open `http://localhost:4300` for the onboarding UI, and send traffic through the edge at `http://localhost:8080`.

### Optional `go-httpbin` Override (`docker-compose.httpbin-lite.yml`)

```bash
docker compose -f docker-compose.yml -f docker-compose.httpbin-lite.yml up --build
```

> **Important limitation:** `mccutchen/go-httpbin` replaces `services/dummy-server` with a minimal generic HTTP test server. Because `go-httpbin` does **not** implement `/_control`, `/users`, or `/external`, **the database and third-party failure-injection demo paths are unavailable** when using this override — use `/status/500`, `/status/404`, and `/delay/3` to trigger status/latency anomalies instead.

---

## Security & Operational Notes

- **Strictly Read-Only (`v0.1`):** SBWK never executes code, restarts containers, or mutates infrastructure. `dryRun` is enforced by architecture; `autoRollback` is recorded in `analysis.policy` metadata for downstream remediation runners. `monitoringActive` controls whether incoming incidents trigger live investigations or are passively logged as `received`.
- **Secret & PII Redaction:** Captured upstream response samples, queries, and log snippets automatically mask Bearer/Basic tokens, JWTs, API keys, URI passwords, JSON secret fields, and email addresses before disk persistence or LLM calls.
- **Technical Review & Hardening Details:** See [`docs/v0.1.0-technical-review-confirmation.md`](./docs/v0.1.0-technical-review-confirmation.md).
