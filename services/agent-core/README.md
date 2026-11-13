# Sleepy Bot — Agent Core (the Brain)

Agent Core receives anomaly **incidents** from the Middleware, investigates them,
reasons about the root cause, suggests fixes, retains context across incidents,
and wakes a human engineer when it cannot confidently resolve the problem.

Zero-dependency Node.js (built-in `http`/`fetch` only) — no `npm install`, no build
step. It is the only component that calls the **Agent Connector** (read-only
dependency diagnostics) and the **LLM**. It is strictly read-only: it never
restarts services, deploys code, or executes remediation — it only suggests.

## Investigation pipeline

For each incident, Agent Core:

1. **Gathers dependency evidence** from the Agent Connector
   (`POST /connector/investigate`) for database, auth and external API.
2. **Inspects the codebase** (read-only) for source relevant to the failing route
   and error, returning small snippets.
3. **Reasons** about root cause:
   - `AGENT_MODE=live` → Groq LLM (OpenAI-compatible chat API), or
   - `AGENT_MODE=mock` → a deterministic, dependency-first heuristic reasoner.
   - Live mode transparently falls back to the heuristic if the LLM is unavailable.
4. **Suggests fixes** (config / code / dependency / investigation).
5. **Retains context** and recognises recurring failures on the same path.
6. **Escalates** via Notification (structured log + optional webhook) when
   confidence is low, a dependency/server is unreachable, severity is critical,
   or the failure is recurring. Engineers can also mark an incident `unresolved`
   to trigger escalation.

## Requirements

- Node.js 20+ (no other dependencies)

## Setup

```bash
cp .env.example .env     # optional
node server.mjs
```

Listens on `http://localhost:4200`. Mock mode needs no API key. For live reasoning
set `AGENT_MODE=live` and `GROQ_API_KEY`. Auto-reload in dev: `node --watch server.mjs`.

## Verification

```bash
node --test
```

## API

All `/incidents/*` routes require `Authorization: Bearer <AGENT_CORE_TOKEN>`.

```http
GET /health                      # liveness (no auth)

POST /incidents                  # receive an incident from the Middleware (202)
POST /incidents?wait=true        # same, but block until the analysis is ready (200)
GET  /incidents?limit=50         # recent incidents + context summary
GET  /incidents/:id              # one incident with its analysis
GET  /incidents/context          # retained-context summary
POST /incidents/:id/feedback     # {"status":"resolved|unresolved","note":"..."}
```

By default `POST /incidents` returns `202` immediately and investigates in the
background; poll `GET /incidents/:id`. Use `?wait=true` for a synchronous `200`
with the full analysis (handy for demos and tests).

### Analysis shape

```json
{
  "incidentId": "uuid",
  "mode": "mock",
  "severity": "high",
  "summary": "Request failed because the database dependency is unhealthy.",
  "rootCause": { "summary": "...", "confidence": 0.82 },
  "confidence": 0.82,
  "suggestedFixes": [ { "title": "...", "description": "...", "kind": "dependency", "file": "..." } ],
  "dependencyFindings": [ { "service": "database", "status": "unhealthy", "signals": ["..."] } ],
  "codeFindings": [ { "file": "server.mjs", "line": 18, "snippet": "...", "reason": "..." } ],
  "escalate": false,
  "escalationReason": null,
  "reasoning": "...",
  "recurring": 0,
  "createdAt": "2026-11-12T12:00:00.000Z"
}
```

## Configuration

See `.env.example`. Key settings:

| Variable | Default | Meaning |
| --- | --- | --- |
| `AGENT_CORE_TOKEN` | dev token | Shared secret with the Middleware (>= 32 chars) |
| `AGENT_MODE` | `mock` | `mock` heuristic or `live` Groq reasoning |
| `GROQ_API_KEY` | — | Required for live mode |
| `GROQ_MODEL` | `llama-3.3-70b-versatile` | Groq model |
| `CONNECTOR_URL` | `http://localhost:4100` | Agent Connector base URL |
| `CONNECTOR_API_TOKEN` | dev token | Shared secret with the connector |
| `CODEBASE_PATH` | — | Read-only source tree to inspect |
| `ESCALATION_CONFIDENCE_THRESHOLD` | `0.8` | Below this confidence, escalate |
| `NOTIFICATION_WEBHOOK_URL` | — | Optional webhook (e.g. Slack); always logged |
| `DATA_DIR` | — | Persist context here (empty = in-memory) |

## Docker

```bash
docker compose up --build
```

The image is `node:22-alpine` plus the `.mjs` source — no install layer. In the
Compose network use `CONNECTOR_URL=http://agent-connector:4100`. Mount your
application source read-only at `CODEBASE_PATH` so the agent can inspect it.

## Project layout

```text
config.mjs       # env config (+ optional .env loader)
store.mjs        # context retention (in-memory + optional disk)
codebase.mjs     # read-only codebase inspector
reason.mjs       # findings, heuristic reasoner, Groq reasoner, selector
notify.mjs       # Notification -> Developer Team (webhook + log)
investigate.mjs  # investigation orchestrator + escalation policy (injectable deps)
server.mjs       # node:http server + incident routes + bearer auth
test/            # node --test
```
