# alert2attack Console

Analyst UI over the alert2attack investigation agent. Design: [`../docs/DESIGN-console.md`](../docs/DESIGN-console.md).

It has an alert queue, a case view with the telemetry window, a live trace of a
running investigation, an evidence drawer for citations, an analyst review form,
optional sign-in, and a search page over ATT&CK techniques. Everything except the
search page is covered under Run it and Authentication below; search is described
in the [main README](../README.md#search).

## Run it

Two processes. The API first:

```bash
uv run uvicorn alert2attack.api.app:app --host 127.0.0.1 --port 8000
```

Then the console:

```bash
npm --prefix web install
npm --prefix web run dev
```

<http://localhost:5173>. Port 5173 is not incidental — it is the origin the API
allows by default (`DEFAULT_CORS_ORIGINS` in `alert2attack.api.app`). Change one and
change the other, or set `ALERT2ATTACK_CORS_ORIGINS`.

Point the console at a different API with `VITE_API_BASE`.

## Types come from the API

`src/lib/schema.d.ts` is generated from the API's own OpenAPI document. The
Pydantic models are the contract; hand-written TypeScript interfaces would be a
second copy of it that drifts silently.

```bash
uv run python -m alert2attack.api.openapi openapi.json
npm --prefix web run gen:types
```

`openapi.json` is generated and gitignored; `schema.d.ts` is committed so the
project typechecks without a running server.

> `src/lib/api.ts` still declares its row types by hand. They mirror the Pydantic
> models and are a deliberate stopgap — they should be replaced by references
> into `schema.d.ts` rather than maintained alongside it.

## Checks

```bash
npm --prefix web run typecheck
npm --prefix web run build
```

## Running it without a model

Press **Investigate (replay)** on any case. The `replay` model is a canned
responder (`alert2attack.agent.replay`) that needs no Ollama and no API key, so the
whole loop — live trace, case file, evidence drawer — works on a bare checkout.

It is not an investigator and the UI says so next to the button. Everything
around it is real: the graph runs, tools execute against the store, the ledger
fills, the verifier checks citations and the deterministic levers fire. Only
the model is fake, and it is deterministic, so a recorded demo reproduces.

Pace it with `ALERT2ATTACK_REPLAY_DELAY_MS` (default 400). Set it to `0` for tests
and something like `600` when filming.

```bash
ALERT2ATTACK_REPLAY_DELAY_MS=600 uv run uvicorn alert2attack.api.app:app --port 8000
```

A replay run often ends **degraded**, and that is the verifier working rather
than a bug: the graph hydrates `scope.involved_pids` after the write and can
add a pid whose `process_create` was never fetched, so the claim is stripped.
A real model on the same scenario hits the same path.

For a real investigation, use `ollama` (needs the sidecar) or `teacher` (needs
an API key).

## Authentication

Off by default: with nothing configured the API is open, which is the existing
local-first posture, and it logs a warning at startup so that is a decision
rather than an accident. Bind to loopback if you leave it off.

To turn it on, make a hash (the password is read from a prompt, never argv):

```bash
uv run python -m alert2attack.api.auth
```

```bash
CONSOLE_PASSWORD_HASH='scrypt$...' CONSOLE_JWT_SECRET='a-long-random-string' uv run uvicorn alert2attack.api.app:app --port 8000
```

`CONSOLE_USER` defaults to `analyst`; `CONSOLE_TOKEN_TTL_MINUTES` to 30. Without
`CONSOLE_JWT_SECRET` a random per-process secret is used, so tokens do not
survive a restart.

**This is demo-grade.** One configured operator, one `scrypt` hash, HS256 JWTs
from PyJWT. No user table, no roles, no reset flow. A real deployment puts the
console behind the organisation's OIDC provider and deletes `alert2attack.api.auth`.

The token is held in module memory in the browser, not `localStorage`: this
console renders attacker-controlled command lines from telemetry, and
`localStorage` is readable by any injected script. A refresh loses the session.
