# Threat model — llm-guard

This document is a lightweight threat model for `llm-guard`, using the STRIDE
framework. It records what the tool protects, where it can be attacked, the
threats in each STRIDE category, and how each is mitigated.

## 1. System overview

`llm-guard` is a request/response-layer proxy that sits between an application
and an LLM API. It inspects every request and reply, blocks prompt-injection
attacks, redacts secrets and PII, validates output, rate-limits clients, and
logs activity. It runs on the operator's own infrastructure.

```
app  ──►  llm-guard  ──►  LLM API  ──►  llm-guard  ──►  app
```

## 2. Assets (what we protect)

| Asset | Why it matters |
|-------|----------------|
| User prompt content | May contain secrets, PII, or confidential data |
| The upstream API credential | A leaked key means financial loss / account abuse |
| The audit log | Records activity; must not itself become a leak |
| Service availability | If the guard is down or overwhelmed, traffic is unprotected or blocked |
| The system prompt of the protected app | Leaking it helps attackers craft bypasses |

## 3. Trust boundaries

- **App → guard (the listen socket):** input from the app/user is **untrusted**. Anything in a prompt may be adversarial.
- **Guard → LLM API (the network):** the upstream is **semi-trusted** — its replies are treated as untrusted and re-scanned.
- **Operator config (env vars, rules file):** **trusted** — set by the operator, not attacker-controllable.

## 4. Entry points / attack surface

- The HTTP listen endpoint (`/v1/chat/completions`).
- The upstream connection (responses flowing back).
- The rules file (`GUARD_RULES_FILE`) and environment configuration (operator-controlled).

## 5. STRIDE analysis

| STRIDE | Threat | Mitigation | Status |
|--------|--------|------------|--------|
| **S**poofing | A client impersonates another to evade rate limits | Client identified by API key / `X-Client-Id`, hashed | Partial — no auth on the proxy itself yet |
| **T**ampering | Attacker disguises an injection (spacing, leetspeak, base64) to slip past rules | Input normalization builds cleaned views before scanning | Done |
| **R**epudiation | No record of what was blocked/redacted | Structured audit log per request | Done |
| **I**nformation disclosure | Secrets/PII leak to the model, in replies, **or into the audit log** | Redaction in both directions; **log stores only lengths, never raw secret values** | Done (log-leak fixed in code review) |
| **D**enial of service | Flood of requests runs up cost or exhausts memory | Per-client rate limiting; rate map is size-bounded to prevent memory exhaustion | Done |
| **E**levation of privilege | Injection makes the model ignore its rules / leak its system prompt | High-severity injection blocked; system-prompt canary detection on replies | Done for covered classes |

## 6. Findings from code review (mapped to STRIDE)

The security code review surfaced two issues, both of which this model
classifies:

- **Secrets written to the audit log** → *Information disclosure*. Fixed: log-safe snippets store only a length.
- **Unbounded rate-limiter memory** → *Denial of service*. Fixed: the tracking map is bounded and evicts expired entries.

## 7. Out of scope (explicitly not defended here)

`llm-guard` is a gateway-layer control. It does **not** address model-training,
supply-chain, or retrieval-layer risks — OWASP LLM03 (supply chain), LLM04
(data/model poisoning), LLM08 (vector/embedding weaknesses), and LLM09
(misinformation). Those require different controls (model provenance scanning,
training-data governance, RAG-pipeline security) and are out of scope by design.

## 8. Residual risk

- Detection is rule-based, so a **novel, reworded** injection the rules have not
  seen can pass. A semantic (ML/LLM-judge) detection layer is the planned
  mitigation.
- In **streaming** mode the reply is not scanned (scanning would require
  buffering the whole reply). Request-side protection still fully applies.
- The proxy has **no built-in authentication**; it should be run on a trusted
  network or behind an authenticating gateway until that is added.
