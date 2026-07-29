# Security

This document describes the secure-by-design principles behind `llm-guard`, its
known limitations, and how to report a vulnerability.

## Secure-by-design principles

`llm-guard` is a security tool, so it is built to be safe by construction — not
just to *add* security, but to *be* secure in how it is designed.

- **External guard (the judge is not the defendant).** The guard runs *outside*
  the LLM. An attacker's goal is to persuade the model; the guard is a separate,
  non-persuadable checkpoint that decides with fixed rules, not language.

- **Defense in depth.** No single check is trusted to hold. Input is normalized
  to undo disguises, then scanned; requests and replies are both inspected. Each
  layer catches what the previous one might miss.

- **Fail-safe defaults.** High-severity injection is blocked by default;
  response scanning is on by default. The safe behavior is the default behavior.

- **Least privilege.** When forwarding upstream, only the headers that are
  needed (`authorization`, `content-type`) are passed through. Nothing else
  about the client is forwarded.

- **Memory safety.** Written in Rust with no `unsafe` code, so entire classes of
  vulnerabilities (buffer overflows, use-after-free) cannot occur.

- **Linear-time matching (no ReDoS).** The Rust `regex` engine runs in
  guaranteed linear time with no backtracking, so the detection rules cannot be
  weaponized into a regular-expression denial-of-service — a real vulnerability
  class in many other regex engines.

- **Log hygiene / data minimization.** The audit log records *that* a secret or
  PII value was found and its length — never the value itself. The tool does not
  log the sensitive data it is designed to protect.

- **Local-first / privacy.** All inspection happens on the operator's own
  infrastructure. Pointed at a local model, no prompt data leaves the machine.

## Known limitations (honest non-goals)

- Detection is **rule-based**; a novel, reworded attack the rules have not seen
  can pass. A semantic detection layer is planned.
- **Streaming** replies are passed through without response-side scanning.
- The proxy has **no built-in authentication** yet — run it on a trusted network
  or behind an authenticating gateway.
- It is a **gateway-layer** control and does not address model-training,
  supply-chain, or retrieval-layer risks (OWASP LLM03/04/08/09).

See `THREAT_MODEL.md` for the full STRIDE analysis.

## Reporting a vulnerability

If you find a security issue in `llm-guard`, please report it responsibly:

- Do **not** open a public issue for a security vulnerability.
- Contact the maintainer privately (add your preferred contact here, e.g. an
  email address or a GitHub private security advisory).
- Include steps to reproduce and the potential impact.

You can expect an acknowledgement and, where valid, a fix and credit.
