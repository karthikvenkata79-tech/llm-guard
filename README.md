# llm-guard (single-file edition)

All the code lives in one file: `src/main.rs`. The only other file is
`Cargo.toml` (the list of libraries — required for any Rust project that uses
outside crates).

Same behavior as before: blocks prompt injection, redacts secrets/PII from
requests and from the model's replies, and logs everything.

## Run it (works on Mac, Windows, Linux — identical)

```bash
cargo run
```

Listens on `http://127.0.0.1:8080`. Configure with environment variables:
`GUARD_LISTEN`, `GUARD_UPSTREAM`, `GUARD_BLOCK`, `GUARD_SCAN_RESPONSE`.

## Make a standalone "click-and-run" binary

```bash
cargo build --release
```

This produces a single executable at:

- macOS / Linux: `target/release/llm-guard`
- Windows: `target\release\llm-guard.exe`

You can run that file directly — no `cargo`, no source needed:

```bash
./target/release/llm-guard
```

Important: a compiled binary only runs on the OS it was built on. A Mac build
won't run on Windows and vice-versa. To ship to all three platforms you build
once on each (or use cross-compilation). Note this is a background server — it
listens for requests; it doesn't open a window when launched.

## Run anywhere with Docker (one image, every platform)

If you have Docker, this is the closest thing to "runs identically everywhere."
Create a file named `Dockerfile` next to `Cargo.toml`:

```dockerfile
FROM rust:1-slim AS build
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:stable-slim
COPY --from=build /app/target/release/llm-guard /usr/local/bin/llm-guard
EXPOSE 8080
ENV GUARD_LISTEN=0.0.0.0:8080
CMD ["llm-guard"]
```

Then:

```bash
docker build -t llm-guard .
docker run -p 8080:8080 -e GUARD_UPSTREAM=https://api.openai.com/v1/chat/completions llm-guard
```

## Evasion resistance (normalization)

Before running the injection rules, the tool also checks "cleaned up" views of
the prompt, so common ways of dodging plain pattern-matching still get caught:

- spaced-out letters — `i g n o r e`
- leetspeak — `1gn0re`
- look-alike (homoglyph) characters
- base64-encoded hidden instructions

This is a first layer, not a complete defense — a determined attacker can still
find gaps. The stronger next step is a semantic check (an LLM or ML model that
judges meaning rather than matching text).

## Rules in a config file (no recompiling)

You can now change what the tool detects without touching the code. Point the
`GUARD_RULES_FILE` variable at a JSON file:

```bash
GUARD_RULES_FILE=rules.json cargo run
```

A starter `rules.json` is included — it contains the same rules that are built
in. Edit it (add, remove, or change rules), save, and restart — no recompiling.
Each rule has four fields:

```json
{ "category": "pii", "name": "phone_number", "severity": "medium", "pattern": "\\d{3}-\\d{3}-\\d{4}" }
```

- `category` — `prompt_injection`, `secret`, or `pii`
- `name` — any label you choose
- `severity` — `low`, `medium`, or `high`
- `pattern` — the regular expression to match (remember: backslashes must be
  doubled in JSON, so `\d` becomes `\\d`)

Rules of category `prompt_injection` at `high` severity are blocked; `secret`
and `pii` are redacted. If the file is missing or has a bad pattern, the tool
logs a warning and falls back to the built-in defaults, so it never crashes.

## Streaming (word-by-word replies)

If the request includes `"stream": true`, the guard passes the reply straight
through, chunk by chunk, as the model produces it. Request-side protection
(blocking attacks, redacting secrets in the prompt) still fully applies.

Trade-off: response-side redaction is skipped for streaming replies, because
scanning the reply would require buffering the whole thing — which defeats the
point of streaming. Non-streaming requests are unaffected and still get full
response scanning.

## Add your own detection rules

Open `src/main.rs`, find the `RULES` list, and add another `Rule { ... }` block.
It's picked up automatically. Or, better, add it to `rules.json` (see above) so
you don't have to recompile.

## License

This project is released under the MIT License — see `LICENSE`. Open it and
replace `<YOUR NAME HERE>` with your name.

It uses several open-source libraries under permissive licenses; they're listed
with attribution in `CREDITS.md`.
