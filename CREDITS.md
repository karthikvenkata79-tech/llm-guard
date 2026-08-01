# Credits and third-party licenses

llm-guard is released under the MIT License (see `LICENSE`).

It is built on the following open-source Rust libraries, each under its own
permissive license (MIT and/or Apache-2.0). Their copyrights belong to their
respective authors, and their license terms are preserved here as attribution.

| Library             | Purpose                        | License          |
|---------------------|--------------------------------|------------------|
| tokio               | Async runtime                  | MIT              |
| axum                | Web server / routing           | MIT              |
| reqwest             | HTTP client (calls the LLM)    | MIT OR Apache-2.0|
| serde, serde_json   | JSON parsing / serialization   | MIT OR Apache-2.0|
| regex               | Pattern matching for rules     | MIT OR Apache-2.0|
| tracing, tracing-subscriber | Logging                | MIT              |
| once_cell           | One-time initialization        | MIT OR Apache-2.0|
| anyhow              | Error handling                 | MIT OR Apache-2.0|

These libraries are permissively licensed, which means you may use, modify, and
distribute (including commercially) software built on them, provided you keep
their license notices intact when you distribute.

## Generating a complete, exact list

The table above covers the direct dependencies. For a full, auto-generated list
of every transitive dependency and its exact license, install and run:

```bash
cargo install cargo-license
cargo license
```

That reads `Cargo.lock` and prints every crate with its license — useful if you
ever ship this and want a precise attribution list.
