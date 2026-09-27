---
name: code-style-rust
description: Rules for implementing Rust source code
paths:
  - "src/**/*.rs"
---

# Rust Source Code Development Rules

- Apply `cargo fmt`
- Confirm that `cargo test` completes successfully
- Resolve all warnings and errors from `cargo build`
- Resolve all warnings and errors from `cargo clippy`
  - However, avoid using `#[allow(unused)]` as much as possible
