---
name: code-style-c
description: Rules for implementing C source code
paths:
  - "src/**/*.{c,h}"
---

# C Source Code Development Rules

- Use `-std=c23`
- Add include guards to `.h` files
- Apply clang-format
- Resolve all compile errors
- Run the `run-clang-tidy-20` command and resolve all reported errors and warnings
- In `dpdk_api.h`, observe the following:
  - Do not expose DPDK header files
  - Do not expose the internal implementation of structs; only declare them
    - However, structs related to statistics may expose their internal implementation
