# AGENTS.md

# Project Overview

`pktflow` is an IXIA-like Traffic Generator/Capture tool built with DPDK.
It has an interface compliant with the Open Traffic Generator (OTG) API.

# Project Structure

```
pktflow/
|- README.md                    : Project description
|- build.rs                     : Build script
|- Cargo.toml                   : Cargo configuration file
|
|- doc/                         : Human-written development documentation
|
+- src/                         : Full set of program code
    |- main.rs                  : Entry point
    |- log.rs                   : Logging
    |- config.rs                : Config file loading logic
    |
    |- backend/                 : Send/Receive implementation
    |   |
    |   +- dpdk/                : DPDK backend
    |       |
    |       + adapter/          : C language DPDK wrapper
    |          +- dpdk_api.h    : Public headers exposed to Rust
    |
    |- proto/                   : Communication protocol implementation
    |
    +- worker/                  : Worker thread implementation
```

# How to Run

Refer to README.md, as it is documented there.

# Things You Should Do

- After making changes, commit with `git -c commit.gpgSign=false commit` (commit without GPG signing)

# Things You Must Never Do

- Do not make any changes to files under `doc/` (read-only; reading is allowed, but no edits)
