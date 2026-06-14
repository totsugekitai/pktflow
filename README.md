# pktflow - Packet stream generator/capture tool

`pktflow` is a packet generator/capture tool that utilizes DPDK.

## Build

```shell
cargo build [--release]
```

## Example

You can change the log level by setting the environment variable `RUST_LOG=(error|warn|info|debug|trace)` .

### Oneshot mode

```shell
bash run.sh -c sample_oneshot.toml [--release]
```

### Daemon mode

You can access and control `pktflow` via the REST API or the `pktflow-web` UI.
See details: [daemon_api.md(Japanese)](/doc/daemon_api.md)

```shell
bash run.sh -d -c sample_daemon.toml [--release]
```

## Notice

This project is developed with Claude Code.
