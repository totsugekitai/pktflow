# TODO

Known gaps in the daemon-mode OTG (Open Traffic Generator) REST API,
left out of the initial implementation on purpose. See
`artifacts/openapi.yaml` (open-traffic-generator/models, v1.61.0) for
the full spec these refer to.

## Flow metrics: Rx side

`Flow.Metric.frames_rx` / `bytes_rx` / `loss` are always reported as 0.
Reporting them accurately requires classifying received frames against
configured flows (e.g. by matching header fields), which `RxWorker`
does not do today (it only keeps a port-wide aggregate). `frames_tx` /
`bytes_tx` are accurate.

## Unimplemented REST endpoints

- `PATCH /config`, `PATCH /config/append`, `PATCH /config/delete`
  (incremental config updates; only the full `POST /config` /
  `GET /config` pair is implemented).
- `POST /control/action` (protocol actions such as ping; pktflow does
  not emulate protocols).
- `POST /monitor/states` (protocol/neighbor state queries).
- `Control.State` choice `protocol` (no protocol emulation).

## `traffic.flow_transmit`

- `pause` / `resume` are rejected outright. Implementing them needs the
  Tx worker to support suspending mid-stream and resuming from the same
  position, which it does not today (only start/stop).
- Stopping only some of a port's currently running flows while others
  keep running is rejected (`400`). pktflow runs one `TxWorker` per
  port covering every flow transmitting on it; stopping a subset would
  require rebuilding the running worker's frame set on the fly rather
  than a plain stop+reap.

## Flow fields

- `Flow.size`: only `choice: "fixed"` is supported (`increment`,
  `random`, `weight_pairs` are rejected).
- `Flow.duration`: only `continuous` and `fixed_packets` are supported
  (`fixed_seconds`, `burst` are rejected).
- `Flow.rate`: `percentage` is rejected (pktflow does not track a
  port's negotiated link speed).
- Pattern `metric_tags` (tagged/egress metrics) are accepted but
  ignored.

## Capture

- `Capture.filters` are accepted but ignored (logged as a warning).
- `Capture.format` only supports `pcapng` (`pcap` is rejected).
- `CaptureRequest.packets`: only `choice: "all"` is supported (`slice`
  is rejected).
