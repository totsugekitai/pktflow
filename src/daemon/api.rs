//! REST API front-end for daemon mode. Runs on a plain OS thread; each
//! request is translated into a [`Command`](super::Command) and executed
//! by the daemon loop, so this layer never touches DPDK itself.
//!
//! Endpoints (all bodies are JSON):
//! - `GET    /ports`                   list ports with their link status
//!   and task states
//! - `POST   /ports`                   `{pci, rxq?, txq?, mode?}` add a port
//! - `DELETE /ports/<pci>`             remove an idle port
//! - `PUT    /ports/<pci>/mode`        `{tx?, rx?, pcap?}` set the mode
//! - `POST   /ports/<pci>/tx/start`    `{streams: [...]}` (same fields as
//!   `[[tx.streams]]` in the config file)
//! - `POST   /ports/<pci>/tx/stop`
//! - `POST   /ports/<pci>/rx/start`
//! - `POST   /ports/<pci>/rx/stop`
//! - `POST   /ports/<pci>/pcap/start`
//! - `POST   /ports/<pci>/pcap/stop`
//! - `GET    /ports/<pci>/pcap`        download the finished capture
//! - `GET    /ports/<pci>/stats`       hardware and software counters

use std::{io::Read, sync::mpsc, thread, time::Duration};

use anyhow::{Context as aContext, Result, anyhow};
use serde::Deserialize;
use serde_json::json;
use tiny_http::{Header, Method, Response, Server};
use tracing::{debug, warn};

use crate::{
    config::Stream,
    daemon::{CmdResult, Command, PortMode, Reply, Request},
    worker::StopFlag,
};

/// How long `recv_timeout` blocks before re-checking the stop flag.
const POLL_INTERVAL: Duration = Duration::from_millis(100);
/// Upper bound on accepted request bodies; a stream list is small.
const MAX_BODY_LEN: u64 = 1 << 20;

/// A failure to answer with, mapped onto an HTTP status code.
struct ApiError {
    status: u16,
    message: String,
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: 400,
            message: message.into(),
        }
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: 404,
            message: message.into(),
        }
    }

    /// The daemon loop is gone (shutting down).
    fn unavailable() -> Self {
        Self {
            status: 503,
            message: "daemon is shutting down".into(),
        }
    }
}

/// Starts the HTTP server on its own OS thread. The thread exits once
/// `stop` is signaled (checked between requests).
pub(super) fn spawn(
    listen: &str,
    cmd_tx: mpsc::Sender<Request>,
    stop: StopFlag,
) -> Result<thread::JoinHandle<()>> {
    let server = Server::http(listen).map_err(|e| anyhow!("Failed to listen on {listen}: {e}"))?;
    thread::Builder::new()
        .name("pktflow-api".into())
        .spawn(move || serve(&server, &cmd_tx, &stop))
        .context("Failed to spawn the API server thread")
}

fn serve(server: &Server, cmd_tx: &mpsc::Sender<Request>, stop: &StopFlag) {
    while !stop.is_signaled() {
        match server.recv_timeout(POLL_INTERVAL) {
            Ok(Some(request)) => handle(request, cmd_tx),
            Ok(None) => {}
            Err(e) => warn!("API server error: {e}"),
        }
    }
}

fn handle(mut request: tiny_http::Request, cmd_tx: &mpsc::Sender<Request>) {
    let method = request.method().clone();
    let url = request.url().to_string();
    debug!("API request: {method} {url}");

    let mut body = String::new();
    if let Err(e) = request
        .as_reader()
        .take(MAX_BODY_LEN)
        .read_to_string(&mut body)
    {
        respond(
            request,
            &error_response(400, &format!("unreadable body: {e}")),
        );
        return;
    }

    let path = url.split('?').next().unwrap_or("");
    let segments: Vec<String> = path
        .split('/')
        .filter(|s| !s.is_empty())
        .map(percent_decode)
        .collect();
    let segments: Vec<&str> = segments.iter().map(String::as_str).collect();

    let outcome = route(&method, &segments, &body).and_then(|cmd| dispatch(cmd, cmd_tx));
    let response = match outcome {
        Ok(Reply::Empty) => json_response(200, &json!({ "ok": true })),
        Ok(Reply::Ports(ports)) => json_response(200, &json!({ "ports": ports })),
        Ok(Reply::Stats(report)) => json_response(200, &json!(report)),
        Ok(Reply::Pcap(data)) => HttpReply {
            status: 200,
            content_type: "application/octet-stream",
            body: data,
        },
        Err(e) => error_response(e.status, &e.message),
    };
    respond(request, &response);
}

fn route(method: &Method, segments: &[&str], body: &str) -> Result<Command, ApiError> {
    match (method, segments) {
        (Method::Get, ["ports"]) => Ok(Command::ListPorts),
        (Method::Post, ["ports"]) => {
            let req: AddPortBody = parse_body(body)?;
            Ok(Command::AddPort {
                pci: req.pci,
                rxq: req.rxq,
                txq: req.txq,
                rxd: req.rxd,
                mode: req.mode.unwrap_or(PortMode::ALL),
            })
        }
        (Method::Delete, ["ports", pci]) => Ok(Command::RemovePort {
            pci: (*pci).to_string(),
        }),
        (Method::Put, ["ports", pci, "mode"]) => Ok(Command::SetMode {
            pci: (*pci).to_string(),
            mode: parse_body(body)?,
        }),
        (Method::Post, ["ports", pci, "tx", "start"]) => {
            let req: TxStartBody = parse_body(body)?;
            let streams = req
                .streams
                .iter()
                .enumerate()
                .map(|(i, s)| {
                    s.to_spec()
                        .map_err(|e| ApiError::bad_request(format!("invalid stream #{i}: {e:#}")))
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Command::StartTx {
                pci: (*pci).to_string(),
                streams,
            })
        }
        (Method::Post, ["ports", pci, "tx", "stop"]) => Ok(Command::StopTx {
            pci: (*pci).to_string(),
        }),
        (Method::Post, ["ports", pci, "rx", "start"]) => Ok(Command::StartRx {
            pci: (*pci).to_string(),
        }),
        (Method::Post, ["ports", pci, "rx", "stop"]) => Ok(Command::StopRx {
            pci: (*pci).to_string(),
        }),
        (Method::Post, ["ports", pci, "pcap", "start"]) => Ok(Command::StartPcap {
            pci: (*pci).to_string(),
        }),
        (Method::Post, ["ports", pci, "pcap", "stop"]) => Ok(Command::StopPcap {
            pci: (*pci).to_string(),
        }),
        (Method::Get, ["ports", pci, "pcap"]) => Ok(Command::GetPcap {
            pci: (*pci).to_string(),
        }),
        (Method::Get, ["ports", pci, "stats"]) => Ok(Command::GetStats {
            pci: (*pci).to_string(),
        }),
        _ => Err(ApiError::not_found("no such endpoint")),
    }
}

/// Sends the command to the daemon loop and waits for its outcome.
fn dispatch(cmd: Command, cmd_tx: &mpsc::Sender<Request>) -> Result<Reply, ApiError> {
    let (reply_tx, reply_rx) = mpsc::channel::<CmdResult>();
    cmd_tx
        .send(Request {
            cmd,
            reply: reply_tx,
        })
        .map_err(|_| ApiError::unavailable())?;
    match reply_rx.recv() {
        Ok(Ok(reply)) => Ok(reply),
        Ok(Err(message)) => Err(ApiError::bad_request(message)),
        Err(_) => Err(ApiError::unavailable()),
    }
}

#[derive(Deserialize)]
struct AddPortBody {
    pci: String,
    #[serde(default = "default_queues")]
    rxq: u16,
    #[serde(default = "default_queues")]
    txq: u16,
    #[serde(default = "default_rx_desc")]
    rxd: u16,
    mode: Option<PortMode>,
}

fn default_queues() -> u16 {
    1
}

fn default_rx_desc() -> u16 {
    crate::config::DEFAULT_RX_DESC
}

#[derive(Deserialize)]
struct TxStartBody {
    streams: Vec<Stream>,
}

fn parse_body<'a, T: Deserialize<'a>>(body: &'a str) -> Result<T, ApiError> {
    serde_json::from_str(body).map_err(|e| ApiError::bad_request(format!("invalid body: {e}")))
}

struct HttpReply {
    status: u16,
    content_type: &'static str,
    body: Vec<u8>,
}

fn json_response(status: u16, value: &serde_json::Value) -> HttpReply {
    HttpReply {
        status,
        content_type: "application/json",
        body: value.to_string().into_bytes(),
    }
}

fn error_response(status: u16, message: &str) -> HttpReply {
    json_response(status, &json!({ "error": message }))
}

fn respond(request: tiny_http::Request, reply: &HttpReply) {
    let header = Header::from_bytes("Content-Type", reply.content_type)
        .expect("static content type is a valid header");
    let response = Response::from_data(reply.body.clone())
        .with_status_code(reply.status)
        .with_header(header);
    if let Err(e) = request.respond(response) {
        warn!("Failed to send API response: {e}");
    }
}

/// Decodes `%XX` escapes so PCI addresses survive strict URL encoders
/// (":" is often escaped in path segments).
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let escape = if bytes[i] == b'%' && i + 2 < bytes.len() {
            std::str::from_utf8(&bytes[i + 1..i + 3])
                .ok()
                .and_then(|h| u8::from_str_radix(h, 16).ok())
        } else {
            None
        };
        match escape {
            Some(b) => {
                out.push(b);
                i += 3;
            }
            None => {
                out.push(bytes[i]);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_decode_decodes_escaped_pci_address() {
        assert_eq!(percent_decode("0000%3A02%3A00.0"), "0000:02:00.0");
    }

    #[test]
    fn percent_decode_keeps_plain_strings() {
        assert_eq!(percent_decode("0000:02:00.0"), "0000:02:00.0");
    }

    #[test]
    fn percent_decode_keeps_invalid_escapes() {
        assert_eq!(percent_decode("a%zz"), "a%zz");
        assert_eq!(percent_decode("a%"), "a%");
    }

    #[test]
    fn routes_tx_start_with_streams() {
        let body = r#"{"streams": [{
            "protocol": "ipv4",
            "src_mac": "00:11:22:33:44:55",
            "dst_mac": "66:77:88:99:aa:bb",
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "count": 100
        }]}"#;
        let cmd = route(
            &Method::Post,
            &["ports", "0000:02:00.0", "tx", "start"],
            body,
        )
        .unwrap_or_else(|e| panic!("{}", e.message));
        let Command::StartTx { pci, streams } = cmd else {
            panic!("expected StartTx");
        };
        assert_eq!(pci, "0000:02:00.0");
        assert_eq!(streams.len(), 1);
        assert_eq!(streams[0].count, 100);
    }

    #[test]
    fn rejects_invalid_stream_with_bad_request() {
        let body = r#"{"streams": [{
            "protocol": "vxlan",
            "src_mac": "00:11:22:33:44:55",
            "dst_mac": "66:77:88:99:aa:bb",
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2"
        }]}"#;
        let err = route(
            &Method::Post,
            &["ports", "0000:02:00.0", "tx", "start"],
            body,
        )
        .err()
        .expect("must be rejected");
        assert_eq!(err.status, 400);
        assert!(err.message.contains("unknown protocol"));
    }

    #[test]
    fn routes_stats_endpoint() {
        let cmd = route(&Method::Get, &["ports", "0000:02:00.0", "stats"], "")
            .unwrap_or_else(|e| panic!("{}", e.message));
        let Command::GetStats { pci } = cmd else {
            panic!("expected GetStats");
        };
        assert_eq!(pci, "0000:02:00.0");
    }

    #[test]
    fn unknown_route_is_not_found() {
        let err = route(&Method::Get, &["nope"], "").err().expect("404");
        assert_eq!(err.status, 404);
    }

    #[test]
    fn add_port_defaults_queues_and_mode() {
        let cmd = route(&Method::Post, &["ports"], r#"{"pci": "0000:02:00.0"}"#)
            .unwrap_or_else(|e| panic!("{}", e.message));
        let Command::AddPort {
            pci,
            rxq,
            txq,
            rxd,
            mode,
        } = cmd
        else {
            panic!("expected AddPort");
        };
        assert_eq!(pci, "0000:02:00.0");
        assert_eq!((rxq, txq), (1, 1));
        assert_eq!(rxd, crate::config::DEFAULT_RX_DESC);
        assert!(mode.tx && mode.rx && mode.pcap);
    }

    #[test]
    fn add_port_honors_explicit_rxd() {
        let cmd = route(
            &Method::Post,
            &["ports"],
            r#"{"pci": "0000:02:00.0", "rxd": 2048}"#,
        )
        .unwrap_or_else(|e| panic!("{}", e.message));
        let Command::AddPort { rxd, .. } = cmd else {
            panic!("expected AddPort");
        };
        assert_eq!(rxd, 2048);
    }

    #[test]
    fn mode_body_defaults_absent_fields_to_disabled() {
        let cmd = route(
            &Method::Put,
            &["ports", "0000:02:00.0", "mode"],
            r#"{"rx": true}"#,
        )
        .unwrap_or_else(|e| panic!("{}", e.message));
        let Command::SetMode { mode, .. } = cmd else {
            panic!("expected SetMode");
        };
        assert!(!mode.tx && mode.rx && !mode.pcap);
    }
}
