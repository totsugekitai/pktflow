//! REST API front-end for daemon mode, implementing the subset of the
//! Open Traffic Generator (OTG) REST API pktflow supports. Runs on a
//! plain OS thread; each request is translated into a
//! [`Command`](super::Command) and executed by the daemon loop, so
//! this layer never touches DPDK itself.
//!
//! Endpoints (all bodies are JSON; see `artifacts/openapi.yaml` in
//! open-traffic-generator/models for the full schema):
//! - `POST /config`               sets the whole configuration
//! - `GET  /config`               returns the current configuration
//! - `POST /control/state`        `choice`: `port` (`link`/`capture`)
//!   or `traffic` (`flow_transmit`)
//! - `POST /monitor/metrics`      `choice`: `port` or `flow`
//! - `POST /monitor/capture`      stops the port's capture (if
//!   running) and returns the pcapng bytes
//! - `GET  /capabilities/version`
//!
//! `PATCH /config` (update/append/delete), `POST /control/action`,
//! `POST /monitor/states` and `protocol` control state are not
//! implemented; see `TODO.md`.

use std::{io::Read, sync::mpsc, thread, time::Duration};

use anyhow::{Context as aContext, Result, anyhow};
use tiny_http::{Header, Method, Response, Server};
use tracing::{debug, warn};

use crate::{
    daemon::{
        CmdResult, Command, Reply, Request,
        otg::model::{
            CaptureRequest, Config, ControlAction, ControlState, ErrorBody, MetricsRequest,
            MetricsSelector, Warning,
        },
    },
    worker::StopFlag,
};

/// How long `recv_timeout` blocks before re-checking the stop flag.
const POLL_INTERVAL: Duration = Duration::from_millis(100);
/// Upper bound on accepted request bodies.
const MAX_BODY_LEN: u64 = 1 << 20;

/// A failure to answer with, mapped onto an HTTP status code and the
/// OTG `Error` schema (`{code, kind, errors}`).
struct ApiError {
    status: u16,
    kind: &'static str,
    message: String,
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: 400,
            kind: "validation",
            message: message.into(),
        }
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: 404,
            kind: "validation",
            message: message.into(),
        }
    }

    /// The daemon loop is gone (shutting down).
    fn unavailable() -> Self {
        Self {
            status: 503,
            kind: "internal",
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
            &error_response(400, "validation", &format!("unreadable body: {e}")),
        );
        return;
    }

    let path = url.split('?').next().unwrap_or("");
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

    let outcome = route(&method, &segments, &body).and_then(|cmd| dispatch(cmd, cmd_tx));
    let response = match outcome {
        Ok(Reply::Empty) => json_response(200, &Warning::none()),
        Ok(Reply::Config(config)) => json_response(200, &config),
        Ok(Reply::Metrics(metrics)) => json_response(200, &metrics),
        Ok(Reply::Version(version)) => json_response(200, &version),
        Ok(Reply::Pcap(data)) => HttpReply {
            status: 200,
            content_type: "application/octet-stream",
            body: data,
        },
        Err(e) => error_response(e.status, e.kind, &e.message),
    };
    respond(request, &response);
}

fn route(method: &Method, segments: &[&str], body: &str) -> Result<Command, ApiError> {
    match (method, segments) {
        (Method::Post, ["config"]) => {
            let config: Config = parse_body(body)?;
            Ok(Command::SetConfig(config))
        }
        (Method::Get, ["config"]) => Ok(Command::GetConfig),
        (Method::Post, ["control", "state"]) => {
            let state: ControlState = parse_body(body)?;
            let action = ControlAction::try_from(state)
                .map_err(|e| ApiError::bad_request(format!("{e:#}")))?;
            Ok(Command::SetControlState(action))
        }
        (Method::Post, ["monitor", "metrics"]) => {
            let req: MetricsRequest = parse_body(body)?;
            let selector = MetricsSelector::try_from(req)
                .map_err(|e| ApiError::bad_request(format!("{e:#}")))?;
            Ok(Command::GetMetrics(selector))
        }
        (Method::Post, ["monitor", "capture"]) => {
            let req: CaptureRequest = parse_body(body)?;
            Ok(Command::GetCapture(req))
        }
        (Method::Get, ["capabilities", "version"]) => Ok(Command::GetVersion),
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

fn parse_body<'a, T: serde::Deserialize<'a>>(body: &'a str) -> Result<T, ApiError> {
    serde_json::from_str(body).map_err(|e| ApiError::bad_request(format!("invalid body: {e}")))
}

struct HttpReply {
    status: u16,
    content_type: &'static str,
    body: Vec<u8>,
}

fn json_response(status: u16, value: &impl serde::Serialize) -> HttpReply {
    HttpReply {
        status,
        content_type: "application/json",
        body: serde_json::to_vec(value).expect("response types always serialize"),
    }
}

fn error_response(status: u16, kind: &'static str, message: &str) -> HttpReply {
    json_response(
        status,
        &ErrorBody {
            code: status,
            kind,
            errors: vec![message.to_string()],
        },
    )
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes_get_config() {
        let cmd = route(&Method::Get, &["config"], "").unwrap_or_else(|e| panic!("{}", e.message));
        assert!(matches!(cmd, Command::GetConfig));
    }

    #[test]
    fn routes_post_config_with_ports_and_flows() {
        let body = r#"{
            "ports": [{"name": "p1", "location": "0000:02:00.0"}],
            "flows": [{
                "name": "f1",
                "tx_rx": {"choice": "port", "port": {"tx_name": "p1", "rx_names": ["p1"]}},
                "packet": [
                    {"choice": "ethernet", "ethernet": {
                        "src": {"choice": "value", "value": "00:11:22:33:44:55"},
                        "dst": {"choice": "value", "value": "66:77:88:99:aa:bb"}
                    }},
                    {"choice": "ipv4", "ipv4": {
                        "src": {"choice": "value", "value": "10.0.0.1"},
                        "dst": {"choice": "value", "value": "10.0.0.2"}
                    }}
                ]
            }]
        }"#;
        let cmd =
            route(&Method::Post, &["config"], body).unwrap_or_else(|e| panic!("{}", e.message));
        let Command::SetConfig(config) = cmd else {
            panic!("expected SetConfig");
        };
        assert_eq!(config.ports.len(), 1);
        assert_eq!(config.flows.len(), 1);
    }

    #[test]
    fn rejects_invalid_control_state_choice() {
        let body = r#"{"choice": "protocol"}"#;
        let err = route(&Method::Post, &["control", "state"], body)
            .err()
            .expect("must be rejected");
        assert_eq!(err.status, 400);
    }

    #[test]
    fn routes_control_state_flow_transmit_start() {
        let body = r#"{"choice": "traffic", "traffic": {"choice": "flow_transmit", "flow_transmit": {"flow_names": ["f1"], "state": "start"}}}"#;
        let cmd = route(&Method::Post, &["control", "state"], body)
            .unwrap_or_else(|e| panic!("{}", e.message));
        let Command::SetControlState(ControlAction::FlowTransmit { flow_names, .. }) = cmd else {
            panic!("expected FlowTransmit");
        };
        assert_eq!(flow_names, vec!["f1".to_string()]);
    }

    #[test]
    fn routes_monitor_metrics_port_choice() {
        let body = r#"{"choice": "port", "port": {"port_names": []}}"#;
        let cmd = route(&Method::Post, &["monitor", "metrics"], body)
            .unwrap_or_else(|e| panic!("{}", e.message));
        assert!(matches!(cmd, Command::GetMetrics(MetricsSelector::Port(_))));
    }

    #[test]
    fn routes_monitor_capture() {
        let body = r#"{"port_name": "p1"}"#;
        let cmd = route(&Method::Post, &["monitor", "capture"], body)
            .unwrap_or_else(|e| panic!("{}", e.message));
        let Command::GetCapture(req) = cmd else {
            panic!("expected GetCapture");
        };
        assert_eq!(req.port_name, "p1");
    }

    #[test]
    fn unknown_route_is_not_found() {
        let err = route(&Method::Get, &["nope"], "").err().expect("404");
        assert_eq!(err.status, 404);
    }
}
