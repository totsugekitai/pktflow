//! Wire-shaped types for the subset of the OTG REST API pktflow
//! implements (`artifacts/openapi.yaml` v1.61.0 in
//! open-traffic-generator/models). Every `pub struct`/`pub enum` here
//! mirrors a JSON object of the spec field-for-field, including the
//! `{"choice": "x", "x": {...}}` shape OTG uses for tagged unions
//! (modeled as a `choice: String` plus one `Option<T>` per variant,
//! since only one is ever populated).
//!
//! [`Config`] is stored verbatim (it round-trips through `GET /config`
//! unchanged); everything that is actually *executed* is converted,
//! on demand, into the tighter internal types next to the logic that
//! uses them (see `flow.rs`, `control.rs`, `metrics.rs`).

use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};

use crate::{
    daemon::otg::pattern::{self, Pattern, RawPattern},
    proto::ether::MacAddr,
};

// ---------------------------------------------------------------------
// Config (stored verbatim; round-trips through GET /config)
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub ports: Vec<Port>,
    #[serde(default)]
    pub captures: Vec<Capture>,
    #[serde(default)]
    pub flows: Vec<Flow>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Port {
    pub name: String,
    /// Implementation-specific: `"<pci>"` or `"<pci>?rxq=N&txq=N&rxd=N"`.
    pub location: String,
}

/// Parsed form of [`Port::location`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortLocation {
    pub pci: String,
    pub rxq: u16,
    pub txq: u16,
    pub rxd: u16,
}

impl Port {
    pub fn parsed_location(&self) -> Result<PortLocation> {
        let mut rxq = 1u16;
        let mut txq = 1u16;
        let mut rxd = crate::config::DEFAULT_RX_DESC;
        let pci = match self.location.split_once('?') {
            None => self.location.clone(),
            Some((pci, query)) => {
                for kv in query.split('&').filter(|s| !s.is_empty()) {
                    let (k, v) = kv.split_once('=').with_context(|| {
                        format!(
                            "invalid location query parameter {kv:?} on port {:?}",
                            self.name
                        )
                    })?;
                    let v: u16 = v.parse().with_context(|| {
                        format!("invalid value {v:?} for {k:?} on port {:?}", self.name)
                    })?;
                    match k {
                        "rxq" => rxq = v,
                        "txq" => txq = v,
                        "rxd" => rxd = v,
                        other => bail!(
                            "unknown location parameter {other:?} on port {:?}",
                            self.name
                        ),
                    }
                }
                pci.to_string()
            }
        };
        Ok(PortLocation { pci, rxq, txq, rxd })
    }
}

impl PortLocation {
    pub fn to_location_string(&self) -> String {
        format!(
            "{}?rxq={}&txq={}&rxd={}",
            self.pci, self.rxq, self.txq, self.rxd
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capture {
    pub name: String,
    pub port_names: Vec<String>,
    #[serde(default = "default_format")]
    pub format: String,
    #[serde(default)]
    pub filters: Vec<serde_json::Value>,
}

fn default_format() -> String {
    "pcapng".into()
}

impl Capture {
    /// Validates the parts of the config we don't implement, warning
    /// (not failing) for the ones that are safe to just ignore.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.format == "pcapng",
            "capture {:?}: only format \"pcapng\" is supported",
            self.name
        );
        if !self.filters.is_empty() {
            tracing::warn!(
                "capture {:?}: \"filters\" is not supported and will be ignored",
                self.name
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Flow {
    pub name: String,
    pub tx_rx: TxRx,
    #[serde(default)]
    pub packet: Vec<Header>,
    #[serde(default)]
    pub size: Option<Size>,
    #[serde(default)]
    pub rate: Option<Rate>,
    #[serde(default)]
    pub duration: Option<Duration>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxRx {
    #[serde(default = "default_choice_port")]
    pub choice: String,
    pub port: Option<FlowPort>,
    pub device: Option<serde_json::Value>,
}

fn default_choice_port() -> String {
    "port".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowPort {
    pub tx_name: String,
    #[serde(default)]
    pub rx_names: Vec<String>,
}

// ---------------------------------------------------------------------
// Packet headers (Flow.packet[])
// ---------------------------------------------------------------------

pub type PatternMac = RawPattern<String>;
pub type PatternIpv4 = RawPattern<String>;
pub type PatternIpv6 = RawPattern<String>;
pub type PatternU8 = RawPattern<u8>;
pub type PatternU16 = RawPattern<u16>;

fn parse_mac(s: String) -> Result<MacAddr> {
    s.parse()
        .with_context(|| format!("invalid MAC address {s:?}"))
}

fn parse_ipv4(s: String) -> Result<Ipv4Addr> {
    s.parse()
        .with_context(|| format!("invalid IPv4 address {s:?}"))
}

fn parse_ipv6(s: String) -> Result<Ipv6Addr> {
    s.parse()
        .with_context(|| format!("invalid IPv6 address {s:?}"))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Header {
    #[serde(default = "default_choice_ethernet")]
    pub choice: String,
    #[serde(default)]
    pub ethernet: Option<EthernetHeader>,
    #[serde(default)]
    pub vlan: Option<VlanHeader>,
    #[serde(default)]
    pub ipv4: Option<Ipv4Header>,
    #[serde(default)]
    pub ipv6: Option<Ipv6Header>,
    #[serde(default)]
    pub arp: Option<ArpHeader>,
}

fn default_choice_ethernet() -> String {
    "ethernet".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EthernetHeader {
    pub dst: Option<PatternMac>,
    pub src: Option<PatternMac>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VlanHeader {
    pub id: Option<PatternU16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ipv4Header {
    pub src: Option<PatternIpv4>,
    pub dst: Option<PatternIpv4>,
    pub time_to_live: Option<PatternU8>,
    pub protocol: Option<PatternU8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ipv6Header {
    pub src: Option<PatternIpv6>,
    pub dst: Option<PatternIpv6>,
    pub hop_limit: Option<PatternU8>,
    pub next_header: Option<PatternU8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArpHeader {
    pub operation: Option<PatternU16>,
    pub sender_protocol_addr: Option<PatternIpv4>,
    pub target_protocol_addr: Option<PatternIpv4>,
}

/// Internal, resolved form of one [`Header`] entry.
pub enum ResolvedHeader {
    Ethernet {
        dst: Pattern<MacAddr>,
        src: Pattern<MacAddr>,
    },
    Vlan {
        id: Pattern<u16>,
    },
    Ipv4 {
        src: Pattern<Ipv4Addr>,
        dst: Pattern<Ipv4Addr>,
        ttl: Pattern<u8>,
        protocol: Pattern<u8>,
    },
    Ipv6 {
        src: Pattern<Ipv6Addr>,
        dst: Pattern<Ipv6Addr>,
        hop_limit: Pattern<u8>,
        next_header: Pattern<u8>,
    },
    Arp {
        operation: Pattern<u16>,
        sender_protocol_addr: Pattern<Ipv4Addr>,
        target_protocol_addr: Pattern<Ipv4Addr>,
    },
}

fn default_mac(octets: [u8; 6]) -> Pattern<MacAddr> {
    Pattern::Value(MacAddr::new(octets))
}

impl TryFrom<Header> for ResolvedHeader {
    type Error = anyhow::Error;

    fn try_from(h: Header) -> Result<Self> {
        Ok(match h.choice.as_str() {
            "ethernet" => {
                let e = h.ethernet.unwrap_or(EthernetHeader {
                    dst: None,
                    src: None,
                });
                Self::Ethernet {
                    dst: match e.dst {
                        Some(p) => pattern::from_raw(p, parse_mac, false)?,
                        None => default_mac([0; 6]),
                    },
                    src: match e.src {
                        Some(p) => pattern::from_raw(p, parse_mac, false)?,
                        None => default_mac([0; 6]),
                    },
                }
            }
            "vlan" => {
                let v = h
                    .vlan
                    .context("header choice \"vlan\" requires a \"vlan\" field")?;
                let id = match v.id {
                    Some(p) => pattern::from_raw(p, |v: u16| Ok(v), true)?,
                    None => Pattern::Value(0),
                };
                Self::Vlan { id }
            }
            "ipv4" => {
                let v = h
                    .ipv4
                    .context("header choice \"ipv4\" requires an \"ipv4\" field")?;
                Self::Ipv4 {
                    src: match v.src {
                        Some(p) => pattern::from_raw(p, parse_ipv4, true)?,
                        None => Pattern::Value(Ipv4Addr::UNSPECIFIED),
                    },
                    dst: match v.dst {
                        Some(p) => pattern::from_raw(p, parse_ipv4, true)?,
                        None => Pattern::Value(Ipv4Addr::UNSPECIFIED),
                    },
                    ttl: match v.time_to_live {
                        Some(p) => pattern::from_raw(p, |v: u8| Ok(v), true)?,
                        None => Pattern::Value(64),
                    },
                    protocol: match v.protocol {
                        Some(p) => pattern::from_raw(p, |v: u8| Ok(v), true)?,
                        None => Pattern::Value(253),
                    },
                }
            }
            "ipv6" => {
                let v = h
                    .ipv6
                    .context("header choice \"ipv6\" requires an \"ipv6\" field")?;
                Self::Ipv6 {
                    src: match v.src {
                        Some(p) => pattern::from_raw(p, parse_ipv6, true)?,
                        None => Pattern::Value(Ipv6Addr::UNSPECIFIED),
                    },
                    dst: match v.dst {
                        Some(p) => pattern::from_raw(p, parse_ipv6, true)?,
                        None => Pattern::Value(Ipv6Addr::UNSPECIFIED),
                    },
                    hop_limit: match v.hop_limit {
                        Some(p) => pattern::from_raw(p, |v: u8| Ok(v), true)?,
                        None => Pattern::Value(64),
                    },
                    next_header: match v.next_header {
                        Some(p) => pattern::from_raw(p, |v: u8| Ok(v), true)?,
                        None => Pattern::Value(253),
                    },
                }
            }
            "arp" => {
                let v = h
                    .arp
                    .context("header choice \"arp\" requires an \"arp\" field")?;
                Self::Arp {
                    operation: match v.operation {
                        Some(p) => pattern::from_raw(p, |v: u16| Ok(v), true)?,
                        None => Pattern::Value(1),
                    },
                    sender_protocol_addr: match v.sender_protocol_addr {
                        Some(p) => pattern::from_raw(p, parse_ipv4, true)?,
                        None => Pattern::Value(Ipv4Addr::UNSPECIFIED),
                    },
                    target_protocol_addr: match v.target_protocol_addr {
                        Some(p) => pattern::from_raw(p, parse_ipv4, true)?,
                        None => Pattern::Value(Ipv4Addr::UNSPECIFIED),
                    },
                }
            }
            other => bail!(
                "unsupported packet header choice {other:?} (pktflow only supports ethernet, vlan, ipv4, ipv6, arp)"
            ),
        })
    }
}

// ---------------------------------------------------------------------
// Flow.size / Flow.rate / Flow.duration
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Size {
    #[serde(default = "default_choice_fixed")]
    pub choice: String,
    pub fixed: Option<u32>,
}

fn default_choice_fixed() -> String {
    "fixed".into()
}

impl Size {
    /// Total on-wire frame length in bytes, FCS included (matching the
    /// OTG default of 64, the minimum Ethernet frame size with FCS).
    pub fn fixed_len(&self) -> Result<u32> {
        ensure!(
            self.choice == "fixed",
            "flow size choice {:?} is not supported (only \"fixed\")",
            self.choice
        );
        Ok(self.fixed.unwrap_or(64))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rate {
    #[serde(default = "default_choice_pps")]
    pub choice: String,
    pub pps: Option<u64>,
    pub bps: Option<u64>,
    pub kbps: Option<u64>,
    pub mbps: Option<u64>,
    pub gbps: Option<u32>,
    pub percentage: Option<f32>,
}

fn default_choice_pps() -> String {
    "pps".into()
}

impl TryFrom<Rate> for crate::proto::stream::Rate {
    type Error = anyhow::Error;

    fn try_from(r: Rate) -> Result<Self> {
        use crate::proto::stream::Rate as R;
        Ok(match r.choice.as_str() {
            "pps" => R::Pps(r.pps.unwrap_or(1000)),
            "bps" => R::Bps(r.bps.unwrap_or(1_000_000_000)),
            "kbps" => R::Bps(r.kbps.unwrap_or(1_000_000) * 1_000),
            "mbps" => R::Bps(r.mbps.unwrap_or(1_000) * 1_000_000),
            "gbps" => R::Bps(r.gbps.unwrap_or(1) as u64 * 1_000_000_000),
            "percentage" => bail!(
                "flow rate choice \"percentage\" is not supported (pktflow does not track negotiated port bandwidth)"
            ),
            other => bail!("unsupported flow rate choice {other:?}"),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Duration {
    #[serde(default = "default_choice_continuous")]
    pub choice: String,
    pub fixed_packets: Option<FixedPackets>,
    pub continuous: Option<serde_json::Value>,
    pub fixed_seconds: Option<serde_json::Value>,
    pub burst: Option<serde_json::Value>,
}

fn default_choice_continuous() -> String {
    "continuous".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixedPackets {
    #[serde(default = "default_packets")]
    pub packets: u64,
}

fn default_packets() -> u64 {
    1
}

impl TryFrom<Duration> for crate::worker::tx::TxCount {
    type Error = anyhow::Error;

    fn try_from(d: Duration) -> Result<Self> {
        use crate::worker::tx::TxCount;
        Ok(match d.choice.as_str() {
            "continuous" => TxCount::Continuous,
            "fixed_packets" => {
                let p = d.fixed_packets.unwrap_or(FixedPackets { packets: 1 });
                ensure!(
                    p.packets >= 1,
                    "duration fixed_packets.packets must be at least 1"
                );
                TxCount::Fixed(p.packets)
            }
            other => bail!(
                "flow duration choice {other:?} is not supported (only \"continuous\" and \"fixed_packets\")"
            ),
        })
    }
}

// ---------------------------------------------------------------------
// Control.State
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct ControlState {
    pub choice: String,
    pub port: Option<StatePort>,
    pub traffic: Option<StateTraffic>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct StatePort {
    pub choice: String,
    pub link: Option<StatePortLink>,
    pub capture: Option<StatePortCapture>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct StatePortLink {
    #[serde(default)]
    pub port_names: Vec<String>,
    pub state: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct StatePortCapture {
    #[serde(default)]
    pub port_names: Vec<String>,
    pub state: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct StateTraffic {
    pub choice: String,
    pub flow_transmit: Option<StateFlowTransmit>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct StateFlowTransmit {
    #[serde(default)]
    pub flow_names: Vec<String>,
    pub state: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransmitState {
    Start,
    Stop,
    Pause,
    Resume,
}

pub enum ControlAction {
    PortLink {
        port_names: Vec<String>,
        up: bool,
    },
    PortCapture {
        port_names: Vec<String>,
        start: bool,
    },
    FlowTransmit {
        flow_names: Vec<String>,
        state: TransmitState,
    },
}

impl TryFrom<ControlState> for ControlAction {
    type Error = anyhow::Error;

    fn try_from(s: ControlState) -> Result<Self> {
        Ok(match s.choice.as_str() {
            "port" => {
                let p = s
                    .port
                    .context("choice \"port\" requires a \"port\" field")?;
                match p.choice.as_str() {
                    "link" => {
                        let l = p
                            .link
                            .context("choice \"link\" requires a \"link\" field")?;
                        let up = match l.state.as_str() {
                            "up" => true,
                            "down" => false,
                            other => bail!("unsupported link state {other:?}"),
                        };
                        ControlAction::PortLink {
                            port_names: l.port_names,
                            up,
                        }
                    }
                    "capture" => {
                        let c = p
                            .capture
                            .context("choice \"capture\" requires a \"capture\" field")?;
                        let start = match c.state.as_str() {
                            "start" => true,
                            "stop" => false,
                            other => bail!("unsupported capture state {other:?}"),
                        };
                        ControlAction::PortCapture {
                            port_names: c.port_names,
                            start,
                        }
                    }
                    other => bail!("unsupported port state choice {other:?}"),
                }
            }
            "traffic" => {
                let t = s
                    .traffic
                    .context("choice \"traffic\" requires a \"traffic\" field")?;
                ensure!(
                    t.choice == "flow_transmit",
                    "unsupported traffic state choice {:?}",
                    t.choice
                );
                let f = t
                    .flow_transmit
                    .context("choice \"flow_transmit\" requires a \"flow_transmit\" field")?;
                let state = match f.state.as_str() {
                    "start" => TransmitState::Start,
                    "stop" => TransmitState::Stop,
                    "pause" => TransmitState::Pause,
                    "resume" => TransmitState::Resume,
                    other => bail!("unsupported transmit state {other:?}"),
                };
                ControlAction::FlowTransmit {
                    flow_names: f.flow_names,
                    state,
                }
            }
            "protocol" => {
                bail!("control state choice \"protocol\" is not supported (no protocol emulation)")
            }
            other => bail!("unsupported control state choice {other:?}"),
        })
    }
}

// ---------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct MetricsRequest {
    pub choice: String,
    pub port: Option<PortMetricsRequest>,
    pub flow: Option<FlowMetricsRequest>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct PortMetricsRequest {
    #[serde(default)]
    pub port_names: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct FlowMetricsRequest {
    #[serde(default)]
    pub flow_names: Vec<String>,
}

pub enum MetricsSelector {
    Port(Vec<String>),
    Flow(Vec<String>),
}

impl TryFrom<MetricsRequest> for MetricsSelector {
    type Error = anyhow::Error;

    fn try_from(r: MetricsRequest) -> Result<Self> {
        Ok(match r.choice.as_str() {
            "port" => MetricsSelector::Port(r.port.unwrap_or_default().port_names),
            "flow" => MetricsSelector::Flow(r.flow.unwrap_or_default().flow_names),
            other => bail!(
                "unsupported metrics choice {other:?} (only \"port\" and \"flow\" are supported)"
            ),
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PortMetric {
    pub name: String,
    pub location: String,
    pub link: &'static str,
    pub capture: &'static str,
    pub transmit: &'static str,
    pub frames_tx: u64,
    pub frames_rx: u64,
    pub bytes_tx: u64,
    pub bytes_rx: u64,
    pub frames_tx_rate: f64,
    pub frames_rx_rate: f64,
    pub bytes_tx_rate: f64,
    pub bytes_rx_rate: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct FlowMetric {
    pub name: String,
    pub port_tx: String,
    pub port_rx: String,
    pub transmit: &'static str,
    pub frames_tx: u64,
    pub frames_rx: u64,
    pub bytes_tx: u64,
    pub bytes_rx: u64,
    pub frames_tx_rate: f64,
    pub frames_rx_rate: f64,
    pub loss: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct MetricsResponse {
    pub choice: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port_metrics: Option<Vec<PortMetric>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow_metrics: Option<Vec<FlowMetric>>,
}

// ---------------------------------------------------------------------
// Capture retrieval
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct CaptureRequest {
    pub port_name: String,
    pub packets: Option<CaptureRequestPackets>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CaptureRequestPackets {
    #[serde(default = "default_all")]
    pub choice: String,
}

fn default_all() -> String {
    "all".into()
}

impl CaptureRequest {
    pub fn validate(&self) -> Result<()> {
        if let Some(p) = &self.packets {
            ensure!(
                p.choice == "all",
                "capture request choice {:?} is not supported (only \"all\")",
                p.choice
            );
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct Warning {
    pub warnings: Vec<String>,
}

impl Warning {
    pub fn none() -> Self {
        Self {
            warnings: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ErrorBody {
    pub code: u16,
    pub kind: &'static str,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Version {
    pub api_spec_version: String,
    pub sdk_version: String,
    pub app_version: String,
}
