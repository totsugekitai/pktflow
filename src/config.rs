use std::{fs, path::PathBuf};

use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;

use crate::proto::{
    arp::ArpOp,
    stream::{L3Spec, Rate, StreamSpec},
};

#[derive(Debug)]
pub struct Config {
    pub eal_args: Vec<String>,
    pub port_configs: Vec<PortConfig>,
    pub lcores: Vec<u32>,
    pub tx_streams: Vec<StreamSpec>,
    /// Received frames are captured into this pcapng file when set.
    pub capture_file: Option<String>,
    pub daemon: DaemonConfig,
}

#[derive(Debug, Clone)]
pub struct DaemonConfig {
    /// Address the REST API listens on in daemon mode.
    pub listen: String,
    /// Directory where daemon-mode captures are spooled.
    pub pcap_dir: PathBuf,
}

const DEFAULT_LISTEN: &str = "127.0.0.1:7878";

#[derive(Debug)]
pub struct PortConfig {
    pub pci: String,
    pub nb_rxq: u16,
    pub nb_txq: u16,
    /// Number of descriptors in each rx queue's ring.
    pub nb_rxd: u16,
}

/// Descriptors per rx queue when the request or config omits `rxd`.
pub const DEFAULT_RX_DESC: u16 = 1024;

#[derive(Debug, Deserialize)]
struct Toml {
    dpdk: Dpdk,
    tx: Option<Tx>,
    capture: Option<Capture>,
    daemon: Option<DaemonToml>,
}

#[derive(Debug, Deserialize)]
struct DaemonToml {
    listen: Option<String>,
    pcap_dir: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Capture {
    file: String,
}

#[derive(Debug, Deserialize)]
struct Tx {
    streams: Vec<Stream>,
}

/// One transmit stream, as written by the user (in `[[tx.streams]]` or in
/// a daemon-mode REST request body, which shares the same field names).
/// Validated and resolved into a [`StreamSpec`] by [`Stream::to_spec`].
#[derive(Debug, Deserialize)]
pub struct Stream {
    protocol: String,
    src_mac: String,
    dst_mac: String,
    src_ip: String,
    dst_ip: String,
    vlan: Option<u16>,
    payload_len: Option<usize>,
    ttl: Option<u8>,
    hop_limit: Option<u8>,
    l4_protocol: Option<u8>,
    arp_op: Option<String>,
    count: Option<u64>,
    rate_pps: Option<u64>,
    rate_mbps: Option<f64>,
}

#[derive(Debug, Deserialize)]
struct Dpdk {
    lcores: String,
    // memory_mb: u32,
    // Daemon mode adds ports via the API, so the section may be absent.
    #[serde(default)]
    ports: Vec<Port>,
}

#[derive(Debug, Deserialize)]
struct Port {
    pci: String,
    rxq: u16,
    txq: u16,
    #[serde(default = "default_rx_desc")]
    rxd: u16,
    // apps: Vec<String>,
}

fn default_rx_desc() -> u16 {
    DEFAULT_RX_DESC
}

impl Toml {
    fn new(tomlpath: &str) -> Self {
        let toml = fs::read_to_string(tomlpath).unwrap();
        let config: Self = toml::from_str(toml.as_str()).unwrap();

        config
    }
}

const DEFAULT_PAYLOAD_LEN: usize = 64;
const MAX_PAYLOAD_LEN: usize = 1500;
const DEFAULT_TTL: u8 = 64;
const DEFAULT_COUNT: u64 = 1;
/// RFC 3692 experimentation protocol number, used when no L4 header follows.
const DEFAULT_L4_PROTOCOL: u8 = 253;

impl Stream {
    pub fn to_spec(&self) -> Result<StreamSpec> {
        let src_mac = self.src_mac.parse().context("invalid src_mac")?;
        let dst_mac = self.dst_mac.parse().context("invalid dst_mac")?;
        if let Some(vid) = self.vlan {
            ensure!(vid < 4096, "vlan VID {vid} must be less than 4096");
        }
        let payload_len = self.payload_len.unwrap_or(DEFAULT_PAYLOAD_LEN);
        ensure!(
            payload_len <= MAX_PAYLOAD_LEN,
            "payload_len {payload_len} exceeds the maximum of {MAX_PAYLOAD_LEN}"
        );
        let count = self.count.unwrap_or(DEFAULT_COUNT);
        ensure!(count >= 1, "count must be at least 1");
        let rate = match (self.rate_pps, self.rate_mbps) {
            (Some(_), Some(_)) => bail!("rate_pps and rate_mbps are mutually exclusive"),
            (Some(pps), None) => {
                ensure!(pps >= 1, "rate_pps must be at least 1");
                Some(Rate::Pps(pps))
            }
            (None, Some(mbps)) => {
                ensure!(
                    mbps.is_finite() && mbps > 0.0,
                    "rate_mbps must be a positive number"
                );
                Some(Rate::Bps((mbps * 1_000_000.0) as u64))
            }
            (None, None) => None,
        };

        let l3 = match self.protocol.as_str() {
            "arp" => L3Spec::Arp {
                op: match self.arp_op.as_deref().unwrap_or("request") {
                    "request" => ArpOp::REQUEST,
                    "reply" => ArpOp::REPLY,
                    op => bail!("invalid arp_op {op:?} (expected \"request\" or \"reply\")"),
                },
                sender_ip: self.src_ip.parse().context("invalid src_ip")?,
                target_ip: self.dst_ip.parse().context("invalid dst_ip")?,
            },
            "ipv4" => L3Spec::Ipv4 {
                src: self.src_ip.parse().context("invalid src_ip")?,
                dst: self.dst_ip.parse().context("invalid dst_ip")?,
                ttl: self.ttl.unwrap_or(DEFAULT_TTL),
                protocol: self.l4_protocol.unwrap_or(DEFAULT_L4_PROTOCOL),
            },
            "ipv6" => L3Spec::Ipv6 {
                src: self.src_ip.parse().context("invalid src_ip")?,
                dst: self.dst_ip.parse().context("invalid dst_ip")?,
                hop_limit: self.hop_limit.unwrap_or(DEFAULT_TTL),
                next_header: self.l4_protocol.unwrap_or(DEFAULT_L4_PROTOCOL),
            },
            p => bail!("unknown protocol {p:?} (expected \"arp\", \"ipv4\" or \"ipv6\")"),
        };

        Ok(StreamSpec {
            src_mac,
            dst_mac,
            vlan: self.vlan,
            l3,
            payload_len,
            count,
            rate,
        })
    }
}

impl Config {
    pub fn parse(tomlpath: &str) -> Result<Self> {
        let toml = Toml::new(tomlpath);
        let mut eal_args = Vec::new();
        eal_args.push(String::from("pktflow"));
        eal_args.push(format!("--lcores={}", toml.dpdk.lcores));

        let mut port_configs = Vec::new();
        for p in toml.dpdk.ports {
            let pcfg = PortConfig {
                pci: p.pci,
                nb_rxq: p.rxq,
                nb_txq: p.txq,
                nb_rxd: p.rxd,
            };
            port_configs.push(pcfg);
        }

        let tx_streams = toml
            .tx
            .map(|tx| tx.streams)
            .unwrap_or_default()
            .iter()
            .enumerate()
            .map(|(i, s)| {
                s.to_spec()
                    .with_context(|| format!("invalid [[tx.streams]] entry #{i}"))
            })
            .collect::<Result<Vec<_>>>()?;

        let daemon = {
            let d = toml.daemon;
            DaemonConfig {
                listen: d
                    .as_ref()
                    .and_then(|d| d.listen.clone())
                    .unwrap_or_else(|| DEFAULT_LISTEN.to_string()),
                pcap_dir: d
                    .as_ref()
                    .and_then(|d| d.pcap_dir.clone())
                    .map(PathBuf::from)
                    .unwrap_or_else(std::env::temp_dir),
            }
        };

        Ok(Self {
            eal_args,
            port_configs,
            lcores: Self::parse_lcores(&toml.dpdk.lcores)?,
            tx_streams,
            capture_file: toml.capture.map(|c| c.file),
            daemon,
        })
    }

    fn parse_lcores(lcores: &str) -> Result<Vec<u32>> {
        let mut v = Vec::new();
        let mut s = String::new();
        let mut prev_n = u32::MAX;
        let mut n = u32::MAX;
        let mut is_continue = false;
        for c in lcores.chars() {
            match c {
                '0'..='9' => {
                    s = s + &c.to_string();
                }
                '-' => {
                    prev_n = s.parse::<u32>().unwrap();
                    s.clear();
                    is_continue = true;
                }
                ',' => {
                    if is_continue && prev_n != u32::MAX && n != u32::MAX {
                        n = s.parse::<u32>().unwrap();
                        for i in prev_n..=n {
                            v.push(i);
                        }
                        n = u32::MAX;
                        prev_n = u32::MAX;
                        is_continue = false;
                    } else {
                        v.push(s.parse::<u32>().unwrap());
                        s.clear();
                    }
                }
                _ => {}
            }
        }
        if is_continue {
            n = s.parse::<u32>().unwrap();
            for i in prev_n..=n {
                v.push(i);
            }
        }
        Ok(v)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use crate::proto::ether::MacAddr;

    use super::*;

    fn parse_stream(toml_str: &str) -> Result<StreamSpec> {
        let toml: Toml = toml::from_str(toml_str).unwrap();
        toml.tx.unwrap().streams[0].to_spec()
    }

    const BASE: &str = r#"
[dpdk]
lcores = "1-2"
ports = []
"#;

    #[test]
    fn sample_config_parses() {
        let config = Config::parse("sample_oneshot.toml").unwrap();
        assert_eq!(config.tx_streams.len(), 3);
    }

    #[test]
    fn missing_tx_section_yields_no_streams() {
        let toml: Toml = toml::from_str(BASE).unwrap();
        assert!(toml.tx.is_none());
    }

    #[test]
    fn parses_capture_section() {
        let toml: Toml = toml::from_str(&format!(
            r#"{BASE}
[capture]
file = "rx.pcapng"
"#
        ))
        .unwrap();
        assert_eq!(toml.capture.unwrap().file, "rx.pcapng");
    }

    #[test]
    fn missing_capture_section_yields_no_capture_file() {
        let toml: Toml = toml::from_str(BASE).unwrap();
        assert!(toml.capture.is_none());
    }

    #[test]
    fn sample_daemon_config_parses() {
        let config = Config::parse("sample_daemon.toml").unwrap();
        assert_eq!(config.daemon.listen, "0.0.0.0:7878");
        assert!(config.port_configs.is_empty());
    }

    #[test]
    fn parses_daemon_section() {
        let toml: Toml = toml::from_str(&format!(
            r#"{BASE}
[daemon]
listen = "0.0.0.0:8080"
pcap_dir = "/var/spool/pktflow"
"#
        ))
        .unwrap();
        let daemon = toml.daemon.unwrap();
        assert_eq!(daemon.listen.as_deref(), Some("0.0.0.0:8080"));
        assert_eq!(daemon.pcap_dir.as_deref(), Some("/var/spool/pktflow"));
    }

    #[test]
    fn missing_daemon_section_and_ports_are_allowed() {
        let toml: Toml = toml::from_str(
            r#"
[dpdk]
lcores = "1-2"
"#,
        )
        .unwrap();
        assert!(toml.daemon.is_none());
        assert!(toml.dpdk.ports.is_empty());
    }

    #[test]
    fn parses_ipv4_stream_with_defaults() {
        let spec = parse_stream(&format!(
            r#"{BASE}
[[tx.streams]]
protocol = "ipv4"
src_mac = "00:11:22:33:44:55"
dst_mac = "66:77:88:99:aa:bb"
src_ip = "10.0.0.1"
dst_ip = "10.0.0.2"
"#
        ))
        .unwrap();

        assert_eq!(
            spec.src_mac,
            MacAddr::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
        );
        assert_eq!(spec.vlan, None);
        assert_eq!(spec.payload_len, DEFAULT_PAYLOAD_LEN);
        assert_eq!(spec.count, DEFAULT_COUNT);
        assert_eq!(
            spec.l3,
            L3Spec::Ipv4 {
                src: Ipv4Addr::new(10, 0, 0, 1),
                dst: Ipv4Addr::new(10, 0, 0, 2),
                ttl: DEFAULT_TTL,
                protocol: DEFAULT_L4_PROTOCOL,
            }
        );
    }

    #[test]
    fn parses_arp_stream_with_vlan() {
        let spec = parse_stream(&format!(
            r#"{BASE}
[[tx.streams]]
protocol = "arp"
arp_op = "reply"
vlan = 100
src_mac = "00:11:22:33:44:55"
dst_mac = "66:77:88:99:aa:bb"
src_ip = "10.0.0.1"
dst_ip = "10.0.0.2"
"#
        ))
        .unwrap();

        assert_eq!(spec.vlan, Some(100));
        assert_eq!(
            spec.l3,
            L3Spec::Arp {
                op: ArpOp::REPLY,
                sender_ip: Ipv4Addr::new(10, 0, 0, 1),
                target_ip: Ipv4Addr::new(10, 0, 0, 2),
            }
        );
    }

    #[test]
    fn parses_ipv6_stream() {
        let spec = parse_stream(&format!(
            r#"{BASE}
[[tx.streams]]
protocol = "ipv6"
src_mac = "00:11:22:33:44:55"
dst_mac = "66:77:88:99:aa:bb"
src_ip = "2001:db8::1"
dst_ip = "2001:db8::2"
hop_limit = 32
payload_len = 128
count = 5000
"#
        ))
        .unwrap();

        assert_eq!(spec.payload_len, 128);
        assert_eq!(spec.count, 5000);
        assert_eq!(
            spec.l3,
            L3Spec::Ipv6 {
                src: "2001:db8::1".parse().unwrap(),
                dst: "2001:db8::2".parse().unwrap(),
                hop_limit: 32,
                next_header: DEFAULT_L4_PROTOCOL,
            }
        );
    }

    #[test]
    fn rejects_unknown_protocol() {
        let err = parse_stream(&format!(
            r#"{BASE}
[[tx.streams]]
protocol = "vxlan"
src_mac = "00:11:22:33:44:55"
dst_mac = "66:77:88:99:aa:bb"
src_ip = "10.0.0.1"
dst_ip = "10.0.0.2"
"#
        ))
        .unwrap_err();
        assert!(err.to_string().contains("unknown protocol"));
    }

    #[test]
    fn rejects_ipv6_address_for_ipv4_stream() {
        assert!(
            parse_stream(&format!(
                r#"{BASE}
[[tx.streams]]
protocol = "ipv4"
src_mac = "00:11:22:33:44:55"
dst_mac = "66:77:88:99:aa:bb"
src_ip = "2001:db8::1"
dst_ip = "10.0.0.2"
"#
            ))
            .is_err()
        );
    }

    #[test]
    fn rejects_oversized_payload_len() {
        let err = parse_stream(&format!(
            r#"{BASE}
[[tx.streams]]
protocol = "ipv4"
src_mac = "00:11:22:33:44:55"
dst_mac = "66:77:88:99:aa:bb"
src_ip = "10.0.0.1"
dst_ip = "10.0.0.2"
payload_len = 1501
"#
        ))
        .unwrap_err();
        assert!(err.to_string().contains("payload_len"));
    }

    #[test]
    fn parses_rate_pps() {
        let spec = parse_stream(&format!(
            r#"{BASE}
[[tx.streams]]
protocol = "ipv4"
src_mac = "00:11:22:33:44:55"
dst_mac = "66:77:88:99:aa:bb"
src_ip = "10.0.0.1"
dst_ip = "10.0.0.2"
rate_pps = 10000
"#
        ))
        .unwrap();
        assert_eq!(spec.rate, Some(Rate::Pps(10000)));
    }

    #[test]
    fn parses_rate_mbps_as_bps() {
        let spec = parse_stream(&format!(
            r#"{BASE}
[[tx.streams]]
protocol = "ipv4"
src_mac = "00:11:22:33:44:55"
dst_mac = "66:77:88:99:aa:bb"
src_ip = "10.0.0.1"
dst_ip = "10.0.0.2"
rate_mbps = 100.5
"#
        ))
        .unwrap();
        assert_eq!(spec.rate, Some(Rate::Bps(100_500_000)));
    }

    #[test]
    fn missing_rate_means_unlimited() {
        let spec = parse_stream(&format!(
            r#"{BASE}
[[tx.streams]]
protocol = "ipv4"
src_mac = "00:11:22:33:44:55"
dst_mac = "66:77:88:99:aa:bb"
src_ip = "10.0.0.1"
dst_ip = "10.0.0.2"
"#
        ))
        .unwrap();
        assert_eq!(spec.rate, None);
    }

    #[test]
    fn rejects_both_rate_units() {
        let err = parse_stream(&format!(
            r#"{BASE}
[[tx.streams]]
protocol = "ipv4"
src_mac = "00:11:22:33:44:55"
dst_mac = "66:77:88:99:aa:bb"
src_ip = "10.0.0.1"
dst_ip = "10.0.0.2"
rate_pps = 100
rate_mbps = 10.0
"#
        ))
        .unwrap_err();
        assert!(err.to_string().contains("mutually exclusive"));
    }

    #[test]
    fn rejects_zero_rate() {
        for rate in ["rate_pps = 0", "rate_mbps = 0.0", "rate_mbps = -1.0"] {
            let err = parse_stream(&format!(
                r#"{BASE}
[[tx.streams]]
protocol = "ipv4"
src_mac = "00:11:22:33:44:55"
dst_mac = "66:77:88:99:aa:bb"
src_ip = "10.0.0.1"
dst_ip = "10.0.0.2"
{rate}
"#
            ))
            .unwrap_err();
            assert!(err.to_string().contains("rate"), "{rate}: {err}");
        }
    }

    #[test]
    fn rejects_zero_count() {
        let err = parse_stream(&format!(
            r#"{BASE}
[[tx.streams]]
protocol = "ipv4"
src_mac = "00:11:22:33:44:55"
dst_mac = "66:77:88:99:aa:bb"
src_ip = "10.0.0.1"
dst_ip = "10.0.0.2"
count = 0
"#
        ))
        .unwrap_err();
        assert!(err.to_string().contains("count"));
    }

    #[test]
    fn rejects_oversized_vlan_vid() {
        assert!(
            parse_stream(&format!(
                r#"{BASE}
[[tx.streams]]
protocol = "ipv4"
vlan = 4096
src_mac = "00:11:22:33:44:55"
dst_mac = "66:77:88:99:aa:bb"
src_ip = "10.0.0.1"
dst_ip = "10.0.0.2"
"#
            ))
            .is_err()
        );
    }
}
