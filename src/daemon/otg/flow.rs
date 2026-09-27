//! Turns a parsed OTG [`model::Flow`] into a [`TxPattern`]: a
//! precomputed cycle of on-wire frames plus a duration and rate. The
//! actual frame bytes are built by [`StreamSpec::build_frame`], which
//! is otherwise untouched (and still used, unmodified, by one-shot
//! mode) -- daemon mode just calls it once per position of the
//! combined pattern cycle instead of once per stream.

use std::sync::Arc;

use anyhow::{Context, Result, bail, ensure};

use crate::{
    daemon::otg::{
        model::{self, ResolvedHeader},
        pattern::{self, Resolved},
    },
    proto::{
        arp::ArpOp,
        ether::{EtherHdr, MacAddr},
        ipv4::Ipv4Hdr,
        ipv6::Ipv6Hdr,
        stream::{L3Spec, Rate, StreamSpec},
        vlan::VlanTag,
    },
    worker::{
        stats::PortCounters,
        tx::{TxCount, TxPattern},
    },
};

/// Upper bound on the combined pattern cycle length (the LCM of every
/// varying header field's own period), to keep the precomputed frame
/// table bounded in size and build time.
const MAX_PATTERN_PERIOD: u64 = 65536;

/// A validated OTG `Flow`, resolved enough to know which port it
/// transmits from but not yet expanded into frames (that happens in
/// [`FlowConfig::expand`], once per `traffic.flow_transmit` start).
pub struct FlowConfig {
    pub name: String,
    pub tx_name: String,
    pub rx_names: Vec<String>,
    headers: Vec<ResolvedHeader>,
    size: model::Size,
    rate: Option<Rate>,
    count: TxCount,
}

impl TryFrom<model::Flow> for FlowConfig {
    type Error = anyhow::Error;

    fn try_from(f: model::Flow) -> Result<Self> {
        ensure!(
            f.tx_rx.choice == "port",
            "flow {:?}: tx_rx choice {:?} is not supported (only \"port\"; \
             pktflow does not emulate devices)",
            f.name,
            f.tx_rx.choice
        );
        let port = f.tx_rx.port.with_context(|| {
            format!(
                "flow {:?}: tx_rx choice \"port\" requires a \"port\" field",
                f.name
            )
        })?;
        ensure!(
            !f.packet.is_empty(),
            "flow {:?}: \"packet\" must not be empty",
            f.name
        );
        let headers = f
            .packet
            .into_iter()
            .map(ResolvedHeader::try_from)
            .collect::<Result<Vec<_>>>()
            .with_context(|| format!("flow {:?}", f.name))?;
        let rate = f.rate.map(Rate::try_from).transpose()?;
        let count = f
            .duration
            .map(TxCount::try_from)
            .transpose()?
            .unwrap_or(TxCount::Continuous);
        let size = f.size.unwrap_or(model::Size {
            choice: "fixed".into(),
            fixed: None,
        });
        Ok(Self {
            name: f.name,
            tx_name: port.tx_name,
            rx_names: port.rx_names,
            headers,
            size,
            rate,
            count,
        })
    }
}

fn combine_period(period: u64, resolved_len: usize, name: &str) -> Result<u64> {
    let combined = pattern::lcm(period, resolved_len as u64)
        .with_context(|| format!("flow {name:?}: combined pattern period overflowed"))?;
    ensure!(
        combined <= MAX_PATTERN_PERIOD,
        "flow {name:?}: combined pattern period {combined} exceeds the limit of {MAX_PATTERN_PERIOD}"
    );
    Ok(combined)
}

impl FlowConfig {
    /// Builds the precomputed frame cycle and wraps it, together with
    /// this flow's rate/duration, into a [`TxPattern`] ready to hand to
    /// a `TxWorker`.
    pub fn expand(&self, flow_counters: Arc<PortCounters>) -> Result<TxPattern> {
        let mut ethernet = None;
        let mut vlan = None;
        let mut l3 = None;
        for h in &self.headers {
            match h {
                ResolvedHeader::Ethernet { .. } => {
                    ensure!(
                        ethernet.is_none(),
                        "flow {:?}: more than one ethernet header",
                        self.name
                    );
                    ethernet = Some(h);
                }
                ResolvedHeader::Vlan { .. } => {
                    ensure!(
                        vlan.is_none(),
                        "flow {:?}: more than one vlan header",
                        self.name
                    );
                    vlan = Some(h);
                }
                ResolvedHeader::Ipv4 { .. }
                | ResolvedHeader::Ipv6 { .. }
                | ResolvedHeader::Arp { .. } => {
                    ensure!(
                        l3.is_none(),
                        "flow {:?}: more than one ipv4/ipv6/arp header",
                        self.name
                    );
                    l3 = Some(h);
                }
            }
        }
        let Some(ResolvedHeader::Ethernet { dst, src }) = ethernet else {
            bail!(
                "flow {:?}: \"packet\" must include an ethernet header",
                self.name
            );
        };
        let l3 = l3.with_context(|| {
            format!(
                "flow {:?}: \"packet\" must include one of ipv4, ipv6, arp",
                self.name
            )
        })?;

        let dst_r = dst.resolve()?;
        let src_r = src.resolve()?;
        let mut period = pattern::lcm(dst_r.period() as u64, src_r.period() as u64)
            .with_context(|| format!("flow {:?}: combined pattern period overflowed", self.name))?;

        let vlan_id_r: Option<Resolved<u16>> = match vlan {
            Some(ResolvedHeader::Vlan { id }) => {
                let r = id.resolve()?;
                period = combine_period(period, r.period(), &self.name)?;
                Some(r)
            }
            _ => None,
        };
        let vlan_len = if vlan_id_r.is_some() { VlanTag::LEN } else { 0 };

        let frame_len = self.size.fixed_len()?;
        let l2_len = EtherHdr::LEN + vlan_len;
        let build = |src_mac: MacAddr,
                     dst_mac: MacAddr,
                     vlan_vid: Option<u16>,
                     l3: L3Spec,
                     payload_len: usize| {
            StreamSpec {
                src_mac,
                dst_mac,
                vlan: vlan_vid,
                l3,
                payload_len,
                count: 1,
                rate: None,
            }
            .build_frame()
        };

        let frames: Vec<Vec<u8>> = match l3 {
            ResolvedHeader::Ipv4 {
                src,
                dst,
                ttl,
                protocol,
            } => {
                let ip_src_r = src.resolve()?;
                let ip_dst_r = dst.resolve()?;
                let ttl_r = ttl.resolve()?;
                let proto_r = protocol.resolve()?;
                for p in [
                    ip_src_r.period(),
                    ip_dst_r.period(),
                    ttl_r.period(),
                    proto_r.period(),
                ] {
                    period = combine_period(period, p, &self.name)?;
                }
                let payload_len = (frame_len as usize)
                    .checked_sub(4 /* FCS */ + l2_len + Ipv4Hdr::LEN)
                    .with_context(|| {
                        format!(
                            "flow {:?}: size.fixed ({frame_len}) is too small for its headers",
                            self.name
                        )
                    })?;
                (0..period)
                    .map(|i| {
                        let i = i as usize;
                        build(
                            src_r.at(i),
                            dst_r.at(i),
                            vlan_id_r.as_ref().map(|v| v.at(i)),
                            L3Spec::Ipv4 {
                                src: ip_src_r.at(i),
                                dst: ip_dst_r.at(i),
                                ttl: ttl_r.at(i),
                                protocol: proto_r.at(i),
                            },
                            payload_len,
                        )
                    })
                    .collect()
            }
            ResolvedHeader::Ipv6 {
                src,
                dst,
                hop_limit,
                next_header,
            } => {
                let ip_src_r = src.resolve()?;
                let ip_dst_r = dst.resolve()?;
                let hop_r = hop_limit.resolve()?;
                let next_r = next_header.resolve()?;
                for p in [
                    ip_src_r.period(),
                    ip_dst_r.period(),
                    hop_r.period(),
                    next_r.period(),
                ] {
                    period = combine_period(period, p, &self.name)?;
                }
                let payload_len = (frame_len as usize)
                    .checked_sub(4 /* FCS */ + l2_len + Ipv6Hdr::LEN)
                    .with_context(|| {
                        format!(
                            "flow {:?}: size.fixed ({frame_len}) is too small for its headers",
                            self.name
                        )
                    })?;
                (0..period)
                    .map(|i| {
                        let i = i as usize;
                        build(
                            src_r.at(i),
                            dst_r.at(i),
                            vlan_id_r.as_ref().map(|v| v.at(i)),
                            L3Spec::Ipv6 {
                                src: ip_src_r.at(i),
                                dst: ip_dst_r.at(i),
                                hop_limit: hop_r.at(i),
                                next_header: next_r.at(i),
                            },
                            payload_len,
                        )
                    })
                    .collect()
            }
            ResolvedHeader::Arp {
                operation,
                sender_protocol_addr,
                target_protocol_addr,
            } => {
                let op_r = operation.resolve()?;
                let sender_r = sender_protocol_addr.resolve()?;
                let target_r = target_protocol_addr.resolve()?;
                for p in [op_r.period(), sender_r.period(), target_r.period()] {
                    period = combine_period(period, p, &self.name)?;
                }
                // ArpHdr's on-wire length is fixed; Flow.size does not
                // apply to ARP (matching the one-shot [[tx.streams]]
                // behavior, where payload_len is likewise ignored).
                (0..period)
                    .map(|i| -> Result<Vec<u8>> {
                        let i = i as usize;
                        let op = match op_r.at(i) {
                            1 => ArpOp::REQUEST,
                            2 => ArpOp::REPLY,
                            other => bail!(
                                "flow {:?}: unsupported arp operation {other} (expected 1=request or 2=reply)",
                                self.name
                            ),
                        };
                        Ok(build(
                            src_r.at(i),
                            dst_r.at(i),
                            vlan_id_r.as_ref().map(|v| v.at(i)),
                            L3Spec::Arp {
                                op,
                                sender_ip: sender_r.at(i),
                                target_ip: target_r.at(i),
                            },
                            0,
                        ))
                    })
                    .collect::<Result<Vec<_>>>()?
            }
            ResolvedHeader::Ethernet { .. } | ResolvedHeader::Vlan { .. } => unreachable!(
                "ethernet/vlan headers are consumed above, never seen as the l3 header"
            ),
        };

        Ok(TxPattern::cycle(
            frames,
            self.count,
            self.rate,
            flow_counters,
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::daemon::otg::pattern::Pattern;

    fn ethernet(src: [u8; 6], dst: [u8; 6]) -> ResolvedHeader {
        ResolvedHeader::Ethernet {
            dst: Pattern::Value(MacAddr::new(dst)),
            src: Pattern::Value(MacAddr::new(src)),
        }
    }

    fn base_flow(headers: Vec<ResolvedHeader>) -> FlowConfig {
        FlowConfig {
            name: "f1".into(),
            tx_name: "p1".into(),
            rx_names: vec![],
            headers,
            size: model::Size {
                choice: "fixed".into(),
                fixed: Some(64),
            },
            rate: None,
            count: TxCount::Fixed(1),
        }
    }

    #[test]
    fn expands_a_fixed_ipv4_flow_to_a_single_frame_matching_stream_spec() {
        let flow = base_flow(vec![
            ethernet(
                [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
                [0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB],
            ),
            ResolvedHeader::Ipv4 {
                src: Pattern::Value(Ipv4Addr::new(10, 0, 0, 1)),
                dst: Pattern::Value(Ipv4Addr::new(10, 0, 0, 2)),
                ttl: Pattern::Value(64),
                protocol: Pattern::Value(17),
            },
        ]);
        let pattern = flow.expand(Arc::new(PortCounters::new())).unwrap();
        let expected = StreamSpec {
            src_mac: MacAddr::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            dst_mac: MacAddr::new([0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB]),
            vlan: None,
            l3: L3Spec::Ipv4 {
                src: Ipv4Addr::new(10, 0, 0, 1),
                dst: Ipv4Addr::new(10, 0, 0, 2),
                ttl: 64,
                protocol: 17,
            },
            payload_len: 64 - 4 - EtherHdr::LEN - Ipv4Hdr::LEN,
            count: 1,
            rate: None,
        }
        .build_frame();
        assert_eq!(pattern.frame_count(), 1);
        assert_eq!(pattern.frame_at(0), expected.as_slice());
    }

    #[test]
    fn combines_periods_of_independent_incrementing_fields() {
        let flow = base_flow(vec![
            ethernet([0; 6], [0xFF; 6]),
            ResolvedHeader::Ipv4 {
                src: Pattern::Increment {
                    start: Ipv4Addr::new(10, 0, 0, 1),
                    step: Ipv4Addr::new(0, 0, 0, 1),
                    count: 4,
                },
                dst: Pattern::Value(Ipv4Addr::new(10, 0, 0, 2)),
                ttl: Pattern::Value(64),
                protocol: Pattern::Value(17),
            },
        ]);
        let pattern = flow.expand(Arc::new(PortCounters::new())).unwrap();
        // src cycles over 4 values, everything else is fixed: period 4.
        assert_eq!(pattern.frame_count(), 4);
    }

    #[test]
    fn rejects_a_flow_without_an_l3_header() {
        let flow = base_flow(vec![ethernet([0; 6], [0xFF; 6])]);
        let err = flow.expand(Arc::new(PortCounters::new())).unwrap_err();
        assert!(err.to_string().contains("ipv4, ipv6, arp"));
    }

    #[test]
    fn rejects_a_frame_size_too_small_for_its_headers() {
        let mut flow = base_flow(vec![
            ethernet([0; 6], [0xFF; 6]),
            ResolvedHeader::Ipv4 {
                src: Pattern::Value(Ipv4Addr::new(10, 0, 0, 1)),
                dst: Pattern::Value(Ipv4Addr::new(10, 0, 0, 2)),
                ttl: Pattern::Value(64),
                protocol: Pattern::Value(17),
            },
        ]);
        flow.size.fixed = Some(1);
        let err = flow.expand(Arc::new(PortCounters::new())).unwrap_err();
        assert!(err.to_string().contains("too small"));
    }
}
