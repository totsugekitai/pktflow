use std::net::{Ipv4Addr, Ipv6Addr};

use crate::proto::{
    arp::{ArpHdr, ArpOp},
    ether::{EtherHdr, EtherType, MacAddr},
    ipv4::Ipv4Hdr,
    ipv6::Ipv6Hdr,
    vlan::VlanTag,
};

/// L3 part of a transmit stream. The L4 part is a zero-filled dummy payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L3Spec {
    Arp {
        op: ArpOp,
        sender_ip: Ipv4Addr,
        target_ip: Ipv4Addr,
    },
    Ipv4 {
        src: Ipv4Addr,
        dst: Ipv4Addr,
        ttl: u8,
        protocol: u8,
    },
    Ipv6 {
        src: Ipv6Addr,
        dst: Ipv6Addr,
        hop_limit: u8,
        next_header: u8,
    },
}

/// Target transmit rate of a stream. `Bps` counts the bits of the L2
/// frame as built (FCS, preamble and IFG excluded), so the achieved
/// rate matches the byte counters reported by the stats API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rate {
    /// Frames per second.
    Pps(u64),
    /// Bits per second.
    Bps(u64),
}

impl Rate {
    /// Resolves the rate into frames per second for frames of
    /// `frame_len` bytes. May be fractional for low bit rates.
    pub fn to_pps(self, frame_len: usize) -> f64 {
        match self {
            Rate::Pps(pps) => pps as f64,
            Rate::Bps(bps) => bps as f64 / (frame_len as f64 * 8.0),
        }
    }
}

/// Specification of one transmit stream, resolved from the TOML config.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamSpec {
    pub src_mac: MacAddr,
    pub dst_mac: MacAddr,
    /// 802.1Q VID; when set, a VLAN tag is inserted after the Ethernet header.
    pub vlan: Option<u16>,
    pub l3: L3Spec,
    /// Dummy payload length appended after the L3 header (ignored for ARP).
    pub payload_len: usize,
    /// Number of frames to transmit for this stream.
    pub count: u64,
    /// Target transmit rate; `None` sends at full speed.
    pub rate: Option<Rate>,
}

impl StreamSpec {
    /// Builds the on-wire frame. Intended to be called once at worker startup,
    /// not in the transmit hot path.
    pub fn build_frame(&self) -> Vec<u8> {
        let l3 = self.build_l3();
        let (ether_type, payload) = match self.vlan {
            Some(vid) => {
                let tag = VlanTag::new(0, false, vid, self.l3.ether_type());
                let mut payload = vec![0u8; VlanTag::LEN + l3.len()];
                tag.write_to(&mut payload[..VlanTag::LEN]);
                payload[VlanTag::LEN..].copy_from_slice(&l3);
                (EtherType::VLAN, payload)
            }
            None => (self.l3.ether_type(), l3),
        };
        let hdr = EtherHdr::new(self.dst_mac, self.src_mac, ether_type);
        let mut frame = vec![0u8; EtherHdr::LEN + payload.len()];
        hdr.write_to(&mut frame, &payload);
        frame
    }

    fn build_l3(&self) -> Vec<u8> {
        match self.l3 {
            L3Spec::Arp {
                op,
                sender_ip,
                target_ip,
            } => {
                // In a request the target MAC is unknown, so it stays zero.
                let target_mac = if op == ArpOp::REQUEST {
                    MacAddr::new([0; 6])
                } else {
                    self.dst_mac
                };
                let hdr = ArpHdr::new(op, self.src_mac, sender_ip, target_mac, target_ip);
                let mut buf = vec![0u8; ArpHdr::LEN];
                hdr.write_to(&mut buf);
                buf
            }
            L3Spec::Ipv4 {
                src,
                dst,
                ttl,
                protocol,
            } => {
                let total_len = u16::try_from(Ipv4Hdr::LEN + self.payload_len)
                    .expect("payload_len is validated at config load");
                let hdr = Ipv4Hdr::new(total_len, 0, ttl, protocol, src, dst);
                let mut buf = vec![0u8; total_len as usize];
                hdr.write_to(&mut buf[..Ipv4Hdr::LEN]);
                buf
            }
            L3Spec::Ipv6 {
                src,
                dst,
                hop_limit,
                next_header,
            } => {
                let payload_len = u16::try_from(self.payload_len)
                    .expect("payload_len is validated at config load");
                let hdr = Ipv6Hdr::new(payload_len, next_header, hop_limit, src, dst);
                let mut buf = vec![0u8; Ipv6Hdr::LEN + self.payload_len];
                hdr.write_to(&mut buf[..Ipv6Hdr::LEN]);
                buf
            }
        }
    }
}

impl L3Spec {
    fn ether_type(&self) -> EtherType {
        match self {
            Self::Arp { .. } => EtherType::ARP,
            Self::Ipv4 { .. } => EtherType::IPV4,
            Self::Ipv6 { .. } => EtherType::IPV6,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::proto::ether::EtherFrame;

    use super::*;

    const SRC_MAC: MacAddr = MacAddr::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    const DST_MAC: MacAddr = MacAddr::new([0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB]);

    #[test]
    fn rate_resolves_to_pps() {
        assert_eq!(Rate::Pps(100).to_pps(1000), 100.0);
        // 8000 bits/s over 100-byte (800-bit) frames = 10 frames/s.
        assert_eq!(Rate::Bps(8_000).to_pps(100), 10.0);
    }

    #[test]
    fn builds_ipv4_frame() {
        let spec = StreamSpec {
            src_mac: SRC_MAC,
            dst_mac: DST_MAC,
            vlan: None,
            l3: L3Spec::Ipv4 {
                src: Ipv4Addr::new(10, 0, 0, 1),
                dst: Ipv4Addr::new(10, 0, 0, 2),
                ttl: 64,
                protocol: 17,
            },
            payload_len: 64,
            count: 1,
            rate: None,
        };

        let frame = spec.build_frame();
        assert_eq!(frame.len(), EtherHdr::LEN + Ipv4Hdr::LEN + 64);

        let ether = EtherFrame::parse(&frame).unwrap();
        assert_eq!(ether.src_mac, SRC_MAC);
        assert_eq!(ether.dst_mac, DST_MAC);
        assert_eq!(ether.ether_type, EtherType::IPV4);

        let ip = Ipv4Hdr::parse(ether.payload).unwrap();
        assert_eq!(ip.total_len as usize, Ipv4Hdr::LEN + 64);
        assert_eq!(ip.ttl, 64);
        assert_eq!(ip.protocol, 17);
        assert_eq!(ip.src, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(ip.dst, Ipv4Addr::new(10, 0, 0, 2));
    }

    #[test]
    fn builds_arp_request_frame_with_zero_target_mac() {
        let spec = StreamSpec {
            src_mac: SRC_MAC,
            dst_mac: DST_MAC,
            vlan: None,
            l3: L3Spec::Arp {
                op: ArpOp::REQUEST,
                sender_ip: Ipv4Addr::new(10, 0, 0, 1),
                target_ip: Ipv4Addr::new(10, 0, 0, 2),
            },
            payload_len: 64, // ignored for ARP
            count: 1,
            rate: None,
        };

        let frame = spec.build_frame();
        assert_eq!(frame.len(), EtherHdr::LEN + ArpHdr::LEN);

        let ether = EtherFrame::parse(&frame).unwrap();
        assert_eq!(ether.ether_type, EtherType::ARP);

        let arp = ArpHdr::parse(ether.payload).unwrap();
        assert_eq!(arp.op, ArpOp::REQUEST);
        assert_eq!(arp.sender_mac, SRC_MAC);
        assert_eq!(arp.target_mac, MacAddr::new([0; 6]));
        assert_eq!(arp.target_ip, Ipv4Addr::new(10, 0, 0, 2));
    }

    #[test]
    fn builds_arp_reply_frame_with_dst_target_mac() {
        let spec = StreamSpec {
            src_mac: SRC_MAC,
            dst_mac: DST_MAC,
            vlan: None,
            l3: L3Spec::Arp {
                op: ArpOp::REPLY,
                sender_ip: Ipv4Addr::new(10, 0, 0, 1),
                target_ip: Ipv4Addr::new(10, 0, 0, 2),
            },
            payload_len: 0,
            count: 1,
            rate: None,
        };

        let frame = spec.build_frame();
        let ether = EtherFrame::parse(&frame).unwrap();
        let arp = ArpHdr::parse(ether.payload).unwrap();
        assert_eq!(arp.op, ArpOp::REPLY);
        assert_eq!(arp.target_mac, DST_MAC);
    }

    #[test]
    fn builds_vlan_tagged_ipv6_frame() {
        let src: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let dst: Ipv6Addr = "2001:db8::2".parse().unwrap();
        let spec = StreamSpec {
            src_mac: SRC_MAC,
            dst_mac: DST_MAC,
            vlan: Some(100),
            l3: L3Spec::Ipv6 {
                src,
                dst,
                hop_limit: 64,
                next_header: 17,
            },
            payload_len: 32,
            count: 1,
            rate: None,
        };

        let frame = spec.build_frame();
        assert_eq!(
            frame.len(),
            EtherHdr::LEN + VlanTag::LEN + Ipv6Hdr::LEN + 32
        );

        let ether = EtherFrame::parse(&frame).unwrap();
        assert_eq!(ether.ether_type, EtherType::VLAN);

        let tag = VlanTag::parse(ether.payload).unwrap();
        assert_eq!(tag.vid, 100);
        assert_eq!(tag.inner_ether_type, EtherType::IPV6);

        let ip = Ipv6Hdr::parse(&ether.payload[VlanTag::LEN..]).unwrap();
        assert_eq!(ip.payload_len, 32);
        assert_eq!(ip.src, src);
        assert_eq!(ip.dst, dst);
    }
}
