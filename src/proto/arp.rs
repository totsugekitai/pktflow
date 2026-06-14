use std::{fmt, net::Ipv4Addr};

use crate::proto::ether::{EtherType, MacAddr};

#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArpOp(pub u16);

impl ArpOp {
    pub const REQUEST: Self = Self(1);
    pub const REPLY: Self = Self(2);

    pub const fn value(self) -> u16 {
        self.0
    }
}

impl fmt::Display for ArpOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// ARP packet for Ethernet/IPv4 (htype=1, ptype=0x0800, hlen=6, plen=4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArpHdr {
    pub op: ArpOp,
    pub sender_mac: MacAddr,
    pub sender_ip: Ipv4Addr,
    pub target_mac: MacAddr,
    pub target_ip: Ipv4Addr,
}

impl ArpHdr {
    /// On-wire length of an Ethernet/IPv4 ARP packet in bytes.
    pub const LEN: usize = 28;

    const HTYPE_ETHERNET: u16 = 1;
    const HLEN_ETHERNET: u8 = 6;
    const PLEN_IPV4: u8 = 4;

    pub const fn new(
        op: ArpOp,
        sender_mac: MacAddr,
        sender_ip: Ipv4Addr,
        target_mac: MacAddr,
        target_ip: Ipv4Addr,
    ) -> Self {
        Self {
            op,
            sender_mac,
            sender_ip,
            target_mac,
            target_ip,
        }
    }

    /// Writes the packet into `buf`, whose length must be exactly `ArpHdr::LEN`.
    pub fn write_to(&self, buf: &mut [u8]) {
        assert_eq!(
            buf.len(),
            Self::LEN,
            "buffer length must match ARP packet length"
        );
        buf[0..2].copy_from_slice(&Self::HTYPE_ETHERNET.to_be_bytes());
        buf[2..4].copy_from_slice(&EtherType::IPV4.value().to_be_bytes());
        buf[4] = Self::HLEN_ETHERNET;
        buf[5] = Self::PLEN_IPV4;
        buf[6..8].copy_from_slice(&self.op.value().to_be_bytes());
        buf[8..14].copy_from_slice(&self.sender_mac.octets());
        buf[14..18].copy_from_slice(&self.sender_ip.octets());
        buf[18..24].copy_from_slice(&self.target_mac.octets());
        buf[24..28].copy_from_slice(&self.target_ip.octets());
    }

    /// Parses an Ethernet/IPv4 ARP packet. Returns `None` if `buf` is too
    /// short or the fixed htype/ptype/hlen/plen fields do not match.
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::LEN {
            return None;
        }
        let htype = u16::from_be_bytes(buf[0..2].try_into().unwrap());
        let ptype = u16::from_be_bytes(buf[2..4].try_into().unwrap());
        if htype != Self::HTYPE_ETHERNET
            || ptype != EtherType::IPV4.value()
            || buf[4] != Self::HLEN_ETHERNET
            || buf[5] != Self::PLEN_IPV4
        {
            return None;
        }
        Some(Self {
            op: ArpOp(u16::from_be_bytes(buf[6..8].try_into().unwrap())),
            sender_mac: MacAddr::new(buf[8..14].try_into().unwrap()),
            sender_ip: Ipv4Addr::from(<[u8; 4]>::try_from(&buf[14..18]).unwrap()),
            target_mac: MacAddr::new(buf[18..24].try_into().unwrap()),
            target_ip: Ipv4Addr::from(<[u8; 4]>::try_from(&buf[24..28]).unwrap()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_hdr() -> ArpHdr {
        ArpHdr::new(
            ArpOp::REQUEST,
            MacAddr::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            Ipv4Addr::new(10, 0, 0, 1),
            MacAddr::new([0x00; 6]),
            Ipv4Addr::new(10, 0, 0, 2),
        )
    }

    #[test]
    fn arp_hdr_len_matches_wire_format() {
        assert_eq!(ArpHdr::LEN, 28);
    }

    #[test]
    fn write_to_lays_out_fields_in_order() {
        let mut buf = [0u8; ArpHdr::LEN];
        sample_hdr().write_to(&mut buf);
        assert_eq!(&buf[0..2], &[0x00, 0x01]); // htype: Ethernet
        assert_eq!(&buf[2..4], &[0x08, 0x00]); // ptype: IPv4
        assert_eq!(buf[4], 6); // hlen
        assert_eq!(buf[5], 4); // plen
        assert_eq!(&buf[6..8], &[0x00, 0x01]); // op: request
        assert_eq!(&buf[8..14], &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert_eq!(&buf[14..18], &[10, 0, 0, 1]);
        assert_eq!(&buf[18..24], &[0x00; 6]);
        assert_eq!(&buf[24..28], &[10, 0, 0, 2]);
    }

    #[test]
    fn parse_round_trips() {
        let hdr = sample_hdr();
        let mut buf = [0u8; ArpHdr::LEN];
        hdr.write_to(&mut buf);
        assert_eq!(ArpHdr::parse(&buf), Some(hdr));
    }

    #[test]
    fn parse_rejects_short_buffer() {
        assert_eq!(ArpHdr::parse(&[0u8; ArpHdr::LEN - 1]), None);
    }

    #[test]
    fn parse_rejects_non_ethernet_ipv4_arp() {
        let mut buf = [0u8; ArpHdr::LEN];
        sample_hdr().write_to(&mut buf);
        buf[1] = 6; // htype: IEEE 802
        assert_eq!(ArpHdr::parse(&buf), None);
    }
}
