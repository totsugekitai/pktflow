use std::{fmt, str::FromStr};

use anyhow::{Context, anyhow, ensure};

#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MacAddr([u8; 6]);

impl MacAddr {
    pub const fn new(octets: [u8; 6]) -> Self {
        Self(octets)
    }

    pub const fn octets(&self) -> [u8; 6] {
        self.0
    }
}

impl From<[u8; 6]> for MacAddr {
    fn from(octets: [u8; 6]) -> Self {
        Self(octets)
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, g] = self.0;
        write!(f, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{g:02x}")
    }
}

impl FromStr for MacAddr {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut octets = [0u8; 6];
        let mut parts = s.split(':');
        for octet in octets.iter_mut() {
            let part = parts
                .next()
                .ok_or_else(|| anyhow!("MAC address {s:?} has fewer than 6 octets"))?;
            *octet = u8::from_str_radix(part, 16)
                .with_context(|| format!("invalid hex octet {part:?} in MAC address {s:?}"))?;
        }
        ensure!(
            parts.next().is_none(),
            "MAC address {s:?} has more than 6 octets"
        );
        Ok(Self(octets))
    }
}

#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EtherType(pub u16);

impl EtherType {
    pub const IPV4: Self = Self(0x0800);
    pub const ARP: Self = Self(0x0806);
    pub const VLAN: Self = Self(0x8100);
    pub const IPV6: Self = Self(0x86DD);

    pub const fn value(self) -> u16 {
        self.0
    }
}

impl From<u16> for EtherType {
    fn from(value: u16) -> Self {
        Self(value)
    }
}

impl fmt::Display for EtherType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:04x}", self.0)
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EtherHdr {
    pub dst_addr: MacAddr,
    pub src_addr: MacAddr,
    pub ether_type: EtherType,
}

impl EtherHdr {
    /// On-wire length of the Ethernet header in bytes.
    pub const LEN: usize = size_of::<Self>();

    pub const fn new(dst_addr: MacAddr, src_addr: MacAddr, ether_type: EtherType) -> Self {
        Self {
            dst_addr,
            src_addr,
            ether_type,
        }
    }

    /// Writes the header followed by `payload` into `buf`, whose length must
    /// be exactly `EtherHdr::LEN + payload.len()`.
    pub fn write_to(&self, buf: &mut [u8], payload: &[u8]) {
        assert_eq!(
            buf.len(),
            Self::LEN + payload.len(),
            "buffer length must match Ethernet header + payload length"
        );
        buf[0..6].copy_from_slice(&self.dst_addr.octets());
        buf[6..12].copy_from_slice(&self.src_addr.octets());
        buf[12..14].copy_from_slice(&self.ether_type.value().to_be_bytes());
        buf[14..].copy_from_slice(payload);
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct EtherFrame<'a> {
    pub dst_mac: MacAddr,
    pub src_mac: MacAddr,
    pub ether_type: EtherType,
    pub payload: &'a [u8],
}

impl<'a> EtherFrame<'a> {
    /// Parses an Ethernet frame. Returns `None` if `frame` is shorter than
    /// the Ethernet header.
    pub fn parse(frame: &'a [u8]) -> Option<Self> {
        if frame.len() < EtherHdr::LEN {
            return None;
        }
        Some(Self {
            dst_mac: MacAddr::new(frame[0..6].try_into().unwrap()),
            src_mac: MacAddr::new(frame[6..12].try_into().unwrap()),
            ether_type: EtherType(u16::from_be_bytes(frame[12..14].try_into().unwrap())),
            payload: &frame[14..],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ether_hdr_len_matches_wire_format() {
        assert_eq!(EtherHdr::LEN, 14);
    }

    #[test]
    fn ether_type_constants_match_iana_values() {
        assert_eq!(EtherType::IPV4.value(), 0x0800);
        assert_eq!(EtherType::ARP.value(), 0x0806);
        assert_eq!(EtherType::VLAN.value(), 0x8100);
        assert_eq!(EtherType::IPV6.value(), 0x86DD);
    }

    #[test]
    fn mac_addr_displays_as_colon_separated_hex() {
        let mac = MacAddr::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert_eq!(mac.to_string(), "00:11:22:33:44:55");
    }

    #[test]
    fn mac_addr_parses_from_str() {
        let mac: MacAddr = "66:77:88:99:aa:BB".parse().unwrap();
        assert_eq!(mac.octets(), [0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB]);
    }

    #[test]
    fn mac_addr_rejects_wrong_octet_count() {
        assert!("00:11:22:33:44".parse::<MacAddr>().is_err());
        assert!("00:11:22:33:44:55:66".parse::<MacAddr>().is_err());
    }

    #[test]
    fn mac_addr_rejects_invalid_hex() {
        assert!("00:11:22:33:44:GG".parse::<MacAddr>().is_err());
    }

    #[test]
    fn write_to_lays_out_fields_in_order() {
        let hdr = EtherHdr::new(
            MacAddr::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            MacAddr::new([0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB]),
            EtherType::IPV4,
        );
        let payload = b"Hello, DPDK! 1";
        let mut buf = vec![0u8; EtherHdr::LEN + payload.len()];

        hdr.write_to(&mut buf, payload);

        assert_eq!(&buf[0..6], &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert_eq!(&buf[6..12], &[0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB]);
        assert_eq!(&buf[12..14], &[0x08, 0x00]);
        assert_eq!(&buf[14..], payload);
    }

    #[test]
    fn write_to_accepts_empty_payload() {
        let hdr = EtherHdr::new(
            MacAddr::new([0; 6]),
            MacAddr::new([0xFF; 6]),
            EtherType::IPV6,
        );
        let mut buf = vec![0u8; EtherHdr::LEN];
        hdr.write_to(&mut buf, &[]);
        assert_eq!(&buf[12..14], &[0x86, 0xDD]);
    }

    #[test]
    #[should_panic(expected = "buffer length must match")]
    fn write_to_rejects_mismatched_buffer() {
        let hdr = EtherHdr::new(MacAddr::new([0; 6]), MacAddr::new([0; 6]), EtherType::IPV4);
        let mut buf = vec![0u8; EtherHdr::LEN];
        hdr.write_to(&mut buf, b"payload");
    }

    #[test]
    fn parse_splits_fields() {
        let hdr = EtherHdr::new(
            MacAddr::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            MacAddr::new([0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB]),
            EtherType::IPV4,
        );
        let payload = b"Hello, DPDK! 1";
        let mut frame = vec![0u8; EtherHdr::LEN + payload.len()];
        hdr.write_to(&mut frame, payload);

        let parsed = EtherFrame::parse(&frame).unwrap();
        assert_eq!(parsed.dst_mac, hdr.dst_addr);
        assert_eq!(parsed.src_mac, hdr.src_addr);
        assert_eq!(parsed.ether_type, EtherType::IPV4);
        assert_eq!(parsed.payload, payload);
    }

    #[test]
    fn parse_accepts_header_only_frame() {
        let frame = [0u8; EtherHdr::LEN];
        let parsed = EtherFrame::parse(&frame).unwrap();
        assert_eq!(parsed.ether_type, EtherType(0x0000));
        assert!(parsed.payload.is_empty());
    }

    #[test]
    fn parse_rejects_short_frame() {
        let frame = [0u8; EtherHdr::LEN - 1];
        assert_eq!(EtherFrame::parse(&frame), None);
    }
}
