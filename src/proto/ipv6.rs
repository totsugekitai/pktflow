use std::net::Ipv6Addr;

/// IPv6 header (version=6, traffic class=0, flow label=0).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6Hdr {
    pub payload_len: u16,
    pub next_header: u8,
    pub hop_limit: u8,
    pub src: Ipv6Addr,
    pub dst: Ipv6Addr,
}

impl Ipv6Hdr {
    /// On-wire length of the IPv6 header in bytes.
    pub const LEN: usize = 40;

    const VERSION: u8 = 6;

    pub const fn new(
        payload_len: u16,
        next_header: u8,
        hop_limit: u8,
        src: Ipv6Addr,
        dst: Ipv6Addr,
    ) -> Self {
        Self {
            payload_len,
            next_header,
            hop_limit,
            src,
            dst,
        }
    }

    /// Writes the header into `buf`, whose length must be exactly
    /// `Ipv6Hdr::LEN`.
    pub fn write_to(&self, buf: &mut [u8]) {
        assert_eq!(
            buf.len(),
            Self::LEN,
            "buffer length must match IPv6 header length"
        );
        buf[0..4].copy_from_slice(&[Self::VERSION << 4, 0, 0, 0]); // version/TC/flow label
        buf[4..6].copy_from_slice(&self.payload_len.to_be_bytes());
        buf[6] = self.next_header;
        buf[7] = self.hop_limit;
        buf[8..24].copy_from_slice(&self.src.octets());
        buf[24..40].copy_from_slice(&self.dst.octets());
    }

    /// Parses an IPv6 header. Returns `None` if `buf` is shorter than the
    /// header or the version field is not 6.
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::LEN || buf[0] >> 4 != Self::VERSION {
            return None;
        }
        Some(Self {
            payload_len: u16::from_be_bytes(buf[4..6].try_into().unwrap()),
            next_header: buf[6],
            hop_limit: buf[7],
            src: Ipv6Addr::from(<[u8; 16]>::try_from(&buf[8..24]).unwrap()),
            dst: Ipv6Addr::from(<[u8; 16]>::try_from(&buf[24..40]).unwrap()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_hdr() -> Ipv6Hdr {
        Ipv6Hdr::new(
            64,
            17,
            64,
            "2001:db8::1".parse().unwrap(),
            "2001:db8::2".parse().unwrap(),
        )
    }

    #[test]
    fn ipv6_hdr_len_matches_wire_format() {
        assert_eq!(Ipv6Hdr::LEN, 40);
    }

    #[test]
    fn write_to_lays_out_fields_in_order() {
        let mut buf = [0u8; Ipv6Hdr::LEN];
        sample_hdr().write_to(&mut buf);
        assert_eq!(&buf[0..4], &[0x60, 0x00, 0x00, 0x00]);
        assert_eq!(&buf[4..6], &[0x00, 0x40]); // payload_len = 64
        assert_eq!(buf[6], 17);
        assert_eq!(buf[7], 64);
        assert_eq!(&buf[8..10], &[0x20, 0x01]);
        assert_eq!(buf[23], 0x01);
        assert_eq!(buf[39], 0x02);
    }

    #[test]
    fn parse_round_trips() {
        let hdr = sample_hdr();
        let mut buf = [0u8; Ipv6Hdr::LEN];
        hdr.write_to(&mut buf);
        assert_eq!(Ipv6Hdr::parse(&buf), Some(hdr));
    }

    #[test]
    fn parse_rejects_short_buffer() {
        assert_eq!(Ipv6Hdr::parse(&[0u8; Ipv6Hdr::LEN - 1]), None);
    }

    #[test]
    fn parse_rejects_wrong_version() {
        let mut buf = [0u8; Ipv6Hdr::LEN];
        sample_hdr().write_to(&mut buf);
        buf[0] = 0x45;
        assert_eq!(Ipv6Hdr::parse(&buf), None);
    }
}
