use std::net::Ipv4Addr;

/// IPv4 header without options (version=4, ihl=5, dscp/ecn=0, flags/frag=0).
/// The header checksum is computed on write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Hdr {
    pub total_len: u16,
    pub id: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
}

impl Ipv4Hdr {
    /// On-wire length of the option-less IPv4 header in bytes.
    pub const LEN: usize = 20;

    const VERSION_IHL: u8 = 0x45;

    pub const fn new(
        total_len: u16,
        id: u16,
        ttl: u8,
        protocol: u8,
        src: Ipv4Addr,
        dst: Ipv4Addr,
    ) -> Self {
        Self {
            total_len,
            id,
            ttl,
            protocol,
            src,
            dst,
        }
    }

    /// Writes the header (with computed checksum) into `buf`, whose length
    /// must be exactly `Ipv4Hdr::LEN`.
    pub fn write_to(&self, buf: &mut [u8]) {
        assert_eq!(
            buf.len(),
            Self::LEN,
            "buffer length must match IPv4 header length"
        );
        buf[0] = Self::VERSION_IHL;
        buf[1] = 0; // DSCP/ECN
        buf[2..4].copy_from_slice(&self.total_len.to_be_bytes());
        buf[4..6].copy_from_slice(&self.id.to_be_bytes());
        buf[6..8].copy_from_slice(&[0, 0]); // flags/fragment offset
        buf[8] = self.ttl;
        buf[9] = self.protocol;
        buf[10..12].copy_from_slice(&[0, 0]); // checksum placeholder
        buf[12..16].copy_from_slice(&self.src.octets());
        buf[16..20].copy_from_slice(&self.dst.octets());
        let csum = checksum(buf);
        buf[10..12].copy_from_slice(&csum.to_be_bytes());
    }

    /// Parses an option-less IPv4 header. Returns `None` if `buf` is shorter
    /// than the header or version/IHL is not 4/5.
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::LEN || buf[0] != Self::VERSION_IHL {
            return None;
        }
        Some(Self {
            total_len: u16::from_be_bytes(buf[2..4].try_into().unwrap()),
            id: u16::from_be_bytes(buf[4..6].try_into().unwrap()),
            ttl: buf[8],
            protocol: buf[9],
            src: Ipv4Addr::from(<[u8; 4]>::try_from(&buf[12..16]).unwrap()),
            dst: Ipv4Addr::from(<[u8; 4]>::try_from(&buf[16..20]).unwrap()),
        })
    }
}

/// RFC 1071 internet checksum: one's complement of the one's complement sum
/// of `data` as big-endian 16-bit words (odd trailing byte padded with zero).
fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in data.chunks(2) {
        let word = match *chunk {
            [hi, lo] => u16::from_be_bytes([hi, lo]),
            [hi] => u16::from_be_bytes([hi, 0]),
            _ => unreachable!("chunks(2) yields 1 or 2 bytes"),
        };
        sum += u32::from(word);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_hdr() -> Ipv4Hdr {
        Ipv4Hdr::new(
            84,
            0x1C46,
            64,
            17,
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
        )
    }

    #[test]
    fn ipv4_hdr_len_matches_wire_format() {
        assert_eq!(Ipv4Hdr::LEN, 20);
    }

    #[test]
    fn checksum_matches_known_vector() {
        // Classic example header (RFC 1071 style) with checksum field zeroed;
        // the expected checksum is 0xB1E6.
        let hdr = [
            0x45, 0x00, 0x00, 0x3C, 0x1C, 0x46, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0xAC, 0x10,
            0x0A, 0x63, 0xAC, 0x10, 0x0A, 0x0C,
        ];
        assert_eq!(checksum(&hdr), 0xB1E6);
    }

    #[test]
    fn write_to_lays_out_fields_in_order() {
        let mut buf = [0u8; Ipv4Hdr::LEN];
        sample_hdr().write_to(&mut buf);
        assert_eq!(buf[0], 0x45);
        assert_eq!(&buf[2..4], &[0x00, 0x54]); // total_len = 84
        assert_eq!(&buf[4..6], &[0x1C, 0x46]);
        assert_eq!(buf[8], 64);
        assert_eq!(buf[9], 17);
        assert_eq!(&buf[12..16], &[10, 0, 0, 1]);
        assert_eq!(&buf[16..20], &[10, 0, 0, 2]);
    }

    #[test]
    fn written_header_verifies_to_zero_checksum() {
        let mut buf = [0u8; Ipv4Hdr::LEN];
        sample_hdr().write_to(&mut buf);
        // Summing a header including its own valid checksum yields 0.
        assert_eq!(checksum(&buf), 0);
    }

    #[test]
    fn parse_round_trips() {
        let hdr = sample_hdr();
        let mut buf = [0u8; Ipv4Hdr::LEN];
        hdr.write_to(&mut buf);
        assert_eq!(Ipv4Hdr::parse(&buf), Some(hdr));
    }

    #[test]
    fn parse_rejects_short_buffer() {
        assert_eq!(Ipv4Hdr::parse(&[0u8; Ipv4Hdr::LEN - 1]), None);
    }

    #[test]
    fn parse_rejects_wrong_version() {
        let mut buf = [0u8; Ipv4Hdr::LEN];
        sample_hdr().write_to(&mut buf);
        buf[0] = 0x65;
        assert_eq!(Ipv4Hdr::parse(&buf), None);
    }
}
