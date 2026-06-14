use crate::proto::ether::EtherType;

/// IEEE 802.1Q tag body: TCI (PCP/DEI/VID) followed by the inner EtherType.
/// The 0x8100 TPID is carried in the outer Ethernet header's EtherType field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VlanTag {
    pub pcp: u8,
    pub dei: bool,
    pub vid: u16,
    pub inner_ether_type: EtherType,
}

impl VlanTag {
    /// On-wire length of the tag body in bytes (TCI + inner EtherType).
    pub const LEN: usize = 4;

    pub const fn new(pcp: u8, dei: bool, vid: u16, inner_ether_type: EtherType) -> Self {
        assert!(pcp < 8, "PCP must fit in 3 bits");
        assert!(vid < 4096, "VID must fit in 12 bits");
        Self {
            pcp,
            dei,
            vid,
            inner_ether_type,
        }
    }

    const fn tci(&self) -> u16 {
        ((self.pcp as u16) << 13) | ((self.dei as u16) << 12) | self.vid
    }

    /// Writes the tag body into `buf`, whose length must be exactly `VlanTag::LEN`.
    pub fn write_to(&self, buf: &mut [u8]) {
        assert_eq!(
            buf.len(),
            Self::LEN,
            "buffer length must match VLAN tag length"
        );
        buf[0..2].copy_from_slice(&self.tci().to_be_bytes());
        buf[2..4].copy_from_slice(&self.inner_ether_type.value().to_be_bytes());
    }

    /// Parses a tag body. Returns `None` if `buf` is shorter than the tag.
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::LEN {
            return None;
        }
        let tci = u16::from_be_bytes(buf[0..2].try_into().unwrap());
        Some(Self {
            pcp: (tci >> 13) as u8,
            dei: (tci >> 12) & 1 == 1,
            vid: tci & 0x0FFF,
            inner_ether_type: EtherType(u16::from_be_bytes(buf[2..4].try_into().unwrap())),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vlan_tag_len_matches_wire_format() {
        assert_eq!(VlanTag::LEN, 4);
    }

    #[test]
    fn write_to_lays_out_tci_and_inner_type() {
        let tag = VlanTag::new(5, true, 100, EtherType::IPV4);
        let mut buf = [0u8; VlanTag::LEN];
        tag.write_to(&mut buf);
        // PCP=5 (101), DEI=1, VID=100 (0x064) => 0xB064
        assert_eq!(buf, [0xB0, 0x64, 0x08, 0x00]);
    }

    #[test]
    fn parse_round_trips() {
        let tag = VlanTag::new(3, false, 4094, EtherType::IPV6);
        let mut buf = [0u8; VlanTag::LEN];
        tag.write_to(&mut buf);
        assert_eq!(VlanTag::parse(&buf), Some(tag));
    }

    #[test]
    fn parse_rejects_short_buffer() {
        assert_eq!(VlanTag::parse(&[0u8; VlanTag::LEN - 1]), None);
    }

    #[test]
    #[should_panic(expected = "VID must fit in 12 bits")]
    fn new_rejects_oversized_vid() {
        VlanTag::new(0, false, 4096, EtherType::IPV4);
    }
}
