use std::fmt::Write;

use crate::proto::{
    arp::ArpHdr,
    ether::{EtherFrame, EtherType},
    ipv4::Ipv4Hdr,
    ipv6::Ipv6Hdr,
    vlan::VlanTag,
};

/// Formats a received frame as a multi-line, human-readable dump: the parsed
/// L2/L3 headers followed by a hex dump of the remaining payload.
pub fn format_frame(frame: &[u8]) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "frame: {} bytes", frame.len());
    match EtherFrame::parse(frame) {
        Some(eth) => {
            let _ = writeln!(
                out,
                "  Ethernet: dst={}, src={}, type={}{}",
                eth.dst_mac,
                eth.src_mac,
                eth.ether_type,
                ether_type_suffix(eth.ether_type),
            );
            write_upper_layer(&mut out, eth.ether_type, eth.payload);
        }
        None => {
            let _ = writeln!(out, "  (shorter than Ethernet header)");
            write_payload(&mut out, "data", frame);
        }
    }
    out.truncate(out.trim_end().len());
    out
}

fn write_upper_layer(out: &mut String, ether_type: EtherType, payload: &[u8]) {
    match ether_type {
        EtherType::VLAN => match VlanTag::parse(payload) {
            Some(tag) => {
                let _ = writeln!(
                    out,
                    "  VLAN: pcp={}, dei={}, vid={}, inner type={}{}",
                    tag.pcp,
                    tag.dei,
                    tag.vid,
                    tag.inner_ether_type,
                    ether_type_suffix(tag.inner_ether_type),
                );
                write_upper_layer(out, tag.inner_ether_type, &payload[VlanTag::LEN..]);
            }
            None => write_malformed(out, "VLAN", payload),
        },
        EtherType::ARP => match ArpHdr::parse(payload) {
            Some(arp) => {
                let _ = writeln!(
                    out,
                    "  ARP: op={}{}, sender={} ({}), target={} ({})",
                    arp.op,
                    arp_op_suffix(arp.op.value()),
                    arp.sender_ip,
                    arp.sender_mac,
                    arp.target_ip,
                    arp.target_mac,
                );
                write_payload(out, "padding", &payload[ArpHdr::LEN..]);
            }
            None => write_malformed(out, "ARP", payload),
        },
        EtherType::IPV4 => match Ipv4Hdr::parse(payload) {
            Some(ip) => {
                let _ = writeln!(
                    out,
                    "  IPv4: src={}, dst={}, proto={}{}, ttl={}, total_len={}, id=0x{:04x}",
                    ip.src,
                    ip.dst,
                    ip.protocol,
                    ip_proto_suffix(ip.protocol),
                    ip.ttl,
                    ip.total_len,
                    ip.id,
                );
                write_payload(out, "payload", &payload[Ipv4Hdr::LEN..]);
            }
            None => write_malformed(out, "IPv4", payload),
        },
        EtherType::IPV6 => match Ipv6Hdr::parse(payload) {
            Some(ip) => {
                let _ = writeln!(
                    out,
                    "  IPv6: src={}, dst={}, next_header={}{}, hop_limit={}, payload_len={}",
                    ip.src,
                    ip.dst,
                    ip.next_header,
                    ip_proto_suffix(ip.next_header),
                    ip.hop_limit,
                    ip.payload_len,
                );
                write_payload(out, "payload", &payload[Ipv6Hdr::LEN..]);
            }
            None => write_malformed(out, "IPv6", payload),
        },
        _ => write_payload(out, "payload", payload),
    }
}

fn write_malformed(out: &mut String, proto: &str, payload: &[u8]) {
    let _ = writeln!(out, "  {proto}: malformed ({} bytes)", payload.len());
    write_payload(out, "data", payload);
}

fn write_payload(out: &mut String, label: &str, data: &[u8]) {
    if data.is_empty() {
        return;
    }
    let _ = writeln!(out, "  {label} ({} bytes):", data.len());
    for (i, chunk) in data.chunks(16).enumerate() {
        let mut hex = String::with_capacity(49);
        for (j, byte) in chunk.iter().enumerate() {
            if j == 8 {
                hex.push(' ');
            }
            let _ = write!(hex, "{byte:02x} ");
        }
        let ascii: String = chunk
            .iter()
            .map(|&b| {
                if b.is_ascii_graphic() || b == b' ' {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();
        let _ = writeln!(out, "    {:04x}  {hex:<49} |{ascii}|", i * 16);
    }
}

fn ether_type_suffix(ether_type: EtherType) -> &'static str {
    match ether_type {
        EtherType::IPV4 => " (IPv4)",
        EtherType::ARP => " (ARP)",
        EtherType::VLAN => " (VLAN)",
        EtherType::IPV6 => " (IPv6)",
        _ => "",
    }
}

fn arp_op_suffix(op: u16) -> &'static str {
    match op {
        1 => " (request)",
        2 => " (reply)",
        _ => "",
    }
}

fn ip_proto_suffix(protocol: u8) -> &'static str {
    match protocol {
        1 => " (ICMP)",
        6 => " (TCP)",
        17 => " (UDP)",
        58 => " (ICMPv6)",
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;
    use crate::proto::{
        arp::ArpOp,
        ether::{EtherHdr, MacAddr},
    };

    fn ether_frame(ether_type: EtherType, payload: &[u8]) -> Vec<u8> {
        let hdr = EtherHdr::new(
            MacAddr::new([0xFF; 6]),
            MacAddr::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            ether_type,
        );
        let mut frame = vec![0u8; EtherHdr::LEN + payload.len()];
        hdr.write_to(&mut frame, payload);
        frame
    }

    #[test]
    fn formats_arp_request() {
        let arp = ArpHdr::new(
            ArpOp::REQUEST,
            MacAddr::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            Ipv4Addr::new(10, 0, 0, 1),
            MacAddr::new([0x00; 6]),
            Ipv4Addr::new(10, 0, 0, 2),
        );
        let mut payload = [0u8; ArpHdr::LEN];
        arp.write_to(&mut payload);
        let dump = format_frame(&ether_frame(EtherType::ARP, &payload));

        assert!(dump.contains("type=0x0806 (ARP)"), "{dump}");
        assert!(
            dump.contains("ARP: op=1 (request), sender=10.0.0.1 (00:11:22:33:44:55), target=10.0.0.2 (00:00:00:00:00:00)"),
            "{dump}"
        );
    }

    #[test]
    fn formats_ipv4_with_payload_hex_dump() {
        let payload = b"Hello, DPDK!";
        let ip = Ipv4Hdr::new(
            (Ipv4Hdr::LEN + payload.len()) as u16,
            0x1C46,
            64,
            17,
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
        );
        let mut l3 = vec![0u8; Ipv4Hdr::LEN + payload.len()];
        ip.write_to(&mut l3[..Ipv4Hdr::LEN]);
        l3[Ipv4Hdr::LEN..].copy_from_slice(payload);
        let dump = format_frame(&ether_frame(EtherType::IPV4, &l3));

        assert!(
            dump.contains(
                "IPv4: src=10.0.0.1, dst=10.0.0.2, proto=17 (UDP), ttl=64, total_len=32, id=0x1c46"
            ),
            "{dump}"
        );
        assert!(
            dump.contains("0000  48 65 6c 6c 6f 2c 20 44  50 44 4b 21"),
            "{dump}"
        );
        assert!(dump.contains("|Hello, DPDK!|"), "{dump}");
    }

    #[test]
    fn formats_vlan_tagged_ipv6() {
        let ip = Ipv6Hdr::new(
            0,
            58,
            64,
            "2001:db8::1".parse::<Ipv6Addr>().unwrap(),
            "2001:db8::2".parse::<Ipv6Addr>().unwrap(),
        );
        let mut l3 = vec![0u8; VlanTag::LEN + Ipv6Hdr::LEN];
        VlanTag::new(5, false, 100, EtherType::IPV6).write_to(&mut l3[..VlanTag::LEN]);
        ip.write_to(&mut l3[VlanTag::LEN..]);
        let dump = format_frame(&ether_frame(EtherType::VLAN, &l3));

        assert!(
            dump.contains("VLAN: pcp=5, dei=false, vid=100, inner type=0x86dd (IPv6)"),
            "{dump}"
        );
        assert!(
            dump.contains(
                "IPv6: src=2001:db8::1, dst=2001:db8::2, next_header=58 (ICMPv6), hop_limit=64, payload_len=0"
            ),
            "{dump}"
        );
    }

    #[test]
    fn formats_unknown_ether_type_as_hex_dump() {
        let dump = format_frame(&ether_frame(EtherType(0x1234), &[0xDE, 0xAD, 0xBE, 0xEF]));
        assert!(dump.contains("type=0x1234\n"), "{dump}");
        assert!(dump.contains("payload (4 bytes):"), "{dump}");
        assert!(dump.contains("de ad be ef"), "{dump}");
    }

    #[test]
    fn formats_short_frame_without_panicking() {
        let dump = format_frame(&[0xAA, 0xBB]);
        assert!(dump.contains("(shorter than Ethernet header)"), "{dump}");
        assert!(dump.contains("aa bb"), "{dump}");
    }

    #[test]
    fn formats_malformed_ipv4_header() {
        // Version nibble is 6, so Ipv4Hdr::parse rejects it.
        let dump = format_frame(&ether_frame(EtherType::IPV4, &[0x65; Ipv4Hdr::LEN]));
        assert!(dump.contains("IPv4: malformed (20 bytes)"), "{dump}");
    }
}
