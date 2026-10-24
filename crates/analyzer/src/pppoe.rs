//! PPPoE sessions on Ethernet interfaces (the WAN NIC and its VLAN under
//! pppoe0): the IP packet inside a frame, and filters that see it. OpenBSD's
//! libpcap has no `pppoes` keyword, so the filter is compiled a second time
//! for DLT_PPP_ETHER (pppoe0's link type: the PPPoE header, the PPP protocol,
//! then IP) and its packet loads are moved behind the Ethernet header. No
//! system calls: tested (and fuzzable) everywhere.

const ETHERTYPE_VLAN: u16 = 0x8100;
const ETHERTYPE_PPPOE: u16 = 0x8864;
const PPP_IP: u16 = 0x0021;
const PPP_IPV6: u16 = 0x0057;
/// the PPPoE session header and the PPP protocol
const PPPOE_LEN: usize = 8;
pub const DLT_EN10MB: i32 = 1;
pub const DLT_PPP_ETHER: i32 = 51;

/// struct bpf_insn
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Insn {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

/// Where the PPPoE session (its header) starts in an Ethernet frame:
/// 14, or 18 behind one 802.1Q tag; None for anything else.
fn session_at(frame: &[u8]) -> Option<usize> {
    let be16 = |at: usize| frame.get(at..at + 2).map(|b| u16::from_be_bytes([b[0], b[1]]));
    match be16(12)? {
        ETHERTYPE_PPPOE => Some(14),
        ETHERTYPE_VLAN if be16(16)? == ETHERTYPE_PPPOE => Some(18),
        _ => None,
    }
}

/// The offset of the IP packet in an Ethernet frame carrying IPv4 or IPv6
/// in a PPPoE session; None for other frames (LCP, discovery, plain IP).
pub fn ip_offset(frame: &[u8]) -> Option<usize> {
    let at = session_at(frame)?;
    let proto = frame.get(at + 6..at + 8).map(|b| u16::from_be_bytes([b[0], b[1]]))?;
    (proto == PPP_IP || proto == PPP_IPV6).then_some(at + PPPOE_LEN)
}

const BPF_LD: u16 = 0x00;
const BPF_LDX: u16 = 0x01;
const BPF_JMP: u16 = 0x05;
const BPF_H: u16 = 0x08;
const BPF_ABS: u16 = 0x20;
const BPF_IND: u16 = 0x40;
const BPF_MSH: u16 = 0xa0;
const BPF_JA: u16 = 0x00;
const BPF_JEQ: u16 = 0x10;
const BPF_K: u16 = 0x00;

/// `prog` (compiled for DLT_PPP_ETHER) reading `off` bytes further into the packet.
fn shifted(prog: &[Insn], off: u32) -> Option<Vec<Insn>> {
    prog.iter()
        .map(|i| {
            let (class, mode) = (i.code & 0x07, i.code & 0xe0);
            let moves =
                (class == BPF_LD && (mode == BPF_ABS || mode == BPF_IND)) || (class == BPF_LDX && mode == BPF_MSH);
            Some(if moves { Insn { k: i.k.checked_add(off)?, ..*i } } else { *i })
        })
        .collect()
}

/// One program for an Ethernet interface: PPPoE sessions (untagged or
/// behind one VLAN tag) go to `ppp`, compiled for DLT_PPP_ETHER, every
/// other frame to `eth`, compiled for DLT_EN10MB. Jumps are relative and
/// every block ends in its own return, so the blocks are laid end to end.
pub fn ethernet_filter(eth: &[Insn], ppp: &[Insn]) -> Option<Vec<Insn>> {
    let ins = |code: u16, jt: u8, jf: u8, k: u32| Insn { code, jt, jf, k };
    let (e, p) = (u32::try_from(eth.len()).ok()?, u32::try_from(ppp.len()).ok()?);
    let mut out = vec![
        ins(BPF_LD | BPF_H | BPF_ABS, 0, 0, 12),
        ins(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, ETHERTYPE_PPPOE as u32),
        // to the untagged block, after the guard's 4 remaining and the Ethernet block
        ins(BPF_JMP | BPF_JA, 0, 0, 4 + e),
        ins(BPF_JMP | BPF_JEQ | BPF_K, 0, 3, ETHERTYPE_VLAN as u32),
        ins(BPF_LD | BPF_H | BPF_ABS, 0, 0, 16),
        ins(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, ETHERTYPE_PPPOE as u32),
        // to the tagged block
        ins(BPF_JMP | BPF_JA, 0, 0, e + p),
    ];
    out.extend_from_slice(eth);
    out.extend(shifted(ppp, 14)?);
    out.extend(shifted(ppp, 18)?);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Just enough of a BPF interpreter to run the programs here.
    fn run(prog: &[Insn], pkt: &[u8]) -> u32 {
        let (mut a, mut x, mut pc) = (0u32, 0u32, 0usize);
        let load = |at: u32, size: u16| -> Option<u32> {
            let at = at as usize;
            Some(match size {
                0x00 => u32::from_be_bytes(pkt.get(at..at + 4)?.try_into().unwrap()),
                0x08 => u16::from_be_bytes(pkt.get(at..at + 2)?.try_into().unwrap()) as u32,
                _ => *pkt.get(at)? as u32,
            })
        };
        loop {
            let i = prog[pc];
            pc += 1;
            let (class, size, mode) = (i.code & 0x07, i.code & 0x18, i.code & 0xe0);
            match (class, mode) {
                (BPF_LD, BPF_ABS) => match load(i.k, size) {
                    Some(v) => a = v,
                    None => return 0,
                },
                (BPF_LD, BPF_IND) => match load(x + i.k, size) {
                    Some(v) => a = v,
                    None => return 0,
                },
                (BPF_LDX, BPF_MSH) => match load(i.k, 0x10) {
                    Some(v) => x = 4 * (v & 0xf),
                    None => return 0,
                },
                (BPF_JMP, _) => {
                    let taken = match i.code & 0xf0 {
                        BPF_JA => {
                            pc += i.k as usize;
                            continue;
                        }
                        BPF_JEQ => a == i.k,
                        0x40 => a & i.k != 0,
                        op => panic!("jump {op:#x}"),
                    };
                    pc += if taken { i.jt } else { i.jf } as usize;
                }
                (0x06, _) => return i.k,
                _ => panic!("instruction {:#x}", i.code),
            }
        }
    }

    fn ins(code: u16, jt: u8, jf: u8, k: u32) -> Insn {
        Insn { code, jt, jf, k }
    }

    /// "tcp" as libpcap compiles it for DLT_EN10MB (IPv4 part only)
    fn eth_tcp() -> Vec<Insn> {
        vec![
            ins(0x28, 0, 0, 12),
            ins(0x15, 0, 3, 0x0800),
            ins(0x30, 0, 0, 23),
            ins(0x15, 0, 1, 6),
            ins(0x6, 0, 0, 65535),
            ins(0x6, 0, 0, 0),
        ]
    }

    /// "tcp and port 443" as OpenBSD's libpcap compiles it for DLT_PPP_ETHER
    /// (tcpdump -d -i pppoe0)
    fn ppp_tcp443() -> Vec<Insn> {
        vec![
            ins(0x28, 0, 0, 6),
            ins(0x15, 0, 6, 0x57),
            ins(0x30, 0, 0, 14),
            ins(0x15, 0, 15, 6),
            ins(0x28, 0, 0, 48),
            ins(0x15, 12, 0, 443),
            ins(0x28, 0, 0, 50),
            ins(0x15, 10, 11, 443),
            ins(0x15, 0, 10, 0x21),
            ins(0x30, 0, 0, 17),
            ins(0x15, 0, 8, 6),
            ins(0x28, 0, 0, 14),
            ins(0x45, 6, 0, 0x1fff),
            ins(0xb1, 0, 0, 8),
            ins(0x48, 0, 0, 8),
            ins(0x15, 2, 0, 443),
            ins(0x48, 0, 0, 10),
            ins(0x15, 0, 1, 443),
            ins(0x6, 0, 0, 65535),
            ins(0x6, 0, 0, 0),
        ]
    }

    /// An IPv4 TCP packet from port 40000 to `dport`.
    fn ip_tcp(dport: u16) -> Vec<u8> {
        let mut p = vec![0x45, 0, 0, 40, 0, 0, 0x40, 0, 64, 6, 0, 0, 10, 0, 0, 5, 1, 1, 1, 1];
        p.extend(40000u16.to_be_bytes());
        p.extend(dport.to_be_bytes());
        p.extend([0u8; 16]);
        p
    }

    fn ether(tag: bool, ethertype: u16, body: &[u8]) -> Vec<u8> {
        let mut f = vec![2u8; 12];
        if tag {
            f.extend([0x81, 0x00, 0x23, 0x50]);
        }
        f.extend(ethertype.to_be_bytes());
        f.extend(body);
        f
    }

    fn pppoe(proto: u16, ip: &[u8]) -> Vec<u8> {
        let mut s = vec![0x11, 0, 0, 1];
        s.extend((ip.len() as u16 + 2).to_be_bytes());
        s.extend(proto.to_be_bytes());
        s.extend(ip);
        s
    }

    #[test]
    fn finds_ip_in_sessions() {
        let ip = ip_tcp(443);
        assert_eq!(ip_offset(&ether(false, 0x8864, &pppoe(0x21, &ip))), Some(22));
        assert_eq!(ip_offset(&ether(true, 0x8864, &pppoe(0x57, &ip))), Some(26));
        // LCP, discovery and plain IP are not sessions with IP in them
        assert_eq!(ip_offset(&ether(false, 0x8864, &pppoe(0xc021, &ip))), None);
        assert_eq!(ip_offset(&ether(false, 0x8863, &pppoe(0x21, &ip))), None);
        assert_eq!(ip_offset(&ether(false, 0x0800, &ip)), None);
        let f = ether(true, 0x8864, &pppoe(0x21, &ip));
        for cut in 0..f.len() {
            let _ = ip_offset(&f[..cut]);
        }
    }

    #[test]
    fn filters_inside_sessions() {
        let prog = ethernet_filter(&eth_tcp(), &ppp_tcp443()).unwrap();
        assert_eq!(prog.len(), 7 + 6 + 2 * 20);
        for tag in [false, true] {
            assert_eq!(run(&prog, &ether(tag, 0x8864, &pppoe(0x21, &ip_tcp(443)))), 65535, "tag {tag}");
            assert_eq!(run(&prog, &ether(tag, 0x8864, &pppoe(0x21, &ip_tcp(80)))), 0, "tag {tag}");
            assert_eq!(run(&prog, &ether(tag, 0x8864, &pppoe(0xc021, &ip_tcp(443)))), 0, "tag {tag}");
        }
        // everything else still goes through the Ethernet program
        assert_eq!(run(&prog, &ether(false, 0x0800, &ip_tcp(80))), 65535);
        assert_eq!(run(&prog, &ether(false, 0x0806, &[0; 28])), 0);
        assert_eq!(run(&prog, &ether(true, 0x0800, &ip_tcp(80))), 0);
        let f = ether(true, 0x8864, &pppoe(0x21, &ip_tcp(443)));
        for cut in 0..f.len() {
            let _ = run(&prog, &f[..cut]);
        }
        assert!(shifted(&[ins(0x20, 0, 0, u32::MAX)], 14).is_none());
    }
}
