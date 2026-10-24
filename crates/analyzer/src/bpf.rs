//! bpf(4) and libpcap's filter compiler, OpenBSD only. The filter is
//! installed and then locked (BIOCLOCK): after that the descriptor can't be
//! pointed at another interface or given another program, so dropping
//! privileges afterwards leaves a capture that can only do this one thing.

use std::ffi::{CStr, CString};
use std::os::fd::RawFd;

use crate::pppoe::{self, Insn};

// from <net/bpf.h> on OpenBSD 7.9 amd64 (checked against the headers)
const BIOCSBLEN: libc::c_ulong = 0xc004_4266;
const BIOCSETF: libc::c_ulong = 0x8010_4267;
const BIOCGDLT: libc::c_ulong = 0x4004_426a;
const BIOCSETIF: libc::c_ulong = 0x8020_426c;
const BIOCIMMEDIATE: libc::c_ulong = 0x8004_4270;
const BIOCLOCK: libc::c_ulong = 0x2000_4276;
const BIOCSDIRFILT: libc::c_ulong = 0x8004_427d;
const BPF_DIRECTION_OUT: libc::c_uint = 1 << 1;
/// bpf_setf refuses longer programs
const BPF_MAXINSNS: libc::c_uint = 512;
pub const BUFLEN: u32 = 1 << 20;

#[repr(C)]
struct BpfProgram {
    bf_len: libc::c_uint,
    bf_insns: *mut Insn,
}

#[link(name = "pcap")]
unsafe extern "C" {
    fn pcap_open_dead(linktype: libc::c_int, snaplen: libc::c_int) -> *mut libc::c_void;
    fn pcap_compile(
        p: *mut libc::c_void,
        fp: *mut BpfProgram,
        s: *const libc::c_char,
        optimize: libc::c_int,
        netmask: u32,
    ) -> libc::c_int;
    fn pcap_freecode(fp: *mut BpfProgram);
    fn pcap_geterr(p: *mut libc::c_void) -> *const libc::c_char;
    fn pcap_close(p: *mut libc::c_void);
}

/// libpcap's program for `filter` on link type `dlt`.
fn program(filter: &str, dlt: i32) -> Result<Vec<Insn>, String> {
    let f = CString::new(filter).map_err(|_| "filter contains NUL")?;
    unsafe {
        let p = pcap_open_dead(dlt, 65535);
        if p.is_null() {
            return Err("pcap_open_dead failed".into());
        }
        let mut prog = BpfProgram { bf_len: 0, bf_insns: std::ptr::null_mut() };
        if pcap_compile(p, &mut prog, f.as_ptr(), 1, 0xffff_ffff) != 0 {
            let e = CStr::from_ptr(pcap_geterr(p)).to_string_lossy().into_owned();
            pcap_close(p);
            return Err(format!("filter {filter:?}: {e}"));
        }
        let insns = match prog.bf_insns.is_null() {
            true => vec![],
            false => std::slice::from_raw_parts(prog.bf_insns, prog.bf_len as usize).to_vec(),
        };
        pcap_freecode(&mut prog);
        pcap_close(p);
        Ok(insns)
    }
}

/// Compile `filter` for link type `dlt`; Ok(()) proves it compiles. On
/// Ethernet it also matches inside PPPoE sessions (see pppoe.rs).
fn compile(filter: &str, dlt: i32, install_on: Option<RawFd>) -> Result<(), String> {
    let mut insns = program(filter, dlt)?;
    if dlt == pppoe::DLT_EN10MB && !filter.is_empty() {
        insns = pppoe::ethernet_filter(&insns, &program(filter, pppoe::DLT_PPP_ETHER)?)
            .ok_or_else(|| format!("filter {filter:?}: no PPPoE program"))?;
    }
    if insns.len() > BPF_MAXINSNS as usize {
        return Err(format!("filter {filter:?} compiles to {} instructions; bpf takes {BPF_MAXINSNS}", insns.len()));
    }
    if let Some(fd) = install_on {
        let prog = BpfProgram { bf_len: insns.len() as libc::c_uint, bf_insns: insns.as_mut_ptr() };
        if unsafe { libc::ioctl(fd, BIOCSETF, &prog) } != 0 {
            return Err(format!("BIOCSETF: {}", std::io::Error::last_os_error()));
        }
    }
    Ok(())
}

/// Check a filter compiles for Ethernet.
pub fn check(filter: &str) -> Result<(), String> {
    compile(filter, pppoe::DLT_EN10MB, None)
}

/// Open bpf on `ifname` with `filter`, lock it; returns (fd, link type).
/// `inbound`: only what arrives on the interface, not what the router sends.
pub fn open(ifname: &str, filter: &str, inbound: bool) -> Result<(RawFd, i32), String> {
    unsafe {
        let fd = libc::open(c"/dev/bpf".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC);
        if fd < 0 {
            return Err(format!("/dev/bpf: {}", std::io::Error::last_os_error()));
        }
        let fail = |what: &str| -> String {
            let e = format!("{what} on {ifname}: {}", std::io::Error::last_os_error());
            libc::close(fd);
            e
        };
        let mut blen: libc::c_uint = BUFLEN;
        if libc::ioctl(fd, BIOCSBLEN, &mut blen) != 0 {
            return Err(fail("BIOCSBLEN"));
        }
        let mut ifr: libc::ifreq = std::mem::zeroed();
        if ifname.len() >= ifr.ifr_name.len() {
            libc::close(fd);
            return Err(format!("interface name {ifname} too long"));
        }
        for (i, b) in ifname.bytes().enumerate() {
            ifr.ifr_name[i] = b as libc::c_char;
        }
        if libc::ioctl(fd, BIOCSETIF, &ifr) != 0 {
            return Err(fail("BIOCSETIF"));
        }
        let mut dlt: libc::c_uint = 0;
        if libc::ioctl(fd, BIOCGDLT, &mut dlt) != 0 {
            return Err(fail("BIOCGDLT"));
        }
        let one: libc::c_uint = 1;
        if libc::ioctl(fd, BIOCIMMEDIATE, &one) != 0 {
            return Err(fail("BIOCIMMEDIATE"));
        }
        let out = BPF_DIRECTION_OUT;
        if inbound && libc::ioctl(fd, BIOCSDIRFILT, &out) != 0 {
            return Err(fail("BIOCSDIRFILT"));
        }
        if let Err(e) = compile(filter, dlt as i32, Some(fd)) {
            libc::close(fd);
            return Err(e);
        }
        if libc::ioctl(fd, BIOCLOCK) != 0 {
            return Err(fail("BIOCLOCK"));
        }
        Ok((fd, dlt as i32))
    }
}

pub use crate::bpfbuf::records;
