//! The records in a bpf(4) read buffer: no system calls, so it is tested
//! (and fuzzable) everywhere.

const HDRLEN_AT: usize = 16;
const CAPLEN_AT: usize = 8;
/// bpf_hdr up to bh_hdrlen
const MIN_HDR: usize = 18;

/// The records in one read(2) of a bpf descriptor:
/// (seconds, microseconds, original length, captured frame). OpenBSD
/// aligns each record to 4 bytes (BPF_WORDALIGN).
pub fn records(data: &[u8]) -> impl Iterator<Item = (u32, u32, u32, &[u8])> {
    let mut off = 0usize;
    std::iter::from_fn(move || {
        if off + MIN_HDR > data.len() {
            return None;
        }
        let word = |at: usize| u32::from_ne_bytes(data[off + at..off + at + 4].try_into().unwrap());
        let (sec, usec, caplen, datalen) = (word(0), word(4), word(CAPLEN_AT) as usize, word(12));
        let hdrlen = u16::from_ne_bytes(data[off + HDRLEN_AT..off + HDRLEN_AT + 2].try_into().unwrap()) as usize;
        let (start, end) = (off + hdrlen, off + hdrlen + caplen);
        if hdrlen < MIN_HDR || end > data.len() {
            return None;
        }
        off += (hdrlen + caplen + 3) & !3;
        Some((sec, usec, datalen, &data[start..end]))
    })
}

#[cfg(test)]
mod tests {
    /// A buffer as the kernel writes it: 30-byte headers, records word aligned.
    fn buffer(frames: &[usize]) -> Vec<u8> {
        let mut b = vec![];
        for (i, len) in frames.iter().enumerate() {
            let mut h = vec![0u8; 30];
            h[0..4].copy_from_slice(&(1000 + i as u32).to_ne_bytes());
            h[8..12].copy_from_slice(&(*len as u32).to_ne_bytes());
            h[12..16].copy_from_slice(&(*len as u32).to_ne_bytes());
            h[16..18].copy_from_slice(&30u16.to_ne_bytes());
            b.extend(h);
            b.extend(std::iter::repeat_n(i as u8, *len));
            while b.len() % 4 != 0 {
                b.push(0xee);
            }
        }
        b
    }

    #[test]
    fn every_record_of_a_read() {
        // 60-byte frames (bare ACKs, ARP) put the next header off an 8-byte boundary
        let lens = [66, 60, 60, 61, 1514, 62, 60];
        let b = buffer(&lens);
        let got: Vec<(u32, usize, u8)> = super::records(&b).map(|(s, _, _, f)| (s, f.len(), f[0])).collect();
        let want: Vec<(u32, usize, u8)> =
            lens.iter().enumerate().map(|(i, l)| (1000 + i as u32, *l, i as u8)).collect();
        assert_eq!(got, want);
        // junk never panics
        for cut in 0..b.len() {
            let _ = super::records(&b[..cut]).count();
        }
    }
}
