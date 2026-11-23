//! ICMP echo without admin rights: IcmpSendEcho on Windows, an unprivileged
//! ICMP datagram socket on macOS (and Linux when ping_group_range allows it).

use crate::util::Stats;
use std::net::IpAddr;
use std::time::Duration;

pub async fn ping(ip: IpAddr, count: u32, gap: Duration) -> Result<Stats, String> {
    let IpAddr::V4(v4) = ip else { return Err("ICMP probe supports IPv4 only".into()) };
    tokio::task::spawn_blocking(move || imp::ping(v4, count, gap)).await.map_err(|e| e.to_string())?
}

#[cfg(unix)]
mod imp {
    use crate::util::Stats;
    use socket2::{Domain, Protocol, SockAddr, Socket, Type};
    use std::mem::MaybeUninit;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::time::{Duration, Instant};

    fn checksum(b: &[u8]) -> u16 {
        let mut s: u32 = 0;
        for c in b.chunks(2) {
            let w = if c.len() == 2 { u16::from_be_bytes([c[0], c[1]]) } else { u16::from_be_bytes([c[0], 0]) };
            s += w as u32;
        }
        while s >> 16 != 0 {
            s = (s & 0xffff) + (s >> 16);
        }
        !(s as u16)
    }

    pub fn ping(dst: Ipv4Addr, count: u32, gap: Duration) -> Result<Stats, String> {
        let mut st = Stats { method: "ICMP echo".into(), ..Default::default() };
        let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4)).map_err(|e| e.to_string())?;
        sock.set_read_timeout(Some(Duration::from_millis(1500))).ok();
        let addr = SockAddr::from(SocketAddrV4::new(dst, 0));
        let id = (std::process::id() & 0xffff) as u16;
        for seq in 1..=count as u16 {
            let mut pkt = vec![8u8, 0, 0, 0, (id >> 8) as u8, id as u8, (seq >> 8) as u8, seq as u8];
            pkt.extend_from_slice(b"netcheckup");
            let c = checksum(&pkt);
            pkt[2] = (c >> 8) as u8;
            pkt[3] = c as u8;
            st.sent += 1;
            let t0 = Instant::now();
            sock.send_to(&pkt, &addr).map_err(|e| e.to_string())?;
            let deadline = t0 + Duration::from_millis(1500);
            loop {
                let now = Instant::now();
                if now >= deadline {
                    break;
                }
                sock.set_read_timeout(Some(deadline - now)).ok();
                let mut buf = [MaybeUninit::<u8>::uninit(); 1500];
                let Ok((n, from)) = sock.recv_from(&mut buf) else { break };
                let b: Vec<u8> = buf[..n].iter().map(|x| unsafe { x.assume_init() }).collect();
                // macOS includes the IP header on datagram ICMP sockets; Linux does not.
                let off = if !b.is_empty() && b[0] >> 4 == 4 { ((b[0] & 0x0f) as usize) * 4 } else { 0 };
                if b.len() < off + 8 || b[off] != 0 {
                    continue;
                }
                let rseq = u16::from_be_bytes([b[off + 6], b[off + 7]]);
                if rseq != seq || from.as_socket_ipv4().map(|a| *a.ip()) != Some(dst) {
                    continue;
                }
                st.received += 1;
                st.rtts.push(t0.elapsed());
                break;
            }
            std::thread::sleep(gap);
        }
        Ok(st)
    }
}

#[cfg(windows)]
mod imp {
    use crate::util::Stats;
    use std::net::Ipv4Addr;
    use std::time::{Duration, Instant};
    use windows_sys::Win32::NetworkManagement::IpHelper::{IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho};

    pub fn ping(dst: Ipv4Addr, count: u32, gap: Duration) -> Result<Stats, String> {
        let mut st = Stats { method: "ICMP echo".into(), ..Default::default() };
        let h = unsafe { IcmpCreateFile() };
        if h.is_null() || h as isize == -1 {
            return Err("IcmpCreateFile failed".into());
        }
        let addr = u32::from_ne_bytes(dst.octets());
        let data = b"netcheckup";
        let mut reply = vec![0u8; 256 + data.len()];
        for _ in 0..count {
            st.sent += 1;
            let t0 = Instant::now();
            let n = unsafe {
                IcmpSendEcho(h, addr, data.as_ptr() as *const _, data.len() as u16, std::ptr::null(), reply.as_mut_ptr() as *mut _, reply.len() as u32, 1500)
            };
            let rtt = t0.elapsed();
            let status = u32::from_ne_bytes([reply[4], reply[5], reply[6], reply[7]]);
            if n > 0 && status == 0 {
                st.received += 1;
                st.rtts.push(rtt);
            }
            std::thread::sleep(gap);
        }
        unsafe { IcmpCloseHandle(h) };
        Ok(st)
    }
}
