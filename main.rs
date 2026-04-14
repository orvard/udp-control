use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::unix::io::AsRawFd;

use anyhow::{Context, Result};
use socket2::{Domain, Protocol, Socket, Type};

// Linux socket constants
const IP_TRANSPARENT: libc::c_int = 19;
const IP_RECVORIGDSTADDR: libc::c_int = 20;
const IP_ORIGDSTADDR: libc::c_int = 20;
const SOL_IP: libc::c_int = 0;

fn set_ip_transparent(sock: &Socket) -> Result<()> {
    unsafe {
        let val: libc::c_int = 1;
        let ret = libc::setsockopt(
            sock.as_raw_fd(),
            SOL_IP,
            IP_TRANSPARENT,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        if ret != 0 {
            return Err(anyhow::anyhow!(
                "setsockopt IP_TRANSPARENT failed: {}",
                std::io::Error::last_os_error()
            ));
        }
    }
    Ok(())
}

fn set_recv_orig_dst(sock: &Socket) -> Result<()> {
    unsafe {
        let val: libc::c_int = 1;
        let ret = libc::setsockopt(
            sock.as_raw_fd(),
            SOL_IP,
            IP_RECVORIGDSTADDR,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        if ret != 0 {
            return Err(anyhow::anyhow!(
                "setsockopt IP_RECVORIGDSTADDR failed: {}",
                std::io::Error::last_os_error()
            ));
        }
    }
    Ok(())
}

/// Receive a UDP packet with ancillary data to extract the original destination.
/// Returns (data, src_addr, orig_dst_addr).
fn recvmsg_with_orig_dst(
    fd: libc::c_int,
    buf: &mut [u8],
) -> Result<(usize, SocketAddrV4, SocketAddrV4)> {
    let mut src_storage: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };

    // Control buffer large enough for IP_ORIGDSTADDR cmsg
    let mut cbuf = [0u8; 256];

    let mut msg = libc::msghdr {
        msg_name: &mut src_storage as *mut _ as *mut libc::c_void,
        msg_namelen: std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        msg_iov: &mut iov,
        msg_iovlen: 1,
        msg_control: cbuf.as_mut_ptr() as *mut libc::c_void,
        msg_controllen: cbuf.len(),
        msg_flags: 0,
    };

    let n = unsafe { libc::recvmsg(fd, &mut msg, 0) };
    if n < 0 {
        return Err(anyhow::anyhow!(
            "recvmsg failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    let src_addr = SocketAddrV4::new(
        Ipv4Addr::from(u32::from_be(src_storage.sin_addr.s_addr)),
        u16::from_be(src_storage.sin_port),
    );

    // Walk control messages to find IP_ORIGDSTADDR
    let mut orig_dst: Option<SocketAddrV4> = None;
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            let level = (*cmsg).cmsg_level;
            let typ = (*cmsg).cmsg_type;
            if level == SOL_IP && typ == IP_ORIGDSTADDR {
                let dst_storage = libc::CMSG_DATA(cmsg) as *const libc::sockaddr_in;
                let dst = *dst_storage;
                orig_dst = Some(SocketAddrV4::new(
                    Ipv4Addr::from(u32::from_be(dst.sin_addr.s_addr)),
                    u16::from_be(dst.sin_port),
                ));
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }

    let orig_dst = orig_dst.context("No IP_ORIGDSTADDR in ancillary data")?;
    Ok((n as usize, src_addr, orig_dst))
}

/// Create a UDP send socket bound to `src` with IP_TRANSPARENT.
fn make_transparent_send_socket(src: SocketAddrV4) -> Result<Socket> {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .context("Failed to create send socket")?;
    sock.set_reuse_address(true)?;
    set_ip_transparent(&sock)?;
    sock.bind(&socket2::SockAddr::from(std::net::SocketAddr::V4(src)))
        .with_context(|| format!("Failed to bind send socket to {src}"))?;
    Ok(sock)
}

fn main() -> Result<()> {
    let listen_addr: SocketAddrV4 = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "0.0.0.0:1234".to_string())
        .parse()
        .context("Invalid listen address, use IP:PORT")?;

    // --- Receive socket ---
    let recv_sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .context("Failed to create recv socket")?;
    recv_sock.set_reuse_address(true)?;
    set_ip_transparent(&recv_sock)?;
    set_recv_orig_dst(&recv_sock)?;
    recv_sock
        .bind(&socket2::SockAddr::from(std::net::SocketAddr::V4(listen_addr)))
        .with_context(|| format!("Failed to bind recv socket to {listen_addr}"))?;

    eprintln!("[udp-tproxy] Listening on {listen_addr}");

    // Cache send sockets keyed by (client_src, orig_dst) so we reuse them
    // for session-like UDP flows (e.g. DNS, gaming, etc.)
    let mut send_socks: HashMap<(SocketAddrV4, SocketAddrV4), Socket> = HashMap::new();

    let mut buf = vec![0u8; 65535];
    let fd = recv_sock.as_raw_fd();

    loop {
        let (n, client_src, orig_dst) = match recvmsg_with_orig_dst(fd, &mut buf) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[udp-tproxy] recvmsg error: {e}");
                continue;
            }
        };

        eprintln!(
            "[udp-tproxy] {client_src} -> {orig_dst} ({n} bytes) — replying with src={orig_dst}"
        );

        // Inspect / modify payload here if needed
        let payload = &buf[..n];

        // Get or create a send socket spoofing src = orig_dst
        let key = (client_src, orig_dst);
        let send_sock = send_socks.entry(key).or_insert_with(|| {
            make_transparent_send_socket(orig_dst)
                .unwrap_or_else(|e| panic!("Failed to create send socket for {orig_dst}: {e}"))
        });

        // Send back to the original client
        let client_saddr = socket2::SockAddr::from(std::net::SocketAddr::V4(client_src));
        if let Err(e) = send_sock.send_to(payload, &client_saddr) {
            eprintln!("[udp-tproxy] sendto {client_src} failed: {e}");
            // Remove stale socket so it gets recreated next time
            send_socks.remove(&key);
        }
    }
}
