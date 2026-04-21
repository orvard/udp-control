use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::unix::io::AsRawFd;
use std::sync::{Arc, Mutex};
use std::thread;

use anyhow::{Context, Result};
use socket2::{Domain, Protocol, Socket, Type};

const IP_TRANSPARENT: libc::c_int = 19;
const IP_RECVORIGDSTADDR: libc::c_int = 20;
const IP_ORIGDSTADDR: libc::c_int = 20;
const IP_PKTINFO: libc::c_int = 8;
const SOL_IP: libc::c_int = 0;

type SessionMap = Arc<Mutex<HashMap<(SocketAddrV4, SocketAddrV4), Arc<Socket>>>>;

// ---------------------------------------------------------------------------
// Socket helpers
// ---------------------------------------------------------------------------

fn set_sockopt_int(sock: &Socket, level: libc::c_int, opt: libc::c_int, val: libc::c_int) -> Result<()> {
    unsafe {
        let ret = libc::setsockopt(
            sock.as_raw_fd(), level, opt,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        if ret != 0 {
            return Err(anyhow::anyhow!("setsockopt({opt}) failed: {}", std::io::Error::last_os_error()));
        }
    }
    Ok(())
}

fn make_recv_sock(bind_addr: SocketAddrV4) -> Result<Socket> {
    let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    s.set_reuse_address(true)?;
    s.set_reuse_port(true)?;
    set_sockopt_int(&s, SOL_IP, IP_TRANSPARENT,    1)?;
    set_sockopt_int(&s, SOL_IP, IP_RECVORIGDSTADDR, 1)?;
    s.bind(&socket2::SockAddr::from(std::net::SocketAddr::V4(bind_addr)))
        .with_context(|| format!("bind recv sock to {bind_addr}"))?;
    Ok(s)
}

fn make_client_tx_sock(reply_port: u16) -> Result<Socket> {
    // Sends replies back to client, spoofing src IP via IP_PKTINFO.
    // Source port is fixed = reply_port (e.g. 53).
    let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    s.set_reuse_address(true)?;
    set_sockopt_int(&s, SOL_IP, IP_TRANSPARENT, 1)?;
    set_sockopt_int(&s, SOL_IP, IP_PKTINFO,     1)?;
    let addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, reply_port);
    s.bind(&socket2::SockAddr::from(std::net::SocketAddr::V4(addr)))
        .with_context(|| format!("bind client_tx sock to 0.0.0.0:{reply_port}"))?;
    Ok(s)
}

fn make_upstream_sock() -> Result<Socket> {
    // Plain UDP socket, kernel assigns ephemeral src port.
    let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    s.set_reuse_address(true)?;
    let addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0);
    s.bind(&socket2::SockAddr::from(std::net::SocketAddr::V4(addr)))?;
    Ok(s)
}

// ---------------------------------------------------------------------------
// recvmsg with IP_ORIGDSTADDR ancdata
// ---------------------------------------------------------------------------

fn recvmsg_with_orig_dst(fd: libc::c_int, buf: &mut [u8]) -> Result<(usize, SocketAddrV4, SocketAddrV4)> {
    let mut src_sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut iov = libc::iovec { iov_base: buf.as_mut_ptr() as *mut _, iov_len: buf.len() };
    let mut cbuf = [0u8; 256];
    let mut msg = libc::msghdr {
        msg_name:       &mut src_sa as *mut _ as *mut _,
        msg_namelen:    std::mem::size_of::<libc::sockaddr_in>() as u32,
        msg_iov:        &mut iov,
        msg_iovlen:     1,
        msg_control:    cbuf.as_mut_ptr() as *mut _,
        msg_controllen: cbuf.len(),
        msg_flags:      0,
    };

    let n = unsafe { libc::recvmsg(fd, &mut msg, 0) };
    if n < 0 {
        return Err(anyhow::anyhow!("recvmsg failed: {}", std::io::Error::last_os_error()));
    }

    let src = SocketAddrV4::new(
        Ipv4Addr::from(u32::from_be(src_sa.sin_addr.s_addr)),
        u16::from_be(src_sa.sin_port),
    );

    let mut orig_dst = None;
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == SOL_IP && (*cmsg).cmsg_type == IP_ORIGDSTADDR {
                let sa = libc::CMSG_DATA(cmsg) as *const libc::sockaddr_in;
                orig_dst = Some(SocketAddrV4::new(
                    Ipv4Addr::from(u32::from_be((*sa).sin_addr.s_addr)),
                    u16::from_be((*sa).sin_port),
                ));
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }

    Ok((n as usize, src, orig_dst.context("No IP_ORIGDSTADDR ancdata")?))
}

// ---------------------------------------------------------------------------
// sendmsg with IP_PKTINFO to spoof source IP
// ---------------------------------------------------------------------------

fn sendmsg_pktinfo(fd: libc::c_int, payload: &[u8], dst: SocketAddrV4, src_ip: Ipv4Addr) -> Result<()> {
    let dst_sa = libc::sockaddr_in {
        sin_family: libc::AF_INET as u16,
        sin_port:   dst.port().to_be(),
        sin_addr:   libc::in_addr { s_addr: u32::from(*dst.ip()).to_be() },
        sin_zero:   [0; 8],
    };
    let mut iov = libc::iovec { iov_base: payload.as_ptr() as *mut _, iov_len: payload.len() };

    #[repr(C)]
    struct InPktinfo { ipi_ifindex: libc::c_int, ipi_spec_dst: libc::in_addr, ipi_addr: libc::in_addr }

    let pktinfo = InPktinfo {
        ipi_ifindex:  0,
        ipi_spec_dst: libc::in_addr { s_addr: u32::from(src_ip).to_be() },
        ipi_addr:     libc::in_addr { s_addr: 0 },
    };

    let cmsg_space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<InPktinfo>() as u32) } as usize;
    let mut cbuf = vec![0u8; cmsg_space];

    let mut msg = libc::msghdr {
        msg_name:       &dst_sa as *const _ as *mut _,
        msg_namelen:    std::mem::size_of::<libc::sockaddr_in>() as u32,
        msg_iov:        &mut iov,
        msg_iovlen:     1,
        msg_control:    cbuf.as_mut_ptr() as *mut _,
        msg_controllen: cmsg_space,
        msg_flags:      0,
    };

    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        (*cmsg).cmsg_level = SOL_IP;
        (*cmsg).cmsg_type  = IP_PKTINFO;
        (*cmsg).cmsg_len   = libc::CMSG_LEN(std::mem::size_of::<InPktinfo>() as u32) as usize;
        std::ptr::write(libc::CMSG_DATA(cmsg) as *mut InPktinfo, pktinfo);
        let n = libc::sendmsg(fd, &msg, 0);
        if n < 0 {
            return Err(anyhow::anyhow!("sendmsg failed: {}", std::io::Error::last_os_error()));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Upstream reply thread — one per session
// ---------------------------------------------------------------------------

fn spawn_upstream_reply_thread(
    upstream_sock: Arc<Socket>,
    client_src:    SocketAddrV4,
    orig_dst:      SocketAddrV4,
    client_tx:     Arc<Socket>,
    sessions:      SessionMap,
) {
    thread::spawn(move || {
        let fd = upstream_sock.as_raw_fd();
        let mut buf = vec![0u8; 65535];
        loop {
            let n = unsafe {
                libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0)
            };
            if n <= 0 {
                eprintln!("[upstream->client] socket closed for session {client_src}->{orig_dst}");
                break;
            }

            // === INSPECT / MODIFY upstream->client payload here ===
            let reply = &buf[..n as usize];

            eprintln!("[upstream->client] upstream -> {client_src}  (spoofing src={}:{}) ({n} bytes)",
                orig_dst.ip(), orig_dst.port());

            if let Err(e) = sendmsg_pktinfo(client_tx.as_raw_fd(), reply, client_src, *orig_dst.ip()) {
                eprintln!("[upstream->client] sendmsg error: {e}");
                break;
            }
        }
        // Clean up session on socket close / error
        sessions.lock().unwrap().remove(&(client_src, orig_dst));
    });
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() -> Result<()> {
    let listen_addr: SocketAddrV4 = std::env::args()
        .nth(1).unwrap_or_else(|| "0.0.0.0:6666".into())
        .parse().context("listen addr (e.g. 0.0.0.0:6666)")?;

    let upstream_addr: SocketAddrV4 = std::env::args()
        .nth(2).unwrap_or_else(|| "8.8.8.8:53".into())
        .parse().context("upstream addr (e.g. 8.8.8.8:53)")?;

    // reply_port: the sport on packets we send back to the client.
    // Must match the original service port so the client accepts the reply.
    let reply_port: u16 = std::env::args()
        .nth(3).unwrap_or_else(|| "53".into())
        .parse().context("reply port (e.g. 53)")?;

    let client_rx = make_recv_sock(listen_addr)?;
    let client_tx = Arc::new(make_client_tx_sock(reply_port)?);

    // sessions: (client_src, orig_dst) -> upstream Socket
    let sessions: SessionMap = Arc::new(Mutex::new(HashMap::new()));

    eprintln!("[udp-tproxy] listen={listen_addr}  upstream={upstream_addr}  reply_sport={reply_port}");

    let rx_fd = client_rx.as_raw_fd();
    let mut buf = vec![0u8; 65535];

    loop {
        // --- Receive intercepted packet from client ---
        let (n, client_src, orig_dst) = match recvmsg_with_orig_dst(rx_fd, &mut buf) {
            Ok(v)  => v,
            Err(e) => { eprintln!("[client_rx] {e}"); continue; }
        };

        eprintln!("[client->upstream] {client_src} -> {orig_dst} ({n} bytes)");

        // === INSPECT / MODIFY client->upstream payload here ===
        let payload = buf[..n].to_vec();

        // --- Look up or create upstream socket for this flow ---
        let upstream_sock = {
            let mut map = sessions.lock().unwrap();
            if let Some(sock) = map.get(&(client_src, orig_dst)) {
                Arc::clone(sock)
            } else {
                // New session — create upstream socket and spawn reply thread
                let sock = match make_upstream_sock() {
                    Ok(s)  => Arc::new(s),
                    Err(e) => { eprintln!("[session] failed to create upstream sock: {e}"); continue; }
                };
                map.insert((client_src, orig_dst), Arc::clone(&sock));
                drop(map); // release lock before spawning thread

                spawn_upstream_reply_thread(
                    Arc::clone(&sock),
                    client_src,
                    orig_dst,
                    Arc::clone(&client_tx),
                    Arc::clone(&sessions),
                );
                sock
            }
        };

        // --- Forward to upstream ---
        let dst_sa = libc::sockaddr_in {
            sin_family: libc::AF_INET as u16,
            sin_port:   upstream_addr.port().to_be(),
            sin_addr:   libc::in_addr { s_addr: u32::from(*upstream_addr.ip()).to_be() },
            sin_zero:   [0; 8],
        };
        let ret = unsafe {
            libc::sendto(
                upstream_sock.as_raw_fd(),
                payload.as_ptr() as *const libc::c_void,
                payload.len(),
                0,
                &dst_sa as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            eprintln!("[client->upstream] sendto failed: {}", std::io::Error::last_os_error());
        }
    }
}
