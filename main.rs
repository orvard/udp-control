use std::collections::HashMap;
use std::io::IoSliceMut;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::unix::io::AsRawFd;
use std::sync::{Arc, Mutex};
use std::thread;

use anyhow::{Context, Result};
use socket2::{Domain, MsgHdrMut, Protocol, SockAddr, Socket, Type};

// Socket options not yet exposed by socket2
const IP_TRANSPARENT: libc::c_int     = 19;
const IP_RECVORIGDSTADDR: libc::c_int = 20;
const IP_ORIGDSTADDR: libc::c_int     = 20;
const IP_PKTINFO: libc::c_int         = 8;
const SOL_IP: libc::c_int             = 0;

const IPV6_TRANSPARENT: libc::c_int   = 75;
const IPV6_RECVPKTINFO: libc::c_int   = 49;
const IPV6_PKTINFO: libc::c_int       = 50;
const SOL_IPV6: libc::c_int           = 41;

type SessionMap = Arc<Mutex<HashMap<(SocketAddr, SocketAddr), Arc<Socket>>>>;

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

fn make_recv_sock(bind_addr: SocketAddr) -> Result<Socket> {
    let domain = if bind_addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
    let s = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    s.set_reuse_address(true)?;
    s.set_reuse_port(true)?;
    if bind_addr.is_ipv4() {
        set_sockopt_int(&s, SOL_IP,   IP_TRANSPARENT,     1)?;
        set_sockopt_int(&s, SOL_IP,   IP_RECVORIGDSTADDR, 1)?;
    } else {
        set_sockopt_int(&s, SOL_IPV6, IPV6_TRANSPARENT,  1)?;
        set_sockopt_int(&s, SOL_IPV6, IPV6_RECVPKTINFO,  1)?;
    }
    s.bind(&SockAddr::from(bind_addr))
        .with_context(|| format!("bind recv sock to {bind_addr}"))?;
    Ok(s)
}

fn make_client_tx_sock(reply_port: u16, ipv6: bool) -> Result<Socket> {
    // Sends replies back to the client, spoofing the source IP via
    // IP_PKTINFO / IPV6_PKTINFO.  Source port is fixed = reply_port (e.g. 53).
    let bind_addr = if ipv6 {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), reply_port)
    } else {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), reply_port)
    };
    let domain = if ipv6 { Domain::IPV6 } else { Domain::IPV4 };
    let s = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    s.set_reuse_address(true)?;
    if ipv6 {
        set_sockopt_int(&s, SOL_IPV6, IPV6_TRANSPARENT, 1)?;
        set_sockopt_int(&s, SOL_IPV6, IPV6_PKTINFO,     1)?;
    } else {
        set_sockopt_int(&s, SOL_IP,   IP_TRANSPARENT,   1)?;
        set_sockopt_int(&s, SOL_IP,   IP_PKTINFO,       1)?;
    }
    s.bind(&SockAddr::from(bind_addr))
        .with_context(|| format!("bind client_tx sock to {bind_addr}"))?;
    Ok(s)
}

fn make_upstream_sock(ipv6: bool) -> Result<Socket> {
    // Plain UDP socket; the kernel assigns an ephemeral source port.
    let bind_addr = if ipv6 {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    };
    let domain = if ipv6 { Domain::IPV6 } else { Domain::IPV4 };
    let s = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    s.set_reuse_address(true)?;
    s.bind(&SockAddr::from(bind_addr))?;
    Ok(s)
}

// ---------------------------------------------------------------------------
// recvmsg — extract source and original-destination addresses
//
// IPv4: IP_RECVORIGDSTADDR delivers a sockaddr_in in a
//       SOL_IP / IP_ORIGDSTADDR control message.
// IPv6: IPV6_RECVPKTINFO delivers an in6_pktinfo in a
//       SOL_IPV6 / IPV6_PKTINFO control message; its ipi6_addr field is the
//       packet's destination address (our "original dst").
//       The port is not carried by pktinfo — we use listen_port instead.
// ---------------------------------------------------------------------------

fn recvmsg_with_orig_dst(
    sock: &Socket,
    buf: &mut [u8],
    listen_port: u16,
) -> Result<(usize, SocketAddr, SocketAddr)> {
    let mut cbuf = [0u8; 256];
    let mut iov  = [IoSliceMut::new(buf)];

    // socket2::MsgHdrMut zero-initialises msghdr and provides a builder API.
    // SockAddr::try_init handles the peer-address storage and length field,
    // replacing the manual sockaddr_in zeroing in the original.
    let mut msg = MsgHdrMut::new()
        .with_buffers(&mut iov)
        .with_control_buffer(&mut cbuf);

    let (n, peer) = unsafe {
        SockAddr::try_init(|storage, len| {
            msg.inner.msg_name    = storage.cast();
            msg.inner.msg_namelen = *len;
            let n = sock.recvmsg(&mut msg, 0)?;
            *len = msg.inner.msg_namelen;
            Ok(n)
        })?
    };
    let src = peer.as_socket().context("peer address is not an IP socket address")?;

    // Walk the ancillary control messages to find the original destination.
    let mut orig_dst: Option<SocketAddr> = None;
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg.inner);
        while !cmsg.is_null() {
            let level = (*cmsg).cmsg_level;
            let typ   = (*cmsg).cmsg_type;
            let data  = libc::CMSG_DATA(cmsg);

            if level == SOL_IP && typ == IP_ORIGDSTADDR {
                let sa = data as *const libc::sockaddr_in;
                orig_dst = Some(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::from(u32::from_be((*sa).sin_addr.s_addr))),
                    u16::from_be((*sa).sin_port),
                ));
            } else if level == SOL_IPV6 && typ == IPV6_PKTINFO {
                // struct in6_pktinfo { struct in6_addr ipi6_addr; unsigned int ipi6_ifindex; }
                #[repr(C)]
                struct In6Pktinfo {
                    ipi6_addr:    libc::in6_addr,
                    ipi6_ifindex: libc::c_uint,
                }
                let pi = data as *const In6Pktinfo;
                orig_dst = Some(SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::from((*pi).ipi6_addr.s6_addr)),
                    listen_port,
                ));
            }
            cmsg = libc::CMSG_NXTHDR(&msg.inner, cmsg);
        }
    }

    Ok((n, src, orig_dst.context("No original-destination ancillary data")?))
}

// ---------------------------------------------------------------------------
// sendmsg with IP_PKTINFO / IPV6_PKTINFO to spoof the source IP
//
// socket2::MsgHdr does not expose its inner msghdr publicly, so the msghdr
// is built by hand.  However, socket2::SockAddr replaces the manual
// sockaddr_in / sockaddr_in6 literals: as_ptr() + len() give the correct
// pointer and length for whichever address family is in use.
// ---------------------------------------------------------------------------

fn sendmsg_spoof_src(sock: &Socket, payload: &[u8], dst: SocketAddr, src_ip: IpAddr) -> Result<()> {
    let dst_sa  = SockAddr::from(dst);
    let mut iov = libc::iovec {
        iov_base: payload.as_ptr() as *mut _,
        iov_len:  payload.len(),
    };

    match src_ip {
        IpAddr::V4(v4) => {
            #[repr(C)]
            struct InPktinfo {
                ipi_ifindex:  libc::c_int,
                ipi_spec_dst: libc::in_addr,
                ipi_addr:     libc::in_addr,
            }
            let pktinfo = InPktinfo {
                ipi_ifindex:  0,
                ipi_spec_dst: libc::in_addr { s_addr: u32::from(v4).to_be() },
                ipi_addr:     libc::in_addr { s_addr: 0 },
            };
            let cmsg_space =
                unsafe { libc::CMSG_SPACE(std::mem::size_of::<InPktinfo>() as u32) } as usize;
            let mut cbuf = vec![0u8; cmsg_space];
            let mut msg  = libc::msghdr {
                msg_name:       dst_sa.as_ptr() as *mut _, // socket2::SockAddr replaces sockaddr_in
                msg_namelen:    dst_sa.len(),
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
                (*cmsg).cmsg_len   =
                    libc::CMSG_LEN(std::mem::size_of::<InPktinfo>() as u32) as usize;
                std::ptr::write(libc::CMSG_DATA(cmsg) as *mut InPktinfo, pktinfo);
                let n = libc::sendmsg(sock.as_raw_fd(), &msg, 0);
                if n < 0 {
                    return Err(anyhow::anyhow!(
                        "sendmsg (v4) failed: {}", std::io::Error::last_os_error()
                    ));
                }
            }
        }

        IpAddr::V6(v6) => {
            #[repr(C)]
            struct In6Pktinfo {
                ipi6_addr:    libc::in6_addr,
                ipi6_ifindex: libc::c_uint,
            }
            let pktinfo = In6Pktinfo {
                ipi6_addr:    libc::in6_addr { s6_addr: v6.octets() },
                ipi6_ifindex: 0,
            };
            let cmsg_space =
                unsafe { libc::CMSG_SPACE(std::mem::size_of::<In6Pktinfo>() as u32) } as usize;
            let mut cbuf = vec![0u8; cmsg_space];
            let mut msg  = libc::msghdr {
                msg_name:       dst_sa.as_ptr() as *mut _, // socket2::SockAddr replaces sockaddr_in6
                msg_namelen:    dst_sa.len(),
                msg_iov:        &mut iov,
                msg_iovlen:     1,
                msg_control:    cbuf.as_mut_ptr() as *mut _,
                msg_controllen: cmsg_space,
                msg_flags:      0,
            };
            unsafe {
                let cmsg = libc::CMSG_FIRSTHDR(&msg);
                (*cmsg).cmsg_level = SOL_IPV6;
                (*cmsg).cmsg_type  = IPV6_PKTINFO;
                (*cmsg).cmsg_len   =
                    libc::CMSG_LEN(std::mem::size_of::<In6Pktinfo>() as u32) as usize;
                std::ptr::write(libc::CMSG_DATA(cmsg) as *mut In6Pktinfo, pktinfo);
                let n = libc::sendmsg(sock.as_raw_fd(), &msg, 0);
                if n < 0 {
                    return Err(anyhow::anyhow!(
                        "sendmsg (v6) failed: {}", std::io::Error::last_os_error()
                    ));
                }
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Upstream reply thread — one per session
// ---------------------------------------------------------------------------

fn spawn_upstream_reply_thread(
    upstream_sock: Arc<Socket>,
    client_src:    SocketAddr,
    orig_dst:      SocketAddr,
    client_tx:     Arc<Socket>,
    sessions:      SessionMap,
) {
    thread::spawn(move || {
        let mut buf = vec![0u8; 65535];
        loop {
            let n = unsafe {
                libc::recv(
                    upstream_sock.as_raw_fd(),
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                    0,
                )
            };
            if n <= 0 {
                eprintln!("[upstream->client] socket closed for session {client_src}->{orig_dst}");
                break;
            }

            // === INSPECT / MODIFY upstream->client payload here ===
            let reply = &buf[..n as usize];

            eprintln!(
                "[upstream->client] upstream -> {client_src}  (spoofing src={orig_dst}) ({n} bytes)",
            );

            if let Err(e) = sendmsg_spoof_src(&client_tx, reply, client_src, orig_dst.ip()) {
                eprintln!("[upstream->client] sendmsg error: {e}");
                break;
            }
        }
        sessions.lock().unwrap().remove(&(client_src, orig_dst));
    });
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() -> Result<()> {
    let listen_addr: SocketAddr = std::env::args()
        .nth(1).unwrap_or_else(|| "0.0.0.0:6666".into())
        .parse().context("listen addr (e.g. 0.0.0.0:6666 or [::]:6666)")?;

    let upstream_addr: SocketAddr = std::env::args()
        .nth(2).unwrap_or_else(|| "8.8.8.8:53".into())
        .parse().context("upstream addr (e.g. 8.8.8.8:53 or [2001:4860:4860::8888]:53)")?;

    // reply_port: the source port on packets we send back to the client.
    // Must match the original service port so the client accepts the reply.
    let reply_port: u16 = std::env::args()
        .nth(3).unwrap_or_else(|| "53".into())
        .parse().context("reply port (e.g. 53)")?;

    let ipv6 = listen_addr.is_ipv6();
    if ipv6 != upstream_addr.is_ipv6() {
        anyhow::bail!("listen address and upstream address must both be IPv4 or both IPv6");
    }

    let client_rx = make_recv_sock(listen_addr)?;
    let client_tx = Arc::new(make_client_tx_sock(reply_port, ipv6)?);

    // sessions: (client_src, orig_dst) -> upstream Socket
    let sessions: SessionMap = Arc::new(Mutex::new(HashMap::new()));

    eprintln!("[udp-tproxy] listen={listen_addr}  upstream={upstream_addr}  reply_sport={reply_port}");

    let mut buf = vec![0u8; 65535];

    loop {
        // --- Receive intercepted packet from client ---
        let (n, client_src, orig_dst) =
            match recvmsg_with_orig_dst(&client_rx, &mut buf, listen_addr.port()) {
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
                let sock = match make_upstream_sock(ipv6) {
                    Ok(s)  => Arc::new(s),
                    Err(e) => {
                        eprintln!("[session] failed to create upstream sock: {e}");
                        continue;
                    }
                };
                map.insert((client_src, orig_dst), Arc::clone(&sock));
                drop(map); // release lock before spawning

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
        // socket2::Socket::send_to replaces the manual libc::sendto call and
        // converts SocketAddr to sockaddr_in or sockaddr_in6 automatically.
        if let Err(e) = upstream_sock.send_to(&payload, &SockAddr::from(upstream_addr)) {
            eprintln!("[client->upstream] send_to failed: {e}");
        }
    }
}
