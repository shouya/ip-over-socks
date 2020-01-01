use bytes::{Buf, BytesMut};
use std::net::IpAddr;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::config::Config;
use crate::dst_map::DstMap;
use crate::error::Result;
use crate::socks::{SocksServer, UdpSession};
use crate::udp_packet::{UdpPacket, UdpPacketSink};

struct UdpPeer {
  session: UdpSession,
  socket: UdpSocket,
}

impl UdpPeer {
  async fn setup(endpoint: &SocksServer) -> Result<Self> {
    let bind_addr: SocketAddr = ([0, 0, 0, 0], 0u16).into();
    let socket = UdpSocket::bind(bind_addr).await?;
    let session = endpoint.udp_associate(bind_addr).await?;

    socket.connect(session.bind_addr.clone());

    Ok(Self { session, socket })
  }

  async fn send_to(
    &mut self,
    bytes: &[u8],
    addr: impl Into<SocketAddr>,
  ) -> Result<usize> {
    let mut buf = SocksServer::udp_assoc_header(addr.into());
    let hdr_len = buf.len();
    buf.extend_from_slice(bytes);
    let sent_len = self.socket.send(&buf).await?;
    Ok(sent_len - hdr_len)
  }

  async fn recv_from(
    &mut self,
    buffer: &mut [u8],
  ) -> Result<(usize, SocketAddr)> {
    // According to RFC 1928 Page 9, the header is at most 262 bytes longer than
    // the packet
    let mut recv_buf = BytesMut::from(vec![0u8; buffer.len() + 262].as_slice());
    let recv_len = self.socket.recv(recv_buf.as_mut()).await?;
    recv_buf.truncate(recv_len);

    let (hdr_len, addr) = SocksServer::parse_udp_assoc_header(&recv_buf)
      .ok_or(failure::err_msg("unable to parse socks5 udp_assoc_header"))?;

    recv_buf.advance(hdr_len);
    buffer[..recv_buf.len()].copy_from_slice(&recv_buf);

    let buf_len = recv_len - hdr_len;
    Ok((buf_len, addr))
  }

  async fn run(
    mut self,
    src: SocketAddr,
    mut packet_sink: UdpPacketSink,
  ) -> Result<!> {
    loop {
      let mut recv_buf = BytesMut::from(vec![0u8; 8196].as_slice());
      let (len, dest) = self.recv_from(&mut recv_buf).await?;
      recv_buf.truncate(len);

      packet_sink
        .send(UdpPacket {
          src: dest,
          dest: src,
          payload: recv_buf.freeze(),
        })
        .await?;
    }
  }
}

pub struct UdpProxy {
  socks_server: SocksServer,
  src_ip: IpAddr,
  listener: UdpSocket,
  dst_map: DstMap,
  packet_sink: UdpPacketSink,
}

impl UdpProxy {
  pub async fn setup(
    conf: &Config,
    dst_map: &DstMap,
    packet_sink: UdpPacketSink,
  ) -> Result<Self> {
    let dst_map = dst_map.clone();

    let udp_conf = &conf.udp_proxy_config;
    let bind_addr = (conf.tun_config.ip, udp_conf.bind_port);
    let listener = UdpSocket::bind(bind_addr).await?;
    let socks_server = SocksServer::new(conf.socks_server_addr);
    let src_ip = conf.tun_config.ip.into();

    Ok(Self {
      listener,
      dst_map,
      socks_server,
      src_ip,
      packet_sink,
    })
  }

  pub async fn start(self) -> Result<!> {
    let (mut recv_half, send_half) = self.listener.split();

    loop {
      let mut recv_buf = BytesMut::from(vec![0u8; 8196].as_slice());
      let (len, mut src) = recv_half.recv_from(&mut recv_buf).await?;
      recv_buf.truncate(len);

      match self.dst_map.get(src.port()).await {
        None => {
          continue;
        }
        Some(dest) => {
          let mut peer = UdpPeer::setup(&self.socks_server).await?;
          peer.send_to(&recv_buf, dest).await?;

          src.set_ip(self.src_ip);
          let sink = self.packet_sink.clone();
          let fut = peer.run(src, sink);

          let expires = Duration::from_secs(30);
          tokio::spawn(timeout(expires, fut));
        }
      }
    }
  }
}
