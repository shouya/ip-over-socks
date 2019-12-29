use bytes::{Buf, Bytes, BytesMut};
use futures::Future;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::udp::{RecvHalf, SendHalf};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

use crate::config::Config;
use crate::dst_map::DstMap;
use crate::error::Result;
use crate::socks::{SocksServer, UdpSession};

pub struct Datagram {
  // the actual destination
  pub dest: SocketAddr,
  pub src: SocketAddr,
  pub payload: Bytes,
}

#[derive(Debug)]
struct Socks5BrokerSender(SendHalf);

impl Socks5BrokerSender {
  async fn send_to(
    &mut self,
    bytes: &[u8],
    addr: impl Into<SocketAddr>,
  ) -> Result<usize> {
    let mut buf = SocksServer::udp_assoc_header(addr.into());
    let hdr_len = buf.len();
    buf.extend_from_slice(bytes);
    let sent_len = self.0.send(&buf).await?;
    Ok(sent_len - hdr_len)
  }
}

pub struct Socks5Broker {
  socket: UdpSocket,
  session: Option<UdpSession>,
  socks_server: SocksServer,
}

impl Socks5Broker {
  async fn setup(conf: &Config) -> Result<Self> {
    let bind_ip: IpAddr = [0u8; 4].into(); // conf.tun_config.ip;
    let bind_port = conf.udp_proxy_config.broker_bind_port;
    let socket = UdpSocket::bind((bind_ip, bind_port)).await?;

    Ok(Self {
      socket,
      session: None,
      socks_server: SocksServer::new(conf.socks_server_addr),
    })
  }

  async fn associate(&mut self) -> Result<()> {
    let dst_addr = ([0, 0, 0, 0], 10002).into();
    let session = self.socks_server.udp_associate(dst_addr).await?;

    self.socket.connect(session.bind_addr).await?;
    self.session = Some(session);

    Ok(())
  }

  async fn serve_listener(mut socket: RecvHalf) -> Result<()> {
    loop {
      let mut recv_buf = BytesMut::from(vec![0u8; 8196].as_slice());
      let (len, addr) = Self::recv_from(&mut socket, &mut recv_buf).await?;
      recv_buf.truncate(dbg!(len));
      // TODO: problem to solve: how to find out the original src address
      //
      // possible solution: bind to a different port to send each udp packet
      dbg!(recv_buf);
      dbg!(addr); // destination address
    }
  }

  fn serve(self) -> (impl Future<Output = Result<()>>, Socks5BrokerSender) {
    let (recv, send) = self.socket.split();
    let recv_fut = Self::serve_listener(recv);

    (recv_fut, Socks5BrokerSender(send))
  }

  async fn recv_from(
    socket: &mut RecvHalf,
    buffer: &mut [u8],
  ) -> Result<(usize, SocketAddr)> {
    // According to RFC 1928 Page 9, the header is at most 262 bytes longer than
    // the packet
    let mut recv_buf = BytesMut::from(vec![0u8; buffer.len() + 262].as_slice());
    let recv_len = socket.recv(recv_buf.as_mut()).await?;
    recv_buf.truncate(recv_len);

    let (hdr_len, addr) = SocksServer::parse_udp_assoc_header(&recv_buf)
      .ok_or(failure::err_msg("unable to parse socks5 udp_assoc_header"))?;

    recv_buf.advance(hdr_len);
    buffer[..recv_buf.len()].copy_from_slice(&recv_buf);

    let buf_len = recv_len - hdr_len;
    Ok((buf_len, addr))
  }
}

pub struct UdpProxy {
  listener: UdpSocket,
  broker: Socks5Broker,
  dst_map: DstMap,
}

impl UdpProxy {
  pub async fn setup(conf: &Config, dst_map: &DstMap) -> Result<Self> {
    let dst_map = dst_map.clone();

    let udp_conf = &conf.udp_proxy_config;
    let bind_addr = (conf.tun_config.ip, udp_conf.bind_port);
    let listener = UdpSocket::bind(bind_addr).await?;

    let mut broker = Socks5Broker::setup(conf).await?;
    broker.associate().await?;

    Ok(Self {
      listener,
      dst_map,
      broker,
    })
  }

  pub async fn start(self) -> Result<()> {
    let (mut recv_half, send_half) = self.listener.split();
    let send_half = Arc::new(Mutex::new(send_half));

    let (fut, mut broker) = self.broker.serve();
    tokio::spawn(fut);

    loop {
      let mut recv_buf = BytesMut::from(vec![0u8; 8196].as_slice());
      let (len, src) = dbg!(recv_half.recv_from(&mut recv_buf).await?);
      recv_buf.truncate(len);
      match self.dst_map.get(src.port()).await {
        None => {
          continue;
        }
        Some(dest) => {
          let payload = recv_buf.clone().freeze();
          broker.send_to(&payload, dest).await?;
        }
      }
    }
  }
}
