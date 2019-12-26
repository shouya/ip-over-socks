use bytes::{Bytes, BytesMut};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{udp, UdpSocket};
use tokio::sync::Mutex;

use crate::config::Config;
use crate::dst_map::DstMap;
use crate::error::Result;
use crate::socks::SocksServer;

pub struct Datagram {
  // the actual destination
  pub dest: SocketAddr,
  // the source
  pub src: SocketAddr,
  // payload
  pub payload: Bytes,
}

pub struct UdpProxy {
  socket: UdpSocket,
  recv_buf: BytesMut,
  socks_server: SocksServer,
  dst_map: DstMap,
}

impl UdpProxy {
  pub async fn setup(conf: &Config, dst_map: &DstMap) -> Result<Self> {
    let udp_conf = &conf.udp_proxy_config;
    let bind_addr = (conf.tun_config.ip, udp_conf.bind_port);
    let socket = UdpSocket::bind(bind_addr).await?;

    let socks_server = SocksServer::new(conf.socks_server_addr);
    let recv_buf = BytesMut::with_capacity(udp_conf.recv_buf_size);
    let dst_map = dst_map.clone();

    Ok(Self {
      socket,
      dst_map,
      recv_buf,
      socks_server,
    })
  }

  pub async fn start(self) -> Result<()> {
    let (mut recv_half, send_half) = self.socket.split();
    let mut recv_buf = self.recv_buf;
    let send_half = Arc::new(Mutex::new(send_half));

    loop {
      let (_, src) = recv_half.recv_from(&mut recv_buf).await?;
      match self.dst_map.get(src.port()).await {
        None => {
          continue;
        }
        Some(dest) => {
          let payload = recv_buf.clone().freeze();
          let datagram = Datagram { src, dest, payload };
          let socks_server = self.socks_server.clone();
          let send_half = send_half.clone();

          tokio::spawn(async move {
            Self::forward_udp_packet(send_half, socks_server, datagram)
              .await
              .expect("failed to send udp packet")
          })
          .await?;
        }
      }
    }
  }

  pub async fn forward_udp_packet(
    send_half: Arc<Mutex<udp::SendHalf>>,
    socks_server: SocksServer,
    datagram: Datagram,
  ) -> Result<()> {
    let bind_addr = socks_server.udp_associate(datagram.dest).await?.bind_addr;
    let mut bytes = SocksServer::udp_assoc_header(datagram.dest);
    bytes.extend_from_slice(&datagram.payload);
    let mut send_half = send_half.lock().await;
    send_half.send_to(&bytes, &bind_addr).await?;

    Ok(())
  }
}
