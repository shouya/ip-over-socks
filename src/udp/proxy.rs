use crate::config::Config;
use crate::dst_map::DstMap;
use crate::error::*;
use crate::socks::SocksServer;
use crate::udp::{
  dispatcher::Dispatcher,
  packet::{Packet, PacketSink},
};

use bytes::BytesMut;
use std::net::IpAddr;
use tokio::net::UdpSocket;

pub struct Proxy {
  src_ip: IpAddr,
  socket: UdpSocket,
  dst_map: DstMap,
  dispatcher: Dispatcher,
}

impl Proxy {
  pub async fn setup(
    conf: &Config,
    dst_map: &DstMap,
    packet_sink: PacketSink,
  ) -> Result<Self> {
    let dst_map = dst_map.clone();

    let udp_conf = &conf.udp_proxy_config;
    let bind_addr = (conf.tun_config.ip, udp_conf.bind_port);
    let socket = UdpSocket::bind(bind_addr).await?;
    let socks_server = SocksServer::new(conf.socks_server_addr);
    let src_ip = conf.tun_config.ip.into();
    let dispatcher = Dispatcher::setup(packet_sink, socks_server);

    Ok(Self {
      socket,
      dst_map,
      dispatcher,
      src_ip,
    })
  }

  pub async fn start(mut self) -> Result<!> {
    loop {
      let mut recv_buf = BytesMut::from(vec![0u8; 8196].as_slice());
      let (len, src) = self.socket.recv_from(&mut recv_buf).await?;
      recv_buf.truncate(len);

      match self.dst_map.get(src.port()).await {
        None => {
          continue;
        }
        Some(dest) => {
          let packet = Packet {
            src: (self.src_ip, src.port()).into(),
            dest: dest,
            payload: recv_buf.freeze(),
          };
          self.dispatcher.dispatch_packet(packet).await;
        }
      }
    }
  }
}
