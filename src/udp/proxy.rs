use crate::config::Config;
use crate::error::*;
use crate::nat::NatTable;
use crate::socks::Client as SocksClient;
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
  nat_table: NatTable,
  dispatcher: Dispatcher,
}

impl Proxy {
  pub async fn setup(
    conf: &Config,
    nat_table: &NatTable,
    packet_sink: PacketSink,
  ) -> Result<Self> {
    let nat_table = nat_table.clone();

    let bind_addr = (conf.ip, conf.udp_port);
    let socket = UdpSocket::bind(bind_addr).await?;
    let socks_client = SocksClient::new(conf.socks_server);
    let src_ip = conf.ip.into();
    let dispatcher = Dispatcher::setup(packet_sink, socks_client);

    Ok(Self {
      socket,
      nat_table,
      dispatcher,
      src_ip,
    })
  }

  pub async fn start(mut self) -> Result<!> {
    loop {
      let mut recv_buf = BytesMut::from(vec![0u8; 8196].as_slice());
      let (len, src) = self.socket.recv_from(&mut recv_buf).await?;
      recv_buf.truncate(len);

      match self.nat_table.get(src.port()).await {
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
