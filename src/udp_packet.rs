use bytes::Bytes;
use std::net::SocketAddr;
use tokio::sync::mpsc;

#[derive(Debug, Clone)]
pub struct UdpPacket {
  pub src: SocketAddr,
  pub dest: SocketAddr,
  pub payload: Bytes,
}

pub type UdpPacketSink = mpsc::Sender<UdpPacket>;
pub type UdpPacketSource = mpsc::Receiver<UdpPacket>;

pub fn channel() -> (UdpPacketSink, UdpPacketSource) {
  mpsc::channel(1)
}
