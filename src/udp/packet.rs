use bytes::Bytes;
use std::net::SocketAddr;
use tokio::sync::mpsc;

#[derive(Debug, Clone)]
pub struct Packet {
  pub src: SocketAddr,
  pub dest: SocketAddr,
  pub payload: Bytes,
}

pub type PacketSink = mpsc::Sender<Packet>;
pub type PacketSource = mpsc::Receiver<Packet>;

pub fn channel() -> (PacketSink, PacketSource) {
  mpsc::channel(0)
}


