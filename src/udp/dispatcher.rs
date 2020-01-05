use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::sync::mpsc;

use crate::socks::SocksServer;
use crate::udp::packet::{Packet, PacketSink};
use crate::udp::peer::Peer;

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
struct Key {
  // local address
  pub src: SocketAddr,

  // remote address
  pub dest: SocketAddr,
}

impl Key {
  pub fn from_packet(packet: &Packet) -> Self {
    Self {
      src: packet.src,
      dest: packet.dest,
    }
  }
}

#[derive(Debug, Clone)]
pub enum Signal {
  Ping,
  SendPacket(Packet),
}

#[derive(Clone)]
pub struct PeerHandle(mpsc::Sender<Signal>);

impl PeerHandle {
  pub fn new(sender: mpsc::Sender<Signal>) -> Self {
    Self(sender)
  }

  async fn send(&mut self, sig: Signal) -> Option<()> {
    self.0.send(sig).await.ok()
  }

  async fn send_packet(&mut self, packet: Packet) {
    use Signal::*;
    self.send(SendPacket(packet)).await;
  }

  async fn is_alive(&mut self) -> bool {
    use Signal::*;
    self.send(Ping).await.is_some()
  }
}

pub struct Dispatcher {
  table: HashMap<Key, PeerHandle>,
  collector: PacketSink,
  socks_server: SocksServer,
}

impl Dispatcher {
  pub fn setup(collector: PacketSink, socks_server: SocksServer) -> Self {
    let table = HashMap::new();
    Self {
      table,
      collector,
      socks_server,
    }
  }

  pub async fn dispatch_packet(&mut self, packet: Packet) {
    let key = Key::from_packet(&packet);
    let mut handle = self.get_handle(&key).await;
    handle.send_packet(packet).await;
  }

  async fn get_handle(&mut self, key: &Key) -> PeerHandle {
    match self.table.get(key) {
      Some(handle) if handle.clone().is_alive().await => handle.clone(),
      _ => self.start_peer(key).await,
    }
  }

  async fn start_peer(&mut self, key: &Key) -> PeerHandle {
    let peer = Peer::setup(
      key.src,
      key.dest,
      self.collector.clone(),
      self.socks_server.clone(),
    )
    .await
    .expect("failed to setup udp peer");
    let handle = peer.handle();
    tokio::spawn(peer.run());
    self.register(&key, handle.clone());
    handle
  }

  fn register(&mut self, key: &Key, handle: PeerHandle) {
    self.table.insert(*key, handle);
  }
}
