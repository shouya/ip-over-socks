use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;

// map from src port to actual dest addr,
// as the info was erased while the packet is been redirected to tcp proxy
#[derive(Clone)]
pub struct NatTable(Arc<Mutex<HashMap<u16, SocketAddr>>>);

impl NatTable {
  pub fn new() -> Self {
    let map = Arc::new(Mutex::new(HashMap::new()));
    NatTable(map)
  }

  pub async fn put(&self, src_port: u16, dst_addr: SocketAddr) -> () {
    self.0.lock().await.insert(src_port, dst_addr);
  }

  pub async fn get(&self, src_port: u16) -> Option<SocketAddr> {
    self.0.lock().await.get(&src_port).cloned()
  }
}
