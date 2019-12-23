use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::sync::Mutex;

use crate::error::*;

// map from src port to actual dest addr,
// as the info was erased while the packet is been redirected to tproxy
pub struct DstMap(Mutex<HashMap<u16, SocketAddr>>);

impl DstMap {
    pub fn new() -> Self {
        let map = Mutex::new(HashMap::new());
        DstMap(map)
    }

    pub async fn push(&self, src_port: u16, dst_addr: SocketAddr) -> Result<()> {
        self.0.lock().await.insert(src_port, dst_addr);
        Ok(())
    }

    pub async fn pop(&self, src_port: u16) -> Result<Option<SocketAddr>> {
        Ok(self.0.lock().await.remove(&src_port))
    }
}
