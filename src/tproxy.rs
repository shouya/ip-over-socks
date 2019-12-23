// this module implements a transparent proxy
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};

use crate::config::Config;
use crate::dst_map::DstMap;
use crate::error::*;
use crate::socks::SocksServer;

pub struct Client {
    pub socket: TcpStream,
    // the actual destination
    pub dest: SocketAddr,
    // the source
    pub src: SocketAddr,
}

// transparent proxy
pub struct Tproxy {
    bind_addr: SocketAddr,
    listener: TcpListener,
    socks_server: SocksServer,
    dst_map: Arc<DstMap>,
}

impl Tproxy {
    pub async fn setup(conf: &Config, dst_map: Arc<DstMap>) -> Result<Self> {
        let bind_addr = conf.tproxy_config.bind_addr;
        let listener = TcpListener::bind(bind_addr).await?;
        let socks_server = SocksServer::new(conf.socks_server_addr);

        Ok(Tproxy {
            socks_server,
            bind_addr,
            listener,
            dst_map,
        })
    }

    pub async fn start(mut self) -> Result<()> {
        let dst_map = self.dst_map.clone();

        loop {
            let (socket, peer_addr) = self.listener.accept().await?;
            match (*dst_map).pop(peer_addr.port()).await? {
                None => continue,
                Some(dest) => {
                    let src = peer_addr.clone();
                    let client = Client { dest, src, socket };
                    let socks_server = self.socks_server.clone();
                    tokio::spawn(async move { Self::forward_to_socks_proxy(socks_server, client) });
                }
            }
        }
    }

    fn forward_to_socks_proxy(_socks_server: SocksServer, _client: Client) {
        ()
    }
}
