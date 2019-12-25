// this module implements a transparent proxy
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};

use crate::config::Config;
use crate::dst_map::DstMap;
use crate::error::Result;
use crate::socks::SocksServer;

pub struct Client {
  pub socket: TcpStream,
  // the actual destination
  pub dest: SocketAddr,
  // the source
  pub src: SocketAddr,
}

pub struct Tproxy {
  listener: TcpListener,
  socks_server: SocksServer,
  dst_map: DstMap,
}

impl Tproxy {
  pub async fn setup(conf: &Config, dst_map: &DstMap) -> Result<Self> {
    let bind_addr = (conf.tun_config.ip, conf.tproxy_config.bind_port);
    dbg!("tproxy bound to {}", &bind_addr);
    let listener = TcpListener::bind(bind_addr).await?;
    let socks_server = SocksServer::new(conf.socks_server_addr);
    let dst_map = dst_map.clone();

    Ok(Tproxy {
      socks_server,
      listener,
      dst_map,
    })
  }

  pub async fn start(mut self) -> Result<()> {
    loop {
      dbg!("tproxy working");
      let (socket, peer_addr) = self.listener.accept().await?;
      dbg!("tproxy accepted");
      match self.dst_map.get(peer_addr.port()).await? {
        None => continue,
        Some(dest) => {
          dbg!("nat performed");
          let src = peer_addr.clone();
          let client = Client { dest, src, socket };
          let socks_server = self.socks_server.clone();

          tokio::spawn(async move {
            dbg!("redir started");
            Self::forward_to_socks_proxy(socks_server, client).await
          })
          .await
          .ok();
        }
      }
    }
  }

  async fn forward_to_socks_proxy(
    socks_server: SocksServer,
    client: Client,
  ) -> Result<()> {
    use futures::future::select;
    use tokio::io::copy;

    dbg!("client!");
    let mut socks_client = socks_server.tcp_connect(client.dest).await?;
    let mut tproxy_client = client.socket;

    let (mut socks_rx, mut socks_tx) = socks_client.split();
    let (mut tproxy_rx, mut tproxy_tx) = tproxy_client.split();
    let down = copy(&mut socks_rx, &mut tproxy_tx);
    let up = copy(&mut tproxy_rx, &mut socks_tx);

    select(up, down).await;
    Ok(())
  }
}
