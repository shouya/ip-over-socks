// this module implements a transparent proxy
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};

use crate::config::Config;
use crate::nat::NatTable;
use crate::error::Result;
use crate::socks::SocksServer;

pub struct Client {
  pub socket: TcpStream,
  // the actual destination
  pub dest: SocketAddr,
  pub src: SocketAddr,
}

pub struct Tproxy {
  listener: TcpListener,
  socks_server: SocksServer,
  nat_table: NatTable,
}

impl Tproxy {
  pub async fn setup(conf: &Config, nat_table: &NatTable) -> Result<Self> {
    let bind_addr = (conf.tun_config.ip, conf.tproxy_config.bind_port);
    let listener = TcpListener::bind(bind_addr).await?;
    let socks_server = SocksServer::new(conf.socks_server_addr);
    let nat_table = nat_table.clone();

    Ok(Tproxy {
      socks_server,
      listener,
      nat_table,
    })
  }

  pub async fn start(mut self) -> Result<!> {
    loop {
      let (socket, peer_addr) = self.listener.accept().await?;
      match self.nat_table.get(peer_addr.port()).await {
        None => continue,
        Some(dest) => {
          let src = peer_addr.clone();
          let client = Client { dest, src, socket };
          let socks_server = self.socks_server.clone();

          tokio::spawn(async move {
            Self::forward_to_socks_proxy(socks_server, client).await
          });
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
