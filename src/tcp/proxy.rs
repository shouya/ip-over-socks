// this module implements a transparent proxy
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};

use crate::config::Config;
use crate::error::Result;
use crate::nat::NatTable;
use crate::socks::Client as SocksClient;

pub struct Client {
  pub socket: TcpStream,
  // the actual destination
  pub dest: SocketAddr,
  pub src: SocketAddr,
}

pub struct Proxy {
  listener: TcpListener,
  socks_client: SocksClient,
  nat_table: NatTable,
}

impl Proxy {
  pub async fn setup(conf: &Config, nat_table: &NatTable) -> Result<Self> {
    let bind_addr = (conf.ip, conf.tcp_port);
    let listener = TcpListener::bind(bind_addr).await?;
    let socks_client = SocksClient::new(conf.socks_server);
    let nat_table = nat_table.clone();

    Ok(Proxy {
      socks_client,
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
          let socks_client = self.socks_client.clone();

          tokio::spawn(async move {
            Self::forward_to_socks_proxy(socks_client, client).await
          });
        }
      }
    }
  }

  async fn forward_to_socks_proxy(
    socks_client: SocksClient,
    client: Client,
  ) -> Result<()> {
    use futures::future::select;
    use tokio::io::copy;

    let mut socks_client = socks_client.tcp_connect(client.dest).await?;
    let mut proxy_client = client.socket;

    let (mut socks_rx, mut socks_tx) = socks_client.split();
    let (mut tcp_proxy_rx, mut tcp_proxy_tx) = proxy_client.split();
    let down = copy(&mut socks_rx, &mut tcp_proxy_tx);
    let up = copy(&mut tcp_proxy_rx, &mut socks_tx);

    select(up, down).await;
    Ok(())
  }
}
