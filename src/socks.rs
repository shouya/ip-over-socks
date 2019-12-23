use std::net::SocketAddr;
use tokio::net::TcpStream;

use crate::error::Result;
use crate::proto::socks5;

#[derive(Clone)]
pub struct SocksServer {
  address: SocketAddr,
}

impl SocksServer {
  pub fn new(address: SocketAddr) -> Self {
    Self { address }
  }

  async fn handshake(&self) -> Result<TcpStream> {
    use socks5::*;
    let mut client = TcpStream::connect(self.address).await?;
    let auth_methods = vec![SOCKS5_AUTH_METHOD_NONE];
    let handshake_req = HandshakeRequest::new(auth_methods);
    handshake_req.write_to(&mut client).await?;

    let handshake_resp = HandshakeResponse::read_from(&mut client).await?;

    ensure!(
      handshake_resp.chosen_method == SOCKS5_AUTH_METHOD_NONE,
      "auth_none not supported!"
    );

    Ok(client)
  }

  pub async fn tcp_connect(&self, address: SocketAddr) -> Result<TcpStream> {
    use socks5::Reply::Succeeded;

    let mut client = self.handshake().await?;
    let req = {
      let command = socks5::Command::TcpConnect;
      let address = address.into();
      socks5::TcpRequestHeader { command, address }
    };

    req.write_to(&mut client).await?;
    let resp = socks5::TcpResponseHeader::read_from(&mut client).await?;
    ensure!(
      resp.reply == Succeeded,
      "socks server responded with non-successful resp"
    );

    Ok(client)
  }
}
