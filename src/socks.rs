use bytes::BytesMut;
use std::net::SocketAddr;
use tokio::net::TcpStream;

use crate::error::Result;
use crate::proto::socks5;

#[derive(Clone, Debug)]
pub struct SocksServer {
  address: SocketAddr,
}

#[derive(Debug)]
pub struct UdpSession {
  session: TcpStream,
  pub bind_addr: SocketAddr,
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
      "socks server responded with non-successful resp (tcp connect)"
    );

    Ok(client)
  }

  pub async fn udp_associate(&self, address: SocketAddr) -> Result<UdpSession> {
    use socks5::Reply::Succeeded;
    use std::net::ToSocketAddrs;

    let mut client = self.handshake().await?;
    let req = {
      let command = socks5::Command::UdpAssociate;
      let address = address.into();
      socks5::TcpRequestHeader { command, address }
    };

    req.write_to(&mut client).await?;
    // it crashes here, I may need to check on the response from socks server
    let resp = socks5::TcpResponseHeader::read_from(&mut client).await?;
    ensure!(
      resp.reply == Succeeded,
      "socks server responded with non-successful resp (udp associate)"
    );

    let bind_addr = resp.address.to_socket_addrs()?.next().unwrap();

    Ok(UdpSession {
      session: client,
      bind_addr,
    })
  }

  pub fn udp_assoc_header(address: SocketAddr) -> BytesMut {
    let hdr = socks5::UdpAssociateHeader::new(0x0, address.into());
    let mut buf = BytesMut::new();
    hdr.write_to_buf(&mut buf);
    buf
  }
}
