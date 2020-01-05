use bytes::BytesMut;
use std::net::SocketAddr;
use tokio::net::TcpStream;

use crate::error::Result;
use crate::socks::proto;

#[derive(Clone, Debug)]
pub struct Client {
  server_addr: SocketAddr,
}

#[derive(Debug)]
pub struct UdpSession {
  session: TcpStream,
  pub bind_addr: SocketAddr,
}

impl Client {
  pub fn new(server_addr: SocketAddr) -> Self {
    Self { server_addr }
  }

  async fn handshake(&self) -> Result<TcpStream> {
    use proto::*;
    let mut client = TcpStream::connect(self.server_addr).await?;
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
    use proto::Reply::Succeeded;

    let mut client = self.handshake().await?;
    let req = {
      let command = proto::Command::TcpConnect;
      let address = address.into();
      proto::TcpRequestHeader { command, address }
    };

    req.write_to(&mut client).await?;
    let resp = proto::TcpResponseHeader::read_from(&mut client).await?;
    ensure!(
      resp.reply == Succeeded,
      "socks server responded with non-successful resp (tcp connect)"
    );

    Ok(client)
  }

  pub async fn udp_associate(&self, address: SocketAddr) -> Result<UdpSession> {
    use proto::Reply::Succeeded;
    use std::net::ToSocketAddrs;

    let mut client = self.handshake().await?;
    let req = {
      let command = proto::Command::UdpAssociate;
      let address = address.into();
      proto::TcpRequestHeader { command, address }
    };

    req.write_to(&mut client).await?;
    // it crashes here, I may need to check on the response from socks server
    let resp = match proto::TcpResponseHeader::read_from(&mut client).await {
      Ok(resp) => resp,
      e => bail!("failed here: {:?}", e),
    };
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
    let hdr = proto::UdpAssociateHeader::new(0x0, address.into());
    let mut buf = BytesMut::new();
    hdr.write_to_buf(&mut buf);
    buf
  }

  // returns (udp_assoc_hdr_len, dst_addr)
  pub fn parse_udp_assoc_header(bytes: &[u8]) -> Option<(usize, SocketAddr)> {
    use futures::executor::block_on;
    use std::net::ToSocketAddrs;
    let hdr = block_on(proto::UdpAssociateHeader::read_from(bytes)).ok()?;
    let addr = hdr.address.to_socket_addrs().ok()?.next()?;
    Some((hdr.serialized_len(), addr))
  }
}
