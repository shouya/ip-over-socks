use bytes::{Bytes, BytesMut};
use futures::select;
use futures::FutureExt;
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::error::*;
use crate::socks::{SocksServer, UdpSession};
use crate::udp::dispatcher::{PeerHandle, Signal};
use crate::udp::packet::{Packet, PacketSink};

pub struct Peer {
  src: SocketAddr,
  #[allow(unused)]
  dest: SocketAddr,
  socks: SocksServer,
  handle: PeerHandle,
  command_source: mpsc::Receiver<Signal>,
  collector: PacketSink,
}

impl Peer {
  pub async fn setup(
    src: SocketAddr,
    dest: SocketAddr,
    collector: PacketSink,
    socks: SocksServer,
  ) -> Result<Self> {
    let (command_receiver, command_source) = mpsc::channel(1);
    Ok(Self {
      src,
      dest,
      socks,
      handle: PeerHandle::new(command_receiver),
      collector,
      command_source,
    })
  }

  pub async fn socks_handshake(&self) -> Result<(UdpSession, UdpSocket)> {
    let bind_addr: SocketAddr = ([0, 0, 0, 0], 0u16).into();
    let socket = UdpSocket::bind(bind_addr).await?;
    let session = self.socks.udp_associate(bind_addr).await?;

    socket.connect(session.bind_addr.clone()).await?;

    Ok((session, socket))
  }

  pub fn handle(&self) -> PeerHandle {
    self.handle.clone()
  }

  pub async fn run(mut self) -> Result<()> {
    use Signal::*;
    let (_session, mut socket) = self.socks_handshake().await?;

    loop {
      select! {
        command = self.command_source.recv().fuse() =>
          match command {
            Some(Ping) => /* silently ignore */ (),
            Some(SendPacket(packet)) =>
              Self::send_packet(&mut socket, packet).await?,
            None => return Ok(()),
          },

        mut packet = Self::recv_packet(&mut socket).fuse() => {
          let mut packet = dbg!(packet?);
          packet.dest = self.src;
          self.collector.send(packet).await?
        }
      };
    }
  }

  async fn send_packet(socket: &mut UdpSocket, packet: Packet) -> Result<()> {
    Self::send_to(socket, packet.payload, packet.dest).await?;
    Ok(())
  }

  async fn recv_packet(socket: &mut UdpSocket) -> Result<Packet> {
    let (bytes, addr) = Self::recv_from(socket).await?;
    Ok(Packet {
      src: addr,
      payload: bytes,
      dest: ([0, 0, 0, 0], 0).into(),
    })
  }

  async fn send_to(
    socket: &mut UdpSocket,
    bytes: Bytes,
    addr: SocketAddr,
  ) -> Result<usize> {
    let mut buf = SocksServer::udp_assoc_header(addr.into());
    let hdr_len = buf.len();
    buf.extend(bytes);
    let sent_len = socket.send(&buf).await?;
    Ok(sent_len - hdr_len)
  }

  async fn recv_from(socket: &mut UdpSocket) -> Result<(Bytes, SocketAddr)> {
    let mut recv_buf = BytesMut::from(vec![0u8; 65535].as_slice());
    let recv_len = socket.recv(recv_buf.as_mut()).await?;
    recv_buf.truncate(recv_len);

    let (hdr_len, addr) = SocksServer::parse_udp_assoc_header(&recv_buf)
      .ok_or(failure::err_msg("unable to parse socks5 udp_assoc_header"))?;
    let payload = recv_buf.split_off(hdr_len);

    Ok((payload.freeze(), addr))
  }
}
