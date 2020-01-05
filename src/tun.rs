use bytes::Bytes;
use failure::Error;
use futures::stream::StreamExt;
use futures::{Sink, Stream};
use std::net::Ipv4Addr;
use std::pin::Pin;
use tokio::sync::mpsc;

use crate::config::Config;
use crate::nat::NatTable;
use crate::error::{AddressNotFoundInNat, Result, TunError};
use crate::udp;

use etherparse::{
  IpHeader,
  IpHeader::Version4,
  PacketBuilder, PacketHeaders, TransportHeader,
  TransportHeader::{Tcp, Udp},
};
use rust_tun::{create_as_async, TunPacket};

struct TunStream {
  stream: Pin<Box<dyn Stream<Item = TunPacket> + Send>>,
  packet_sink: mpsc::Sender<IpPacket>,
}

impl TunStream {
  pub async fn start(mut self) -> Result<!> {
    while let Some(frame) = self.stream.next().await {
      match IpPacket::parse(frame.get_bytes())? {
        Some(packet) => self.packet_sink.send(packet).await?,
        None => continue,
      }
    }
    panic!("tun stream terminates")
  }
}

struct TunSink {
  sink: Box<dyn Sink<TunPacket, Error = Error> + Unpin + Send>,
  packet_source: mpsc::Receiver<IpPacket>,
}

impl TunSink {
  pub async fn start(mut self) -> Result<!> {
    use crate::futures::SinkExt;

    while let Some(packet) = self.packet_source.next().await {
      match self.sink.send(packet.into()).await {
        Err(_) => bail!("failed to send packet"),
        Ok(_) => continue,
      }
    }
    panic!("packet source interrupted")
  }
}

struct PacketRewriter {
  ip: Ipv4Addr,
  dummy_ip: Ipv4Addr,
  tcp_proxy_port: u16,
  udp_proxy_port: u16,
  tcp_nat: NatTable,
  udp_nat: NatTable,
}

impl PacketRewriter {
  pub fn setup(conf: &Config, tcp_nat: &NatTable, udp_nat: &NatTable) -> Self {
    Self {
      ip: conf.tun_config.ip,
      dummy_ip: conf.tun_config.dummy_ip,
      tcp_proxy_port: conf.tcp_proxy_config.bind_port,
      udp_proxy_port: conf.udp_proxy_config.bind_port,
      tcp_nat: tcp_nat.clone(),
      udp_nat: udp_nat.clone(),
    }
  }
  pub async fn rewrite(
    &mut self,
    packet: IpPacket,
  ) -> Result<Option<IpPacket>> {
    match packet.transport {
      Tcp(_) => Ok(Some(self.rewrite_tcp_packet(packet).await?)),
      Udp(_) => Ok(Some(self.rewrite_udp_packet(packet).await?)),
    }
  }

  async fn rewrite_tcp_packet(&mut self, packet: IpPacket) -> Result<IpPacket> {
    let ip = match &packet.ip {
      Version4(hdr) => hdr,
      _ => bail!("unreachable"),
    };

    if ip.destination == self.dummy_ip.octets() {
      Ok(self.rewrite_incoming_tcp_packet(packet).await?)
    } else if ip.source == self.ip.octets() {
      Ok(self.rewrite_outgoing_tcp_packet(packet).await?)
    } else {
      bail!("unrecognized packet");
    }
  }

  async fn rewrite_outgoing_tcp_packet(
    &self,
    mut packet: IpPacket,
  ) -> Result<IpPacket> {
    let mut ip = match packet.ip {
      Version4(hdr) => hdr,
      _ => bail!("unreachable"),
    };
    let mut tcp = match packet.transport {
      Tcp(hdr) => hdr,
      _ => bail!("unreachable"),
    };

    let dest_addr = (ip.destination, tcp.destination_port).into();
    self.tcp_nat.put(tcp.source_port, dest_addr).await;

    ip.source = self.dummy_ip.octets();
    ip.destination = self.ip.octets();
    tcp.destination_port = self.tcp_proxy_port;

    ip.header_checksum = ip.calc_header_checksum()?;
    tcp.checksum = tcp.calc_checksum_ipv4(&ip, &packet.payload)?;

    packet.ip = Version4(ip);
    packet.transport = Tcp(tcp);
    Ok(packet)
  }

  async fn rewrite_incoming_tcp_packet(
    &self,
    mut packet: IpPacket,
  ) -> Result<IpPacket> {
    let mut ip = match packet.ip {
      Version4(hdr) => hdr,
      _ => bail!("unreachable"),
    };
    let mut tcp = match packet.transport {
      Tcp(hdr) => hdr,
      _ => bail!("unreachable"),
    };
    use std::net::IpAddr::V4;
    let dest_addr = self
      .tcp_nat
      .get(tcp.destination_port)
      .await
      .ok_or(AddressNotFoundInNat)?;

    let dest_ipv4 = match dest_addr.ip() {
      V4(v4) => v4,
      _ => bail!("unreachable"),
    };

    ip.source = dest_ipv4.octets();
    ip.destination = self.ip.octets();
    tcp.source_port = dest_addr.port();

    ip.header_checksum = ip.calc_header_checksum().unwrap();
    tcp.checksum = tcp.calc_checksum_ipv4(&ip, &packet.payload).unwrap();

    packet.ip = Version4(ip);
    packet.transport = Tcp(tcp);
    Ok(packet)
  }

  async fn rewrite_udp_packet(&mut self, packet: IpPacket) -> Result<IpPacket> {
    let ip = match &packet.ip {
      Version4(hdr) => hdr,
      _ => bail!("unreachable"),
    };

    if ip.destination == self.dummy_ip.octets() {
      Ok(self.rewrite_incoming_udp_packet(packet).await?)
    } else if ip.source == self.ip.octets() {
      Ok(self.rewrite_outgoing_udp_packet(packet).await?)
    } else {
      bail!("unrecognized packet");
    }
  }

  async fn rewrite_outgoing_udp_packet(
    &self,
    mut packet: IpPacket,
  ) -> Result<IpPacket> {
    let mut ip = match packet.ip {
      Version4(hdr) => hdr,
      _ => bail!("unreachable"),
    };
    let mut udp = match packet.transport {
      Udp(hdr) => hdr,
      _ => bail!("unreachable"),
    };

    let dest_addr = (ip.destination, udp.destination_port).into();
    self.udp_nat.put(udp.source_port, dest_addr).await;

    ip.source = self.dummy_ip.octets();
    ip.destination = self.ip.octets();
    udp.destination_port = self.udp_proxy_port;

    ip.header_checksum = ip.calc_header_checksum()?;
    udp.checksum = udp.calc_checksum_ipv4(&ip, &packet.payload)?;

    packet.ip = Version4(ip);
    packet.transport = Udp(udp);
    Ok(packet)
  }

  async fn rewrite_incoming_udp_packet(
    &self,
    mut packet: IpPacket,
  ) -> Result<IpPacket> {
    let mut ip = match packet.ip {
      Version4(hdr) => hdr,
      _ => bail!("unreachable"),
    };
    let mut udp = match packet.transport {
      Udp(hdr) => hdr,
      _ => bail!("unreachable"),
    };
    use std::net::IpAddr::V4;
    let dest_addr = self
      .udp_nat
      .get(udp.destination_port)
      .await
      .ok_or(AddressNotFoundInNat)?;

    let dest_ipv4 = match dest_addr.ip() {
      V4(v4) => v4,
      _ => bail!("unreachable"),
    };

    ip.source = dest_ipv4.octets();
    ip.destination = self.ip.octets();
    udp.source_port = dest_addr.port();

    ip.header_checksum = ip.calc_header_checksum().unwrap();
    udp.checksum = udp.calc_checksum_ipv4(&ip, &packet.payload).unwrap();

    packet.ip = Version4(ip);
    packet.transport = Udp(udp);
    Ok(packet)
  }
}

pub struct TunDev {
  dev: rust_tun::DeviceAsync,
}

impl TunDev {
  pub async fn setup(config: &Config) -> Result<Self> {
    let Config { tun_config, .. } = config;
    let mut conf = rust_tun::Configuration::default();
    conf
      .address(tun_config.ip)
      .netmask(tun_config.netmask)
      .mtu(tun_config.mtu as i32)
      .up();

    #[cfg(target_os = "linux")]
    config.platform(|config| {
      config.packet_information(true);
    });

    let dev = create_as_async(&conf).map_err(TunError::from)?;
    Ok(Self { dev })
  }

  fn split(
    self,
  ) -> (
    TunSink,
    TunStream,
    mpsc::Sender<IpPacket>,
    mpsc::Receiver<IpPacket>,
  ) {
    use crate::futures::SinkExt;
    let (ret_packet_sink, packet_source) = mpsc::channel(1);
    let (packet_sink, ret_packet_source) = mpsc::channel(1);
    let (sink, stream) = self.dev.into_framed().split();

    let sink = TunSink {
      sink: Box::new(sink.sink_err_into()),
      packet_source: packet_source,
    };
    let stream = TunStream {
      stream: stream.filter_map(async move |x| x.ok()).boxed(),
      packet_sink: packet_sink,
    };

    (sink, stream, ret_packet_sink, ret_packet_source)
  }
}

pub struct Tun {
  dev: TunDev,
  rewriter: PacketRewriter,
  udp_packet_source: udp::PacketSource,
}

impl Tun {
  pub async fn setup(
    config: &Config,
    tcp_nat: &NatTable,
    udp_nat: &NatTable,
    udp_packet_source: udp::PacketSource,
  ) -> Result<Self> {
    let dev = TunDev::setup(config).await?;
    let rewriter = PacketRewriter::setup(config, tcp_nat, udp_nat);

    Ok(Self {
      dev,
      rewriter,
      udp_packet_source,
    })
  }

  pub async fn start(mut self) -> Result<!> {
    let (sender_service, receiver_service, mut packet_sink, mut packet_source) =
      self.dev.split();

    let sender_fut = sender_service.start();
    let receiver_fut = receiver_service.start();
    let udp_handler_fut =
      Self::handle_udp_packet(self.udp_packet_source, packet_sink.clone());

    tokio::spawn(async move {
      let (a, b, c) = futures::join!(sender_fut, receiver_fut, udp_handler_fut);
      (a.ok(), b.ok(), c.ok())
    });

    while let Some(packet) = packet_source.next().await {
      match self.rewriter.rewrite(packet).await? {
        Some(packet) => packet_sink.send(packet).await?,
        None => continue,
      }
    }

    panic!("tun device unavailable")
  }

  async fn handle_udp_packet(
    mut udp_source: udp::PacketSource,
    mut packet_sink: mpsc::Sender<IpPacket>,
  ) -> Result<!> {
    while let Some(udp_packet) = udp_source.next().await {
      packet_sink.send(udp_packet.into()).await?
    }
    panic!("udp packet translator failed")
  }
}

#[derive(Clone, Debug)]
pub struct IpPacket {
  ip: IpHeader,
  transport: TransportHeader,
  payload: Bytes,
}

impl IpPacket {
  // return None if packet is valid but is not tcp nor udp
  pub fn parse(bytes: &[u8]) -> Result<Option<Self>> {
    let hdr = PacketHeaders::from_ip_slice(bytes)?;
    match (hdr.ip, hdr.transport) {
      (Some(ip @ Version4(_)), Some(transport)) => {
        let payload = Bytes::copy_from_slice(hdr.payload);
        Ok(Some(Self {
          ip,
          transport,
          payload,
        }))
      }
      _ => Ok(None),
    }
  }
}

impl Into<TunPacket> for IpPacket {
  fn into(self) -> TunPacket {
    use std::io::Write;
    let mut buf = Vec::new();
    self.ip.write(&mut buf).ok();
    self.transport.write(&mut buf).ok();
    Write::write(&mut buf, &self.payload).ok();
    TunPacket::new(buf)
  }
}

impl Into<IpPacket> for udp::Packet {
  fn into(self) -> IpPacket {
    use std::net::SocketAddr::{V4, V6};

    let builder = {
      match (&self.src, &self.dest) {
        (&V4(src), &V4(dest)) => {
          PacketBuilder::ipv4(src.ip().octets(), dest.ip().octets(), 5)
            .udp(self.src.port(), self.dest.port())
        }
        (&V6(src), &V6(dest)) => {
          PacketBuilder::ipv6(src.ip().octets(), dest.ip().octets(), 5)
            .udp(self.src.port(), self.dest.port())
        }
        _ => panic!("UDP packet has different src and dest IP types"),
      }
    };

    let packet = {
      let packet_size = builder.size(self.payload.len());
      let mut buf = Vec::with_capacity(packet_size);
      builder.write(&mut buf, &self.payload).unwrap();
      buf
    };

    IpPacket::parse(&packet).unwrap().unwrap()
  }
}

#[cfg(test)]
mod test {
  use super::*;
  #[test]
  fn test_udp_packet() -> Result<()> {
    let udp_packet = udp::Packet {
      src: ([1, 2, 3, 4], 56).into(),
      dest: ([4, 3, 2, 1], 65).into(),
      payload: Bytes::from("hello"),
    };

    let ip_packet: IpPacket = udp_packet.into();
    if let IpHeader::Version4(hdr) = ip_packet.ip {
      assert_eq!(hdr.source, [1, 2, 3, 4])
    } else {
      bail!("invalid ip packet")
    };

    Ok(())
  }
}
