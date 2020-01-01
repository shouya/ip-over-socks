use crate::config::{Config, TunConfig};
use crate::dst_map::DstMap;
use crate::error::{AddressNotFoundInDstMap, Result, TunError};
use crate::udp_packet::UdpPacketSource;

use bytes::Bytes;
use futures::stream::StreamExt;
use futures::{Sink, Source};
use std::net::Ipv4Addr;

use etherparse::{
  IpHeader,
  IpHeader::Version4,
  PacketHeaders, TransportHeader,
  TransportHeader::{Tcp, Udp},
};
use rust_tun::{create_as_async, DeviceAsync, TunPacket};

struct TunSource {
  pub source: Box<dyn Source<TunSource> + Unpin>,
}

struct TunSink {
  sink: Box<dyn Sink<TunPacket> + Unpin>,
  dev: Option<DeviceAsync>,
  mtu: u16,
}

impl TunSink {
  pub async fn start<S>(mut self, packet_source: S) -> Result<!>
  where
    S: Source<rust_tun::TunPacket> + std::marker::Unpin,
  {
    use crate::futures::SinkExt;

    while let Some(packet) = packet_source.next() {
      match self.sink.send(packet.into()).await {
        Err(_) => bail!("failed to send packet"),
        Ok(_) => Ok(()),
      };
    }
    panic!("packet source interrupted")
  }
}

struct PacketRewriter {
  ip: Ipv4Addr,
  dummy_ip: Ipv4Addr,
  tproxy_port: u16,
  udp_proxy_port: u16,
  tcp_nat: DstMap,
  udp_nat: DstMap,
}

impl PacketRewriter {
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
    tcp.destination_port = self.tproxy_port;

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
      .ok_or(AddressNotFoundInDstMap)?;

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

    dbg!(ip.source, self.dummy_ip);

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
      .ok_or(AddressNotFoundInDstMap)?;

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

pub struct Tun {
  udp_packet_source: UdpPacketSource,
}

impl Tun {
  pub async fn setup(
    config: &Config,
    tcp_nat: &DstMap,
    udp_nat: &DstMap,
    udp_packet_source: UdpPacketSource,
  ) -> Result<Self> {
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

    let dev = Some(create_as_async(&conf).map_err(TunError::from)?);
    let TunConfig {
      mtu, ip, dummy_ip, ..
    } = *tun_config;
    let tproxy_port = config.tproxy_config.bind_port;
    let udp_proxy_port = config.udp_proxy_config.bind_port;
    let tcp_nat = tcp_nat.clone();
    let udp_nat = udp_nat.clone();

    Ok(Tun {
      dev,
      ip,
      mtu,
      tcp_nat,
      udp_nat,
      dummy_ip,
      tproxy_port,
      udp_proxy_port,
      udp_packet_source,
    })
  }

  pub async fn start(mut self) -> Result<!> {
    let (mut sink, mut stream) = self.dev.take().unwrap().into_framed().split();

    while let Some(frame) = stream.next().await {
      match IpPacket::parse(frame?.get_bytes())? {
        Some(packet) => self.rewriter.rewrite(packet),
        None => continue,
      }
    }

    panic!("tun device unavailable")
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
    self.ip.write(&mut buf)?;
    self.transport.write(&mut buf)?;
    Write::write(&mut buf, &self.payload)?;
    TunPacket::new(buf)
  }
}
