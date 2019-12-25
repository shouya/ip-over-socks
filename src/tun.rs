use crate::config::{Config, TunConfig};
use crate::dst_map::DstMap;
use crate::error::{AddressNotFoundInDstMap, Result, TunError};

use bytes::Bytes;
use futures::stream::StreamExt;
use futures::Sink;
use std::net::Ipv4Addr;

use etherparse::{IpHeader, PacketHeaders, TransportHeader};
use rust_tun::{create_as_async, DeviceAsync, TunPacket};

pub struct Tun {
  dev: Option<DeviceAsync>,
  ip: Ipv4Addr,
  dummy_ip: Ipv4Addr,
  tproxy_port: u16,
  mtu: u16,
  dst_map: DstMap,
}

impl Tun {
  pub async fn setup(config: &Config, dst_map: &DstMap) -> Result<Self> {
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
    let dst_map = dst_map.clone();

    Ok(Tun {
      dev,
      ip,
      mtu,
      dst_map,
      dummy_ip,
      tproxy_port,
    })
  }

  pub async fn start(mut self) -> Result<()> {
    use etherparse::TransportHeader::{Tcp, Udp};
    let (mut sink, mut stream) = self.dev.take().unwrap().into_framed().split();

    while let Some(frame) = stream.next().await {
      let packet =
        Self::parse_packet(frame?.get_bytes()).expect("unable to parse packet");
      dbg!(&packet);

      if let Some(packet) = packet {
        match packet.transport {
          Tcp(_) => {
            println!("Got a tcp packet");
            let new_packet = self.rewrite_tcp_packet(packet).await?;
            // dbg!("Rewriting as {:?}", &new_packet);
            self.send_packet(&new_packet, &mut sink).await?;
            dbg!("packet sent");
          }
          Udp(_) => {
            println!("udp not supported yet");
            continue;
          }
        };
      }
    }
    Ok(())
  }

  pub fn parse_packet(buf: &[u8]) -> Result<Option<Packet>> {
    use etherparse::IpHeader::Version4;

    let hdr =
      PacketHeaders::from_ip_slice(&buf).expect("failed to decode packet");
    match (hdr.ip, hdr.transport) {
      (Some(ip @ Version4(_)), Some(transport)) => {
        let payload = Bytes::copy_from_slice(hdr.payload);
        Ok(Some(Packet {
          ip,
          transport,
          payload,
        }))
      }
      _ => Ok(None),
    }
  }

  async fn rewrite_tcp_packet(&mut self, packet: Packet) -> Result<Packet> {
    use etherparse::IpHeader::Version4;
    let ip = match &packet.ip {
      Version4(hdr) => hdr,
      _ => bail!("unreachable"),
    };

    dbg!(ip.source, self.dummy_ip);

    if ip.destination == self.dummy_ip.octets() {
      dbg!("recognized as incoming");
      Ok(self.rewrite_incoming_packet(packet).await?)
    } else if ip.source == self.ip.octets() {
      dbg!("recognized as outgoing");
      Ok(self.rewrite_outgoing_packet(packet).await?)
    } else {
      bail!("unrecognized packet");
    }
  }

  async fn rewrite_outgoing_packet(
    &self,
    mut packet: Packet,
  ) -> Result<Packet> {
    use etherparse::IpHeader::Version4;
    use etherparse::TransportHeader::Tcp;

    let mut ip = match packet.ip {
      Version4(hdr) => hdr,
      _ => bail!("unreachable"),
    };
    let mut tcp = match packet.transport {
      Tcp(hdr) => hdr,
      _ => bail!("unreachable"),
    };

    let dest_addr = (ip.destination, tcp.destination_port).into();
    self.dst_map.put(tcp.source_port, dest_addr).await?;

    ip.source = self.dummy_ip.octets();
    ip.destination = self.ip.octets();
    tcp.destination_port = self.tproxy_port;

    ip.header_checksum = ip.calc_header_checksum()?;
    tcp.checksum = tcp.calc_checksum_ipv4(&ip, &packet.payload)?;

    packet.ip = Version4(ip);
    packet.transport = Tcp(tcp);
    Ok(packet)
  }

  async fn rewrite_incoming_packet(
    &self,
    mut packet: Packet,
  ) -> Result<Packet> {
    use etherparse::IpHeader::Version4;
    use etherparse::TransportHeader::Tcp;

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
      .dst_map
      .get(tcp.destination_port)
      .await?
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

  async fn send_packet<S>(
    &mut self,
    packet: &Packet,
    sink: &mut S,
  ) -> Result<()>
  where
    S: Sink<rust_tun::TunPacket> + std::marker::Unpin,
  {
    use crate::futures::SinkExt;
    use std::io::Write;

    let mut buf = Vec::with_capacity(self.mtu as usize);
    packet.ip.write(&mut buf)?;
    packet.transport.write(&mut buf)?;
    Write::write(&mut buf, &packet.payload)?;

    match sink.send(TunPacket::new(buf)).await {
      Err(_) => bail!("failed to send packet"),
      Ok(_) => Ok(()),
    }
  }
}

#[derive(Clone, Debug)]
pub struct Packet {
  ip: IpHeader,
  transport: TransportHeader,
  payload: Bytes,
}
