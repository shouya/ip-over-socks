use std::net::Ipv4Addr;

use crate::config::{Config, TunConfig};
use crate::dst_map::DstMap;
use crate::error::{AddressNotFoundInDstMap, Result, TunError};

use bytes::{Bytes, BytesMut};
use tokio::io::AsyncReadExt;

use etherparse::{IpHeader, PacketHeaders, TransportHeader};
use rust_tun::{create_as_async, DeviceAsync};

pub struct Tun {
  dev: DeviceAsync,
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

    let dev = create_as_async(&conf).map_err(TunError::from)?;
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

    loop {
      let packet = self.read_packet().await.expect("unable to read packet");
      if let Some(packet) = packet {
        match packet.transport {
          Tcp(_) => {
            let new_packet = self.rewrite_tcp_packet(packet).await?;
            self.send_packet(&new_packet).await?;
          }
          Udp(_) => {
            println!("udp not supported yet");
            continue;
          }
        };
      }
    }
  }

  pub async fn read_packet(&mut self) -> Result<Option<Packet>> {
    use etherparse::IpHeader::Version4;

    let mut buf = BytesMut::with_capacity(self.mtu as usize);
    let _ = self.dev.read_exact(&mut buf).await?;
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

    if ip.source == self.dummy_ip.octets() {
      Ok(self.rewrite_outgoing_packet(packet).await?)
    } else if ip.destination == self.dummy_ip.octets() {
      Ok(self.rewrite_incoming_packet(packet).await?)
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

  async fn send_packet(&mut self, packet: &Packet) -> Result<()> {
    use std::io::Write;
    use tokio::io::AsyncWriteExt;

    let mut buf = Vec::with_capacity(self.mtu as usize);
    packet.ip.write(&mut buf)?;
    packet.transport.write(&mut buf)?;
    Write::write(&mut buf, &packet.payload)?;

    self.dev.write_all(&buf).await?;
    Ok(())
  }
}

#[derive(Clone)]
pub struct Packet {
  ip: IpHeader,
  transport: TransportHeader,
  payload: Bytes,
}
