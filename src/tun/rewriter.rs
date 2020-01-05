use etherparse::IpHeader::{Version4};
use etherparse::TransportHeader::{Tcp, Udp};
use std::net::Ipv4Addr;

use crate::config::Config;
use crate::error::*;
use crate::nat::NatTable;

use super::packet::Packet;

pub struct Rewriter {
  ip: Ipv4Addr,
  dummy_ip: Ipv4Addr,
  tcp_proxy_port: u16,
  udp_proxy_port: u16,
  tcp_nat: NatTable,
  udp_nat: NatTable,
}

impl Rewriter {
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
  pub async fn rewrite(&mut self, packet: Packet) -> Result<Option<Packet>> {
    match packet.transport {
      Tcp(_) => Ok(Some(self.rewrite_tcp_packet(packet).await?)),
      Udp(_) => Ok(Some(self.rewrite_udp_packet(packet).await?)),
    }
  }

  async fn rewrite_tcp_packet(&mut self, packet: Packet) -> Result<Packet> {
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
    mut packet: Packet,
  ) -> Result<Packet> {
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
    mut packet: Packet,
  ) -> Result<Packet> {
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

  async fn rewrite_udp_packet(&mut self, packet: Packet) -> Result<Packet> {
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
    mut packet: Packet,
  ) -> Result<Packet> {
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
    mut packet: Packet,
  ) -> Result<Packet> {
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
