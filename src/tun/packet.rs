use bytes::Bytes;
use etherparse::{
  IpHeader::{self, Version4},
  PacketBuilder, PacketHeaders, TransportHeader,
};

use crate::error::*;
use crate::udp;

#[derive(Clone, Debug)]
pub struct Packet {
  pub ip: IpHeader,
  pub transport: TransportHeader,
  pub payload: Bytes,
}

impl Packet {
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

impl Into<Packet> for udp::Packet {
  fn into(self) -> Packet {
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

    Packet::parse(&packet).unwrap().unwrap()
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

    let ip_packet: Packet = udp_packet.into();
    if let IpHeader::Version4(hdr) = ip_packet.ip {
      assert_eq!(hdr.source, [1, 2, 3, 4])
    } else {
      bail!("invalid ip packet")
    };

    Ok(())
  }
}
