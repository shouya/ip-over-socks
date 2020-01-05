use futures::{future::FutureExt, select, sink::SinkExt, stream::StreamExt};

use crate::config::Config;
use crate::error::Result;
use crate::nat::NatTable;
use crate::udp;

use super::{dev::Dev, rewriter::Rewriter};

pub struct Tun {
  dev: Dev,
  rewriter: Rewriter,
  udp_packet_source: udp::PacketSource,
}

impl Tun {
  pub async fn setup(
    config: &Config,
    tcp_nat: &NatTable,
    udp_nat: &NatTable,
    udp_packet_source: udp::PacketSource,
  ) -> Result<Self> {
    let dev = Dev::setup(config).await?;
    let rewriter = Rewriter::setup(config, tcp_nat, udp_nat);

    Ok(Self {
      dev,
      rewriter,
      udp_packet_source,
    })
  }

  pub async fn start(mut self) -> Result<!> {
    loop {
      select! {
        packet = self.dev.next().fuse() => match packet {
          None => panic!("tun device closed"),
          Some(packet) =>
            match self.rewriter.rewrite(packet).await {
              Ok(Some(new_packet)) => self.dev.send(new_packet).await?,
              _ => ()
            }
        },

        udp_packet = self.udp_packet_source.recv().fuse() => match udp_packet {
          None => panic!("udp proxy closed"),
          Some(packet) => self.dev.send(packet.into()).await?
        }
      }
    }
  }
}
