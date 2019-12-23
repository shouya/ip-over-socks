extern crate tun as rust_tun;
#[macro_use]
extern crate failure;
extern crate etherparse;
extern crate tokio;

mod config;
mod dst_map;
mod error;
mod proto;
mod socks;
mod tproxy;
mod tun;

use crate::config::Config;
use crate::dst_map::DstMap;
use crate::error::*;
use crate::tproxy::Tproxy;
use crate::tun::Tun;

use std::sync::Arc;
use tokio::sync::mpsc;

#[tokio::main]
async fn main() -> Result<()> {
  let config = initialize_config();

  // destination map
  let dst_map = Arc::new(DstMap::new());

  // setup tun
  let (tcp_chan_tx, _tcp_chan_rx) = mpsc::channel(0);
  let (udp_chan_tx, _udp_chan_rx) = mpsc::channel(0);
  let tun = Tun::setup(&config, tcp_chan_tx, udp_chan_tx).await?;

  // setup tproxy
  let tproxy = Tproxy::setup(&config, dst_map.clone()).await?;

  // start processing packets from tun
  tokio::spawn(async move { tun.start().await });
  tokio::spawn(async move { tproxy.start().await });

  Ok(())
}

fn initialize_config() -> Config {
  use config::{TproxyConfig, TunConfig};
  let tun_config = TunConfig {
    address: [10, 0, 0, 1].into(),
    netmask: [255, 255, 0, 0].into(),
    mtu: 1500,
  };
  let tproxy_config = TproxyConfig {
    bind_addr: ([10, 0, 0, 2], 10000).into(),
  };
  let socks_server_addr = ([127, 0, 0, 1], 1080).into();
  Config {
    tun_config,
    tproxy_config,
    socks_server_addr,
  }
}
