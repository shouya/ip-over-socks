extern crate tun as rust_tun;
#[macro_use]
extern crate failure;
extern crate etherparse;
extern crate futures;
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

#[tokio::main]
async fn main() -> Result<()> {
  let config = initialize_config();

  // destination map
  let dst_map = DstMap::new();

  // setup tun
  let tun = Tun::setup(&config, &dst_map).await?;

  // setup transparent proxy
  let tproxy = Tproxy::setup(&config, &dst_map).await?;

  // start processing packets from tun
  tokio::spawn(async move { tun.start().await });
  tokio::spawn(async move { tproxy.start().await });

  Ok(())
}

fn initialize_config() -> Config {
  use config::{TproxyConfig, TunConfig};
  let tun_config = TunConfig {
    ip: [10, 0, 0, 1].into(),
    dummy_ip: [10, 0, 0, 2].into(),
    netmask: [255, 255, 0, 0].into(),
    mtu: 1500,
  };
  let tproxy_config = TproxyConfig { bind_port: 10000 };
  let socks_server_addr = ([127, 0, 0, 1], 1080).into();
  Config {
    tun_config,
    tproxy_config,
    socks_server_addr,
  }
}
