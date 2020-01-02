#![feature(never_type)]
#![feature(async_closure)]

extern crate tun as rust_tun;
#[macro_use]
extern crate failure;
extern crate etherparse;
extern crate futures;
extern crate tokio;
extern crate transient_hashmap;

mod config;
mod dst_map;
mod error;
mod proto;
mod socks;
mod tproxy;
mod tun;
mod udp_packet;
mod udp_proxy;

use crate::config::Config;
use crate::dst_map::DstMap;
use crate::error::Result;
use crate::tproxy::Tproxy;
use crate::tun::Tun;
use crate::udp_proxy::UdpProxy;

use futures::future;

#[tokio::main]
async fn main() -> Result<()> {
  let config = initialize_config();

  // udp packet channel
  let (sink, source) = udp_packet::channel();

  // destination map
  let tcp_nat = DstMap::new();
  let udp_nat = DstMap::new();

  // setup tun
  let tun = Tun::setup(&config, &tcp_nat, &udp_nat, source).await?;

  // setup transparent proxy
  let tproxy = Tproxy::setup(&config, &tcp_nat).await?;

  // setup udp proxy
  let udp_proxy = UdpProxy::setup(&config, &udp_nat, sink).await?;

  // start processing packets from tun
  let tun_fut = tokio::spawn(async move { tun.start().await });
  let tproxy_fut = tokio::spawn(async move { tproxy.start().await });
  let udp_fut = tokio::spawn(async move { udp_proxy.start().await });

  let futs = future::join_all(vec![tun_fut, tproxy_fut, udp_fut]).await;
  futs.into_iter().for_each(|x| {
    x.expect("failed to resolve future")
      .expect("error while running server")
  });
  Ok(())
}

fn initialize_config() -> Config {
  use config::{TproxyConfig, TunConfig, UdpProxyConfig};
  let tun_config = TunConfig {
    ip: [10, 0, 0, 1].into(),
    dummy_ip: [10, 0, 0, 2].into(),
    netmask: [255, 255, 0, 0].into(),
    mtu: 1500,
  };
  let tproxy_config = TproxyConfig { bind_port: 10001 };
  let udp_proxy_config = UdpProxyConfig {
    broker_bind_port: 10002,
    bind_port: 10001,
    recv_buf_size: 8196,
  };
  let socks_server_addr = ([127, 0, 0, 1], 6155).into();
  Config {
    tun_config,
    tproxy_config,
    udp_proxy_config,
    socks_server_addr,
  }
}
