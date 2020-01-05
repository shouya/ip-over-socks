#![feature(never_type)]
#![feature(async_closure)]

extern crate tun as rust_tun;
#[macro_use]
extern crate failure;
extern crate etherparse;
extern crate futures;
extern crate tokio;

mod config;
mod error;
mod nat;
mod socks;
mod tcp;
mod tun;
mod udp;

use crate::config::Config;
use crate::error::Result;
use crate::nat::NatTable;
use crate::tun::Tun;

use futures::future;

#[tokio::main]
async fn main() -> Result<()> {
  let config = initialize_config();

  // udp packet channel
  let (sink, source) = udp::channel();

  // nat tables
  let tcp_nat = NatTable::new();
  let udp_nat = NatTable::new();

  // setup tun
  let tun = Tun::setup(&config, &tcp_nat, &udp_nat, source).await?;

  // setup tcp proxy
  let tcp_proxy = tcp::Proxy::setup(&config, &tcp_nat).await?;

  // setup udp proxy
  let udp_proxy = udp::Proxy::setup(&config, &udp_nat, sink).await?;

  // start processing packets from tun
  let tun_fut = tokio::spawn(tun.start());
  let tcp_fut = tokio::spawn(tcp_proxy.start());
  let udp_fut = tokio::spawn(udp_proxy.start());

  let futs = future::join_all(vec![tun_fut, tcp_fut, udp_fut]).await;
  futs.into_iter().for_each(|x| {
    x.expect("failed to resolve future")
      .expect("error while running server")
  });
  Ok(())
}

fn initialize_config() -> Config {
  use config::{TcpProxyConfig, TunConfig, UdpProxyConfig};
  let tun_config = TunConfig {
    ip: [10, 0, 0, 1].into(),
    dummy_ip: [10, 0, 0, 2].into(),
    netmask: [255, 255, 0, 0].into(),
    mtu: 1500,
  };
  let tcp_proxy_config = TcpProxyConfig { bind_port: 10001 };
  let udp_proxy_config = UdpProxyConfig {
    broker_bind_port: 10002,
    bind_port: 10001,
    recv_buf_size: 8196,
  };
  let socks_server_addr = ([127, 0, 0, 1], 6155).into();
  Config {
    tun_config,
    tcp_proxy_config,
    udp_proxy_config,
    socks_server_addr,
  }
}
