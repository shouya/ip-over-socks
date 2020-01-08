#![feature(never_type)]
#![feature(async_closure)]
#![feature(type_ascription)]

extern crate tun as rust_tun;
#[macro_use]
extern crate failure;

mod cli;
mod config;
mod error;
mod nat;
mod socks;
mod tcp;
mod tun;
mod udp;

use structopt::StructOpt;

use crate::config::Config;
use crate::error::Result;
use crate::nat::NatTable;
use crate::tun::Tun;

use futures::{pin_mut, select, FutureExt};

async fn start(conf: Config) -> Result<!> {
  // udp packet channel
  let (sink, source) = udp::channel();

  // nat tables
  let tcp_nat = NatTable::new();
  let udp_nat = NatTable::new();

  // setup tun, tcp proxy, udp proxy
  let tun = Tun::setup(&conf, &tcp_nat, &udp_nat, source).await?;
  let tcp_proxy = tcp::Proxy::setup(&conf, &tcp_nat).await?;
  let udp_proxy = udp::Proxy::setup(&conf, &udp_nat, sink).await?;

  // start processing packets
  let tun_fut = tun.start().fuse();
  let tcp_fut = tcp_proxy.start().fuse();
  let udp_fut = udp_proxy.start().fuse();
  pin_mut!(tun_fut, tcp_fut, udp_fut);

  select! {
    _ = tun_fut => (),
    _ = tcp_fut => (),
    _ = udp_fut => ()
  }

  panic!("unreachable")
}

#[tokio::main]
async fn main() -> Result<!> {
  let cli_conf = cli::CliConfig::from_args();
  start(cli_conf.into()).await
}
