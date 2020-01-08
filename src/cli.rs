use crate::config::Config;

use ipnet::Ipv4Net;
use std::net::SocketAddr;
use structopt::StructOpt;

#[derive(StructOpt, Debug)]
#[structopt(about = "Tunnel TCP and UDP traffic over SOCKS5 Proxy")]
pub struct CliConfig {
  /// The address space for the device
  ///
  /// The first available address will get assigned to the device, the second
  /// address will be taken as a dummy address for internal use. Therefore, you
  /// need to assign it a network space to support at least 2 hosts. In other
  /// words, the prefix length needs to be shorter than /31.
  #[structopt(short, long, default_value = "10.0.0.1/16")]
  net: Ipv4Net,

  /// MTU value for the interface
  #[structopt(short, long, default_value = "1490")]
  mtu: u16,

  /// Address to the socks5 server
  ///
  /// The proxy must support CONNECT and UDP ASSOCIATE methods and do not have authentication.
  socks_server: SocketAddr,

  /// Port for internal TCP proxy
  #[structopt(short, long, default_value = "10001")]
  tcp_port: u16,

  /// Port for internal UDP proxy
  #[structopt(short, long, default_value = "10001")]
  udp_port: u16,
}

impl Into<Config> for CliConfig {
  fn into(self) -> Config {
    let mut hosts = self.net.hosts();
    Config {
      ip: hosts.next().expect("network is too small"),
      dummy_ip: hosts.next().expect("network is too small"),
      netmask: self.net.netmask(),
      mtu: self.mtu,
      tcp_port: self.tcp_port,
      udp_port: self.udp_port,
      socks_server: self.socks_server,
    }
  }
}
