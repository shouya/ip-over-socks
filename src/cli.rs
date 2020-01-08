use crate::config::Config;

use ipnet::Ipv4Net;
use std::net::SocketAddr;
use structopt::StructOpt;

#[derive(StructOpt, Debug)]
#[structopt(about = "Forward TCP/UDP (L3) packets to a Socks5 Proxy (L4)")]
pub struct CliConfig {
  /// The address space for the device
  ///
  /// The first available address will get assigned to the device, the second
  /// address will be used by the internal proxies, Therefore, you need to
  /// assign it a network space to support at least 2 hosts. In other words, the
  /// prefix needs to be smaller than /31.
  #[structopt(short, long, default_value = "10.0.0.1/16")]
  net: Ipv4Net,

  /// MTU value for the interface
  #[structopt(short, long, default_value = "1490")]
  mtu: u16,

  /// Address to the socks5 proxy
  ///
  /// The proxy must support CONNECT and UDP ASSOCIATE methods and do not have authentication.
  socks_proxy: SocketAddr,

  /// Port for internal TCP proxy
  #[structopt(short, long, default_value = "10001")]
  tcp_port: u16,

  /// Port for internal UDP proxy
  #[structopt(short, long, default_value = "10001")]
  udp_port: u16,
}

impl Into<Config> for CliConfig {
  fn into(self) -> Config {
    use crate::config::*;
    let tcp_config = TcpProxyConfig {
      bind_port: self.tcp_port,
    };
    let udp_config = UdpProxyConfig {
      bind_port: self.udp_port,
    };
    let tun_config = TunConfig {
      ip: self.net.hosts().nth(0).expect("Network too small"),
      dummy_ip: self.net.hosts().nth(1).expect("Network too small"),
      netmask: self.net.netmask(),
      mtu: self.mtu,
    };

    Config {
      tcp_proxy_config: tcp_config,
      udp_proxy_config: udp_config,
      tun_config: tun_config,
      socks_server_addr: self.socks_proxy,
    }
  }
}
