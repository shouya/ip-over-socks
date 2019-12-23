use std::net::{Ipv4Addr, SocketAddr};

#[derive(Debug, Clone)]
pub struct TunConfig {
  pub ip: Ipv4Addr,
  pub dummy_ip: Ipv4Addr,
  pub netmask: Ipv4Addr,
  pub mtu: u16,
}

#[derive(Debug, Clone)]
pub struct TproxyConfig {
  pub bind_port: u16,
}

#[derive(Debug, Clone)]
pub struct Config {
  // tun interface configuration
  pub tun_config: TunConfig,

  // transparent proxy server config
  pub tproxy_config: TproxyConfig,

  // address to the socks5 server
  pub socks_server_addr: SocketAddr,
}
