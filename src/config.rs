use std::net::{Ipv4Addr, SocketAddr};

#[derive(Debug, Clone)]
pub struct Config {
  // tun interface configuration
  pub ip: Ipv4Addr,
  pub netmask: Ipv4Addr,
  pub mtu: u16,
  // a dummy ip address reserved for internal use
  pub dummy_ip: Ipv4Addr,
  // socks server address
  pub socks_server: SocketAddr,
  // port for internal tcp/udp proxy
  pub udp_port: u16,
  pub tcp_port: u16,
}
