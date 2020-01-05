use std::net::{Ipv4Addr, SocketAddr};

#[derive(Debug, Clone)]
pub struct TunConfig {
  pub ip: Ipv4Addr,
  pub dummy_ip: Ipv4Addr,
  pub netmask: Ipv4Addr,
  pub mtu: u16,
}

#[derive(Debug, Clone)]
pub struct TcpProxyConfig {
  pub bind_port: u16,
}

#[derive(Debug, Clone)]
pub struct UdpProxyConfig {
  pub broker_bind_port: u16,
  pub bind_port: u16,
  pub recv_buf_size: usize
}

#[derive(Debug, Clone)]
pub struct Config {
  // tun interface configuration
  pub tun_config: TunConfig,

  // transparent proxy server config
  pub tcp_proxy_config: TcpProxyConfig,

  // udp proxy server config
  pub udp_proxy_config: UdpProxyConfig,

  // address to the socks5 server
  pub socks_server_addr: SocketAddr,
}
