use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Mutex;

#[derive(Debug, Clone)]
pub struct TunConfig {
    pub address: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub mtu: u16,
}

#[derive(Debug, Clone)]
pub struct TproxyConfig {
    pub bind_addr: SocketAddr,
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
