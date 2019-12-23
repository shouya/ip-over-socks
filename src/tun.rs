use std::net::SocketAddr;

use crate::config::Config;
use crate::error::*;

use bytes::{Bytes, BytesMut};
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc::Sender;

use etherparse::{IpHeader, PacketHeaders, TransportHeader};
use rust_tun::{create_as_async, Configuration, DeviceAsync};

pub struct Tun {
    dev: DeviceAsync,
    mtu: u16,
    tcp_chan_tx: Sender<Packet>,
    udp_chan_tx: Sender<Packet>,
}

impl Tun {
    pub async fn setup(
        config: &Config,
        tcp_chan_tx: Sender<Packet>,
        udp_chan_tx: Sender<Packet>,
    ) -> Result<Self> {
        let Config { tun_config, .. } = config;
        let mut conf = Configuration::default();
        conf.address(tun_config.address)
            .netmask(tun_config.netmask)
            .mtu(tun_config.mtu as i32)
            .up();

        #[cfg(target_os = "linux")]
        config.platform(|config| {
            config.packet_information(true);
        });

        let dev = create_as_async(&conf).map_err(TunError::from)?;
        let mtu = tun_config.mtu;

        Ok(Tun {
            dev,
            mtu,
            tcp_chan_tx,
            udp_chan_tx,
        })
    }

    pub async fn start(mut self) -> Result<()> {
        use etherparse::TransportHeader::{Tcp, Udp};

        loop {
            let packet = self.read_packet().await.expect("unable to read packet");
            if let Some(packet) = packet {
                match packet.transport {
                    Tcp(_) => self.tcp_chan_tx.send(packet),
                    Udp(_) => self.udp_chan_tx.send(packet),
                };
            }
        }
    }

    pub async fn read_packet(&mut self) -> Result<Option<Packet>> {
        let mut buf = BytesMut::with_capacity(self.mtu as usize);
        let _ = self.dev.read_exact(&mut buf).await?;
        let hdr = PacketHeaders::from_ip_slice(&buf).expect("failed to decode packet");
        match (hdr.ip, hdr.transport) {
            (Some(ip), Some(transport)) => {
                let payload = Bytes::copy_from_slice(hdr.payload);
                Ok(Some(Packet {
                    ip,
                    transport,
                    payload,
                }))
            }
            _ => Ok(None),
        }
    }
}

struct Packet {
    ip: IpHeader,
    transport: TransportHeader,
    payload: Bytes,
}

impl Packet {
    pub fn dest(&self) -> SocketAddr {
        use etherparse::IpHeader::{Version4, Version6};
        use etherparse::TransportHeader::{Tcp, Udp};
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

        let ip: IpAddr = match &self.ip {
            Version4(hdr) => Ipv4Addr::from(hdr.destination).into(),
            Version6(hdr) => Ipv6Addr::from(hdr.destination).into(),
        };

        let port = match &self.transport {
            Tcp(hdr) => hdr.destination_port,
            Udp(hdr) => hdr.destination_port,
        };

        (ip, port).into()
    }

    pub fn src(&self) -> SocketAddr {
        use etherparse::IpHeader::{Version4, Version6};
        use etherparse::TransportHeader::{Tcp, Udp};
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

        let ip: IpAddr = match &self.ip {
            Version4(hdr) => Ipv4Addr::from(hdr.source).into(),
            Version6(hdr) => Ipv6Addr::from(hdr.source).into(),
        };

        let port = match &self.transport {
            Tcp(hdr) => hdr.source_port,
            Udp(hdr) => hdr.source_port,
        };

        (ip, port).into()
    }
}
