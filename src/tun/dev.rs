use bytes::Bytes;
use failure::Error;
use futures::{Sink, Stream};
use rust_tun::create_as_async;
use rust_tun::{r#async::TunPacketCodec, TunPacket};
use std::convert::TryInto;
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;
use tokio_util::codec::Framed;

use crate::config::Config;
use crate::error::*;

use super::packet::Packet;

pub struct Dev(Framed<rust_tun::DeviceAsync, TunPacketCodec>);

impl Dev {
  pub async fn setup(config: &Config) -> Result<Self> {
    let Config { tun_config, .. } = config;
    let mut conf = rust_tun::Configuration::default();
    conf
      .address(tun_config.ip)
      .netmask(tun_config.netmask)
      .mtu(tun_config.mtu as i32)
      .up();

    #[cfg(target_os = "linux")]
    config.platform(|config| {
      config.packet_information(true);
    });

    let dev = create_as_async(&conf).map_err(TunError::from)?;
    let framed = dev.into_framed();
    Ok(Self(framed))
  }

  fn inner(
    self: Pin<&mut Self>,
  ) -> Pin<&mut Framed<rust_tun::DeviceAsync, TunPacketCodec>> {
    // this block is safe because self:Pin implies self.0:Pin
    unsafe { self.map_unchecked_mut(|x| &mut x.0) }
  }
}

impl Stream for Dev {
  type Item = Packet;

  fn poll_next(
    self: Pin<&mut Self>,
    cx: &mut Context,
  ) -> Poll<Option<Self::Item>> {
    match self.inner().poll_next(cx) {
      Poll::Pending => Poll::Pending,
      Poll::Ready(None) => Poll::Ready(None),
      Poll::Ready(Some(Err(_))) => Poll::Pending,
      Poll::Ready(Some(Ok(packet))) => match packet.try_into() {
        Ok(packet) => Poll::Ready(Some(packet)),
        _ => Poll::Pending,
      },
    }
  }
}

impl Sink<Packet> for Dev {
  type Error = Error;

  fn poll_ready(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<()>> {
    match self.inner().poll_ready(cx) {
      Poll::Pending => Poll::Pending,
      Poll::Ready(x) => Poll::Ready(x.map_err(|x| x.into())),
    }
  }

  fn start_send(self: Pin<&mut Self>, item: Packet) -> Result<()> {
    match item.try_into() {
      Ok(packet) => self.inner().start_send(packet).map_err(|x| x.into()),
      Err(_) => Ok(()),
    }
  }
  fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<()>> {
    match self.inner().poll_flush(cx) {
      Poll::Pending => Poll::Pending,
      Poll::Ready(x) => Poll::Ready(x.map_err(|x| x.into())),
    }
  }
  fn poll_close(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<()>> {
    match self.inner().poll_close(cx) {
      Poll::Pending => Poll::Pending,
      Poll::Ready(x) => Poll::Ready(x.map_err(|x| x.into())),
    }
  }
}

impl TryInto<Packet> for TunPacket {
  type Error = Error;

  fn try_into(self) -> Result<Packet> {
    use etherparse::{IpHeader::Version4, PacketHeaders};
    let hdr = PacketHeaders::from_ip_slice(self.get_bytes())?;
    match (hdr.ip, hdr.transport) {
      (Some(ip @ Version4(_)), Some(transport)) => {
        let payload = Bytes::copy_from_slice(hdr.payload);
        Ok(Packet {
          ip,
          transport,
          payload,
        })
      }
      _ => bail!("unsupported protocol"),
    }
  }
}

impl TryInto<TunPacket> for Packet {
  type Error = Error;

  fn try_into(self) -> Result<TunPacket> {
    use std::io::Write;
    let mut buf = Vec::new();
    self.ip.write(&mut buf)?;
    self.transport.write(&mut buf)?;
    Write::write(&mut buf, &self.payload)?;
    Ok(TunPacket::new(buf))
  }
}
