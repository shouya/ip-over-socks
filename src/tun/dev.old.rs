use failure::Error;
use futures::{Sink, Stream, StreamExt};
use rust_tun::create_as_async;
use rust_tun::{TunPacket, r#async::TunPacketCodec};
use std::pin::Pin;
use tokio::sync::mpsc;
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

  fn split(
    self,
  ) -> (
    TunSink,
    TunStream,
    mpsc::Sender<TunPacket>,
    mpsc::Receiver<TunPacket>,
  ) {
    use crate::futures::SinkExt;
    let (ret_packet_sink, packet_source) = mpsc::channel(1);
    let (packet_sink, ret_packet_source) = mpsc::channel(1);
    let (sink, stream) = .split();

    let sink = TunSink {
      sink: Box::new(sink.sink_err_into()),
      packet_source: packet_source,
    };
    let stream = TunStream {
      stream: stream.filter_map(async move |x| x.ok()).boxed(),
      packet_sink: packet_sink,
    };

    (sink, stream, ret_packet_sink, ret_packet_source)
  }
}

impl Stream for Dev {
  type Item = Packet;

  fn poll_next(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
    unsafe { Pin::new_unchecked(self.0) }.poll_next(cx)
  }

}

struct TunStream {
  stream: Pin<Box<dyn Stream<Item = TunPacket> + Send>>,
  packet_sink: mpsc::Sender<Packet>,
}

impl TunStream {
  pub async fn start(mut self) -> Result<!> {
    while let Some(frame) = self.stream.next().await {
      match Packet::parse(frame.get_bytes())? {
        Some(packet) => self.packet_sink.send(packet).await?,
        None => continue,
      }
    }
    panic!("tun stream terminates")
  }
}

struct TunSink {
  sink: Box<dyn Sink<TunPacket, Error = Error> + Unpin + Send>,
  packet_source: mpsc::Receiver<Packet>,
}

impl TunSink {
  pub async fn start(mut self) -> Result<!> {
    use crate::futures::SinkExt;

    while let Some(packet) = self.packet_source.next().await {
      match self.sink.send(packet.into()).await {
        Err(_) => bail!("failed to send packet"),
        Ok(_) => continue,
      }
    }
    panic!("packet source interrupted")
  }
}

impl From<Packet> for TunPacket {
  fn from(ip_packet: Packet) -> Self {
    use std::io::Write;
    let mut buf = Vec::new();
    ip_packet.ip.write(&mut buf).ok();
    ip_packet.transport.write(&mut buf).ok();
    Write::write(&mut buf, &ip_packet.payload).ok();
    Self::new(buf)
  }
}
