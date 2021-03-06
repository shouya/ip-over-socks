use failure::{Fail, Error, SyncFailure};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Fail)]
#[fail(display = "tun error {}", _0)]
pub struct TunError(SyncFailure<tun::Error>);

#[derive(Debug, Fail)]
#[fail(display = "unsupported packet")]
pub struct UnsupportedPacket;

#[derive(Debug, Fail)]
#[fail(display = "address not found in dst map")]
pub struct AddressNotFoundInNat;

impl From<tun::Error> for TunError {
  fn from(e: tun::Error) -> TunError {
    TunError(SyncFailure::new(e))
  }
}
