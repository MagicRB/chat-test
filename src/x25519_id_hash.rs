use std::fmt::{ Formatter, Display, Debug, Error };
use serde::{ Serialize, Deserialize };
use crate::x25519::SharedKey;

#[derive(Serialize, Deserialize, Eq, PartialEq, Hash)]
pub struct x25519IDHash ([u8; 32]);

impl x25519IDHash {
    pub fn new(shared_key: SharedKey, shared_mac_secret: ()) -> Self {
        Self ([0u8; 32])
    }
}

impl AsRef<[u8]> for x25519IDHash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for x25519IDHash {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl Debug for x25519IDHash {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        f.write_str(format!("\"{}\"", base64::encode(&self.0)).as_str()).unwrap();

        Ok(())
    }
}

impl Display for x25519IDHash {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        f.write_str(format!("\"{}\"", base64::encode(&self.0)).as_str()).unwrap();

        Ok(())
    }
}