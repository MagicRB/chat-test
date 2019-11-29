use std::fmt::{ Formatter, Display, Debug, Error };
use serde::{ Serialize, Deserialize };
use crate::{
    SharedMacSecret,
    x25519::PublicKey
};

#[derive(Serialize, Deserialize, Eq, PartialEq, Hash, Copy, Clone)]
pub struct x25519IDHash ([u8; 32]);

impl x25519IDHash {
    pub fn new(public_key: PublicKey, shared_mac_secret: SharedMacSecret) -> Self {
        let mut sha256 = openssl::sha::Sha256::new();

        sha256.update(public_key.as_ref());
        sha256.update(shared_mac_secret.as_ref());
        Self (sha256.finish())
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

impl From<Vec<u8>> for x25519IDHash {
    fn from(vec: Vec<u8>) -> Self {
        let mut slice = [0u8; 32];
        slice.copy_from_slice(vec.as_slice());

        x25519IDHash(slice)
    }
}