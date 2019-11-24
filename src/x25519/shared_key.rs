use std::fmt::{ Formatter, Display, Debug, Error };
use crate::x25519::{PublicKey, PrivateKey};
use serde::{ Serialize, Deserialize };

#[derive(Serialize, Deserialize)]
pub struct SharedKey ([u8; 32]);

impl SharedKey {
    pub fn derive(private_key: &PrivateKey, public_key: &PublicKey) -> SharedKey {
        SharedKey(crate::x25519::curve25519::create_shared_key(public_key.as_ref(), private_key.as_ref()))
    }
}

impl AsRef<[u8]> for SharedKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for SharedKey {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl Debug for SharedKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        f.write_str(format!("\"{}\"", base64::encode(&self.0)).as_str()).unwrap();

        Ok(())
    }
}

impl Display for SharedKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        f.write_str(format!("\"{}\"", base64::encode(&self.0)).as_str()).unwrap();

        Ok(())
    }
}