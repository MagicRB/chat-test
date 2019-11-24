use std::fmt::{ Formatter, Display, Debug, Error };
use serde::{ Serialize, Deserialize };

#[derive(Serialize, Deserialize)]
pub struct PublicKey ([u8; 32]);

impl PublicKey {
    pub fn new(secret: &[u8]) -> Self {
        PublicKey(crate::x25519::curve25519::calculate_public_key(secret.as_ref()))
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for PublicKey {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl Debug for PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        f.write_str(format!("\"{}\"", base64::encode(&self.0)).as_str()).unwrap();

        Ok(())
    }
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        f.write_str(format!("\"{}\"", base64::encode(&self.0)).as_str()).unwrap();

        Ok(())
    }
}