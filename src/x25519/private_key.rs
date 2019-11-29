use std::fmt::{ Formatter, Display, Debug, Error };
use serde::{ Serialize, Deserialize };

big_array! { BigArray; }

#[derive(Serialize, Deserialize, Copy, Clone)]
pub struct PrivateKey (#[serde(with = "BigArray")] [u8; 64]);

impl PrivateKey {
    pub fn new(secret: &[u8]) -> Self {
        PrivateKey(crate::x25519::curve25519::create_key_pair(secret).0)
    }
}

impl AsRef<[u8]> for PrivateKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for PrivateKey {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl Debug for PrivateKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        f.write_str(format!("\"{}\"", base64::encode(&self.0 as &[u8])).as_str()).unwrap();

        Ok(())
    }
}

impl Display for PrivateKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        f.write_str(format!("\"{}\"", base64::encode(&self.0 as &[u8])).as_str()).unwrap();

        Ok(())
    }
}

impl From<Vec<u8>> for PrivateKey {
    fn from(vec: Vec<u8>) -> Self {
        let mut slice = [0u8; 64];
        slice.copy_from_slice(vec.as_slice());

        PrivateKey(slice)
    }
}

impl PartialEq for PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_ref() == other.0.as_ref()
    }

    fn ne(&self, other: &Self) -> bool {
        self.0.as_ref() != other.0.as_ref()
    }
}

impl Eq for PrivateKey {}