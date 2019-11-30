use std::fmt::{ Formatter, Display, Debug, Error };
use serde::{ Serialize, Deserialize };
use rand::{
    prelude::ThreadRng,
    RngCore,
};

#[derive(Serialize, Deserialize, Copy, Clone, PartialEq, Eq)]
pub struct EphemeralBlob ([u8; 32]);

impl EphemeralBlob {
    pub fn new(rng: &mut ThreadRng) -> Self {
        let mut slice = [0u8; 32];
        rng.fill_bytes(&mut slice);

        Self (slice)
    }
}

impl AsRef<[u8]> for EphemeralBlob {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for EphemeralBlob {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl Debug for EphemeralBlob {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        f.write_str(format!("\"{}\"", base64::encode(&self.0)).as_str()).unwrap();

        Ok(())
    }
}

impl Display for EphemeralBlob {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        f.write_str(format!("\"{}\"", base64::encode(&self.0)).as_str()).unwrap();

        Ok(())
    }
}

impl From<Vec<u8>> for EphemeralBlob {
    fn from(vec: Vec<u8>) -> Self {
        let mut slice = [0u8; 32];
        slice.copy_from_slice(vec.as_slice());

        EphemeralBlob(slice)
    }
}