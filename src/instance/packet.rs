use serde::{ Serialize, Deserialize };
use crate::x25519IDHash;

#[derive(Serialize, Deserialize)]
pub struct Packet {
    pub hash: x25519IDHash
}