use serde::{ Serialize, Deserialize };
use crate::{
    x25519IDHash,
    instance::EphemeralBlob,
};

#[derive(Serialize, Deserialize)]
pub struct Packet {
    pub hash: x25519IDHash,
    pub data: Data,
}

#[derive(Serialize, Deserialize)]
pub enum Data {
    Handshake {
        ephemeral_blob: EphemeralBlob
    }
}