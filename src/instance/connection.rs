use std::net::SocketAddr;
use crate::{
    x25519IDHash,
    x25519::PublicKey,
    instance::EphemeralBlob,
};

#[derive(Debug, Copy, Clone)]
pub struct Connection {
    pub local_x25519_id_hash: x25519IDHash,
    pub remote_x25519_id_hash: x25519IDHash,
    pub public_key: PublicKey,
    pub endpoint: Option<SocketAddr>,
    pub local_ephemeral_blob: Option<EphemeralBlob>,
    pub remote_ephemeral_blob: Option<EphemeralBlob>,
}