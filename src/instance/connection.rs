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
    pub endpoint: Option<SocketAddr>,
    pub state: State
}

#[derive(Debug, Copy, Clone)]
pub enum State {
    Pending {
        public_key: PublicKey,
        local_ephemeral_blob: Option<EphemeralBlob>,
        remote_ephemeral_blob: Option<EphemeralBlob>,
        sent_handshake: bool,
    },
    Established {
        placeholder: ()
    }
}