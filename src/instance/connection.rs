use crate::x25519IDHash;

#[derive(Debug, Copy, Clone)]
pub struct Connection {
    pub x25519_id_hash: x25519IDHash
}