use std::{
    collections::HashMap,
    net::SocketAddr,
};
use crate::{
    x25519::PublicKey,
    SharedMacSecret,
    x25519IDHash,
    instance::Connection,
};

pub enum Command {
    Exit,
    AddConnection {
        public_key: PublicKey,
        shared_mac_secret: SharedMacSecret,
    },
    ListConnections,
    Connect {
        x25519_id_hash: x25519IDHash,
        endpoint: SocketAddr,
    },
}