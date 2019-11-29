use std::collections::HashMap;
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
        shared_mac_secret: SharedMacSecret
    },
    ListConnections,
}