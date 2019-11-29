use std::collections::HashMap;
use crate::{
    x25519IDHash,
    instance::Connection,
};

pub enum Response {
    ListConnections {
        connections: HashMap<x25519IDHash, Connection>
    }
}