use std::{
    net::{
        SocketAddr,
        UdpSocket,
    },
    sync::mpsc::{
        Sender,
        Receiver,
        channel
    },
    time::Duration,
    thread::JoinHandle,
    collections::HashMap,
};
use rand::prelude::{ ThreadRng, thread_rng };

use crate::{
    x25519::{PrivateKey, PublicKey},
    x25519IDHash
};

mod packet;
pub use packet::Packet;
mod command;
pub use command::Command;
mod response;
pub use response::Response;
mod connection;
pub use connection::Connection;

pub struct InstanceBuilder {
    control_address: SocketAddr,
    protocol_address: SocketAddr,
}

impl Default for InstanceBuilder {
    fn default() -> Self {
        InstanceBuilder {
            control_address: "127.0.0.1:65500".parse().unwrap(),
            protocol_address: "127.0.0.1:6555".parse().unwrap(),
        }
    }
}

impl InstanceBuilder {
    pub fn new() -> Self {
        InstanceBuilder::default()
    }

    pub fn set_control_address(mut self, control_address: SocketAddr) -> Self {
        self.control_address = control_address;

        self
    }

    pub fn set_protocol_address(mut self, protocol_address: SocketAddr) -> Self {
        self.protocol_address = protocol_address;

        self
    }
}

pub struct Instance {
    control_address: SocketAddr, // @TODO currently unused, could accept command response through it?
    protocol_address: SocketAddr,
    private_key: PrivateKey,
    public_key: PublicKey,
    rx: Receiver<Command>,
    tx: Sender<Response>,
    connections: HashMap<x25519IDHash, Connection>
}

impl Instance {
    pub(super) fn new(instance_builder: InstanceBuilder, private_key: PrivateKey, public_key: PublicKey) -> (Self, (Sender<Command>, Receiver<Response>)) {
        let (instance_tx, return_rx) = channel();
        let (return_tx, instance_rx) = channel();

        (Instance {
            control_address: instance_builder.control_address,
            protocol_address: instance_builder.protocol_address,
            private_key,
            public_key,
            rx: instance_rx,
            tx: instance_tx,
            connections: HashMap::new(),
        }, (return_tx, return_rx))
    }

    fn run_threaded(&mut self) {
        let socket = UdpSocket::bind(self.protocol_address).unwrap();
        socket.set_read_timeout(Some(Duration::from_millis(5))).unwrap();

        loop {
            let mut data = [0u8; 4096];
            if let Ok((length, sender)) = socket.recv_from(&mut data) {
                if let Ok(packet) = bincode::deserialize::<Packet>(&data) {
                    if let Some(connection) = self.connections.get_mut(&packet.hash) {

                    }
                }
            }

            if let Ok(command) = self.rx.recv_timeout(Duration::from_millis(5)) {
                match command {
                    Command::Exit => { break }
                    _ => {}
                }
            }
        }
    }

    pub fn run(mut self) -> JoinHandle<()> {
        std::thread::spawn(move || { self.run_threaded() })
    }
}