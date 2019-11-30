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
pub use packet::{
    Packet,
    Data
};
mod command;
pub use command::Command;
mod response;
pub use response::Response;
mod connection;
pub use connection::Connection;
mod ephemeral_blob;
pub use ephemeral_blob::EphemeralBlob;

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
            connections: HashMap::new()
        }, (return_tx, return_rx))
    }

    fn run_threaded(&mut self) {
        let socket = UdpSocket::bind(self.protocol_address).unwrap();
        socket.set_read_timeout(Some(Duration::from_millis(5))).unwrap();
        let mut rng = thread_rng();

        loop {
            let mut data = [0u8; 4096];
            if let Ok((_, sender)) = socket.recv_from(&mut data) {
                if let Ok(packet) = bincode::deserialize::<Packet>(&data) {
                    if let Some(connection) = self.connections.get_mut(&packet.hash) {
                        if let Some(endpoint) = connection.endpoint {
                            if sender != endpoint {
                                connection.endpoint = Some(sender);
                            }
                        }

                        if let Data::Handshake { ephemeral_blob } = packet.data {
                            if connection.remote_ephemeral_blob.is_none() {
                                socket.send_to(bincode::serialize(&Packet {
                                    hash: connection.x25519_id_hash,
                                    data: Data::Handshake {
                                        ephemeral_blob: connection.local_ephemeral_blob.unwrap()
                                    }
                                }).unwrap().as_slice(), sender).unwrap();
                            } else {
                                println!("{} sent double handshake something is wrong!", packet.hash);
                            }
                        }
                    }
                }
            }

            if let Ok(command) = self.rx.recv_timeout(Duration::from_millis(5)) {
                match command {
                    Command::Exit => { break },
                    Command::AddConnection { public_key, shared_mac_secret } => {
                        let x25519_id_hash = x25519IDHash::new(public_key, shared_mac_secret);
                        self.connections.insert(x25519_id_hash.clone(), Connection {
                            x25519_id_hash,
                            public_key,
                            endpoint: None,
                            local_ephemeral_blob: Some(EphemeralBlob::new(&mut rng)),
                            remote_ephemeral_blob: None,
                        });
                    },
                    Command::ListConnections => {
                        self.tx.send(Response::ListConnections { connections: self.connections.clone() }).unwrap();
                    },
                    Command::Connect { x25519_id_hash, endpoint } => {
                        if let Some(connection) = self.connections.get_mut(&x25519_id_hash) {
                            connection.endpoint = Some(endpoint);

                            socket.send_to(bincode::serialize(&Packet {
                                hash: x25519_id_hash,
                                data: Data::Handshake {
                                    ephemeral_blob: connection.local_ephemeral_blob.unwrap()
                                }
                            }).unwrap().as_slice(), endpoint).unwrap();
                        }
                    },
                    _ => {}
                }
            }
        }
    }

    pub fn run(mut self) -> JoinHandle<()> {
        std::thread::spawn(move || { self.run_threaded() })
    }
}