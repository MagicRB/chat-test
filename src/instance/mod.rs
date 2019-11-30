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
use rand::prelude::thread_rng;
use openssl::sha::Sha256;

use crate::{
    x25519::{PrivateKey, PublicKey, SharedKey},
    x25519IDHash,
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
            protocol_address: "0.0.0.0:6555".parse().unwrap(),
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
                        if connection.endpoint.is_none() {
                            connection.endpoint = Some(sender)
                        } else if connection.endpoint != Some(sender) {
                            connection.endpoint = Some(sender)
                        } // @TODO Denial of Service?

                        match packet.data {
                            Data::Handshake { ephemeral_blob } => {
                                let mut ready_to_establish = false;

                                if let connection::State::Pending {
                                    remote_public_key,
                                    local_ephemeral_blob,
                                    remote_ephemeral_blob,
                                    sent_handshake,
                                } = &mut connection.state {
                                    if remote_ephemeral_blob.is_some() {
                                        println!("Received handshake from {} multiple times!", remote_public_key)
                                    } else {
                                        *remote_ephemeral_blob = Some(ephemeral_blob);
                                        ready_to_establish = true;
                                    }

                                    if !*sent_handshake {
                                        let data = bincode::serialize(&Packet {
                                            hash: connection.local_x25519_id_hash,
                                            data: Data::Handshake {
                                                ephemeral_blob: local_ephemeral_blob.unwrap()
                                            }
                                        }).unwrap();
                                        socket.send_to(data.as_slice(), sender).unwrap();
                                        *sent_handshake = true;
                                    }
                                }

                                if ready_to_establish {
                                    if let connection::State::Pending {
                                        remote_public_key,
                                        local_ephemeral_blob,
                                        remote_ephemeral_blob,
                                        sent_handshake
                                    } = connection.state {
                                        let shared_key = SharedKey::derive(&self.private_key, &remote_public_key);

                                        let mut sha256 = Sha256::new();
                                        sha256.update(shared_key.as_ref());

                                        if local_ephemeral_blob.as_ref().unwrap() > remote_ephemeral_blob.as_ref().unwrap() {
                                            sha256.update(local_ephemeral_blob.unwrap().as_ref());
                                            sha256.update(remote_ephemeral_blob.unwrap().as_ref());
                                        } else {
                                            sha256.update(remote_ephemeral_blob.unwrap().as_ref());
                                            sha256.update(local_ephemeral_blob.unwrap().as_ref());
                                        }

                                        println!("{}", base64::encode(&sha256.finish()));

                                        connection.state = connection::State::Established { placeholder: () };
                                    }
                                }
                            },
                        }
                    }
                }
            }

            if let Ok(command) = self.rx.recv_timeout(Duration::from_millis(5)) {
                match command {
                    Command::Exit => { break },
                    Command::AddConnection { public_key, shared_mac_secret } => {
                        let remote_x5519_id_hash = x25519IDHash::new(public_key, shared_mac_secret);
                        self.connections.insert(remote_x5519_id_hash.clone(), Connection {
                            local_x25519_id_hash: x25519IDHash::new(self.public_key, shared_mac_secret),
                            remote_x25519_id_hash: remote_x5519_id_hash,
                            endpoint: None,
                            state: connection::State::Pending {
                                remote_public_key: public_key,
                                local_ephemeral_blob: Some(EphemeralBlob::new(&mut rng)),
                                remote_ephemeral_blob: None,
                                sent_handshake: false
                            },
                        });
                    },
                    Command::ListConnections => {
                        self.tx.send(Response::ListConnections { connections: self.connections.clone() }).unwrap();
                    },
                    Command::Connect { x25519_id_hash, endpoint } => {
                        if let Some(connection) = self.connections.get_mut(&x25519_id_hash) {
                            if let connection::State::Pending {
                                remote_public_key,
                                local_ephemeral_blob,
                                remote_ephemeral_blob,
                                sent_handshake
                            } = &mut connection.state {
                                connection.endpoint = Some(endpoint);
                                *sent_handshake = true;

                                let data = bincode::serialize(&Packet {
                                    hash: connection.local_x25519_id_hash,
                                    data: Data::Handshake {
                                        ephemeral_blob: local_ephemeral_blob.unwrap()
                                    }
                                }).unwrap();
                                socket.send_to(data.as_slice(), endpoint).unwrap();
                            }
                        }
                    },
                }
            }
        }
    }

    pub fn run(mut self) -> JoinHandle<()> {
        std::thread::spawn(move || { self.run_threaded() })
    }
}