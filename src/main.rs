extern crate openssl;
#[macro_use]
extern crate serde;
#[macro_use]
extern crate serde_big_array;

mod instance;
mod x25519;
mod x25519_id_hash;
pub use x25519_id_hash::x25519IDHash;
mod shared_mac_secret;
pub use shared_mac_secret::SharedMacSecret;


use std::io::stdin;
use rand::{ thread_rng, RngCore };
use crate::{
    instance::{ InstanceBuilder, Instance },
    x25519::{ PrivateKey, PublicKey },
};
use crate::instance::{Command, Response};

fn main() {
    let mut rng = thread_rng();
    let mut secret = [0u8; 128];
    rng.fill_bytes(&mut secret);

    let private_key = PrivateKey::new(&secret);
    let public_key = PublicKey::new(&secret);

    let instance_builder = InstanceBuilder::new();
    let (instance, (tx, rx)) = Instance::new(instance_builder, private_key, public_key);

    let joiner = instance.run();

    let stdin = stdin();
    let mut input = String::new();
    loop {
        input.clear();
        stdin.read_line(&mut input).unwrap();
        let input = input.trim().split(" ").collect::<Vec<&str>>();

        match input[0] {
            "secret" => {
                rng.fill_bytes(&mut secret);

                println!("\"{}\"", base64::encode(&secret as &[u8]));
            },
            "privkey" => {
                println!("{}", PrivateKey::new(base64::decode(input[1]).unwrap().as_slice()));
            },
            "pubkey" => {
                println!("{}", PublicKey::new(base64::decode(input[1]).unwrap().as_slice()));
            },
            "shared_mac_secret" => {
                println!("{}", SharedMacSecret::new(&mut rng));
            }
            "exit" => {
                tx.send(Command::Exit).unwrap();

                break
            },
            "add_connection" => {
                let shared_mac_secret = SharedMacSecret::from(base64::decode(input[1]).unwrap());
                let public_key = PublicKey::from(base64::decode(input[2]).unwrap());

                tx.send(Command::AddConnection {
                    public_key,
                    shared_mac_secret,
                });
            },
            "list_connections" => {
                tx.send(Command::ListConnections);

                if let Response::ListConnections { connections } = rx.recv().unwrap() { //@TODO no unwrap maybe?
                    println!("{:?}", connections);
                }
            },
            _ => { println!("Unknown command"); }
        }
    }

    joiner.join().unwrap();
}