mod public_key;
pub use public_key::PublicKey;
mod private_key;
pub use private_key::PrivateKey;
mod shared_key;
pub use shared_key::SharedKey;

#[allow(unused_imports)]
#[allow(unused_variables)]
#[allow(dead_code)]
pub(super) mod curve25519;

#[cfg(test)]
mod tests {
    use crate::x25519::{PrivateKey, PublicKey, SharedKey};
    use rand::RngCore;

    #[test]
    fn gen_private_key() {
        let mut secret = [0u8; 128];
        let mut rng = rand::thread_rng();

        rng.fill_bytes(&mut secret);

        let private_key = PrivateKey::new(&secret);

        println!("Generated private key: {}", private_key);
    }

    #[test]
    fn gen_public_key() {
        let mut secret = [0u8; 128];
        let mut rng = rand::thread_rng();

        rng.fill_bytes(&mut secret);

        let public_key = PublicKey::new(&secret);

        println!("Generated public key: {}", public_key);
    }

    #[test]
    fn gen_shared_key() {
        let mut secret = [0u8; 128];
        let mut rng = rand::thread_rng();

        rng.fill_bytes(&mut secret);

        let private_key = PrivateKey::new(&secret);
        let public_key = PublicKey::new(&secret);

        let shared_key = SharedKey::derive(&private_key, &public_key);

        println!("Generated shared key: {}", shared_key);
    }
}