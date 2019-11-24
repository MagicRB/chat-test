use crate::x25519::PublicKey;

pub enum Command {
    Exit,
    AddConnection {
        public_key: PublicKey,
        salt: ()
    }
}