use bitcoin::{
    key::{Keypair, Parity, Secp256k1},
    secp256k1::SecretKey,
};
use getset::Getters;

use super::error::TaprootUtilsError;

#[derive(Debug, Clone, PartialEq, Eq, Getters)]
#[get = "pub with_prefix"]
pub struct TapKeySet {
    keypair: bitcoin::secp256k1::Keypair,
    secretkey: bitcoin::secp256k1::SecretKey,
    secretkey_bytes: [u8; 32],
    secretkey_scalar: bitcoin::secp256k1::Scalar,
    publickey: bitcoin::secp256k1::PublicKey,
    publickey_serialized_33byte: [u8; 33],
    publickey_serialized_65byte: [u8; 65],
    publickey_x_only: bitcoin::XOnlyPublicKey,
    parity: bitcoin::key::Parity,
    publickey_x_only_bytes: [u8; 32],
}

impl TapKeySet {
    pub fn new() -> Self {
        let secp = Secp256k1::new();
        let mut rng = rand::thread_rng();
        let secretkey_interim = bitcoin::secp256k1::SecretKey::new(&mut rng);
        let publickey_interim = secretkey_interim.public_key(&secp);
        let secretkey = if publickey_interim.x_only_public_key().1 == Parity::Even {
            secretkey_interim
        } else {
            secretkey_interim.negate()
        };
        let publickey = secretkey.public_key(&secp);
        let keypair = Keypair::from_secret_key(&secp, &secretkey);
        let secretkey_bytes = secretkey.secret_bytes();
        let secretkey_scalar = bitcoin::secp256k1::Scalar::from_be_bytes(secretkey_bytes).unwrap();  
        let publickey_serialized_33byte = publickey.serialize();
        let publickey_serialized_65byte = publickey.serialize_uncompressed();
        let (publickey_x_only, parity) = publickey.x_only_public_key();
        let publickey_x_only_bytes = publickey_x_only.serialize();

        TapKeySet {
            keypair,
            secretkey,
            secretkey_bytes,
            secretkey_scalar,
            publickey,
            publickey_serialized_33byte,
            publickey_serialized_65byte,
            publickey_x_only,
            parity,
            publickey_x_only_bytes,
        }
    }

    pub fn from_secret_bytes(secret_bytes: [u8; 32]) -> Result<Self, TaprootUtilsError> {
        let secp = Secp256k1::new();
        let secretkey_bytes = secret_bytes;
        let secretkey_interim = SecretKey::from_slice(&secret_bytes)?;
        let publickey_interim = secretkey_interim.public_key(&secp);
        let secretkey = if publickey_interim.x_only_public_key().1 == Parity::Even {
            secretkey_interim
        } else {
            secretkey_interim.negate()
        };
        let publickey = secretkey.public_key(&secp);
        let secretkey_scalar = bitcoin::secp256k1::Scalar::from_be_bytes(secretkey_bytes).unwrap();
        let keypair = Keypair::from_secret_key(&secp, &secretkey);
        let publickey_serialized_33byte = publickey.serialize();
        let publickey_serialized_65byte = publickey.serialize_uncompressed();
        let (publickey_x_only, parity) = publickey.x_only_public_key();
        let publickey_x_only_bytes = publickey_x_only.serialize();
        Ok(TapKeySet {
            keypair,
            secretkey,
            secretkey_bytes,
            secretkey_scalar,
            publickey,
            publickey_serialized_33byte,
            publickey_serialized_65byte,
            publickey_x_only,
            parity,
            publickey_x_only_bytes,
        })
    }
}
