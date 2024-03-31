use bitcoin::{
    hashes::Hash,
    key::{Parity, Secp256k1, TapTweak},
    TapTweakHash,
};

pub fn tap_add_tweak_secretkey(
    secretkey: &bitcoin::secp256k1::SecretKey,
    taptweak: &TapTweakHash,
) -> bitcoin::secp256k1::SecretKey {
    let secp = Secp256k1::new();
    let taptweak_scalar = bitcoin::secp256k1::Scalar::from_be_bytes(taptweak.to_byte_array()).unwrap();
    let secretkey = if secretkey.public_key(&secp).x_only_public_key().1 == Parity::Even {
        secretkey.clone()
    } else {
        secretkey.clone().negate()
    };
    let tweaked_secretkey = secretkey.add_tweak(&taptweak_scalar).unwrap();
    if tweaked_secretkey.public_key(&secp).x_only_public_key().1 == Parity::Even {
        tweaked_secretkey
    } else {
        tweaked_secretkey.negate()
    }
}
