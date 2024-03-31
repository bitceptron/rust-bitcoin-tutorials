use getset::Getters;
use musig2::{PubNonce, SecNonce};
use rand::RngCore;

#[derive(Debug, Clone, PartialEq, Eq, Getters)]
#[get = "pub with_prefix"]
pub struct NonceSet {
    secnonce: SecNonce,
    pubnonce: PubNonce,
}


