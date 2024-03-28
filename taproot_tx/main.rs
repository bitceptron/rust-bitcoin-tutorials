use std::{str::FromStr, sync::Arc};

use bitcoin::{
    key::{Keypair, Secp256k1, UntweakedPublicKey},
    taproot::TaprootBuilder,
    Address, Amount, Network, XOnlyPublicKey,
};
use bitcoincore_rpc::{
    json::{AddressType, ScanTxOutRequest},
    RpcApi,
};
use miniscript::{descriptor::TapTree, policy::Concrete, Descriptor, Tap};
use rust_bitcoin_tutorials::regtest_utils::{
    spawn_regtest::{spawn_regtest, RegtestConf},
    unwind_regtest::unwind_regtest,
};
use schnorr_fun::{fun::Point, musig};
use sha2::Digest;

// -->> SET THESE FIRST! <<--
const BITCOIND_PATH: &str = "/Users/bedlam/Desktop/bitcoin-26.0/bin/bitcoind";
const BITCOIN_CONF_PATH: &str = "/Users/bedlam/Desktop/bitcoin-26.0/bitcoin.conf";
const TEMP_PATH: &str = "/Users/bedlam/Desktop/regtemp";
const NETWORK: Network = Network::Regtest;

fn main() {
    // Creating secp and rng for future use.
    let secp = Secp256k1::new();
    let mut rng = rand::thread_rng();

    // Spinning up two connected clients. One for mining and one for our rusty person.
    let mut clients = spawn_regtest(
        BITCOIND_PATH,
        BITCOIN_CONF_PATH,
        TEMP_PATH,
        vec![
            RegtestConf::new(18447, 18448).unwrap(),
            RegtestConf::new(18449, 18450).unwrap(),
        ],
        500,
        2,
    )
    .unwrap();
    let mining_client = clients.remove(0);
    let rusty_client = clients.remove(0);

    // Mining some bitcoin on our mining client to get things going.
    let mining_address = mining_client
        .get_new_address(Some("mining"), Some(AddressType::Bech32))
        .unwrap()
        .require_network(NETWORK)
        .unwrap();
    let _ = mining_client
        .generate_to_address(150, &mining_address)
        .unwrap(); // Now our mining client has some 250 bitcoins to spend.

    // Creating a keypair for Rusty.
    let rusty_keypair_1 = Keypair::new(&secp, &mut rng);
    let rusty_pubkey_1 = rusty_keypair_1.public_key();
    let rusty_secretkey_1 = rusty_keypair_1.secret_key();
    let (rusty_xonly_pubkey_1, _rusty_internal_xonly_pubkey_parity_1) =
        rusty_keypair_1.x_only_public_key();

    // Creating another keypair for Rusty.
    let rusty_keypair_2 = Keypair::new(&secp, &mut rng);
    let rusty_pubkey_2 = rusty_keypair_2.public_key();
    let rusty_secretkey_2 = rusty_keypair_2.secret_key();
    let (rusty_xonly_pubkey_2, _rusty_internal_xonly_pubkey_parity_2) =
        rusty_keypair_2.x_only_public_key();

    // Creating yet another keypair for Rusty.
    let rusty_keypair_3 = Keypair::new(&secp, &mut rng);
    let rusty_pubkey_3 = rusty_keypair_3.public_key();
    let rusty_secretkey_3 = rusty_keypair_3.secret_key();
    let (rusty_xonly_pubkey_3, _rusty_internal_xonly_pubkey_parity_3) =
        rusty_keypair_3.x_only_public_key();

    // Creating a taproot address for Rusty to receive from the miner.
    // We want the address to have two policies:
    //  1- key_1 and key_2 and key_3 can always spend together (keypath spend).
    //  2- 2-of-3 from key_1,key_2 and key_3 can spend (scriptpath spend).
    //  3- After 200 blocks, key_2 can spend alone (scriptpath spend).
    //  4- After 400 blocks, key_1 can spend alone if it provides a preimage to a sha256 digest (scriptpath spend).

    // First let's create an aggregated key of the 3 keys above.
    let rusty_musig = musig::new_with_deterministic_nonces::<sha2::Sha256>();
    let rusty_pubkey_1_point = Point::from_bytes(rusty_pubkey_1.serialize()).unwrap();
    let rusty_pubkey_2_point = Point::from_bytes(rusty_pubkey_2.serialize()).unwrap();
    let rusty_pubkey_3_point = Point::from_bytes(rusty_pubkey_3.serialize()).unwrap();
    let rusty_agg_key = rusty_musig.new_agg_key(vec![
        rusty_pubkey_1_point,
        rusty_pubkey_2_point,
        rusty_pubkey_3_point,
    ]);
    let rusty_agg_key_x_only = rusty_agg_key
        .into_xonly_key()
        .agg_public_key()
        .to_xonly_bytes();

    let rusty_policy_4_preimage = "Hegel loves bitcoin and zizek and so on.";
    let mut hasher = sha2::Sha256::new();
    hasher.update(rusty_policy_4_preimage);
    let rusty_policy_4_preimage_digest = hex::encode(hasher.finalize());

    // Then, let's define leaf policies.
    let policy_2_str = format!(
        "thresh(2,pk({}),pk({}),pk({}))",
        rusty_xonly_pubkey_1, rusty_xonly_pubkey_2, rusty_xonly_pubkey_3
    );
    let policy_2 = Concrete::<XOnlyPublicKey>::from_str(&policy_2_str).unwrap();
    let policy_2_desc = policy_2.compile::<Tap>().unwrap();
    policy_2_desc.sanity_check().unwrap();
    println!("\nPolicy 2 descriptor:\n{:?}", policy_2_desc);
    let policy_2_script = policy_2_desc.encode();
    println!("Policy 2 script:\n{:?}", policy_2_script);
    let policy_2_leaf = TapTree::Leaf(Arc::new(policy_2_desc));

    let policy_3_str = format!("and(pk({}),older(200))", rusty_xonly_pubkey_2);
    let policy_3 = Concrete::<XOnlyPublicKey>::from_str(&policy_3_str).unwrap();
    let policy_3_desc = policy_3.compile::<Tap>().unwrap();
    policy_3_desc.sanity_check().unwrap();
    println!("\nPolicy 3 descriptor:\n{:?}", policy_3_desc);
    let policy_3_script = policy_3_desc.encode();
    println!("Policy 3 script:\n{:?}", policy_3_script);
    let policy_3_leaf = TapTree::Leaf(Arc::new(policy_3_desc));

    let policy_4_str = format!(
        "and(sha256({}),and(pk({}),older(400)))",
        rusty_policy_4_preimage_digest, rusty_xonly_pubkey_1
    );
    let policy_4 = Concrete::<XOnlyPublicKey>::from_str(&policy_4_str).unwrap();
    let policy_4_desc = policy_4.compile::<Tap>().unwrap();
    policy_4_desc.sanity_check().unwrap();
    println!("\nPolicy 4 descriptor:\n{:?}", policy_4_desc);
    let policy_4_script = policy_4_desc.encode();
    println!("Policy 4 script:\n{:?}", policy_4_script);
    let policy_4_leaf = TapTree::Leaf(Arc::new(policy_4_desc));

    let mut rusty_taptree = TapTree::combine(policy_4_leaf, policy_3_leaf);
    rusty_taptree = TapTree::combine(policy_2_leaf, rusty_taptree);

    let policy_weights = vec![
        (80, policy_2_script),
        (15, policy_3_script),
        (5, policy_4_script),
    ];

    let rusty_taproot_builder = TaprootBuilder::with_huffman_tree(policy_weights).unwrap();
    let is_rusty_taproot_finalizable = rusty_taproot_builder.is_finalizable();
    println!(
        "\nRusty taproot is{} finalizable",
        if is_rusty_taproot_finalizable {
            ""
        } else {
            " not"
        }
    );

    let rusty_taproot_internal_key = UntweakedPublicKey::from_slice(&rusty_agg_key_x_only).unwrap();

    let finalized_rusty_taproot_spend_info = rusty_taproot_builder
        .clone()
        .finalize(&secp, rusty_taproot_internal_key)
        .unwrap();
    println!(
        "\nRusty taproot spend info:\n{:#?}",
        finalized_rusty_taproot_spend_info
    );

    //let rusty_taptree = rusty_taproot_builder.clone().try_into_taptree().unwrap();

    let rusty_taproot_descriptor =
        Descriptor::new_tr(rusty_taproot_internal_key, Some(rusty_taptree)).unwrap();
    println!(
        "\nRusty taproot descriptor:\n{:#?}",
        rusty_taproot_descriptor
    );

    let rusty_taproot_address_from_descriptor = rusty_taproot_descriptor.address(NETWORK).unwrap();

    let rusty_taproot_address_bitcoin_crate_merkle_root = Address::p2tr(
        &secp,
        rusty_taproot_internal_key,
        finalized_rusty_taproot_spend_info.merkle_root(),
        NETWORK,
    );

    println!(
        "\nRusty taproot address from descriptor:  {}",
        rusty_taproot_address_from_descriptor
    );
    println!(
        "\nRusty taproot address from merkle root: {}",
        rusty_taproot_address_bitcoin_crate_merkle_root
    );

    // Now let's send some bitcoins from thw minwr to Rusty's taproot address.
    let miner_to_rusty_txid = mining_client
        .send_to_address(
            &rusty_taproot_address_bitcoin_crate_merkle_root,
            Amount::from_int_btc(68),
            None,
            None,
            Some(false),
            Some(true),
            None,
            None,
        )
        .unwrap();
    println!("\nMiner propogated transaction {}", miner_to_rusty_txid);
    let _ = mining_client.generate_to_address(20, &mining_address);

    let rusty_scan_request = ScanTxOutRequest::Single(rusty_taproot_descriptor.to_string());
    let rusty_scan_result = rusty_client
        .scan_tx_out_set_blocking(&[rusty_scan_request])
        .unwrap();
    println!(
        "\nRusty now has {} bitcoins.",
        rusty_scan_result.total_amount
    );

    // Now we want to send back 20 bitcoins back to the miner, via 4 transactions, each transferring 5 bitcoins
    // and using one of the 4 policies described above.

    unwind_regtest(vec![rusty_client, mining_client], TEMP_PATH);
}
