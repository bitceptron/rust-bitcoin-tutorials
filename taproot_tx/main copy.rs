use bitcoin::{
    absolute::LockTime,
    hashes::Hash,
    key::{Keypair, Secp256k1, TapTweak, UntweakedPublicKey},
    secp256k1::Message,
    sighash::{Prevouts, SighashCache},
    taproot::{Signature, TapTree, TaprootBuilder},
    transaction::Version,
    Address, Amount, Network, OutPoint, PublicKey, ScriptBuf, Sequence, TapSighashType,
    Transaction, TxIn, TxOut, Witness, XOnlyPublicKey,
};
use bitcoincore_rpc::{
    json::{AddressType, ScanTxOutRequest},
    RpcApi,
};
use miniscript::{Descriptor, ToPublicKey};
use musig2::{AggNonce, KeyAggContext, PartialSignature, SecNonce};
use rand::RngCore;
use rand_chacha::ChaCha20Rng;
use rust_bitcoin_tutorials::{
    regtest_utils::{
        spawn_regtest::{spawn_regtest, RegtestConf},
        unwind_regtest::unwind_regtest,
    },
    taproot_utils::{
        policy_compiler::TapPolicyData, tweaks::tap_add_tweak_secretkey, TapKeySet,
        TaprootUtilsError,
    },
};
// use schnorr_fun::{
//     fun::{marker::{Normal, EvenY}, Point},
//     musig::{self},
// };
use sha2::Digest;

// -->> SET THESE FIRST! <<--
const BITCOIND_PATH: &str = "/Users/bedlam/Desktop/bitcoin-26.0/bin/bitcoind";
const BITCOIN_CONF_PATH: &str = "/Users/bedlam/Desktop/bitcoin-26.0/bitcoin.conf";
const TEMP_PATH: &str = "/Users/bedlam/Desktop/regtemp";
const NETWORK: Network = Network::Regtest;

fn main() -> Result<(), TaprootUtilsError> {
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

    // Creating 3 keysets for Rusty.
    let keyset1 = TapKeySet::new();
    let keyset2 = TapKeySet::new();
    let keyset3 = TapKeySet::new();

    // Creating a taproot address for Rusty to receive from the miner.
    // We want the address to have two policies:
    //  1- key_1 and key_2 and key_3 can always spend together (keypath spend).
    //  2- 2-of-3 from key_1,key_2 and key_3 can spend (scriptpath spend).
    //  3- After block 300, key_2 can spend alone (scriptpath spend).
    //  4- After block 500, key_1 can spend alone if it provides a preimage to a sha256 digest (scriptpath spend).

    // First we need to create our TapTree
    // To do so, we create scripts for policies 2 to 4 as follows

    // Policy 2:
    let policy_2_str = format!(
        "thresh(2,pk({}),pk({}),pk({}))",
        keyset1.get_publickey_x_only(),
        keyset2.get_publickey_x_only(),
        keyset3.get_publickey_x_only()
    );
    let policy_2_data = TapPolicyData::from_x_only_policy_str(&policy_2_str)?;

    // Policy 3:
    let policy_3_str = format!("and(pk({}),after(300))", keyset2.get_publickey_x_only());
    let policy_3_data = TapPolicyData::from_x_only_policy_str(&policy_3_str)?;

    // Policy 4:
    let policy_4_hashlock_preimage = "Hegel loves bitcoin and so on.";
    let mut hasher = sha2::Sha256::new();
    hasher.update(policy_4_hashlock_preimage);
    let policy_4_hashlock_digest = hex::encode(hasher.finalize());
    let policy_4_str = format!(
        "and(sha256({}),and(pk({}),after(500)))",
        policy_4_hashlock_digest,
        keyset1.get_publickey_x_only()
    );
    let policy_4_data = TapPolicyData::from_x_only_policy_str(&policy_4_str)?;

    // Now we pot them all in a taproot structure
    let script_weights = vec![
        (80, policy_2_data.get_script().clone()),
        (15, policy_3_data.get_script().clone()),
        (5, policy_4_data.get_script().clone()),
    ];
    let taproot_builder = TaprootBuilder::with_huffman_tree(script_weights)?;
    assert!(taproot_builder.is_finalizable());

    // Finalization needs the tree and an internal key. The internal key is policy 1.
    // Which is a MuSig2 for 3 keys.
    let pubkeys = vec![
        keyset1.get_publickey().clone(),
        keyset2.get_publickey().clone(),
        keyset3.get_publickey().clone(),
    ];
    let key_agg_ctx = KeyAggContext::new(pubkeys)?;
    let untweaked_aggregated_pubkey =
        key_agg_ctx.aggregated_pubkey_untweaked::<musig2::secp256k1::PublicKey>();

    // Back to our taproot builder to finalize it.
    let taproot_spend_info = taproot_builder
        .clone()
        .finalize(&secp, untweaked_aggregated_pubkey.x_only_public_key().0)
        .unwrap();
    let taptweak_scalar =
        bitcoin::secp256k1::Scalar::from_be_bytes(taproot_spend_info.tap_tweak().to_byte_array())
            .unwrap();

    // let tweaked_aggregated_pubkey = untweaked_aggregated_pubkey
    //     .add_exp_tweak(&secp, &taptweak_scalar)
    //     .unwrap();
    // println!("tweaked agg pubkey:\n{:#?}",tweaked_aggregated_pubkey.x_only_public_key());
    // println!("SPEND INFO:\n{:#?}",taproot_spend_info);

    // Now we wanna create a descriptor.
    let mut miniscript_taptree = miniscript::descriptor::TapTree::combine(
        policy_4_data.get_leaf().clone(),
        policy_3_data.get_leaf().clone(),
    );
    miniscript_taptree = miniscript::descriptor::TapTree::combine(
        policy_2_data.get_leaf().clone(),
        miniscript_taptree,
    );
    let taproot_descriptor =
        Descriptor::new_tr(taproot_spend_info.internal_key(), Some(miniscript_taptree))?;

    // Now let's create a taproot address, one way:
    let rusty_taproot_address = taproot_descriptor.address(NETWORK)?;

    // Another way:
    let rusty_taproot_address = Address::p2tr(
        &secp,
        taproot_spend_info.internal_key(),
        taproot_spend_info.merkle_root(),
        NETWORK,
    );

    // Now let's send some bitcoins from the miner to Rusty's taproot address and mine the transaction
    let miner_to_rusty_txid = mining_client
        .send_to_address(
            &rusty_taproot_address,
            Amount::from_int_btc(68),
            None,
            None,
            Some(false),
            Some(true),
            None,
            None,
        )
        .unwrap();

    let _ = mining_client.generate_to_address(20, &mining_address);

    let rusty_scan_request = ScanTxOutRequest::Single(taproot_descriptor.to_string());
    let rusty_scan_result = rusty_client
        .scan_tx_out_set_blocking(&[rusty_scan_request])
        .unwrap();
    println!(
        "\nRusty now has {} bitcoins.\n",
        rusty_scan_result.total_amount
    );

    // Now we want to send back 20 bitcoins back to the miner, via 4 transactions, each transferring 5 bitcoins
    // and using one of the 4 policies described above.

    // tx policy 1 (txp1) - Keypath spend, all 3 keys must sign through a MuSig2.
    // First, let's create the unsigned transaction.

    let txp1_input_utxo = rusty_scan_result.unspents[0].clone();
    let txp1_vesrion = Version::TWO;
    let txp1_locktime =
        LockTime::from_height(rusty_client.get_block_count().unwrap() as u32).unwrap();

    let txp1_input_previous_output = OutPoint {
        txid: txp1_input_utxo.txid,
        vout: txp1_input_utxo.vout,
    };

    let txp1_input_sequence = Sequence::ZERO;

    let txp1_input = TxIn {
        previous_output: txp1_input_previous_output,
        script_sig: ScriptBuf::default(),
        sequence: txp1_input_sequence,
        witness: Witness::default(),
    };

    let txp1_spend_output = TxOut {
        value: Amount::from_int_btc(5),
        script_pubkey: mining_address.script_pubkey(),
    };

    let txp1_change_output = TxOut {
        value: Amount::from_btc(62.9995).unwrap(),
        script_pubkey: rusty_taproot_address.script_pubkey(),
    };

    let mut txp1_unsigned = Transaction {
        version: txp1_vesrion,
        lock_time: txp1_locktime,
        input: vec![txp1_input],
        output: vec![txp1_spend_output.clone(), txp1_change_output],
    };

    let txp1_sighash_type = TapSighashType::Default;
    let txp1_prevout = vec![TxOut {
        value: txp1_input_utxo.amount,
        script_pubkey: txp1_input_utxo.script_pub_key,
    }];
    let txp1_prevouts = Prevouts::All(&txp1_prevout);

    let mut txp1_sighasher = SighashCache::new(&mut txp1_unsigned);
    let txp1_sighash = txp1_sighasher
        .taproot_key_spend_signature_hash(0, &txp1_prevouts, txp1_sighash_type)
        .unwrap();
    println!("{:#?}",txp1_sighash);
    let txp1_msg = Message::from_digest(txp1_sighash.to_byte_array());
    let txp1_msg_bytes = txp1_sighash.to_byte_array();

    // Since this keypath spend is a MuSig, we must sign the message via MuSig protocol.

    let party1_tweaked_secretkey =
        tap_add_tweak_secretkey(keyset1.get_secretkey(), &taproot_spend_info.tap_tweak());
    let party1_tweaked_pubkey = party1_tweaked_secretkey.public_key(&secp);

    let party2_tweaked_secretkey =
        tap_add_tweak_secretkey(keyset2.get_secretkey(), &taproot_spend_info.tap_tweak());
    let party2_tweaked_pubkey = party2_tweaked_secretkey.public_key(&secp);

    let party3_tweaked_secretkey =
        tap_add_tweak_secretkey(keyset3.get_secretkey(), &taproot_spend_info.tap_tweak());
    let party3_tweaked_pubkey = party3_tweaked_secretkey.public_key(&secp);

    let tweaked_pubkeys = vec![
        party1_tweaked_pubkey,
        party2_tweaked_pubkey,
        party3_tweaked_pubkey,
    ];
    let tweaked_key_agg_ctx = KeyAggContext::new(tweaked_pubkeys).unwrap();

    let tweaked_aggregated_pubkey =
        tweaked_key_agg_ctx.aggregated_pubkey::<musig2::secp256k1::PublicKey>();

    // Each party creates a public and private nonce:
    // Party 1

    let mut party1_nonce_seed = [0u8; 32];
    rng.fill_bytes(&mut party1_nonce_seed);
    let party1_secnonce = SecNonce::generate(
        party1_nonce_seed,
        party1_tweaked_secretkey,
        tweaked_aggregated_pubkey,
        txp1_msg_bytes,
        party1_nonce_seed,
    );
    let party1_pubnonce = party1_secnonce.public_nonce();

    // Party 2

    let mut party2_nonce_seed = [0u8; 32];
    rng.fill_bytes(&mut party2_nonce_seed);
    let party2_secnonce = SecNonce::generate(
        party2_nonce_seed,
        party2_tweaked_secretkey,
        tweaked_aggregated_pubkey,
        txp1_msg_bytes,
        party2_nonce_seed,
    );
    let party2_pubnonce = party2_secnonce.public_nonce();

    // Party 3

    let mut party3_nonce_seed = [0u8; 32];
    rng.fill_bytes(&mut party3_nonce_seed);
    let party3_secnonce = SecNonce::generate(
        party3_nonce_seed,
        party3_tweaked_secretkey,
        tweaked_aggregated_pubkey,
        txp1_msg_bytes,
        party3_nonce_seed,
    );
    let party3_pubnonce = party3_secnonce.public_nonce();

    // Each of the parties act:
    let pubnonces = vec![
        party1_pubnonce.clone(),
        party2_pubnonce.clone(),
        party3_pubnonce.clone(),
    ];

    let aggregated_pubnonce: AggNonce = pubnonces.iter().sum();

    // Now the signing:
    // Party 1
    let party1_partial_signature: PartialSignature = musig2::sign_partial(
        &tweaked_key_agg_ctx,
        party1_tweaked_secretkey,
        party1_secnonce,
        &aggregated_pubnonce,
        txp1_msg_bytes,
    )
    .unwrap();
    let party1_partial_sig_verification = musig2::verify_partial(
        &tweaked_key_agg_ctx,
        party1_partial_signature,
        &aggregated_pubnonce,
        party1_tweaked_pubkey,
        &party1_pubnonce,
        txp1_msg_bytes,
    );
    println!(
        "Party 1 partial sig verification: {:?}",
        party1_partial_sig_verification
    );

    // Party 2
    let party2_partial_signature: PartialSignature = musig2::sign_partial(
        &tweaked_key_agg_ctx,
        party2_tweaked_secretkey,
        party2_secnonce,
        &aggregated_pubnonce,
        txp1_msg_bytes,
    )
    .unwrap();
    let party2_partial_sig_verification = musig2::verify_partial(
        &tweaked_key_agg_ctx,
        party2_partial_signature,
        &aggregated_pubnonce,
        party2_tweaked_pubkey,
        &party2_pubnonce,
        txp1_msg_bytes,
    );
    println!(
        "Party 2 partial sig verification: {:?}",
        party2_partial_sig_verification
    );

    // Party 3
    let party3_partial_signature: PartialSignature = musig2::sign_partial(
        &tweaked_key_agg_ctx,
        party3_tweaked_secretkey,
        party3_secnonce,
        &aggregated_pubnonce,
        txp1_msg_bytes,
    )
    .unwrap();
    let party3_partial_sig_verification = musig2::verify_partial(
        &tweaked_key_agg_ctx,
        party3_partial_signature,
        &aggregated_pubnonce,
        party3_tweaked_pubkey,
        &party3_pubnonce,
        txp1_msg_bytes,
    );
    println!(
        "Party 3 partial sig verification: {:?}",
        party3_partial_sig_verification
    );

    // Now let's aggregate partial signatures.
    let partial_signatures = vec![
        party1_partial_signature,
        party2_partial_signature,
        party3_partial_signature,
    ];
    let final_signature: [u8; 64] = musig2::aggregate_partial_signatures(
        &tweaked_key_agg_ctx,
        &aggregated_pubnonce,
        partial_signatures,
        txp1_msg_bytes,
    )
    .unwrap();

    let sig_verify =
        musig2::verify_single(tweaked_aggregated_pubkey, final_signature, txp1_msg_bytes);
    println!("Signature verification: {:?}", sig_verify);
    println!("{:?}", taproot_spend_info.output_key().to_inner());
    println!("{:?}", untweaked_aggregated_pubkey.to_x_only_pubkey());
    println!("{:?}", untweaked_aggregated_pubkey.add_exp_tweak(&secp, &taptweak_scalar).unwrap().to_x_only_pubkey());

    // Now let's update our sighash with this final_signature.

    let txp1_final_signature_bitcoin =
        bitcoin::secp256k1::schnorr::Signature::from_slice(&final_signature).unwrap();

    // Back to our unsigned transaction.
    let txp1_signature = Signature {
        sig: txp1_final_signature_bitcoin,
        hash_ty: txp1_sighash_type,
    };

    let mut txp1_witness = Witness::new();
    txp1_witness.push(txp1_signature.to_vec());
    *txp1_sighasher.witness_mut(0).unwrap() = txp1_witness;

    let txp1 = txp1_sighasher.into_transaction();
    let txp1_acceptance = rusty_client.test_mempool_accept(&[&*txp1]).unwrap();
    println!("txp1 acceptance result:\n{:#?}", txp1_acceptance);
    // // println!("TXP1:\n{:#?}", txp1);

    // // Now we send the txp1

    // mining_client
    //     .generate_to_address(100, &mining_address)
    //     .unwrap();

    // let rusty_scan_request = ScanTxOutRequest::Single(rusty_taproot_descriptor.to_string());
    // let rusty_scan_result = rusty_client
    //     .scan_tx_out_set_blocking(&[rusty_scan_request])
    //     .unwrap();
    // println!(
    //     "\nRusty now has {} bitcoins.",
    //     rusty_scan_result.total_amount
    // );

    unwind_regtest(vec![rusty_client, mining_client], TEMP_PATH);
    Ok(())
}
