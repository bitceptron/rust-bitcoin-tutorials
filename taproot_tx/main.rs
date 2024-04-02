use bitcoin::{
    absolute::LockTime,
    hashes::Hash,
    key::Secp256k1,
    sighash::{Prevouts, SighashCache},
    taproot::{ControlBlock, LeafVersion, Signature, TaprootBuilder},
    transaction::Version,
    Address, Amount, Network, OutPoint, ScriptBuf, Sequence, TapLeafHash, TapSighashType,
    Transaction, TxIn, TxOut, Witness,
};
use bitcoincore_rpc::{
    json::{AddressType, ScanTxOutRequest},
    RpcApi,
};
use miniscript::Descriptor;
use musig2::{secp256k1::Message, AggNonce, KeyAggContext, PartialSignature, SecNonce};
use rand::RngCore;
use rust_bitcoin_tutorials::{
    regtest_utils::{
        common::{get_balance, send_and_mine},
        spawn_regtest::{spawn_regtest, RegtestConf},
        unwind_regtest::unwind_regtest,
    },
    taproot_utils::{policy_compiler::TapPolicyData, TapKeySet, TaprootUtilsError},
};
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
        //"or(pk({}),pk({}))",
        //"pk({})",
        keyset1.get_publickey_x_only(),
        keyset2.get_publickey_x_only(),
        keyset3.get_publickey_x_only()
    );
    let policy_2_data = TapPolicyData::from_x_only_policy_str(&policy_2_str)?;

    // Policy 3:
    let policy_3_str = format!("and(pk({}),after(300))", keyset2.get_publickey_x_only());
    let policy_3_data = TapPolicyData::from_x_only_policy_str(&policy_3_str)?;

    // Policy 4:
    let policy_4_hashlock_preimage = b"Hegel loves bitcoin and so on.";
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

    let key_agg_ctx = key_agg_ctx
        .with_taproot_tweak(&taproot_spend_info.merkle_root().unwrap().to_byte_array())
        .unwrap();
    let aggregated_pubkey: bitcoin::secp256k1::PublicKey = key_agg_ctx.aggregated_pubkey();

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
    let _rusty_taproot_address = taproot_descriptor.address(NETWORK)?;

    // Another way:
    let rusty_taproot_address = Address::p2tr(
        &secp,
        taproot_spend_info.internal_key(),
        taproot_spend_info.merkle_root(),
        NETWORK,
    );

    // Now let's send some bitcoins from the miner to Rusty's taproot address and mine the transaction
    let _miner_to_rusty_txid = mining_client
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

    println!(
        "\nRusty now has {} bitcoins.\n",
        get_balance(&taproot_descriptor, &rusty_client)
    );

    // Now we want to send back 20 bitcoins back to the miner, via 4 transactions, each transferring 5 bitcoins
    // and using one of the 4 policies described above.

    // tx policy 1 (txp1) - Keypath spend, all 3 keys must sign through a MuSig2.
    // First, let's create the unsigned transaction.

    let rusty_scan_request = ScanTxOutRequest::Single(taproot_descriptor.to_string());
    let rusty_scan_result = rusty_client
        .scan_tx_out_set_blocking(&[rusty_scan_request])
        .unwrap();
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
    let txp1_msg_bytes = txp1_sighash.to_byte_array();

    // Each party creates a public and private nonce:
    // Party 1

    let mut party1_nonce_seed = [0u8; 32];
    rng.fill_bytes(&mut party1_nonce_seed);
    let party1_secnonce = SecNonce::generate(
        party1_nonce_seed,
        keyset1.get_secretkey().clone(),
        aggregated_pubkey,
        txp1_msg_bytes,
        party1_nonce_seed,
    );
    let party1_pubnonce = party1_secnonce.public_nonce();

    // Party 2

    let mut party2_nonce_seed = [0u8; 32];
    rng.fill_bytes(&mut party2_nonce_seed);
    let party2_secnonce = SecNonce::generate(
        party2_nonce_seed,
        keyset2.get_secretkey().clone(),
        aggregated_pubkey,
        txp1_msg_bytes,
        party2_nonce_seed,
    );
    let party2_pubnonce = party2_secnonce.public_nonce();

    // Party 3

    let mut party3_nonce_seed = [0u8; 32];
    rng.fill_bytes(&mut party3_nonce_seed);
    let party3_secnonce = SecNonce::generate(
        party3_nonce_seed,
        keyset3.get_secretkey().clone(),
        aggregated_pubkey,
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
        &key_agg_ctx,
        keyset1.get_secretkey().clone(),
        party1_secnonce,
        &aggregated_pubnonce,
        txp1_msg_bytes,
    )
    .unwrap();
    let _party1_partial_sig_verification = musig2::verify_partial(
        &key_agg_ctx,
        party1_partial_signature,
        &aggregated_pubnonce,
        keyset1.get_publickey().x_only_public_key(),
        &party1_pubnonce,
        txp1_msg_bytes,
    )
    .unwrap();

    // Party 2
    let party2_partial_signature: PartialSignature = musig2::sign_partial(
        &key_agg_ctx,
        keyset2.get_secretkey().clone(),
        party2_secnonce,
        &aggregated_pubnonce,
        txp1_msg_bytes,
    )
    .unwrap();
    let _party2_partial_sig_verification = musig2::verify_partial(
        &key_agg_ctx,
        party2_partial_signature,
        &aggregated_pubnonce,
        keyset2.get_publickey().x_only_public_key(),
        &party2_pubnonce,
        txp1_msg_bytes,
    )
    .unwrap();

    // Party 3
    let party3_partial_signature: PartialSignature = musig2::sign_partial(
        &key_agg_ctx,
        keyset3.get_secretkey().clone(),
        party3_secnonce,
        &aggregated_pubnonce,
        txp1_msg_bytes,
    )
    .unwrap();
    let _party3_partial_sig_verification = musig2::verify_partial(
        &key_agg_ctx,
        party3_partial_signature,
        &aggregated_pubnonce,
        keyset3.get_publickey().x_only_public_key(),
        &party3_pubnonce,
        txp1_msg_bytes,
    )
    .unwrap();

    // Now let's aggregate partial signatures.
    let partial_signatures = vec![
        party1_partial_signature,
        party2_partial_signature,
        party3_partial_signature,
    ];
    let final_signature: [u8; 64] = musig2::aggregate_partial_signatures(
        &key_agg_ctx,
        &aggregated_pubnonce,
        partial_signatures,
        txp1_msg_bytes,
    )
    .unwrap();

    let _sig_verify =
        musig2::verify_single(aggregated_pubkey, final_signature, txp1_msg_bytes).unwrap();

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
    let _txp1_acceptance = rusty_client.test_mempool_accept(&[&*txp1]).unwrap();

    // Now we send the txp1 and mine it
    let _txp1_txid = send_and_mine(txp1, &mining_client, &mining_address, 50).unwrap();
    println!(
        "\nAfter txp1, Rusty has {} bitcoins.\n",
        get_balance(&taproot_descriptor, &rusty_client)
    );
    // DONE!!!

    // ----------------------------------------------------------------------------------------------------------
    // ----------------------------------------------------------------------------------------------------------
    // ----------------------------------------------------------------------------------------------------------
    // ----------------------------------------------------------------------------------------------------------
    // ----------------------------------------------------------------------------------------------------------

    // Now let's spend policy 2.
    let rusty_scan_request = ScanTxOutRequest::Single(taproot_descriptor.to_string());
    let rusty_scan_result = rusty_client
        .scan_tx_out_set_blocking(&[rusty_scan_request])
        .unwrap();
    let txp2_input_utxo = rusty_scan_result.unspents[0].clone();
    let txp2_vesrion = Version::TWO;
    let txp2_locktime =
        LockTime::from_height(rusty_client.get_block_count().unwrap() as u32).unwrap();

    let txp2_input_previous_output = OutPoint {
        txid: txp2_input_utxo.txid,
        vout: txp2_input_utxo.vout,
    };

    let txp2_input_sequence = Sequence::ZERO;

    let txp2_input = TxIn {
        previous_output: txp2_input_previous_output,
        script_sig: ScriptBuf::default(),
        sequence: txp2_input_sequence,
        witness: Witness::default(),
    };

    let txp2_spend_output = TxOut {
        value: Amount::from_int_btc(5),
        script_pubkey: mining_address.script_pubkey(),
    };

    let txp2_change_output = TxOut {
        value: Amount::from_btc(57.9990).unwrap(),
        script_pubkey: rusty_taproot_address.script_pubkey(),
    };

    let mut txp2_unsigned = Transaction {
        version: txp2_vesrion,
        lock_time: txp2_locktime,
        input: vec![txp2_input],
        output: vec![txp2_spend_output.clone(), txp2_change_output],
    };

    let txp2_sighash_type = TapSighashType::Default;
    let txp2_prevout = vec![TxOut {
        value: txp2_input_utxo.amount,
        script_pubkey: txp2_input_utxo.script_pub_key,
    }];
    let txp2_prevouts = Prevouts::All(&txp2_prevout);

    let mut txp2_sighasher = SighashCache::new(&mut txp2_unsigned);

    let policy2_leaf_hash = TapLeafHash::from_script(
        policy_2_data.get_script(),
        bitcoin::taproot::LeafVersion::TapScript,
    );

    let txp2_sighash = txp2_sighasher
        .taproot_script_spend_signature_hash(
            0,
            &txp2_prevouts,
            policy2_leaf_hash,
            txp2_sighash_type,
        )
        .unwrap();

    let txp2_msg = bitcoin::secp256k1::Message::from_digest(txp2_sighash.to_byte_array());
    // let txp2_msg_bytes = txp2_sighash.to_byte_array();

    let txp2_party1_signature = secp.sign_schnorr(&txp2_msg, keyset1.get_keypair());
    let txp2_party1_signature = Signature {
        sig: txp2_party1_signature,
        hash_ty: txp2_sighash_type,
    };

    let txp2_party3_signature = secp.sign_schnorr(&txp2_msg, keyset3.get_keypair());
    let txp2_party3_signature = Signature {
        sig: txp2_party3_signature,
        hash_ty: txp2_sighash_type,
    };

    secp.verify_schnorr(
        &txp2_party1_signature.sig,
        &txp2_msg,
        keyset1.get_publickey_x_only(),
    )
    .unwrap();
    secp.verify_schnorr(
        &txp2_party3_signature.sig,
        &txp2_msg,
        keyset3.get_publickey_x_only(),
    )
    .unwrap();

    // Creating a witness and populating it.
    let mut txp2_witness = Witness::new();

    // The control block
    let txp2_merkle_branch = taproot_spend_info
        .script_map()
        .get(&(
            policy_2_data.get_script().clone(),
            bitcoin::taproot::LeafVersion::TapScript,
        ))
        .unwrap()
        .clone()
        .pop_first()
        .unwrap();
    let txp2_control_block = ControlBlock {
        leaf_version: bitcoin::taproot::LeafVersion::TapScript,
        output_key_parity: taproot_spend_info.output_key_parity(),
        internal_key: taproot_spend_info.internal_key(),
        merkle_branch: txp2_merkle_branch,
    };

    let _policy_commitment = txp2_control_block.verify_taproot_commitment(
        &secp,
        taproot_spend_info.output_key().to_inner(),
        policy_2_data.get_script(),
    );

    // The signatures must be in order and reversed compared to what we have put on the policy
    txp2_witness.push(txp2_party3_signature.to_vec());
    // In place of the 2nd key we must put an empty element in witness
    txp2_witness.push(Vec::new());
    txp2_witness.push(txp2_party1_signature.to_vec());
    txp2_witness.push(policy_2_data.get_script().as_bytes());
    txp2_witness.push(txp2_control_block.serialize());

    *txp2_sighasher.witness_mut(0).unwrap() = txp2_witness;

    // Checking if txp2 is acceptable in mempool
    let txp2 = txp2_sighasher.into_transaction();

    let _txp2_acceptance = rusty_client.test_mempool_accept(&[&*txp2]).unwrap();

    let _txp2_txid = send_and_mine(&txp2, &mining_client, &mining_address, 30);

    println!(
        "\nAfter txp2, Rusty has {} bitcoins.\n",
        get_balance(&taproot_descriptor, &rusty_client)
    );
    // DONE!!!

    // ----------------------------------------------------------------------------------------------------------
    // ----------------------------------------------------------------------------------------------------------
    // ----------------------------------------------------------------------------------------------------------
    // ----------------------------------------------------------------------------------------------------------
    // ----------------------------------------------------------------------------------------------------------

    // We are now at block 250. Lets mine 50 so that we get to block 300, after which we can spend with policy 3.
    mining_client
        .generate_to_address(50, &mining_address)
        .unwrap();

    let rusty_scan_request = ScanTxOutRequest::Single(taproot_descriptor.to_string());
    let rusty_scan_result = rusty_client
        .scan_tx_out_set_blocking(&[rusty_scan_request])
        .unwrap();
    let txp3_input_utxo = rusty_scan_result.unspents[0].clone();

    let txp3_version = Version::TWO;
    let txp3_locktime =
        LockTime::from_height(rusty_client.get_block_count().unwrap() as u32).unwrap();

    let txp3_input_previous_output = OutPoint {
        txid: txp3_input_utxo.txid,
        vout: txp3_input_utxo.vout,
    };
    let txp3_input_sequence = Sequence::ZERO;

    let txp3_input = TxIn {
        previous_output: txp3_input_previous_output,
        script_sig: ScriptBuf::default(),
        sequence: txp3_input_sequence,
        witness: Witness::default(),
    };

    let txp3_spend_output = TxOut {
        value: Amount::from_int_btc(5),
        script_pubkey: mining_address.script_pubkey(),
    };

    let txp3_change_output = TxOut {
        value: Amount::from_btc(52.9985).unwrap(),
        script_pubkey: rusty_taproot_address.script_pubkey(),
    };

    let mut txp3_unsigned = Transaction {
        version: txp3_version,
        lock_time: txp3_locktime,
        input: vec![txp3_input],
        output: vec![txp3_spend_output, txp3_change_output],
    };

    let mut txp3_sighasher = SighashCache::new(&mut txp3_unsigned);
    let txp3_sighash_type = TapSighashType::Default;
    let txp3_prevout = vec![TxOut {
        value: txp3_input_utxo.amount,
        script_pubkey: txp3_input_utxo.script_pub_key,
    }];
    let txp3_prevouts = Prevouts::All(&txp3_prevout);
    let txp3_leaf_hash = TapLeafHash::from_script(
        &policy_3_data.get_script().clone(),
        bitcoin::taproot::LeafVersion::TapScript,
    );
    let txp3_sighash = txp3_sighasher
        .taproot_script_spend_signature_hash(0, &txp3_prevouts, txp3_leaf_hash, txp3_sighash_type)
        .unwrap();

    let txp3_msg = Message::from_digest(txp3_sighash.to_byte_array());

    let txp3_party2_signature = secp.sign_schnorr(&txp3_msg, keyset2.get_keypair());
    let txp3_party2_signature = Signature {
        sig: txp3_party2_signature,
        hash_ty: txp3_sighash_type,
    };

    let txp3_policy3_merkle_branch = taproot_spend_info
        .script_map()
        .get(&(policy_3_data.get_script().clone(), LeafVersion::TapScript))
        .unwrap()
        .first()
        .unwrap()
        .clone();

    let txp3_control_block = ControlBlock {
        leaf_version: bitcoin::taproot::LeafVersion::TapScript,
        output_key_parity: taproot_spend_info.output_key_parity(),
        internal_key: taproot_spend_info.internal_key(),
        merkle_branch: txp3_policy3_merkle_branch,
    };

    let mut txp3_witness = Witness::new();
    txp3_witness.push(txp3_party2_signature.to_vec());
    txp3_witness.push(policy_3_data.get_script().as_bytes());
    txp3_witness.push(txp3_control_block.serialize());

    *txp3_sighasher.witness_mut(0).unwrap() = txp3_witness;

    let txp3 = txp3_sighasher.into_transaction();

    let _txp3_acceptance = rusty_client.test_mempool_accept(&[&*txp3]).unwrap();

    let _txp3_txid = send_and_mine(&txp3, &mining_client, &mining_address, 50);

    println!(
        "\nAfter txp3, Rusty has {} bitcoins.\n",
        get_balance(&taproot_descriptor, &rusty_client)
    );
    // DONE!!!

    // ----------------------------------------------------------------------------------------------------------
    // ----------------------------------------------------------------------------------------------------------
    // ----------------------------------------------------------------------------------------------------------
    // ----------------------------------------------------------------------------------------------------------
    // ----------------------------------------------------------------------------------------------------------




    unwind_regtest(vec![rusty_client, mining_client], TEMP_PATH);
    Ok(())
}
