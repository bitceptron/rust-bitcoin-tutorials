// Heavily based on https://github.com/rust-bitcoin/rust-bitcoin/blob/master/bitcoin/examples/sign-tx-segwit-v0.rs

use bitcoin::{
    absolute::LockTime,
    bip32::{ChildNumber, DerivationPath, Xpriv, Xpub},
    key::Secp256k1,
    secp256k1::Message,
    sighash::SighashCache,
    transaction::Version,
    Address, Amount, EcdsaSighashType, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn,
    TxOut, Witness,
};
use bitcoincore_rpc::{
    json::{AddressType, ScanTxOutRequest},
    RawTx, RpcApi,
};
use miniscript::Descriptor;
use rand::Rng;
use rust_bitcoin_tutorials::regtest_utils::{
    spawn_regtest::{spawn_regtest, RegtestConf},
    unwind_regtest::unwind_regtest,
};

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

    // Creating a bip39 seed phrase for our rusty person.
    let rusty_entropy = rng.gen::<[u8; 32]>();
    let rusty_seed = bip39::Mnemonic::from_entropy(&rusty_entropy).unwrap();
    println!("\nRusty has her seed phrase:\n{}", rusty_seed);

    // Creating a pair of keys for our rusty person from a specific child
    // of the seed and extacting out the secretkey and publickey for that child.
    let rusty_master_xpriv = Xpriv::new_master(NETWORK, &rusty_seed.to_entropy()).unwrap();
    let rusty_bip84_derivation_children = vec![
        ChildNumber::from_hardened_idx(84).unwrap(),
        ChildNumber::from_hardened_idx(0).unwrap(),
        ChildNumber::from_hardened_idx(0).unwrap(),
    ];
    let rusty_bip84_derivation_path = DerivationPath::from(rusty_bip84_derivation_children);
    let rusty_bip84_xpriv = rusty_master_xpriv
        .derive_priv(&secp, &rusty_bip84_derivation_path)
        .unwrap();
    let rusty_bip84_xpub = Xpub::from_priv(&secp, &rusty_bip84_xpriv);
    let rusty_bip84_secretkey = rusty_bip84_xpriv.private_key;
    let _rusty_bip84_pubkey = rusty_bip84_secretkey.public_key(&secp);
    println!(
        "\nNow rusty creates a master xpriv:\nxpriv = {} at {}",
        rusty_master_xpriv, rusty_bip84_derivation_path
    );
    println!(
        "\nHer xpub at {} is:\n{}",
        rusty_bip84_derivation_path, rusty_bip84_xpub
    );

    // Creating a P2WPKH descriptor for our rusty person from its public key and deriving an address from it.
    // First Rusty needs to add the [0/0] path for her first receiving address.
    let rusty_first_receive_children = vec![
        ChildNumber::from_normal_idx(0).unwrap(),
        ChildNumber::from_normal_idx(0).unwrap(),
    ];
    let rusty_first_receive_path = DerivationPath::from(rusty_first_receive_children);
    let rusty_first_receive_secretkey = rusty_bip84_xpriv
        .derive_priv(&secp, &rusty_first_receive_path)
        .unwrap()
        .private_key;
    let rusty_first_receive_xpub = rusty_bip84_xpub
        .derive_pub(&secp, &rusty_first_receive_path)
        .unwrap();
    let rusty_first_receive_pubkey = rusty_first_receive_xpub.public_key;
    // Rusty creates a P2WPKH segwit address.
    let rusty_first_receive_address =
        Address::p2wpkh(&rusty_first_receive_pubkey.into(), NETWORK).unwrap();
    // But for Rusty to easily scan her address, she needs a descriptor here.
    let rusty_first_receive_descriptor =
        miniscript::Descriptor::new_wpkh(rusty_first_receive_pubkey).unwrap();

    println!(
        "\nRusty creates an address from the the pubkr derived from the path 84'/0'/0'/0/0:\n{}",
        rusty_first_receive_address
    );
    println!(
        "\nThe descriptor for that address is:\n{}",
        rusty_first_receive_descriptor
    );

    // Sending 42 bitcoins from our mining node to our rusty person. Making her rich!
    let charging_rusty_txid = mining_client
        .send_to_address(
            &rusty_first_receive_address,
            Amount::from_int_btc(42),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
    println!(
        "\nOur benevolant mining node, sends 42 bitcoins to rusty through this txid:\n{}",
        charging_rusty_txid
    );

    // We gonna mine the transaction.
    let _ = mining_client.generate_to_address(50, &mining_address);

    // Let's see if our rusty person has received her funds.
    let utxo_set_scan_request = ScanTxOutRequest::Extended {
        desc: rusty_first_receive_descriptor.to_string(),
        range: (0, 100),
    };
    let utxo_set_scan_result = rusty_client
        .scan_tx_out_set_blocking(&[utxo_set_scan_request])
        .unwrap();
    let rusty_balance = utxo_set_scan_result.total_amount;
    println!("\nRusty sends an rpc request to a bitcoincore node to scan the UTXO set for any utxo related to hes descriptor.");
    println!(
        "Lo and behold! Rusty has {} bitcoins.",
        rusty_balance.to_btc(),
    );

    // Now we want to create a transaction from our rusty person back to our mining node.
    println!(
        "\nNow let's return the favor by sending back 5 bitcoins to our generous miner friend."
    );

    // Let's first create a mining_node_receiving_address. And let's make it a taproot one.
    let mining_node_receiving_address = mining_client
        .get_new_address(Some("receiving address"), Some(AddressType::Bech32m))
        .unwrap()
        .require_network(NETWORK)
        .unwrap();
    println!(
        "\nRusty asks our miner friend for a receiving address and she provides her with one:\n{}",
        mining_node_receiving_address
    );

    // Let's create the spending transaction by rusty.
    // First we need to figure out what UTXOs we have the possesion of.
    // Hence we need to scan the UTXO set to see what we have (we did it before to get Rusty's balance).
    let rusty_scan_request = ScanTxOutRequest::Extended {
        desc: rusty_first_receive_descriptor.to_string(),
        range: (0, 100),
    };
    let rusty_scan_result = rusty_client
        .scan_tx_out_set_blocking(&[rusty_scan_request])
        .unwrap();
    let rusty_utxos = rusty_scan_result.unspents;
    println!("\nRusty scans the UTXO set for UTXOs controlled by her descriptor, hence her xpriv. She gets this:\n{:#?}", rusty_utxos);
    // To create a transaction with rust bitcoin, we need:
    // 1- A transaction version.
    // 2- A Locktime.
    // 3- A vector of inputs.
    // 4- A vector of outputs.
    // These indeed reflect the structure of a raw bitcoin transaction's top level format.

    // We chhose version 2 to comply with BIP68 which is about enabling relative locktime by a different interpretation of the nSequence.
    let rusty_tx_version = Version::TWO;

    // We set the locktime to the current block to prevent fee sniping as does bitcoincore.
    let current_block_height = rusty_client.get_block_count().unwrap();
    let rusty_tx_locktime = LockTime::from_height(current_block_height as u32).unwrap();

    // Now let's work on inputs. Rust bitcoin has the TxIn struct to define each of the inputs to the transaction.
    // TxIn needs an outpoint, an unlocking script, a sequence number and the witness data.

    // For the outpoint which is as https://developer.bitcoin.org/reference/transactions.html says,
    // "a specific part of a specific output", we need the txid of the transaction we are spending from,
    // and the vout of the output. Together, these specify a UTXO. So, we can use out scan results
    // to gather this information. Note that rusty has only one UTXO under her control. She may have
    // plenty as time goes by. In that case her wallet software must handle UTXO selection and she may
    // have multiple inputs to hes transaction.
    let rusty_utxo_txid = rusty_utxos[0].txid;
    let rusty_utxo_vout = rusty_utxos[0].vout;
    let rusty_utxo_outpoint = OutPoint {
        txid: rusty_utxo_txid,
        vout: rusty_utxo_vout,
    };

    // The next item required for our input is script_sig. But we are spending a SegWit output. Remember? Rusty's address was a P2WPKH type.
    // So this field should be empty. Rust bitcoin has a ScriptBuf::default() which we can use.
    let rusty_utxo_script_sig = ScriptBuf::default();

    // Now we have to indicate the sequence for our input. As a refresher, look at this excerpt from
    // https://github.com/BlockchainCommons/Learning-Bitcoin-from-the-Command-Line/blob/master/11_3_Using_CSV_in_Scripts.md:
    // ℹ️ NOTE — SEQUENCE: This is the third use of the nSequence value in Bitcoin. Any nSequence value without the 32nd bit //
    // set (1<<31), so 0x00000001 to 0x7ffffffff, will be interpreted as a relative timelock if nVersion ≥ 2 (which is the //
    // default starting in Bitcoin Core 0.14.0). You should be careful to ensure that relative timelocks don't conflict with //
    // the other two uses of nSequence, for signalling nTimeLock and RBF. nTimeLock usually sets a value of 0xffffffff-1, //
    // where a relative timelock is disallowed; and RBF usually sets a value of "1", where a relative timelock is irrelevent, //
    // because it defines a timelock of 1 block. //
    // In general, remember: with a nVersion value of 2, a nSequence value of 0x00000001 to 0x7fffffff allows relative timelock, //
    // RBF, and nTimeLock; a nSequence value of 0x7fffffff to 0xffffffff-2 allows RBF and nTimeLock; a nSequence value of //
    // 0xffffffff-1 allows only nTimeLock; a nSequence value of 0xffffffff allows none; and nVersion can be set to 1 to //
    // disallow relative timelocks for any value of nSequence. Whew! //
    // We had previously enabled LockTime and don't want a relative timelock. So we use something between 0x7fffffff to 0xffffffff-2.
    let rusty_utxo_sequence = Sequence::ENABLE_RBF_NO_LOCKTIME;

    // Next we need to fill the witness. But wait! Isn't the witness essentially a signature on our transaction?
    // The very same transaction we are building right now. So we don't have it yet and we must leave it empty
    // by using the Witness::default() from rust bitcoin.
    let rusty_utxo_witness = Witness::default();

    // Now we can finally create our TxIn!
    let rusty_tx_txin = TxIn {
        previous_output: rusty_utxo_outpoint,
        script_sig: rusty_utxo_script_sig,
        sequence: rusty_utxo_sequence,
        witness: rusty_utxo_witness,
    };

    // Now we come to the outputs part of our transaction. It's where you indicate where your inputs are bein sent.
    // This is where if we want some change back, we have to add a change address. We have a 42 bitcoin utxo. We want
    // to send 5 back to the miner. Hence we need a change of about 37. The "about" part is due to fees.
    // So, let's first create a change address for rusty.
    let rusty_first_change_children = vec![
        ChildNumber::from_normal_idx(1).unwrap(),
        ChildNumber::from_normal_idx(0).unwrap(),
    ];
    let rusty_first_change_path = DerivationPath::from(rusty_first_change_children);
    let rusty_first_change_xpub = rusty_bip84_xpub
        .derive_pub(&secp, &rusty_first_change_path)
        .unwrap();
    let rusty_first_change_pubkey = rusty_first_change_xpub.public_key;
    let rusty_first_change_address =
        Address::p2wpkh(&rusty_first_change_pubkey.into(), NETWORK).unwrap();
    let rusty_first_change_descriptor = Descriptor::new_wpkh(rusty_first_change_pubkey).unwrap();

    // Now that we have the change address, we can continue with creating our transaction outputs.
    // The output needs value and a script_pubky. The script_pubky is the locking script which is
    // derivable from the address our generous miner provided Rusty with.
    let rusty_tx_out_send = TxOut {
        value: Amount::from_int_btc(5),
        script_pubkey: mining_node_receiving_address.script_pubkey(),
    };

    // Then it's time for our change output. Mind the fees!
    let rusty_tx_out_change = TxOut {
        value: Amount::from_btc(36.99995).unwrap(),
        script_pubkey: rusty_first_change_address.script_pubkey(),
    };

    // Finally! We can put them all together to create our unsigned transaction! It's mutable since we are going to
    // complete it momentarily.
    let mut rusty_unsigned_tx = Transaction {
        version: rusty_tx_version,
        lock_time: rusty_tx_locktime,
        input: vec![rusty_tx_txin],
        output: vec![rusty_tx_out_send, rusty_tx_out_change],
    };

    println!("\nNow Rusty, after going through quite an ordeal, has an unsigned transaction to send 5 bitcoins to the miner friend:\n{:#?}", rusty_unsigned_tx);

    // And now comes the mysterious SIGHASH!
    // We must setup a SighashCache to sign the transaction. Since it is a simple sign all transaction,
    // we use SIGHASH_ALL. So, no fancy stuff yet.
    let mut sighasher = SighashCache::new(&mut rusty_unsigned_tx);
    // The sighasher needs the following:
    // 1- Input index.
    // 2- ScriptPubkey of the input at the above mentioned index.
    // 3- Value of the input.
    // 4- type of the SIGHASH.
    let sighash_input_index = 0;
    let sighash_script_pubkey = rusty_utxos[0].clone().script_pub_key;
    let sighash_value = rusty_utxos[0].amount;
    let sighash_type = EcdsaSighashType::All;
    // Now we put these into the hasher.
    let sighash = sighasher
        .p2wpkh_signature_hash(
            sighash_input_index,
            &sighash_script_pubkey,
            sighash_value,
            sighash_type,
        )
        .unwrap();
    // Now we have to serialize it as a message to sign.
    let tx_as_msg = Message::from(sighash);
    // Let's see how thw message look like.
    println!("Unsigned tx as a message:\n{}", tx_as_msg);
    // You see? It's a sha256 digest. Now let's go ahead and signn it.
    // Now let's sign it with our corresponding secret key.
    let tx_signature = secp.sign_ecdsa(&tx_as_msg, &rusty_first_receive_secretkey);
    // Then we should update the witness field of our unsigned_tx
    let signature = bitcoin::ecdsa::Signature {
        sig: tx_signature,
        hash_ty: sighash_type,
    };
    *sighasher.witness_mut(sighash_input_index).unwrap() =
        Witness::p2wpkh(&signature, &rusty_first_receive_pubkey);

    // Now we can turn the sighasher into a completed transaction!
    let rusty_tx = sighasher.into_transaction();

    println!("\nSigned transaction is:\n{:#?}", rusty_tx);

    let rusty_raw_tx = rusty_tx.raw_hex();

    // Let's check if mempool accepts this transaction
    let mempool_test_result = rusty_client
        .test_mempool_accept(&[rusty_raw_tx.clone()])
        .unwrap();
    println!(
        "Mempool acceptance test result:\n{:#?}",
        mempool_test_result[0]
    );
    // Now let's send the tx and mine it!
    let rusty_tx_txid = rusty_client
        .send_raw_transaction(rusty_raw_tx.clone())
        .unwrap();
    println!("\nTransaction is sent. It's txid is:\n{}", rusty_tx_txid);
    let _ = mining_client
        .generate_to_address(10, &mining_address)
        .unwrap();
    let _ = rusty_client.send_raw_transaction(rusty_raw_tx.clone()); // repeating the send since we only have two nodes.
    let _ = mining_client
        .generate_to_address(10, &mining_address)
        .unwrap();
    let _ = rusty_client.send_raw_transaction(rusty_raw_tx); // repeating the send since we only have two nodes.

    // Now let's mine some blocks.
    let _ = mining_client
        .generate_to_address(120, &mining_address)
        .unwrap();

    // Let's check Rusty's balance
    let rusty_scan_request_recieve =
        ScanTxOutRequest::Single(rusty_first_receive_descriptor.to_string());
    let rusty_scan_request_change =
        ScanTxOutRequest::Single(rusty_first_change_descriptor.to_string());
    let rusty_scan_results = rusty_client
        .scan_tx_out_set_blocking(&[rusty_scan_request_recieve, rusty_scan_request_change])
        .unwrap();
    let rusty_new_balance = rusty_scan_results.total_amount;
    println!("\nRusty now has {} bitcoins.", rusty_new_balance.to_sat());
    println!(
        "Miner now has {} bitcoins.",
        mining_client.get_balance(Some(0), None).unwrap().to_sat()
    );
    println!("\nNote:\nRegtest block reward halves every 150 blocks. So don't freak out like me about that 0.5 block reward hanging in there.\n");

    unwind_regtest(vec![rusty_client, mining_client], TEMP_PATH);
}
