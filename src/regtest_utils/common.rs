use std::collections::HashSet;

use bitcoin::{Address, Amount, Transaction, Txid};
use bitcoincore_rpc::{json::ScanTxOutRequest, Client, RpcApi};
use miniscript::Descriptor;
use regex::Regex;

use super::{error::RegtestUtilsError, spawn_regtest::RegtestConf};

pub fn check_ports_vec(ports: Vec<String>) -> Result<(), RegtestUtilsError> {
    let re = Regex::new(r"[0-9]+").unwrap();
    if ports.is_empty() || ports.iter().any(|port| !re.is_match(port)) {
        Err(RegtestUtilsError::InvalidPort)
    } else {
        Ok(())
    }
}

pub fn check_confs_uniqueness(confs: &Vec<RegtestConf>) -> bool {
    let confs_len = confs.len();
    let mut unique_ports = HashSet::new();
    confs.iter().for_each(|conf| {
        unique_ports.insert(conf.get_port());
    });
    if unique_ports.len() != confs_len {
        return false;
    }
    let mut unique_rpc_ports = HashSet::new();
    confs.iter().for_each(|conf| {
        unique_rpc_ports.insert(conf.get_port());
    });
    if unique_rpc_ports.len() != confs_len {
        return false;
    }
    true
}

pub fn send_and_mine(
    tx: &Transaction,
    mining_client: &Client,
    mining_address: &Address,
    blocks_to_mine: u64,
) -> Result<Txid, RegtestUtilsError> {
    let txid = mining_client.send_raw_transaction(tx)?;
    mining_client.generate_to_address(blocks_to_mine, &mining_address)?;
    Ok(txid)
}

pub fn get_balance(descriptor: &Descriptor<bitcoin::XOnlyPublicKey>, checking_client: &Client) -> Amount {
    let scan_request = ScanTxOutRequest::Single(descriptor.to_string());
    let scan_result = checking_client
        .scan_tx_out_set_blocking(&[scan_request])
        .unwrap();
    scan_result.total_amount
}
