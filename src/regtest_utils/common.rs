use std::collections::HashSet;

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
