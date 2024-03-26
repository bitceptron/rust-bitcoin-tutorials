use std::fs;

use bitcoincore_rpc::{Client, RpcApi};

pub fn unwind_regtest(clients: Vec<Client>, temp_path: &str) {
    for client in clients {
        client.stop().unwrap();
    }
    let _ = fs::remove_dir_all(temp_path);
}
