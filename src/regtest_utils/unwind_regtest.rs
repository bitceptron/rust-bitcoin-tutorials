use std::{fs, thread::sleep, time::Duration};

use bitcoincore_rpc::{Client, RpcApi};

pub fn unwind_regtest(clients: Vec<Client>, temp_path: &str) {
    for client in clients {
        client.stop().unwrap();
    }
    sleep(Duration::from_millis(500));
    let _ = fs::remove_dir_all(temp_path);
    sleep(Duration::from_millis(500));
}
