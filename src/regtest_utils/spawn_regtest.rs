use std::{
    fs,
    io::BufRead,
    process::{Command, Stdio},
    thread::sleep,
    time::Duration,
};

use bitcoincore_rpc::{Auth, Client, RpcApi};

use super::{common::{check_confs_uniqueness, check_ports_vec}, error::RegtestUtilsError};

pub fn spawn_regtest(
    bitcoind_path: &str,
    bitcoin_conf_path: &str,
    temp_path: &str,
    regtest_confs: Vec<RegtestConf>,
    respite_period_milisecs: u64,
    connection_respite_factor: u64,
) -> Result<Vec<Client>, RegtestUtilsError> {
    // See if all RegtestCons are unique in regtest_confs.
    if !check_confs_uniqueness(&regtest_confs) {
        return Err(RegtestUtilsError::RepetitiveRegtestPortOrRpcportConfs);
    };

    // Kill bitcoind processes on designated ports.
    let all_ports = regtest_confs
        .iter()
        .flat_map(|conf| vec![conf.get_port(), conf.get_rpc_port()])
        .collect::<Vec<String>>();
    kill_regtest_ports(all_ports)?;

    // Clear possible past data in temp.
    if fs::read_dir(temp_path).is_ok() {
        clear_regtest_data(vec![temp_path.to_string().clone()]);
    }

    // Spawn regtest instances.
    for conf in regtest_confs.clone() {
        let temp_path = temp_path;
        let regtest_data_path = format!("{}/{}", temp_path, conf.id_tag());

        let bitcoin_conf_path = bitcoin_conf_path;
        let _ = fs::create_dir_all(regtest_data_path.clone());

        let bitcoind_path = bitcoind_path;

        Command::new(bitcoind_path.to_owned())
            .args([
                "-regtest",
                "-daemon",
                format!("-port={}", conf.get_port()).as_str(),
                format!("-rpcport={}", conf.get_rpc_port()).as_str(),
                format!("-datadir={}", regtest_data_path).as_str(),
                "-rpcuser=test",
                "-rpcpassword=test",
                format!("-conf={}", bitcoin_conf_path).as_str(),
            ])
            .stdout(Stdio::piped())
            .spawn()
            .expect("Couldn't run bitcoind.")
            .wait_with_output()
            .unwrap();
    }

    sleep(Duration::from_millis(respite_period_milisecs));

    // Create bitcoincore_rpc Clients.
    let mut clients = vec![];
    for conf in regtest_confs.clone() {
        let rpc_client = Client::new(
            &format!("http://127.0.0.1:{}", conf.get_rpc_port()),
            Auth::UserPass("test".to_string(), "test".to_string()),
        )?;
        clients.push(rpc_client);
    }

    // Connect clients to each other.
    let ports = regtest_confs
        .iter()
        .map(|conf| conf.get_port())
        .collect::<Vec<String>>();

    for client in clients.iter() {
        for port in ports.iter() {
            client
                .add_node(format!("127.0.0.1:{}", port).as_str())
                .unwrap();
            sleep(Duration::from_millis(respite_period_milisecs));
        }
    }

    sleep(Duration::from_millis(
        respite_period_milisecs * connection_respite_factor,
    ));

    for client in clients.iter() {
        client
            .create_wallet("test", None, None, None, None)
            .unwrap();
    }

    // Return clients.
    Ok(clients)
}

fn clear_regtest_data(paths: Vec<String>) {
    paths.iter().for_each(|path| {
        let _ = fs::remove_dir_all(path);
    });
}

fn kill_regtest_ports(ports: Vec<String>) -> Result<(), RegtestUtilsError> {
    check_ports_vec(ports.clone())?;
    let pid_of_ports_in_use: Vec<String> = Command::new("lsof")
        .args([
            "-i",
            format!(":{}", ports.join(",")).as_str(),
            "-a",
            "-c",
            "bitcoind",
            "-t",
        ])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap()
        .wait_with_output()
        .unwrap()
        .stdout
        .lines()
        .map(|line| line.unwrap())
        .collect();
    if !pid_of_ports_in_use.is_empty() {
        for pid in pid_of_ports_in_use {
            let _ = Command::new("kill")
                .args(["-9", format!("{}", pid.as_str()).as_str()])
                .spawn()
                .unwrap()
                .wait();
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct RegtestConf {
    port: String,
    rpc_port: String,
}

impl RegtestConf {
    pub fn new(port: u64, rpc_port: u64) -> Result<Self, RegtestUtilsError> {
        check_ports_vec(vec![port.to_string()])?;
        check_ports_vec(vec![rpc_port.to_string()])?;
        Ok(RegtestConf {
            port: port.to_string(),
            rpc_port: rpc_port.to_string(),
        })
    }

    pub fn get_port(&self) -> String {
        self.port.clone()
    }

    pub fn get_rpc_port(&self) -> String {
        self.rpc_port.clone()
    }

    pub fn id_tag(&self) -> String {
        format!("port{}_rpcport{}", self.port, self.rpc_port)
    }
}
