# Rust Bitcoin Tutorials

A few bitcoin tutorials about subjects a bit hard to gather from scattered sources.

To run:

 1- Change the following constants in pertinent bins e.g. taproot_tx/main.rs:

    // -->> SET THESE FIRST! <<--

    const BITCOIND_PATH: &str = "Your path to bitcoind here. Include the file in the path.";

    const BITCOIN_CONF_PATH: &str = "Your path to bitcoin.conf here. Include the file in the path.";

    const TEMP_PATH: &str = "Your path to a temp folder here.";

 2- To run the Segwit P2WPKH tutorial, enter the following command in repo's root directory via the terminal:
 ```
 cargo run --bin p2wpkh_tx
 ```
 3- To ran the Taproot tutorial, enter the following command in repo's root directory via the terminal:
 ```
 cargo run --bin taproot_tx
 ```

 Happy Rusting plebs.
