use log::debug;
use r2pipe::R2Pipe;
use serde_json;
use std::fs;
use std::path::PathBuf;

/// Generate a coverage file for the passed binary and write it to output_path
pub fn generate_cov_file(binary_path: &PathBuf, output_path: &PathBuf) {
    // Open radare2 with the passed file
    let mut r2p = r2pipe::open_pipe!(binary_path.as_path().to_str()).unwrap();

    // Analyze the binary
    r2p.cmd("aaa").unwrap();

    // Get a list of all basic blocks
    let basic_blocks = r2p.cmdj("ablj").unwrap();
    let mut output_json: Vec<u64> = Vec::new();

    // Get the original instruction at the start of each basic block
    for block in basic_blocks["blocks"].as_array().unwrap() {
        // Convert hex integer to u64
        let addr_str = block["addr"].as_str().unwrap();
        let without_prefix = addr_str.trim_start_matches("0x");
        let addr = u64::from_str_radix(without_prefix, 16).unwrap();
        output_json.push(addr);
    }

    // Write to file
    let serialized = serde_json::to_string(&output_json).unwrap();
    fs::write(output_path, serialized).unwrap();
    debug!("Generated coverage file");
}
