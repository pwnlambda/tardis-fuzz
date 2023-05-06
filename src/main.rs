use clap::{Args, Parser, Subcommand, ValueHint};
use log::debug;
use std::path::PathBuf;

mod fuzzer;
mod vmm;
extern crate vm_memory;

// Subcommand to run a fresh Linux VM
#[derive(Args, Debug)]
struct RunArgs {
    /// Path to the vmlinux kernel that will be executed
    #[arg(short, long, value_hint = ValueHint::FilePath)]
    kernel_path: PathBuf,

    /// Path to the output state
    #[arg(short, long, value_hint = ValueHint::FilePath)]
    state_path: PathBuf,

    /// Memory allocated to the VM in MB
    #[arg(short, long)]
    mem: u32,
}

// Subcommand to fuzz a previous snapshot
#[derive(Args, Debug)]
struct FuzzArgs {
    /// Path to the snapshot that will be executed
    #[arg(short, long, value_hint = ValueHint::FilePath)]
    snapshot_path: PathBuf,

    /// Path to the coverage file for the target
    #[arg(short, long, value_hint = ValueHint::FilePath)]
    cov_path: PathBuf,

    /// VCPUs available
    #[arg(short, long)]
    vcpus: u32,
    
    /// Path to the corpus
    #[arg(short, long, value_hint = ValueHint::FilePath)]
    corpus_path: PathBuf,
}

// Continue the execution a previous snapshot
#[derive(Args, Debug)]
struct ContinueArgs {
    /// Path to the snapshot that will be executed
    #[arg(short, long, value_hint = ValueHint::FilePath)]
    snapshot_path: PathBuf,

    /// Memory allocated to the VM in MB
    #[arg(short, long)]
    mem: u32,
}

// Generate coverage file for the selected target
#[derive(Args, Debug)]
struct GenCovArgs {
    /// Path to the binary for which the coverage will be generated
    #[arg(short, long, value_hint = ValueHint::FilePath)]
    binary_path: PathBuf,

    /// Path to the file which will be saved as output
    #[arg(short, long, value_hint = ValueHint::FilePath)]
    output_path: PathBuf,
}

// List of subcommands
#[derive(Subcommand)]
enum Commands {
    Run(RunArgs),
    Fuzz(FuzzArgs),
    Continue(ContinueArgs),
    GenCov(GenCovArgs),
}

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

fn main() {
    // Setup better logging
    env_logger::init();

    // Parse Cli arguments
    let cli = Cli::parse();

    match &cli.command {
        Commands::Run(RunArgs {
            kernel_path,
            state_path,
            mem,
        }) => {
            debug!(
                "Running VM with kernel {}",
                kernel_path.as_path().to_string_lossy()
            );
            let mut vm = vmm::VM::new(*mem);
            vm.boot(kernel_path, state_path);
            vm.run();
        }

        Commands::Fuzz(FuzzArgs {
            snapshot_path,
            cov_path,
            corpus_path,
            vcpus,
        }) => {
            fuzzer::fuzzer::fuzz_vm(snapshot_path, cov_path, corpus_path, *vcpus);
        }

        Commands::GenCov(GenCovArgs {
            binary_path,
            output_path,
        }) => {
            vmm::coverage::generate_cov_file(binary_path, output_path);
        }

        Commands::Continue(ContinueArgs { snapshot_path, mem }) => {
            debug!(
                "Continuing execution of snapshot {}",
                snapshot_path.as_path().to_string_lossy()
            );
            let mut vm = vmm::VM::new(*mem);
            let snapshot = vmm::VMFileState::read_from_file(snapshot_path);
            vm.load_snapshot(&snapshot);
            vm.run();
        }
    }
}
