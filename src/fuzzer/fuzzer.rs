use crate::fuzzer::executor::TardisExecutor;
use crate::vmm::{VMFileState, VM};
use std::path::PathBuf;
use std::fs;
use serde_json::Value;
use libafl::monitors::tui::{TuiMonitor};

use libafl::monitors::SimpleMonitor;
use libafl::{
    bolts::{
        tuples::tuple_list,
        core_affinity::Cores,
        current_nanos,
        rands::StdRand,
        launcher::Launcher,
        shmem::{ShMemProvider, StdShMemProvider},
    },
    Error,
    events::{EventConfig},
    observers::StdMapObserver,
    feedbacks::{CrashFeedback, MaxMapFeedback},
    state::StdState,
    inputs::{BytesInput, HasTargetBytes},
    fuzzer::{Fuzzer, StdFuzzer},
    stages::mutational::StdMutationalStage,
    mutators::scheduled::{havoc_mutations, StdScheduledMutator},
    schedulers::QueueScheduler,
    corpus::InMemoryCorpus,
};

/// Coverage byte size
const COVERAGE_SIZE: usize = 1 << 15;
static mut COVERAGE: [u8; COVERAGE_SIZE] = [0; COVERAGE_SIZE];

pub fn fuzz_vm(state_path: &PathBuf, cov_path: &PathBuf, corpus_path: &PathBuf, vcpus: u32) {
    // First start by parsing the coverage file
    let cov_json = fs::read(cov_path).unwrap();
    let covp: Value = serde_json::from_slice(cov_json.as_slice()).unwrap();
    let cov = covp.as_array().unwrap();
    
    // Create shm provider
    let shmem_provider = StdShMemProvider::new().expect("Failed to init shared memory");
    let snapshot = VMFileState::read_from_file(state_path);
    //let mon = SimpleMonitor::new(|s| println!("{s}"));
    
    // Tuple to start a VM
    let mut run_client = |state: Option<_>, mut restarting_mgr, _core_id| {
        // TODO: Stop hardcoding this and add timeout
        let mut vm = VM::new(128);
        vm.load_snapshot(&snapshot);
        vm.eventmgr_thread();

        // Create a coverage map
        let observer = unsafe { StdMapObserver::new("coverage", &mut COVERAGE) };
        let mut feedback = MaxMapFeedback::new(&observer);

        // Harness that loads the input into the snapshot
        let mut harness = |vm: &mut VM, input: &[u8]| {};

        // Feedback to choose if an input is a solution or not
        let mut objective = CrashFeedback::new();

        // The fuzzer's state, create a State from scratch if restarting
        let mut state = state.unwrap_or_else(|| {StdState::new(
            // First argument is the randomness
            StdRand::with_seed(current_nanos()),
            // Second argument is the corpus
            InMemoryCorpus::<BytesInput>::new(),
            // Third argument is the solutions corpus (here crashes)
            InMemoryCorpus::<BytesInput>::new(),
            // Fourth argument is the feedback states, used to evaluate the input
             &mut feedback,
             &mut objective
        ).unwrap()
        });

        // A queue policy to get testcasess from the corpus
        let scheduler = QueueScheduler::new();

        // A fuzzer with feedbacks and a corpus scheduler
        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

        // A tardis executor 400130 0x45a568
        let mut executor = TardisExecutor::new(&mut vm, tuple_list!(observer), 0x400130, &mut harness);

        // Insert coverage breakpoints into it
        for b in cov {
            executor.add_coverage(b.as_u64().unwrap());
        }
        // If the corput is empty then load
        if state.must_load_initial_inputs() {
            state.load_initial_inputs(&mut fuzzer, &mut executor, &mut restarting_mgr, &[corpus_path.into()]).unwrap();
        }

        // Setup a basic mutator with a mutational stage
        let mutator = StdScheduledMutator::new(havoc_mutations());
        let mut stages = tuple_list!(StdMutationalStage::new(mutator));

        fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut restarting_mgr).unwrap();
        Ok(())
    };
    // The Monitor trait define how the fuzzer stats are displayed to the user
    let mon = TuiMonitor::new("Tardis".to_string(), false);
    
    match Launcher::builder()
        .shmem_provider(shmem_provider)
        .configuration(EventConfig::from_name("default"))
        .broker_port(31337)
        .stdout_file(Some("/dev/null"))
        .monitor(mon)
        .run_client(&mut run_client)
        .cores(&Cores::from_cmdline("all").unwrap())
        .build()
        .launch()
    {
        Ok(()) => (),
        Err(Error::ShuttingDown) => println!("Fuzzing stopped by user. Good bye."),
        Err(err) => panic!("Failed to run launcher: {err:?}"),
    }
    
    
    println!("Done");
}
