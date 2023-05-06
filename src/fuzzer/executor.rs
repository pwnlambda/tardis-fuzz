use crate::vmm::aarch64;
use crate::vmm::VM;
use core::fmt::{Debug, Formatter};
use core::marker::PhantomData;
use kvm_ioctls::VcpuExit;
use libafl::{
    bolts::{AsMutSlice, AsSlice},
    executors::{Executor, ExitKind, HasObservers},
    inputs::{HasTargetBytes, UsesInput},
    observers::{ObserversTuple, StdMapObserver, UsesObservers},
    state::UsesState,
    Error,
};
use std::collections::{BTreeMap, BTreeSet};

/// Function that writes the input inside the VM
pub type TardisInput = dyn FnMut(&mut VM, &[u8]);

/// LibAFL compatible Executor for Tardis
pub struct TardisExecutor<'a, OT, S> {
    /// Function to prepare the vm state before execution
    harness_fn: &'a mut TardisInput,

    /// Execution observers
    observers: OT,

    /// Set of addresses for which we track coverage
    coverage: BTreeSet<u64>,

    /// Original instruction before coverage was applies
    orig_instr: BTreeMap<u64, u32>,

    /// Vm used for the execution
    exec_vm: &'a mut VM,

    /// Address where the fuzzing test case ends
    end_addr: u64,

    phantom: PhantomData<S>,
}

impl<'a, OT, S> TardisExecutor<'a, OT, S> {
    pub fn new(vm: &'a mut VM, observers: OT, end_addr: u64, harness: &'a mut TardisInput) -> Self {
        // Start a event manager thread for this structure
        vm.eventmgr_thread();

        TardisExecutor {
            harness_fn: harness,
            observers,
            coverage: Default::default(),
            orig_instr: Default::default(),
            exec_vm: vm,
            end_addr,
            phantom: PhantomData::<S>,
        }
    }

    /// Adds coverage for all the addresses passed in `basic_blocks`
    pub fn add_coverage(&mut self, addr: u64) {
        // First get the original instruction
        let orig_inst = self.exec_vm.read_virt_u32(addr);

        // Insert it into the executor's state
        self.orig_instr.insert(addr, orig_inst);
        self.coverage.insert(addr);

        // Replace the original instruction with a BRK #0;
        self.exec_vm.write_virt_u32(addr, aarch64::BRK0);
        
        // Also replace it in the snapshot, that way when we restore pages
        // the breakpoints will also be restored
    }
}

impl<'a, EM, OT, S, Z> Executor<EM, Z> for TardisExecutor<'a, OT, S>
where
    EM: UsesState<State = S>,
    OT: ObserversTuple<S>,
    S: UsesInput,
    S::Input: HasTargetBytes,
    Z: UsesState<State = S>,
{
    fn run_target(
        &mut self,
        _fuzzer: &mut Z,
        _state: &mut Self::State,
        _mgr: &mut EM,
        input: &Self::Input,
    ) -> Result<ExitKind, Error> {
        // Load the coverage map
        let map_observer = self
            .observers
            .match_name_mut::<StdMapObserver<u8, false>>("coverage")
            .expect("TardisExecutor expects a StdMapObserver<u8> named 'coverage'");

        // Write the input into the VM's memory
        (self.harness_fn)(self.exec_vm, input.target_bytes().as_slice());
        
        // Write a bkpt at the end addr
        self.exec_vm.write_virt_u32(self.end_addr, aarch64::BRK0);
        
        // Get the original TTBR
        let new_ttbr = self.exec_vm.get_reg(aarch64::TTBR0_EL1);
        
        //debug!("Starting vCPU end addr {:x}", self.end_addr);
        
        // Execute our VM
        let exit_reason = loop {
            let vmexit = self.exec_vm.vcpu_run_one();

            match vmexit {
                VcpuExit::Debug(_debug) => {
                    let pc = self.exec_vm.get_reg(aarch64::PC) as u64;
                    let ttbr = self.exec_vm.get_reg(aarch64::TTBR0_EL1);
                    
                    // If TTBR changed then we are in a different process, exit this run
                    if ttbr != new_ttbr {
                        break ExitKind::Ok;
                    }
                    
                    // Handle coverage
                    if self.coverage.contains(&pc) {
                        // Restore the original instruction in snapshot and current memory
                        let orig_inst = self.orig_instr.get(&pc).unwrap();
                        self.exec_vm.write_virt_u32(pc, *orig_inst);

                        // Remove breakpoint from coverage
                        self.coverage.remove(&pc);
                        self.orig_instr.remove(&pc);

                        // Add the coverage to the map
                        let map = map_observer.map_mut().as_mut_slice();
                        map[(pc as usize) % map.len()] += 1;
                        
                        // Do not increment PC in this case
                        continue;
                    }

                    // Exit if we finished executing the current test case
                    if pc == self.end_addr {
                        break ExitKind::Ok;
                    }
                    
                    // Increment PC to skip over BP
                    self.exec_vm.set_reg(aarch64::PC, (pc+4) as u128);
                }
                _ => {}
            }
        };

        // Rollback state before returning
        //debug!("Rollback");
        self.exec_vm.rollback();
        Ok(exit_reason)
    }
}

impl<'a, OT, S> UsesState for TardisExecutor<'a, OT, S>
where
    OT: ObserversTuple<S>,
    S: UsesInput,
{
    type State = S;
}

impl<'a, OT, S> UsesObservers for TardisExecutor<'a, OT, S>
where
    OT: ObserversTuple<S>,
    S: UsesInput,
{
    type Observers = OT;
}

impl<'a, OT, S> HasObservers for TardisExecutor<'a, OT, S>
where
    OT: ObserversTuple<S>,
    S: UsesInput,
{
    #[inline]
    fn observers(&self) -> &OT {
        &self.observers
    }

    #[inline]
    fn observers_mut(&mut self) -> &mut OT {
        &mut self.observers
    }
}

impl<'a, OT, S> Debug for TardisExecutor<'a, OT, S> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TardisExecutor").finish()
    }
}
