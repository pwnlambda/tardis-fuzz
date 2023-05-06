pub mod aarch64;
pub mod bits;
pub mod coverage;
pub mod devices;
pub mod fdt;
pub mod memory;
pub mod setup;
pub mod snapshot;

use event_manager::{EventManager, MutEventSubscriber};
use kvm_ioctls::{DeviceFd, VcpuFd, VmFd};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{Write};
use std::path::PathBuf;
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex};
use vm_allocator::AddressAllocator;
use vm_device::device_manager::IoManager;
use vm_memory::{GuestAddress, GuestMemoryMmap};
use vm_superio::serial::NoEvents;
use vm_superio_ser::{RtcStateSer, SerialStateSer};

/// VM related data that is only relevant for running this single instance
#[derive(Clone)]
pub struct VM {
    vm: Arc<VmFd>,
    state: VMState,
    device_mgr: Arc<Mutex<IoManager>>,
    event_mgr: Arc<Mutex<EventManager<Arc<Mutex<dyn MutEventSubscriber + Send>>>>>,
    vcpu_fd: Arc<VcpuFd>,
    fdt_builder: Option<Arc<Mutex<fdt::FDTBuilder>>>,
    state_path: Option<Arc<PathBuf>>,
    rtc: Option<Arc<Mutex<devices::rtc::RtcWrapper>>>,
    serial: Option<
        Arc<
            Mutex<
                devices::serial::StdioSerialWrapper<
                    devices::serial::EventFdTrigger,
                    NoEvents,
                    std::io::Stdout,
                >,
            >,
        >,
    >,
    gic: Option<Arc<DeviceFd>>,
    reset_cnt: Arc<AtomicUsize>,
    page_size: u64,
}

/// State of the Virtual Machine that implements Rust's Clone trait
#[derive(Clone)]
pub struct VMState {
    guest_mem: GuestMemoryMmap,
    addr_alloc: AddressAllocator,
    mem_size: u64,
    kern_load: Option<GuestAddress>,
    original_state: Option<Box<VMFileState>>,
}

/// State of a VM that gets restored from disk
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct VMFileState {
    // The output of get_one_reg
    regs: HashMap<u64, u128>,

    // Memory dump
    #[serde(with = "serde_bytes")]
    memory: Vec<u8>,

    // Device States
    serial: SerialStateSer,
    rtc: RtcStateSer,

    // VGIC3 State
    dist_regs: Vec<aarch64::GicRegState<u32>>,
    redist_regs: Vec<aarch64::GicRegState<u32>>,
    icc_regs: aarch64::GicSysRegsState,
}
