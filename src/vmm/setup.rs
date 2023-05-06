extern crate core;
extern crate kvm_bindings;
extern crate kvm_ioctls;

use libc::siginfo_t;
use log::debug;
use std::ffi::c_void;
use std::io;
use std::os::raw::c_int;
use std::path::PathBuf;
use std::process;
use std::time::Duration;

use kvm_bindings::*;
use vmm_sys_util::signal::{register_signal_handler, SIGRTMIN};

use crate::vmm::{aarch64, devices, fdt};
use event_manager::{EventManager, SubscriberOps};
use kvm_ioctls::{Kvm, VcpuExit};
use linux_loader::loader::KernelLoader;
use std::fs::File;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use vm_allocator::{AddressAllocator, AllocPolicy, RangeInclusive};
use vm_device::bus::{MmioAddress, MmioRange};
use vm_device::device_manager::{IoManager, MmioManager};
use vm_memory::{GuestAddress, GuestMemory, GuestMemoryMmap, GuestMemoryRegion};
use vm_superio::{Rtc, Serial};
use vmm_sys_util::terminal::Terminal;

impl super::VM {
    /// Boot linux on a blank VM. If a breakpoint happens in userspace the VM's state will
    /// be saved to state_path
    pub fn boot(&mut self, vmlinux: &PathBuf, state_path: &PathBuf) {
        // Read the kernel image and load it into memory
        let mut kernel_image = File::open(vmlinux).unwrap();
        let load_res = linux_loader::loader::pe::PE::load(
            &self.state.guest_mem,
            Some(GuestAddress(aarch64::DEFAULT_KERNEL_LOAD_ADDR)),
            &mut kernel_image,
            None,
        )
        .unwrap();

        self.state_path = Some(Arc::new(state_path.into()));

        // Setup the default cmd line
        let mut fdt_builder = fdt::FDTBuilder::new();
        fdt_builder.cmdline.insert("reboot", "t").unwrap();
        fdt_builder.cmdline.insert("panic", "1").unwrap();
        fdt_builder.cmdline.insert("pci", "off").unwrap();
        fdt_builder.cmdline.insert("console", "ttyS0").unwrap();
        fdt_builder
            .cmdline
            .insert(
                "earlycon",
                &format!("uart,mmio,0x{:08x}", aarch64::AARCH64_MMIO_BASE),
            )
            .unwrap();

        // Save an instance to the fdt builder
        self.fdt_builder = Some(Arc::new(Mutex::new(fdt_builder)));
        self.state.kern_load = Some(load_res.kernel_load);

        // Setup RTC
        let rtc = Arc::new(Mutex::new(devices::rtc::RtcWrapper(Rtc::new())));
        self.rtc = Some(rtc);

        // Setup Serial
        let intr_evt = devices::serial::EventFdTrigger::new(libc::EFD_NONBLOCK).unwrap();
        let serial = Arc::new(Mutex::new(devices::serial::StdioSerialWrapper(
            Serial::new(intr_evt.try_clone().unwrap(), io::stdout()),
        )));
        self.serial = Some(serial);

        // Setup the devices
        self.map_memory(false);
        self.setup_registers();
        self.setup_vgic();
        self.setup_serial();
        self.setup_rtc();
        self.redirect_breakpoints();

        // Register the EventFD
        self.vm
            .register_irqfd(&intr_evt, aarch64::SERIAL_IRQ)
            .unwrap();

        // Create FDT and copy it into memory
        let mut serialized = self
            .fdt_builder
            .clone()
            .unwrap()
            .lock()
            .unwrap()
            .serialize(self.state.mem_size);
        let mut fdt_offset: u64 = self.state.guest_mem.iter().map(|region| region.len()).sum();
        fdt_offset = fdt_offset - aarch64::AARCH64_FDT_MAX_SIZE - 0x10000;
        let fdt_addr = GuestAddress(aarch64::AARCH64_PHYS_MEM_START + fdt_offset);
        let fdt_backing = self.state.guest_mem.get_host_address(fdt_addr).unwrap();
        unsafe {
            std::ptr::copy(serialized.as_mut_ptr(), fdt_backing, serialized.len());
        }

        // Get the kernel load addr
        let kernel_load = self.state.kern_load.unwrap();

        // Set PC
        self.vcpu_fd
            .set_one_reg(
                aarch64::AARCH64_CORE_REG_BASE + 2 * 32,
                (kernel_load.0) as u128,
            )
            .unwrap();

        // Set x0 to the device tree
        self.vcpu_fd
            .set_one_reg(aarch64::AARCH64_CORE_REG_BASE, (fdt_addr.0) as u128)
            .unwrap();
    }

    /// Create a blank virtual machine, which can either be used to load a Snapshot
    /// Or to boot a fresh Linux image.
    pub fn new(memory_mib: u32) -> super::VM {
        // Open /dev/kvm and create a VM
        let kvm = Arc::new(Kvm::new().unwrap());
        let vm = Arc::new(kvm.create_vm().unwrap());

        // mmap the memory for the guest
        let mem_size = ((memory_mib as u64) << 20) as usize;
        let regions = vec![(GuestAddress(aarch64::AARCH64_PHYS_MEM_START), mem_size)];
        let guest_mem = GuestMemoryMmap::from_ranges(&regions).unwrap();

        // Create an AddressAllocator for the VM
        let addr_alloc =
            AddressAllocator::new(aarch64::AARCH64_MMIO_BASE, mem_size as u64).unwrap();

        // Setup device and event managers
        let device_mgr = Arc::new(Mutex::new(IoManager::new()));
        let event_mgr = Arc::new(Mutex::new(EventManager::new().unwrap()));

        // Create VCpu
        let state = super::VMState {
            guest_mem,
            addr_alloc,
            mem_size: (mem_size as u64),
            kern_load: None,
            original_state: None,
        };
        let vcpu_fd = Arc::new(vm.create_vcpu(0).unwrap());

        // AArch64 specific registry setup.
        let mut kvi = kvm_bindings::kvm_vcpu_init::default();
        vm.get_preferred_target(&mut kvi).unwrap();
        kvi.features[0] |= 1 << KVM_ARM_VCPU_PSCI_0_2;
        vcpu_fd.vcpu_init(&kvi).unwrap();

        // Create RTC state
        super::VM {
            vm,
            state,
            device_mgr,
            event_mgr,
            vcpu_fd,
            fdt_builder: None,
            state_path: None,
            rtc: None,
            serial: None,
            gic: None,
            reset_cnt: Arc::new(AtomicUsize::new(0)),
            page_size: unsafe { libc::sysconf(libc::_SC_PAGE_SIZE) } as u64,
        }
    }

    /// Run the VM
    pub fn run(&mut self) {
        // Run vcpu a different thread
        self.vcpu_thread();
        //self.bench_thread();

        // Lock stdio since inputs will be intercepted by the console
        if std::io::stdin().lock().set_raw_mode().is_err() {
            debug!("Failed to set raw mode on terminal. Stdin will echo.");
        }
        debug!("Starting Events Handler");

        // Run a thread for event manager
        loop {
            match self.event_mgr.lock().unwrap().run() {
                Ok(_) => {}
                Err(e) => debug!("Failed to handle {:?}", e),
            };
        }
    }

    /// Run the event manager in a separate thread
    pub fn eventmgr_thread(&mut self) {
        let event_manager = self.event_mgr.clone();
        // Lock stdio since inputs will be intercepted by the console
        /*if std::io::stdin().lock().set_raw_mode().is_err() {
            debug!("Failed to set raw mode on terminal. Stdin will echo.");
        }*/

        thread::Builder::new()
            .spawn(move || loop {
                match event_manager.lock().unwrap().run() {
                    Ok(_) => {}
                    Err(e) => debug!("Failed to handle {:?}", e),
                }
            })
            .unwrap();
    }

    /// Run the VCPU and handle PIO/MMIO. Returns the `VcpuExit` in all other cases to be
    /// handled by the caller.
    pub fn vcpu_run_one(&mut self) -> VcpuExit {
        loop {
            let exit = self.vcpu_fd.run().expect("Error runnning CPU");
            match exit {
                VcpuExit::MmioRead(addr, data) => {
                    if self
                        .device_mgr
                        .lock()
                        .unwrap()
                        .mmio_read(MmioAddress(addr), data)
                        .is_err()
                    {
                        debug!("MmioRead error");
                    }
                }
                VcpuExit::MmioWrite(addr, data) => {
                    if self
                        .device_mgr
                        .lock()
                        .unwrap()
                        .mmio_write(MmioAddress(addr), data)
                        .is_err()
                    {
                        debug!("MmioWrite error");
                    }
                }
                _ => {return exit;}
            }
        }
    }

    fn setup_registers(&mut self) {
        // set up registers
        let data: u128 = (PSR_D_BIT | PSR_A_BIT | PSR_I_BIT | PSR_F_BIT | PSR_MODE_EL1h).into();
        self.vcpu_fd
            .set_one_reg(aarch64::PSTATE_REG_ID, data)
            .unwrap();
    }

    fn bench_thread(&mut self) {
        let state = self.clone();
        thread::Builder::new()
            .spawn(move || {
                use std::time::Instant;
                let mut now = Instant::now();

                loop {
                    thread::sleep(Duration::from_millis(1000));
                    let elapsed = now.elapsed();
                    now = Instant::now();
                    let execs =
                        state.reset_cnt.load(Ordering::Relaxed) as f64 / elapsed.as_secs_f64();
                    state.reset_cnt.store(0, Ordering::Relaxed);
                    debug!("Resets/s {execs}");
                }
            })
            .unwrap();
    }

    fn vcpu_thread(&mut self) {
        let mut state = self.clone();
        super::VM::setup_signal_handler();
        thread::Builder::new()
            .spawn(move || {
                super::VM::setup_signal_handler();

                loop {
                    match state.vcpu_fd.run().expect("Error running CPU") {
                        VcpuExit::Shutdown | VcpuExit::Hlt => {
                            debug!("Hlt");
                            break;
                        }
                        VcpuExit::IoOut(_addr, _data) => {
                            debug!("PIO Write");
                            //break;
                        }
                        VcpuExit::MmioRead(addr, data) => {
                            if state
                                .device_mgr
                                .lock()
                                .unwrap()
                                .mmio_read(MmioAddress(addr), data)
                                .is_err()
                            {
                                debug!("MmioRead error");
                            }
                        }
                        VcpuExit::MmioWrite(addr, data) => {
                            if state
                                .device_mgr
                                .lock()
                                .unwrap()
                                .mmio_write(MmioAddress(addr), data)
                                .is_err()
                            {
                                debug!("MmioWrite error");
                            }
                        }

                        // We hit a software breakpoint
                        VcpuExit::Debug(_exit_state) => {
                            //debug!("Hit breakpoint");

                            // Serialize the state of the VM and write it to the fs if we have a path for it
                            if state.state_path.is_some() {
                                debug!("Saving state");
                                let mut state_file = state.dump_state();
                                state_file
                                    .write_to_file(state.state_path.clone().unwrap().as_ref());
                                process::exit(0);
                            }

                            // If we have an original state roll back
                            if state.state.original_state.is_some() {
                                //debug!("Rolling back state");
                                state.reset_cnt.fetch_add(1, Ordering::Relaxed);
                                state.rollback();
                            }

                            // Continue the execution
                            let currpc = state.vcpu_fd.get_one_reg(aarch64::PC).unwrap();
                            //debug!("curr pc: {:x}", currpc);
                            state.vcpu_fd.set_one_reg(aarch64::PC, currpc + 4).unwrap();
                        }
                        _ => {
                            debug!("Exit");
                            process::exit(1);
                        }
                    }
                }
            })
            .unwrap();
    }

    pub fn get_reg(&mut self, reg_id: u64) -> u128 {
        self.vcpu_fd.get_one_reg(reg_id).unwrap()
    }
    
    pub fn set_reg(&mut self, reg_id: u64, value: u128) {
        self.vcpu_fd.set_one_reg(reg_id, value).unwrap()
    }

    pub fn setup_rtc(&mut self) {
        let rtc = self.rtc.clone();

        // Setup a timer
        let range = self
            .state
            .addr_alloc
            .allocate(
                0x1000,
                aarch64::DEFAULT_ADDRESSS_ALIGNEMNT,
                AllocPolicy::FirstMatch,
            )
            .unwrap();

        // Set the addrs to be used in the fdt
        if self.fdt_builder.is_some() {
            self.fdt_builder.clone().unwrap().lock().unwrap().rtc_addr = range.start();
            self.fdt_builder.clone().unwrap().lock().unwrap().rtc_len = range.len();
        }

        let range = super::VM::mmio_from_range(&range);
        // Handle MMIO for RTC
        self.device_mgr
            .lock()
            .unwrap()
            .register_mmio(range, rtc.unwrap())
            .unwrap();
    }

    pub fn setup_vgic(&mut self) {
        // Create vGIC
        let gicfd = self
            .vm
            .create_device(&mut kvm_create_device {
                type_: kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V3,
                fd: 0,
                flags: 0,
            })
            .unwrap();

        // Configure VGIC redist
        let redist_addr: u64 = aarch64::AARCH64_GIC_DIST_BASE - aarch64::AARCH64_GIC_REDIST_SIZE;
        let raw_redist_addr = &redist_addr as *const u64;
        gicfd
            .set_device_attr(&kvm_device_attr {
                group: KVM_DEV_ARM_VGIC_GRP_ADDR,
                attr: KVM_VGIC_V3_ADDR_TYPE_REDIST as u64,
                addr: raw_redist_addr as u64,
                flags: 0,
            })
            .unwrap();

        // Configure VGIC distr addr
        let dist_if_addr: u64 = aarch64::AARCH64_GIC_DIST_BASE;
        let raw_dist_if_addr = &dist_if_addr as *const u64;
        gicfd
            .set_device_attr(&kvm_device_attr {
                group: KVM_DEV_ARM_VGIC_GRP_ADDR,
                addr: raw_dist_if_addr as u64,
                attr: KVM_VGIC_V3_ADDR_TYPE_DIST as u64,
                flags: 0,
            })
            .unwrap();

        // Set min irqs
        const MIN_IRQ: u32 = 64;
        let nr_irqs_ptr = &MIN_IRQ as *const u32;
        gicfd
            .set_device_attr(&kvm_device_attr {
                group: KVM_DEV_ARM_VGIC_GRP_NR_IRQS,
                addr: nr_irqs_ptr as u64,
                ..Default::default()
            })
            .unwrap();

        // Initialize VGIC
        gicfd
            .set_device_attr(&kvm_device_attr {
                group: KVM_DEV_ARM_VGIC_GRP_CTRL,
                attr: KVM_DEV_ARM_VGIC_CTRL_INIT as u64,
                ..Default::default()
            })
            .unwrap();
        self.gic = Some(Arc::new(gicfd));

        debug!("Created vGIC");
    }

    pub fn redirect_breakpoints(&mut self) {
        // Route breakpoints to KVM
        let enable_dbg = kvm_guest_debug {
            control: KVM_GUESTDBG_ENABLE,
            pad: 0,
            arch: Default::default(),
        };
        self.vcpu_fd.set_guest_debug(&enable_dbg).unwrap();
    }

    pub(crate) fn setup_signal_handler() {
        extern "C" fn handle_signal(_: c_int, _: *mut siginfo_t, _: *mut c_void) {
            debug!("Got signal");
        }
        register_signal_handler(SIGRTMIN() + 0, handle_signal).unwrap();
    }

    pub fn setup_serial(&mut self) {
        // Allocate Serial MMIO rang∂e
        let range = self
            .state
            .addr_alloc
            .allocate(
                0x1000,
                aarch64::DEFAULT_ADDRESSS_ALIGNEMNT,
                AllocPolicy::ExactMatch(aarch64::AARCH64_MMIO_BASE),
            )
            .unwrap();

        // If we need to create an FDT save the ranges
        if self.fdt_builder.is_some() {
            self.fdt_builder
                .clone()
                .unwrap()
                .lock()
                .unwrap()
                .serial_start = range.start();
            self.fdt_builder.clone().unwrap().lock().unwrap().serial_len = range.len();
        }

        let range = super::VM::mmio_from_range(&range);

        // Register the serial device with the device manager
        self.device_mgr
            .lock()
            .unwrap()
            .register_mmio(range, self.serial.clone().unwrap())
            .unwrap();

        // Register with the event manager
        self.event_mgr
            .lock()
            .unwrap()
            .add_subscriber(self.serial.clone().unwrap());
    }

    pub fn map_memory(&mut self, track_dirty: bool) {
        // Map every GuestMemoryRegion into KVM
        for (index, region) in self.state.guest_mem.iter().enumerate() {
            let memory_region = kvm_bindings::kvm_userspace_memory_region {
                slot: index as u32,
                guest_phys_addr: region.start_addr().0,
                memory_size: region.len(),
                userspace_addr: self
                    .state
                    .guest_mem
                    .get_host_address(region.start_addr())
                    .ok()
                    .unwrap() as u64,
                flags: if track_dirty {
                    KVM_MEM_LOG_DIRTY_PAGES
                } else {
                    0
                },
            };

            debug!(
                "Mapped 0x{:08x}-0x{:08x} @ 0x{:08x}",
                region.start_addr().0,
                region.last_addr().0,
                self.state
                    .guest_mem
                    .get_host_address(region.start_addr())
                    .ok()
                    .unwrap() as u64
            );

            unsafe {
                self.vm.set_user_memory_region(memory_region).unwrap();
            }
        }
    }

    fn mmio_from_range(range: &RangeInclusive) -> MmioRange {
        // The following unwrap is safe because the address allocator makes
        // sure that the address is available and correct
        MmioRange::new(MmioAddress(range.start()), range.len()).unwrap()
    }
}
