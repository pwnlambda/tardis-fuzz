use crate::vmm::{aarch64, devices};
use kvm_bindings::*;
use log::debug;
use serde::Deserialize;
use std::fs;
use std::fs::File;
use std::io;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use vm_memory::{GuestAddress, GuestMemory, GuestMemoryRegion};
use vm_superio::{serial::NoEvents, Rtc, RtcState, Serial, SerialState};
use vm_superio_ser::{RtcStateSer, SerialStateSer};

impl super::VMFileState {
    pub fn read_from_file(snapshot_path: &PathBuf) -> Self {
        // Load the snapshot into memory
        let snapshot_enc = File::open(snapshot_path).unwrap();

        // Deserialize the snapshot
        let mut des = rmp_serde::Deserializer::new(snapshot_enc);
        super::VMFileState::deserialize(&mut des).unwrap()
    }

    pub fn write_to_file(&mut self, snapshot_path: &PathBuf) {
        // Write the encoded state to the file
        let encoded = rmp_serde::encode::to_vec(self).unwrap();
        fs::write(snapshot_path, encoded).unwrap();
    }
    
    pub fn write_u32(&mut self, phys_addr: u64, value: u32) {
        // Calculate the equivalent idx into self.memory
        let addr = phys_addr - aarch64::AARCH64_PHYS_MEM_START;
        let u32_bytes = u32::to_le_bytes(value);
        
    }
}

impl super::VM {
    /// Load a snapshot from scratch on an empty VM
    pub fn load_snapshot(&mut self, snapshot: &super::VMFileState) {
        // Get the backing memory for the VM mem
        let backing_mem = self
            .state
            .guest_mem
            .get_host_address(GuestAddress(aarch64::AARCH64_PHYS_MEM_START))
            .unwrap();

        // Copy the snapshotted memory to the VM
        unsafe {
            backing_mem.copy_from(snapshot.memory.as_ptr(), snapshot.memory.len());
        }

        // Set all the registers to the correct values
        let mut midpr = 0u64;
        for (reg, val) in snapshot.regs.clone() {
            if reg == aarch64::MPIDR_EL1 {
                midpr = aarch64::convert_to_kvm_mpidrs(val as u64);
            }

            let _ = self.vcpu_fd.set_one_reg(reg, val);
        }

        // Restore serial state
        let intr_evt = devices::serial::EventFdTrigger::new(libc::EFD_NONBLOCK).unwrap();
        let serial_des = SerialState::from(&snapshot.serial);
        let serial_state = Serial::from_state(
            &serial_des,
            intr_evt.try_clone().unwrap(),
            NoEvents,
            io::stdout(),
        )
        .unwrap();

        let serial = Arc::new(Mutex::new(devices::serial::StdioSerialWrapper(
            serial_state,
        )));
        self.serial = Some(serial);

        // Restore RTC state
        let rtc_des = RtcState::from(&snapshot.rtc);
        let rtc_state = Rtc::from_state(&rtc_des, vm_superio::rtc_pl031::NoEvents);
        let rtc = Arc::new(Mutex::new(devices::rtc::RtcWrapper(rtc_state)));
        self.rtc = Some(rtc);

        // Setup devices and track dirty memory
        self.map_memory(true);
        self.setup_serial();
        self.setup_rtc();
        self.setup_vgic();
        self.redirect_breakpoints();

        // Restore dist reg
        aarch64::set_vgic_dist_regs(&self.gic.clone().unwrap(), snapshot.dist_regs.as_slice());

        // Restore redist state
        aarch64::set_vgic_redist_regs(
            &self.gic.clone().unwrap(),
            snapshot.redist_regs.as_slice(),
            midpr,
        );

        // Restore ICC
        aarch64::set_vgic_icc_regs(&self.gic.clone().unwrap(), &snapshot.icc_regs, midpr);

        // Register the EventFD
        self.vm
            .register_irqfd(&intr_evt, aarch64::SERIAL_IRQ)
            .unwrap();

        // Save the original state to restore to
        self.state.original_state = Some(Box::new(snapshot.clone()));

        // Print the value of x4, which holds the pointer to the bash string
        // tardis-cli -b 0x403A74 -- bash -c "echo hi; testbp"

        // Continue the execution
        let currpc = self.vcpu_fd.get_one_reg(aarch64::PC).unwrap();
        debug!("pc: {currpc:x}");
        debug!("pc virt: {:x}", self.read_virt_u32((currpc
        ) as u64));
        self.vcpu_fd.set_one_reg(aarch64::PC, currpc + 4).unwrap();
    }

    /// Serialize the state of a virtual machine
    pub fn dump_state(&mut self) -> super::VMFileState {
        // Initialize the state that will be serialized
        let mut state_file = super::VMFileState::default();

        // Get all CPU registers we can save
        let mut regs = RegList::new(500).unwrap();
        self.vcpu_fd.get_reg_list(&mut regs).unwrap();

        // Save the MIDPR
        let mut midpr = 0u64;

        // Get a copy of all the registers
        regs.as_slice().iter().for_each(|reg| {
            let val = self.vcpu_fd.get_one_reg(*reg).unwrap();
            if *reg == aarch64::MPIDR_EL1 {
                midpr = aarch64::convert_to_kvm_mpidrs(val as u64);
            }
            state_file.regs.insert(*reg, val);
        });

        // Flush redistributors pending tables to guest RAM.
        let gicfd = self.gic.clone().unwrap();
        gicfd
            .set_device_attr(&kvm_device_attr {
                group: KVM_DEV_ARM_VGIC_GRP_CTRL,
                attr: KVM_DEV_ARM_VGIC_SAVE_PENDING_TABLES as u64,
                ..Default::default()
            })
            .unwrap();

        // Get vCPU GIC system registers. icc_regs
        state_file.icc_regs = aarch64::get_vgic_icc_regs(gicfd.as_ref(), midpr);

        // Save dist registers
        state_file.dist_regs = aarch64::get_vgic_dist_regs(gicfd.as_ref());

        // Get vCPU redistributor registers. redist_regs
        state_file.redist_regs = aarch64::get_vgic_redist_regs(gicfd.as_ref(), midpr);

        // Copy the memory to the state
        self.state.guest_mem.iter().for_each(|region| unsafe {
            state_file
                .memory
                .extend_from_slice(region.as_mut_slice().unwrap());
        });

        // Copy the state of the RTC
        state_file.rtc =
            RtcStateSer::from(&self.rtc.clone().unwrap().as_ref().lock().unwrap().0.state());

        // Copy the state of the serial console
        let serial_state = self.serial.clone().unwrap().lock().unwrap().0.state();
        state_file.serial = SerialStateSer::from(&serial_state);

        state_file
    }

    /// Restore VM to the snapshotted state after execution
    /// Note: The state of devices currently isn't rolled back
    /// but can easily be implemented in the same way as load_snapshot
    pub fn rollback(&mut self) {
        // Get the backing memory for the VM mem
        let backing_mem = self
            .state
            .guest_mem
            .get_host_address(GuestAddress(aarch64::AARCH64_PHYS_MEM_START))
            .unwrap();

        let state = self.state.original_state.as_ref().unwrap();
        let page_size = self.page_size;

        // Get the dirty pages for this vcpu
        // Note: This is inefficient for large bitmaps, however this loop was hand tweaked
        // in godbolt to take advantage of SIMD and ARM specific instriction for bit ops.
        let bitmap = self
            .vm
            .get_dirty_log(0, self.state.mem_size as usize)
            .unwrap();
        for (index, bp) in bitmap.iter().enumerate() {
            let mut bm = *bp;
            // If this bitmap has any dirty pages
            if bm != 0 {
                // Count the dirty bits using the cnt instruction
                while bm != 0 {
                    // Find the index of the first dirty bit using the rbit instruction
                    let idx = bm.trailing_zeros();

                    // Flip the bit
                    bm ^= 1 << idx;

                    // Compute the address of the page that needs to be restored
                    let page_idx = (index as u64 * 64) + idx as u64;

                    // Copy the original back into the current memory
                    // compiles into pointer arithmetics and a memmove
                    unsafe {
                        let curr_mem = backing_mem.offset(((page_idx) * page_size) as isize);
                        let og_mem = state
                            .memory
                            .as_ptr()
                            .offset((page_idx * page_size) as isize);
                        og_mem.copy_to(curr_mem, page_size as usize);
                    }
                }
            }
        }

        // Set all the registers to the correct values and ignore errors
        // +   49.71%     0.56%  tardis-fuzz  tardis-fuzz            [.] kvm_ioctls::ioctls::vcpu::VcpuFd::set_one_reg                                                                                                    ▒
        // Note: This eats up most of our CPU time while doing continous rollbacks. We can't set multiple registers
        // in one call since this is unsupported by KVM.
        for (reg, val) in state.regs.clone() {
            let _ = self.vcpu_fd.set_one_reg(reg, val);
        }
    }
}
