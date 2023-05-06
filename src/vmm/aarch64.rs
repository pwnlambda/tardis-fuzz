#![allow(dead_code)]
// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
use kvm_bindings::*;
use kvm_ioctls::DeviceFd;
use serde::{Deserialize, Serialize};
use std::iter::StepBy;
use std::ops::Range;
use vm_memory::ByteValued;

#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
// See kernel doc Documentation/arm64/booting.txt for more information.
// All these fields should be little endian.
pub struct arm64_image_header {
    code0: u32,
    code1: u32,
    text_offset: u64,
    image_size: u64,
    flags: u64,
    res2: u64,
    res3: u64,
    res4: u64,
    magic: u32,
    res5: u32,
}

// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for arm64_image_header {}

/// Default kernel command line.
pub const DEFAULT_KERNEL_CMDLINE: &str = "reboot=t panic=1 pci=off";
/// Default address allocator alignment. It needs to be a power of 2.
pub const DEFAULT_ADDRESSS_ALIGNEMNT: u64 = 4;
pub const SERIAL_IRQ: u32 = 4;

pub const AARCH64_FDT_MAX_SIZE: u64 = 0x200000;

// This indicates the start of DRAM inside the physical address space.
pub const AARCH64_PHYS_MEM_START: u64 = 0x80000000;

// This is the base address of MMIO devices.
pub const AARCH64_MMIO_BASE: u64 = 1 << 30;

pub const PSTATE_REG_ID: u64 = 0x6030_0000_0010_0042;
pub const AARCH64_AXI_BASE: u64 = 0x40000000;

// These constants indicate the address space used by the ARM vGIC.
pub const AARCH64_GIC_DIST_SIZE: u64 = 0x10000;
pub const AARCH64_GIC_CPUI_SIZE: u64 = 0x20000;

// These constants indicate the placement of the GIC registers in the physical
// address space.
pub const AARCH64_GIC_DIST_BASE: u64 = AARCH64_AXI_BASE - AARCH64_GIC_DIST_SIZE;
pub const AARCH64_GIC_CPUI_BASE: u64 = AARCH64_GIC_DIST_BASE - AARCH64_GIC_CPUI_SIZE;
pub const AARCH64_GIC_REDIST_SIZE: u64 = 0x20000;
pub const AARCH64_CORE_REG_BASE: u64 = 0x6030_0000_0010_0000;
// These are specified by the Linux GIC bindings
pub const GIC_FDT_IRQ_NUM_CELLS: u32 = 3;
pub const GIC_FDT_IRQ_TYPE_SPI: u32 = 0;
pub const GIC_FDT_IRQ_TYPE_PPI: u32 = 1;
pub const GIC_FDT_IRQ_PPI_CPU_SHIFT: u32 = 8;
pub const GIC_FDT_IRQ_PPI_CPU_MASK: u32 = 0xff << GIC_FDT_IRQ_PPI_CPU_SHIFT;
pub const IRQ_TYPE_EDGE_RISING: u32 = 0x00000001;
pub const IRQ_TYPE_LEVEL_HIGH: u32 = 0x00000004;
pub const IRQ_TYPE_LEVEL_LOW: u32 = 0x00000008;

// PMU PPI interrupt, same as qemu
pub const AARCH64_PMU_IRQ: u32 = 7;
pub const PHANDLE_GIC: u32 = 1;

// BRK 0;
pub const BRK0: u32 = 0xd4200000;

pub const PC: u64 = AARCH64_CORE_REG_BASE + 2 * 32;

/// Default address for loading the kernel.
pub const DEFAULT_KERNEL_LOAD_ADDR: u64 = AARCH64_PHYS_MEM_START;

// Compute the ID of a specific ARM64 system register similar to how
// the kernel C macro does.
// https://elixir.bootlin.com/linux/v4.20.17/source/arch/arm64/include/uapi/asm/kvm.h#L203
const fn arm64_sys_reg(op0: u64, op1: u64, crn: u64, crm: u64, op2: u64) -> u64 {
    KVM_REG_ARM64
        | KVM_REG_SIZE_U64
        | KVM_REG_ARM64_SYSREG as u64
        | ((op0 << KVM_REG_ARM64_SYSREG_OP0_SHIFT) & KVM_REG_ARM64_SYSREG_OP0_MASK as u64)
        | ((op1 << KVM_REG_ARM64_SYSREG_OP1_SHIFT) & KVM_REG_ARM64_SYSREG_OP1_MASK as u64)
        | ((crn << KVM_REG_ARM64_SYSREG_CRN_SHIFT) & KVM_REG_ARM64_SYSREG_CRN_MASK as u64)
        | ((crm << KVM_REG_ARM64_SYSREG_CRM_SHIFT) & KVM_REG_ARM64_SYSREG_CRM_MASK as u64)
        | ((op2 << KVM_REG_ARM64_SYSREG_OP2_SHIFT) & KVM_REG_ARM64_SYSREG_OP2_MASK as u64)
}

// The MPIDR_EL1 and TTBR?_EL1 register ID is defined in the kernel:
// https://elixir.bootlin.com/linux/v4.20.17/source/arch/arm64/include/asm/sysreg.h#L135
pub const MPIDR_EL1: u64 = arm64_sys_reg(3, 0, 0, 0, 5);
pub const TTBR0_EL1: u64 = arm64_sys_reg(3, 0, 2, 0, 0);
pub const TTBR1_EL1: u64 = arm64_sys_reg(3, 0, 2, 0, 1);
pub const TCR_EL1: u64 = arm64_sys_reg(3, 0, 2, 0, 2);
pub const ID_AA64MMFR0_EL1: u64 = arm64_sys_reg(3, 0, 0, 7, 0);

/// Structure representing a simple register.
#[derive(PartialEq, Eq)]
pub struct SimpleReg {
    /// The offset from the component address. The register is memory mapped here.
    offset: u64,
    /// Size in bytes.
    size: u16,
}

impl SimpleReg {
    const fn new(offset: u64, size: u16) -> Self {
        Self { offset, size }
    }

    const fn gic_sys_reg(op0: u64, op1: u64, crn: u64, crm: u64, op2: u64) -> SimpleReg {
        let offset = (((op0 as u64) << KVM_REG_ARM64_SYSREG_OP0_SHIFT)
            & KVM_REG_ARM64_SYSREG_OP0_MASK as u64)
            | (((op1 as u64) << KVM_REG_ARM64_SYSREG_OP1_SHIFT)
                & KVM_REG_ARM64_SYSREG_OP1_MASK as u64)
            | (((crn as u64) << KVM_REG_ARM64_SYSREG_CRN_SHIFT)
                & KVM_REG_ARM64_SYSREG_CRN_MASK as u64)
            | (((crm as u64) << KVM_REG_ARM64_SYSREG_CRM_SHIFT)
                & KVM_REG_ARM64_SYSREG_CRM_MASK as u64)
            | (((op2 as u64) << KVM_REG_ARM64_SYSREG_OP2_SHIFT)
                & KVM_REG_ARM64_SYSREG_OP2_MASK as u64);

        SimpleReg { offset, size: 8 }
    }

    const fn sys_icc_ap0rn_el1(n: u64) -> SimpleReg {
        Self::gic_sys_reg(3, 0, 12, 8, 4 | n)
    }

    const fn sys_icc_ap1rn_el1(n: u64) -> SimpleReg {
        Self::gic_sys_reg(3, 0, 12, 9, n)
    }
}
/// Generic GIC register state,
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GicRegState<T> {
    pub(crate) chunks: Vec<T>,
}

/// Structure for serializing the state of the GIC ICC regs
#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct GicSysRegsState {
    main_icc_regs: Vec<GicRegState<u64>>,
    ap_icc_regs: Vec<Option<GicRegState<u64>>>,
}

pub fn convert_to_kvm_mpidrs(mpidr: u64) -> u64 {
    let cpu_affid = ((mpidr & 0xFF_0000_0000) >> 8) | (mpidr & 0xFF_FFFF);
    cpu_affid << 32
}

const SYS_ICC_SRE_EL1: SimpleReg = SimpleReg::gic_sys_reg(3, 0, 12, 12, 5);
const SYS_ICC_CTLR_EL1: SimpleReg = SimpleReg::gic_sys_reg(3, 0, 12, 12, 4);
const SYS_ICC_IGRPEN0_EL1: SimpleReg = SimpleReg::gic_sys_reg(3, 0, 12, 12, 6);
const SYS_ICC_IGRPEN1_EL1: SimpleReg = SimpleReg::gic_sys_reg(3, 0, 12, 12, 7);
const SYS_ICC_PMR_EL1: SimpleReg = SimpleReg::gic_sys_reg(3, 0, 4, 6, 0);
const SYS_ICC_BPR0_EL1: SimpleReg = SimpleReg::gic_sys_reg(3, 0, 12, 8, 3);
const SYS_ICC_BPR1_EL1: SimpleReg = SimpleReg::gic_sys_reg(3, 0, 12, 12, 3);
const ICC_CTLR_EL1_PRIBITS_SHIFT: u64 = 8;
const ICC_CTLR_EL1_PRIBITS_MASK: u64 = 7 << ICC_CTLR_EL1_PRIBITS_SHIFT;

pub static MAIN_GIC_ICC_REGS: &[SimpleReg] = &[
    SYS_ICC_SRE_EL1,
    SYS_ICC_CTLR_EL1,
    SYS_ICC_IGRPEN0_EL1,
    SYS_ICC_IGRPEN1_EL1,
    SYS_ICC_PMR_EL1,
    SYS_ICC_BPR0_EL1,
    SYS_ICC_BPR1_EL1,
];

const SYS_ICC_AP0R0_EL1: SimpleReg = SimpleReg::sys_icc_ap0rn_el1(0);
const SYS_ICC_AP0R1_EL1: SimpleReg = SimpleReg::sys_icc_ap0rn_el1(1);
const SYS_ICC_AP0R2_EL1: SimpleReg = SimpleReg::sys_icc_ap0rn_el1(2);
const SYS_ICC_AP0R3_EL1: SimpleReg = SimpleReg::sys_icc_ap0rn_el1(3);
const SYS_ICC_AP1R0_EL1: SimpleReg = SimpleReg::sys_icc_ap1rn_el1(0);
const SYS_ICC_AP1R1_EL1: SimpleReg = SimpleReg::sys_icc_ap1rn_el1(1);
const SYS_ICC_AP1R2_EL1: SimpleReg = SimpleReg::sys_icc_ap1rn_el1(2);
const SYS_ICC_AP1R3_EL1: SimpleReg = SimpleReg::sys_icc_ap1rn_el1(3);

pub static AP_GIC_ICC_REGS: &[SimpleReg] = &[
    SYS_ICC_AP0R0_EL1,
    SYS_ICC_AP0R1_EL1,
    SYS_ICC_AP0R2_EL1,
    SYS_ICC_AP0R3_EL1,
    SYS_ICC_AP1R0_EL1,
    SYS_ICC_AP1R1_EL1,
    SYS_ICC_AP1R2_EL1,
    SYS_ICC_AP1R3_EL1,
];

// Relevant PPI redistributor registers that we want to save/restore.
const GICR_CTLR: SimpleReg = SimpleReg::new(0x0000, 4);
const GICR_STATUSR: SimpleReg = SimpleReg::new(0x0010, 4);
const GICR_WAKER: SimpleReg = SimpleReg::new(0x0014, 4);
const GICR_PROPBASER: SimpleReg = SimpleReg::new(0x0070, 8);
const GICR_PENDBASER: SimpleReg = SimpleReg::new(0x0078, 8);

// Relevant SGI redistributor registers that we want to save/restore.
const GICR_SGI_OFFSET: u64 = 0x0001_0000;
const GICR_IGROUPR0: SimpleReg = SimpleReg::new(GICR_SGI_OFFSET + 0x0080, 4);
const GICR_ISENABLER0: SimpleReg = SimpleReg::new(GICR_SGI_OFFSET + 0x0100, 4);
const GICR_ICENABLER0: SimpleReg = SimpleReg::new(GICR_SGI_OFFSET + 0x0180, 4);
const GICR_ISPENDR0: SimpleReg = SimpleReg::new(GICR_SGI_OFFSET + 0x0200, 4);
const GICR_ICPENDR0: SimpleReg = SimpleReg::new(GICR_SGI_OFFSET + 0x0280, 4);
const GICR_ISACTIVER0: SimpleReg = SimpleReg::new(GICR_SGI_OFFSET + 0x0300, 4);
const GICR_ICACTIVER0: SimpleReg = SimpleReg::new(GICR_SGI_OFFSET + 0x0380, 4);
const GICR_IPRIORITYR0: SimpleReg = SimpleReg::new(GICR_SGI_OFFSET + 0x0400, 32);
const GICR_ICFGR0: SimpleReg = SimpleReg::new(GICR_SGI_OFFSET + 0x0C00, 8);
const IRQ_BASE: u32 = 32;
const IRQ_MAX: u32 = 128;

// List with relevant redistributor registers and SGI associated redistributor
// registers that we will be restoring.
pub static VGIC_RDIST_AND_SGI_REGS: &[SimpleReg] = &[
    GICR_CTLR,
    GICR_STATUSR,
    GICR_WAKER,
    GICR_PROPBASER,
    GICR_PENDBASER,
    GICR_IGROUPR0,
    GICR_ICENABLER0,
    GICR_ISENABLER0,
    GICR_ICFGR0,
    GICR_ICPENDR0,
    GICR_ISPENDR0,
    GICR_ICACTIVER0,
    GICR_ISACTIVER0,
    GICR_IPRIORITYR0,
];

struct SharedIrqReg {
    /// The offset from the component address. The register is memory mapped here.
    offset: u64,
    /// Number of bits per interrupt.
    bits_per_irq: u8,
}

enum DistReg {
    Simple(SimpleReg),
    SharedIrq(SharedIrqReg),
}

impl DistReg {
    const fn simple(offset: u64, size: u16) -> DistReg {
        DistReg::Simple(SimpleReg { offset, size })
    }

    const fn shared_irq(offset: u64, bits_per_irq: u8) -> DistReg {
        DistReg::SharedIrq(SharedIrqReg {
            offset,
            bits_per_irq,
        })
    }
}

impl MmioReg for DistReg {
    fn range(&self) -> Range<u64> {
        match self {
            DistReg::Simple(reg) => reg.range(),
            DistReg::SharedIrq(reg) => reg.range(),
        }
    }
}
// Distributor registers as detailed at page 456 from
// https://developer.arm.com/documentation/ihi0069/c/.
// Address offsets are relative to the Distributor base
// address defined by the system memory map.
const GICD_CTLR: DistReg = DistReg::simple(0x0, 4);
const GICD_STATUSR: DistReg = DistReg::simple(0x0010, 4);
const GICD_IGROUPR: DistReg = DistReg::shared_irq(0x0080, 1);
const GICD_ISENABLER: DistReg = DistReg::shared_irq(0x0100, 1);
const GICD_ICENABLER: DistReg = DistReg::shared_irq(0x0180, 1);
const GICD_ISPENDR: DistReg = DistReg::shared_irq(0x0200, 1);
const GICD_ICPENDR: DistReg = DistReg::shared_irq(0x0280, 1);
const GICD_ISACTIVER: DistReg = DistReg::shared_irq(0x0300, 1);
const GICD_ICACTIVER: DistReg = DistReg::shared_irq(0x0380, 1);
const GICD_IPRIORITYR: DistReg = DistReg::shared_irq(0x0400, 8);
const GICD_ICFGR: DistReg = DistReg::shared_irq(0x0C00, 2);
const GICD_IROUTER: DistReg = DistReg::shared_irq(0x6000, 64);

static VGIC_DIST_REGS: &[DistReg] = &[
    GICD_CTLR,
    GICD_STATUSR,
    GICD_ICENABLER,
    GICD_ISENABLER,
    GICD_IGROUPR,
    GICD_IROUTER,
    GICD_ICFGR,
    GICD_ICPENDR,
    GICD_ISPENDR,
    GICD_ICACTIVER,
    GICD_ISACTIVER,
    GICD_IPRIORITYR,
];

// Helper trait for working with the different types of the GIC registers
// in a unified manner.
pub trait MmioReg {
    fn range(&self) -> Range<u64>;

    fn iter<T>(&self) -> StepBy<Range<u64>>
    where
        Self: Sized,
    {
        self.range().step_by(std::mem::size_of::<T>())
    }
}

impl MmioReg for SimpleReg {
    fn range(&self) -> Range<u64> {
        // It's technically possible for this addition to overflow.
        // However, SimpleReg is only used to define register descriptors
        // with constant offsets and sizes, so any overflow would be detected
        // during testing.
        self.offset..self.offset + u64::from(self.size)
    }
}

impl MmioReg for SharedIrqReg {
    fn range(&self) -> Range<u64> {
        // The ARM® TrustZone® implements a protection logic which contains a
        // read-as-zero/write-ignore (RAZ/WI) policy.
        // The first part of a shared-irq register, the one corresponding to the
        // SGI and PPI IRQs (0-32) is RAZ/WI, so we skip it.
        //
        // It's technically possible for this operation to overflow.
        // However, SharedIrqReg is only used to define register descriptors
        // with constant offsets and bits_per_irq, so any overflow would be detected
        // during testing.
        let start = self.offset + u64::from(IRQ_BASE) * u64::from(self.bits_per_irq) / 8;

        let size_in_bits = u64::from(self.bits_per_irq) * u64::from(IRQ_MAX - IRQ_BASE);
        let mut size_in_bytes = size_in_bits / 8;
        if size_in_bits % 8 > 0 {
            size_in_bytes += 1;
        }

        start..start + size_in_bytes
    }
}

/// Get distributor registers.
pub fn get_vgic_dist_regs(fd: &DeviceFd) -> Vec<GicRegState<u32>> {
    get_regs_data(
        fd,
        VGIC_DIST_REGS.iter(),
        KVM_DEV_ARM_VGIC_GRP_DIST_REGS,
        0,
        0,
    )
}

/// Set distributor registers.
pub fn set_vgic_dist_regs(fd: &DeviceFd, dist: &[GicRegState<u32>]) {
    set_regs_data(
        fd,
        VGIC_DIST_REGS.iter(),
        KVM_DEV_ARM_VGIC_GRP_DIST_REGS,
        dist,
        0,
        0,
    )
}

pub fn get_vgic_redist_regs(fd: &DeviceFd, mpidr: u64) -> Vec<GicRegState<u32>> {
    get_regs_data(
        fd,
        VGIC_RDIST_AND_SGI_REGS.iter(),
        KVM_DEV_ARM_VGIC_GRP_REDIST_REGS,
        mpidr,
        KVM_DEV_ARM_VGIC_V3_MPIDR_MASK as u64,
    )
}

/// Set vCPU redistributor registers.
pub fn set_vgic_redist_regs(fd: &DeviceFd, redist: &[GicRegState<u32>], mpidr: u64) {
    set_regs_data(
        fd,
        VGIC_RDIST_AND_SGI_REGS.iter(),
        KVM_DEV_ARM_VGIC_GRP_REDIST_REGS,
        redist,
        mpidr,
        KVM_DEV_ARM_VGIC_V3_MPIDR_MASK as u64,
    );
}

pub fn get_vgic_icc_regs(fd: &DeviceFd, mpidr: u64) -> GicSysRegsState {
    let main_icc_regs = get_regs_data(
        fd,
        MAIN_GIC_ICC_REGS.iter(),
        KVM_DEV_ARM_VGIC_GRP_CPU_SYSREGS,
        mpidr,
        KVM_DEV_ARM_VGIC_V3_MPIDR_MASK as u64,
    );

    let mut ap_icc_regs = Vec::with_capacity(AP_GIC_ICC_REGS.len());
    let num_priority_bits = num_priority_bits(fd, mpidr);
    for reg in AP_GIC_ICC_REGS {
        if is_ap_reg_available(reg, num_priority_bits) {
            ap_icc_regs.push(Some(get_reg_data(
                fd,
                reg,
                KVM_DEV_ARM_VGIC_GRP_CPU_SYSREGS,
                mpidr,
                KVM_DEV_ARM_VGIC_V3_MPIDR_MASK as u64,
            )));
        } else {
            ap_icc_regs.push(None);
        }
    }

    GicSysRegsState {
        main_icc_regs,
        ap_icc_regs,
    }
}

/// Set vCPU GIC system registers.
pub fn set_vgic_icc_regs(fd: &DeviceFd, state: &GicSysRegsState, mpidr: u64) {
    set_regs_data(
        fd,
        MAIN_GIC_ICC_REGS.iter(),
        KVM_DEV_ARM_VGIC_GRP_CPU_SYSREGS,
        &state.main_icc_regs,
        mpidr,
        KVM_DEV_ARM_VGIC_V3_MPIDR_MASK as u64,
    );

    let num_priority_bits = num_priority_bits(fd, mpidr);

    for (reg, maybe_reg_data) in AP_GIC_ICC_REGS.iter().zip(&state.ap_icc_regs) {
        if is_ap_reg_available(reg, num_priority_bits) != maybe_reg_data.is_some() {
            return;
        }

        if let Some(reg_data) = maybe_reg_data {
            set_reg_data(
                fd,
                reg,
                KVM_DEV_ARM_VGIC_GRP_CPU_SYSREGS,
                reg_data,
                mpidr,
                KVM_DEV_ARM_VGIC_V3_MPIDR_MASK as u64,
            );
        }
    }
}

pub fn get_regs_data<'a, Reg, RegChunk>(
    fd: &DeviceFd,
    regs: impl Iterator<Item = &'a Reg>,
    group: u32,
    mpidr: u64,
    mpidr_mask: u64,
) -> Vec<GicRegState<RegChunk>>
where
    Reg: MmioReg + 'a,
    RegChunk: Default,
{
    let mut data = Vec::new();
    for reg in regs {
        data.push(get_reg_data(fd, reg, group, mpidr, mpidr_mask));
    }

    data
}

fn get_reg_data<Reg, RegChunk>(
    fd: &DeviceFd,
    reg: &Reg,
    group: u32,
    mpidr: u64,
    mpidr_mask: u64,
) -> GicRegState<RegChunk>
where
    Reg: MmioReg,
    RegChunk: Default,
{
    let mut data = Vec::with_capacity(reg.iter::<RegChunk>().count());
    for offset in reg.iter::<RegChunk>() {
        let mut val = RegChunk::default();
        fd.get_device_attr(&mut kvm_device_attr(
            group, offset, &mut val, mpidr, mpidr_mask,
        ))
        .unwrap();
        data.push(val);
    }

    GicRegState { chunks: data }
}

fn set_regs_data<'a, Reg, RegChunk>(
    fd: &DeviceFd,
    regs: impl Iterator<Item = &'a Reg>,
    group: u32,
    data: &[GicRegState<RegChunk>],
    mpidr: u64,
    mpidr_mask: u64,
) where
    Reg: MmioReg + 'a,
    RegChunk: Clone,
{
    for (reg, reg_data) in regs.zip(data) {
        set_reg_data(fd, reg, group, reg_data, mpidr, mpidr_mask);
    }
}

fn set_reg_data<Reg, RegChunk>(
    fd: &DeviceFd,
    reg: &Reg,
    group: u32,
    data: &GicRegState<RegChunk>,
    mpidr: u64,
    mpidr_mask: u64,
) where
    Reg: MmioReg,
    RegChunk: Clone,
{
    for (offset, val) in reg.iter::<RegChunk>().zip(&data.chunks) {
        let mut tmp = (*val).clone();
        fd.set_device_attr(&kvm_device_attr(group, offset, &mut tmp, mpidr, mpidr_mask))
            .unwrap();
    }
}

fn kvm_device_attr<RegChunk>(
    group: u32,
    offset: u64,
    val: &mut RegChunk,
    mpidr: u64,
    mpidr_mask: u64,
) -> kvm_device_attr {
    kvm_device_attr {
        group,
        attr: (mpidr & mpidr_mask) | offset,
        addr: val as *mut RegChunk as u64,
        flags: 0,
    }
}

fn is_ap_reg_available(reg: &SimpleReg, num_priority_bits: u64) -> bool {
    // As per ARMv8 documentation:
    // https://developer.arm.com/documentation/ihi0069/c/
    // page 178,
    // ICC_AP0R1_EL1 is only implemented in implementations that support 6 or more bits of
    // priority.
    // ICC_AP0R2_EL1 and ICC_AP0R3_EL1 are only implemented in implementations that support
    // 7 bits of priority.
    if (reg == &SYS_ICC_AP0R1_EL1 || reg == &SYS_ICC_AP1R1_EL1) && num_priority_bits < 6 {
        return false;
    }
    if (reg == &SYS_ICC_AP0R2_EL1
        || reg == &SYS_ICC_AP0R3_EL1
        || reg == &SYS_ICC_AP1R2_EL1
        || reg == &SYS_ICC_AP1R3_EL1)
        && num_priority_bits != 7
    {
        return false;
    }

    true
}

fn num_priority_bits(fd: &DeviceFd, mpidr: u64) -> u64 {
    let reg_val: u64 = get_reg_data(
        fd,
        &SYS_ICC_CTLR_EL1,
        KVM_DEV_ARM_VGIC_GRP_CPU_SYSREGS,
        mpidr,
        KVM_DEV_ARM_VGIC_V3_MPIDR_MASK as u64,
    )
    .chunks[0];

    ((reg_val & ICC_CTLR_EL1_PRIBITS_MASK) >> ICC_CTLR_EL1_PRIBITS_SHIFT) + 1
}
