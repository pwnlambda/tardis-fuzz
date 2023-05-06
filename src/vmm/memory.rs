use crate::vmm::aarch64;
use log::debug;
use vm_memory::{GuestAddress, GuestMemory};

/// Extract the specified bits of a 64-bit integer.
/// For example, to extract 2 bits from offset 1 (zero based) of `6u64`,
/// following expression should return 3 (`0b11`):
/// `extract_bits_64!(0b0000_0110u64, 1, 2)`
macro_rules! extract_bits_64 {
    ($value: tt, $offset: tt, $length: tt) => {
        ($value >> $offset) & (!0u64 >> (64 - $length))
    };
}

impl super::VM {
    /// Translates an address from the guest's address space to physical memory
    /// using the CPU's current TTBR0_EL1. Cannot translate kernel pointers currently.
    pub fn guest_to_host(&mut self, addr: u64) -> u64 {
        // https://documentation-service.arm.com/static/5efa1d23dbdee951c1ccdec5?token=
        // https://armv8-ref.codingbelief.com/en/chapter_d4/d42_2_controlling_address_translation_stages.html
        // However to have a full understanding of address translation look at the Arm Architecture Reference Manual

        // Find the Translation Control Register
        // Note: To support kernel addrs check if upper bits are set in ptr
        // and switch between TTBR0 and TTBR1 based on that.
        let ttbr0 = self.vcpu_fd.get_one_reg(aarch64::TTBR0_EL1).unwrap() as u64;
        let tcr_el1 = self.vcpu_fd.get_one_reg(aarch64::TCR_EL1).unwrap() as u64;

        // TG0, bits [15:14] Granule size for the TTBR0_EL1.
        let tg = extract_bits_64!(tcr_el1, 14, 2);

        // T0SZ, bits [5:0] The size offset of the memory region addressed by TTBR0_EL1.
        // The region size is 2(64-T0SZ) bytes.
        let tsz = extract_bits_64!(tcr_el1, 0, 6);

        // VA size is determined by TCR_EL1.T0SZ
        let va_size = 64 - tsz;

        // Number of bits in VA consumed in each level of translation
        let stride = match tg {
            3 => 13, // 64KB granule size
            1 => 11, // 16KB granule size
            _ => 9,  // 4KB, default
        };

        // Starting level of walking
        let mut level = 4 - (va_size - 4) / stride;

        // Calculate masks
        let indexmask_grainsize = (!0u64) >> (64 - (stride + 3));
        let mut indexmask = (!0u64) >> (64 - (va_size - (stride * (4 - level))));

        // Mask with 48 least significant bits to extract next table addr
        let descaddrmask = !0u64 >> (64 - 48);
        let mut descaddr: u64 = extract_bits_64!(ttbr0, 0, 48);

        // Loop through tables of each level
        loop {
            // Table offset for current level
            let table_offset: u64 = (addr >> (stride * (4 - level))) & indexmask;
            descaddr |= table_offset;
            descaddr &= !7u64;

            let descriptor = self.read_host_u64(descaddr);
            descaddr = descriptor & descaddrmask;

            // This is a table entry. Go down to next level.
            if (descriptor & 2) != 0 && (level < 3) {
                level += 1;
                indexmask = indexmask_grainsize;
                continue;
            }

            break;
        }

        // Fix the VA bits
        let page_size = 1u64 << ((stride * (4 - level)) + 3);
        descaddr &= !(page_size - 1);
        descaddr |= addr & (page_size - 1);

        //debug!("{addr:x} -> {descaddr:x}");

        descaddr
    }

    pub fn read_host_u64(&mut self, addr: u64) -> u64 {
        let mut u64_bytes = [0u8; 8];
        let backing_ptr = self
            .state
            .guest_mem
            .get_host_address(GuestAddress(addr))
            .unwrap();

        unsafe {
            backing_ptr.copy_to(u64_bytes.as_mut_ptr(), 8);
        }

        u64::from_le_bytes(u64_bytes)
    }

    pub fn read_host_u32(&mut self, addr: u64) -> u32 {
        let mut u32_bytes = [0u8; 4];
        let backing_ptr = self
            .state
            .guest_mem
            .get_host_address(GuestAddress(addr));
        
        if backing_ptr.is_err() {
            return 0;
        }

        unsafe {
            backing_ptr.unwrap().copy_to(u32_bytes.as_mut_ptr(), 4);
        }

        u32::from_le_bytes(u32_bytes)
    }

    pub fn write_host_u32(&mut self, addr: u64, value: u32) {
        let u32_bytes = u32::to_le_bytes(value);
        let dest_ptr = self
            .state
            .guest_mem
            .get_host_address(GuestAddress((addr)));
        
        // Ignore invalid addr
        if dest_ptr.is_err() {
            return;
        }

        unsafe { u32_bytes.as_ptr().copy_to(dest_ptr.unwrap(), u32_bytes.len()) }
    }

    pub fn read_virt_u32(&mut self, addr: u64) -> u32 {
        let virt_addr = self.guest_to_host(addr);
        self.read_host_u32(virt_addr)
    }

    pub fn write_virt_u32(&mut self, addr: u64, value: u32) {
        let virt_addr = self.guest_to_host(addr);
        self.write_host_u32(virt_addr, value)
    }
}
