use crate::vmm::aarch64;
use linux_loader::loader::Cmdline;
use log::debug;
use vm_fdt::{FdtWriter, FdtWriterNode};

#[derive(Clone)]
pub struct FDTBuilder {
    pub cmdline: Cmdline,
    pub serial_start: u64,
    pub serial_len: u64,
    pub rtc_addr: u64,
    pub rtc_len: u64,
    pub initrd_start: u64,
    pub initrd_end: u64,
}

impl FDTBuilder {
    pub fn new() -> Self {
        let cmdline = Cmdline::new(1000).unwrap();
        FDTBuilder {
            cmdline,
            serial_start: 0,
            serial_len: 0,
            rtc_addr: 0,
            rtc_len: 0,
            initrd_start: 0,
            initrd_end: 0,
        }
    }

    fn create_root(fdt: &mut FdtWriter) -> FdtWriterNode {
        let root_node = fdt.begin_node("").unwrap();
        fdt.property_u32("interrupt-parent", aarch64::PHANDLE_GIC)
            .unwrap();
        fdt.property_string("compatible", "linux,dummy-virt")
            .unwrap();
        fdt.property_u32("#address-cells", 0x2).unwrap();
        fdt.property_u32("#size-cells", 0x2).unwrap();
        root_node
    }

    fn create_chosen_node(fdt: &mut FdtWriter, cmdline: &str, _initrd_s: u64, _initrd_e: u64) {
        let chosen_node = fdt.begin_node("chosen").unwrap();
        fdt.property_string("bootargs", cmdline).unwrap();
        //fdt.property_u64("linux,initrd-start", initrd_s).unwrap();
        //fdt.property_u64("linux,initrd-end", initrd_e).unwrap();
        fdt.end_node(chosen_node).unwrap();
    }

    fn create_cpu_node(fdt: &mut FdtWriter) {
        // Create a cpu node as implemented by vmm-reference
        let cpus_node = fdt.begin_node("cpus").unwrap();
        fdt.property_u32("#address-cells", 0x1).unwrap();
        fdt.property_u32("#size-cells", 0x0).unwrap();

        let cpu_node = fdt.begin_node("cpu@0").unwrap();
        fdt.property_string("device_type", "cpu").unwrap();
        fdt.property_string("compatible", "arm,arm-v8").unwrap();
        fdt.property_string("enable-method", "psci").unwrap();
        fdt.property_u32("reg", 0).unwrap();
        fdt.end_node(cpu_node).unwrap();
        fdt.end_node(cpus_node).unwrap();
    }

    fn create_memory_node(fdt: &mut FdtWriter, mem_size: u64) {
        // Create a memory node as implemented by vmm-reference
        let mem_reg_prop = [aarch64::AARCH64_PHYS_MEM_START, mem_size];

        let memory_node = fdt.begin_node("memory").unwrap();
        fdt.property_string("device_type", "memory").unwrap();
        fdt.property_array_u64("reg", &mem_reg_prop).unwrap();
        fdt.end_node(memory_node).unwrap();
    }

    fn create_timer_node(fdt: &mut FdtWriter) {
        // Create a timer node as implemented by vmm-reference
        // These are fixed interrupt numbers for the timer device.
        let irqs = [13, 14, 11, 10];
        let compatible = "arm,armv8-timer";
        let cpu_mask: u32 = (((1 << 1) - 1) << aarch64::GIC_FDT_IRQ_PPI_CPU_SHIFT)
            & aarch64::GIC_FDT_IRQ_PPI_CPU_MASK;
        let mut timer_reg_cells = Vec::new();
        for &irq in &irqs {
            timer_reg_cells.push(aarch64::GIC_FDT_IRQ_TYPE_PPI);
            timer_reg_cells.push(irq);
            timer_reg_cells.push(cpu_mask | aarch64::IRQ_TYPE_LEVEL_LOW);
        }

        let timer_node = fdt.begin_node("timer").unwrap();
        fdt.property_string("compatible", compatible).unwrap();
        fdt.property_array_u32("interrupts", &timer_reg_cells)
            .unwrap();
        fdt.property_null("always-on").unwrap();
        fdt.end_node(timer_node).unwrap();
    }

    fn create_serial_node(fdt: &mut FdtWriter, addr: u64, size: u64) {
        // Create a UART serial node as implemented by vmm-reference
        let serial_node = fdt.begin_node(&format!("uart@{addr:x}")).unwrap();
        fdt.property_string("compatible", "ns16550a").unwrap();

        let serial_reg_prop = [addr, size];
        fdt.property_array_u64("reg", &serial_reg_prop).unwrap();

        const CLK_PHANDLE: u32 = 24;
        fdt.property_u32("clocks", CLK_PHANDLE).unwrap();
        fdt.property_string("clock-names", "apb_pclk").unwrap();
        let irq = [
            aarch64::GIC_FDT_IRQ_TYPE_SPI,
            4,
            aarch64::IRQ_TYPE_EDGE_RISING,
        ];
        fdt.property_array_u32("interrupts", &irq).unwrap();
        fdt.end_node(serial_node).unwrap();
    }

    fn create_gicv3_node(fdt: &mut FdtWriter) {
        // Create a GICv3 node as implemented by vmm-reference for only one vcpu
        let mut gic_reg_prop = [
            aarch64::AARCH64_GIC_DIST_BASE,
            aarch64::AARCH64_GIC_DIST_SIZE,
            0,
            0,
        ];
        let intc_node = fdt.begin_node("intc").unwrap();
        fdt.property_string("compatible", "arm,gic-v3").unwrap();
        gic_reg_prop[2] = aarch64::AARCH64_GIC_DIST_BASE - (aarch64::AARCH64_GIC_REDIST_SIZE);
        gic_reg_prop[3] = aarch64::AARCH64_GIC_REDIST_SIZE;
        fdt.property_u32("#interrupt-cells", aarch64::GIC_FDT_IRQ_NUM_CELLS)
            .unwrap();
        fdt.property_null("interrupt-controller").unwrap();
        fdt.property_array_u64("reg", &gic_reg_prop).unwrap();
        fdt.property_phandle(aarch64::PHANDLE_GIC).unwrap();
        fdt.property_u32("#address-cells", 2).unwrap();
        fdt.property_u32("#size-cells", 2).unwrap();
        fdt.end_node(intc_node).unwrap();
    }

    fn create_psci_node(fdt: &mut FdtWriter) {
        // Create a PSCI node as implemented by vmm-reference
        let compatible = "arm,psci-0.2";
        let psci_node = fdt.begin_node("psci").unwrap();
        fdt.property_string("compatible", compatible).unwrap();
        fdt.property_string("method", "hvc").unwrap();
        fdt.end_node(psci_node).unwrap();
    }

    fn create_pmu_node(fdt: &mut FdtWriter) {
        // Create a PMU node as implemented by vmm-reference
        let compatible = "arm,armv8-pmuv3";
        let cpu_mask: u32 =
            (1 << aarch64::GIC_FDT_IRQ_PPI_CPU_SHIFT) & aarch64::GIC_FDT_IRQ_PPI_CPU_MASK;
        let irq = [
            aarch64::GIC_FDT_IRQ_TYPE_PPI,
            aarch64::AARCH64_PMU_IRQ,
            cpu_mask | aarch64::IRQ_TYPE_LEVEL_HIGH,
        ];

        let pmu_node = fdt.begin_node("pmu").unwrap();
        fdt.property_string("compatible", compatible).unwrap();
        fdt.property_array_u32("interrupts", &irq).unwrap();
        fdt.end_node(pmu_node).unwrap();
    }

    fn create_rtc_node(fdt: &mut FdtWriter, rtc_addr: u64, size: u64) {
        // the kernel driver for pl030 really really wants a clock node
        // associated with an AMBA device or it will fail to probe, so we
        // need to make up a clock node to associate with the pl030 rtc
        // node and an associated handle with a unique phandle value.
        const CLK_PHANDLE: u32 = 24;
        let clock_node = fdt.begin_node("apb-pclk").unwrap();
        fdt.property_u32("#clock-cells", 0).unwrap();
        fdt.property_string("compatible", "fixed-clock").unwrap();
        fdt.property_u32("clock-frequency", 24_000_000).unwrap();
        fdt.property_string("clock-output-names", "clk24mhz")
            .unwrap();
        fdt.property_phandle(CLK_PHANDLE).unwrap();
        fdt.end_node(clock_node).unwrap();

        let rtc_name = format!("rtc@{rtc_addr:x}");
        let reg = [rtc_addr, size];
        let irq = [
            aarch64::GIC_FDT_IRQ_TYPE_SPI,
            33,
            aarch64::IRQ_TYPE_LEVEL_HIGH,
        ];

        let rtc_node = fdt.begin_node(&rtc_name).unwrap();
        fdt.property_string_list(
            "compatible",
            vec![String::from("arm,pl031"), String::from("arm,primecell")],
        )
        .unwrap();
        // const PL030_AMBA_ID: u32 = 0x00041030;
        // fdt.property_string("arm,pl031", PL030_AMBA_ID)?;
        fdt.property_array_u64("reg", &reg).unwrap();
        fdt.property_array_u32("interrupts", &irq).unwrap();
        fdt.property_u32("clocks", CLK_PHANDLE).unwrap();
        fdt.property_string("clock-names", "apb_pclk").unwrap();
        fdt.end_node(rtc_node).unwrap();
    }

    pub fn serialize(&mut self, mem_size: u64) -> Vec<u8> {
        let mut fdt = FdtWriter::new().unwrap();

        // Create the root
        let root = FDTBuilder::create_root(&mut fdt);
        let cmd = self.cmdline.as_cstring().unwrap().into_string().unwrap();

        debug!(
            "rtc {:x} {:x} serial {:x} {:x}",
            self.rtc_addr, self.rtc_len, self.serial_start, self.serial_len
        );

        // Add boot-args
        FDTBuilder::create_chosen_node(&mut fdt, &cmd, self.initrd_start, self.initrd_end);
        // Add RAM
        FDTBuilder::create_memory_node(&mut fdt, mem_size);
        // Add CPU
        FDTBuilder::create_cpu_node(&mut fdt);
        // Add vGICv3
        FDTBuilder::create_gicv3_node(&mut fdt);
        // Add Serial node
        FDTBuilder::create_serial_node(&mut fdt, self.serial_start, self.serial_len);
        // Add RTC
        FDTBuilder::create_rtc_node(&mut fdt, self.rtc_addr, self.rtc_len);
        // Add Timer
        FDTBuilder::create_timer_node(&mut fdt);
        // Add PSCI
        FDTBuilder::create_psci_node(&mut fdt);
        // Add PMU
        FDTBuilder::create_pmu_node(&mut fdt);

        // Complete the FDT
        fdt.end_node(root).unwrap();
        fdt.finish().unwrap()
    }
}
