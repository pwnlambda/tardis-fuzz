use log::debug;
use vm_device::bus::MmioAddress;
use vm_device::MutDeviceMmio;
use vm_superio::{rtc_pl031::NoEvents, Rtc};
pub struct RtcWrapper(pub Rtc<NoEvents>);

impl MutDeviceMmio for RtcWrapper {
    fn mmio_read(&mut self, _base: MmioAddress, offset: u64, data: &mut [u8]) {
        if data.len() != 4 {
            debug!("RTC invalid data length on read: {}", data.len());
            return;
        }

        match offset.try_into() {
            // The unwrap() is safe because we checked that `data` has length 4.
            Ok(offset) => self.0.read(offset, data.try_into().unwrap()),
            Err(_) => debug!("Invalid RTC read offset."),
        }
    }

    fn mmio_write(&mut self, _base: MmioAddress, offset: u64, data: &[u8]) {
        if data.len() != 4 {
            debug!("RTC invalid data length on write: {}", data.len());
            return;
        }

        match offset.try_into() {
            // The unwrap() is safe because we checked that `data` has length 4.
            Ok(offset) => self.0.write(offset, data.try_into().unwrap()),
            Err(_) => debug!("Invalid RTC write offset."),
        }
    }
}
