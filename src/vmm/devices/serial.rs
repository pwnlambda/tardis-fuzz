use event_manager::{EventOps, Events, MutEventSubscriber};
use log::debug;
use std::convert::TryInto;
use std::io::{self, stdin, Read, Write};
use std::ops::Deref;

use vm_device::{bus::MmioAddress, MutDeviceMmio};
use vm_superio::serial::{NoEvents, SerialEvents};
use vm_superio::{Serial, Trigger};
use vmm_sys_util::epoll::EventSet;
use vmm_sys_util::eventfd::EventFd;
/// Newtype for implementing `event-manager` functionalities.
pub struct StdioSerialWrapper<T: Trigger, EV: SerialEvents, W: Write>(pub Serial<T, EV, W>);

impl<T: Trigger, W: Write> MutEventSubscriber for StdioSerialWrapper<T, NoEvents, W> {
    fn process(&mut self, events: Events, ops: &mut EventOps) {
        // Respond to stdin events.
        // `EventSet::IN` => send what's coming from stdin to the guest.
        // `EventSet::HANG_UP` or `EventSet::ERROR` => deregister the serial input.
        let mut out = [0u8; 32];
        match stdin().read(&mut out) {
            Err(e) => {
                eprintln!("Error while reading stdin: {:?}", e);
            }
            Ok(count) => {
                let event_set = events.event_set();
                let unregister_condition =
                    event_set.contains(EventSet::ERROR) | event_set.contains(EventSet::HANG_UP);
                if count > 0 {
                    if self.0.enqueue_raw_bytes(&out[..count]).is_err() {
                        eprintln!("Failed to send bytes to the guest via serial input");
                    }
                } else if unregister_condition {
                    // Got 0 bytes from serial input; is it a hang-up or error?
                    ops.remove(events)
                        .expect("Failed to unregister serial input");
                }
            }
        }
    }

    fn init(&mut self, ops: &mut EventOps) {
        // Hook to stdin events.
        ops.add(Events::new(&stdin(), EventSet::IN))
            .expect("Failed to register serial input event");
    }
}

impl<T: Trigger<E = io::Error>, W: Write> MutDeviceMmio for StdioSerialWrapper<T, NoEvents, W> {
    fn mmio_read(&mut self, _base: MmioAddress, offset: u64, data: &mut [u8]) {
        // TODO: this function can't return an Err, so we'll mark error conditions
        // (data being more than 1 byte, offset overflowing an u8) with logs & metrics.

        match offset.try_into() {
            Ok(offset) => self.bus_read(offset, data),
            Err(_) => debug!("Invalid serial console read offset."),
        }
    }

    fn mmio_write(&mut self, _base: MmioAddress, offset: u64, data: &[u8]) {
        // TODO: this function can't return an Err, so we'll mark error conditions
        // (data being more than 1 byte, offset overflowing an u8) with logs & metrics.

        match offset.try_into() {
            Ok(offset) => self.bus_write(offset, data),
            Err(_) => debug!("Invalid serial console write offset."),
        }
    }
}

impl<T: Trigger<E = io::Error>, W: Write> StdioSerialWrapper<T, NoEvents, W> {
    fn bus_read(&mut self, offset: u8, data: &mut [u8]) {
        if data.len() != 1 {
            debug!("Serial console invalid data length on read: {}", data.len());
            return;
        }

        // This is safe because we checked that `data` has length 1.
        data[0] = self.0.read(offset);
    }

    fn bus_write(&mut self, offset: u8, data: &[u8]) {
        if data.len() != 1 {
            debug!(
                "Serial console invalid data length on write: {}",
                data.len()
            );
            return;
        }

        // This is safe because we checked that `data` has length 1.
        let res = self.0.write(offset, data[0]);
        if res.is_err() {
            debug!("Error writing to serial console: {:#?}", res.unwrap_err());
        }
    }
}

/// Newtype for implementing the trigger functionality for `EventFd`.
///
/// The trigger is used for handling events in the legacy devices.
pub struct EventFdTrigger(EventFd);

impl Trigger for EventFdTrigger {
    type E = io::Error;

    fn trigger(&self) -> io::Result<()> {
        self.write(1)
    }
}
impl Deref for EventFdTrigger {
    type Target = EventFd;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl EventFdTrigger {
    pub fn try_clone(&self) -> io::Result<Self> {
        Ok(EventFdTrigger((**self).try_clone()?))
    }
    pub fn new(flag: i32) -> io::Result<Self> {
        let event_fd = EventFd::new(flag)?;
        Ok(EventFdTrigger(event_fd))
    }
}
