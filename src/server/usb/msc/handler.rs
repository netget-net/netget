//! USB Mass Storage Class handler with BOT protocol and SCSI commands
//!
//! This module implements the UsbInterfaceHandler trait for Mass Storage Class devices.
//! It handles Bulk-Only Transport (BOT) protocol and SCSI transparent command set.
//!
//! **Everything here is synchronous.** `usbip` calls `UsbInterfaceHandler::handle_urb` from
//! inside an async fn on a tokio worker thread, so `Handle::current().block_on(...)` — which is
//! what this file used to do for every SCSI command — panics with "Cannot block the current
//! thread from within a runtime". The disk sits behind a `std::sync::Mutex` and the SCSI path
//! never awaits.

#[cfg(all(unix, feature = "libusb"))]
use super::disk::DiskImage;
#[cfg(all(unix, feature = "libusb"))]
use crate::server::usb::descriptors::{
    scsi_opcode, scsi_sense_key, CommandBlockWrapper, CommandStatusWrapper,
};
#[cfg(all(unix, feature = "libusb"))]
use anyhow::Result;
#[cfg(all(unix, feature = "libusb"))]
use std::sync::{Arc, Mutex};
#[cfg(all(unix, feature = "libusb"))]
use tokio::sync::mpsc;
#[cfg(all(unix, feature = "libusb"))]
use tracing::{debug, error, info, trace, warn};

/// Shared handle on the mounted disk image.
#[cfg(all(unix, feature = "libusb"))]
pub type SharedDisk = Arc<Mutex<DiskImage>>;

/// A completed sector transfer, reported to the connection task so it can raise an LLM event.
///
/// `handle_urb` is synchronous and cannot call the LLM, so it pushes these onto a channel
/// instead. This is the only reason `usb_msc_read` / `usb_msc_write` can fire at all.
#[cfg(all(unix, feature = "libusb"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MscIoEvent {
    Read {
        lba: u32,
        sectors: u32,
        bytes: usize,
    },
    Write {
        lba: u32,
        sectors: u32,
        bytes: usize,
    },
}

/// USB Mass Storage Class handler implementing BOT protocol
///
/// `Debug` is required by `usbip::UsbInterfaceHandler` as of 0.9. Derived rather than
/// hand-written: none of the fields is a secret, and the disk image behind the `Mutex`
/// prints as a handle, not as its contents.
#[cfg(all(unix, feature = "libusb"))]
#[derive(Debug)]
pub struct UsbMscHandler {
    /// Virtual disk image backend
    disk_image: SharedDisk,

    /// Whether a medium is present. `eject_disk` clears it; `mount_disk` sets it.
    medium_present: bool,

    /// BOT protocol state
    current_cbw: Option<CommandBlockWrapper>,
    pending_data: Vec<u8>,
    last_tag: u32,
    /// Bytes the host asked for in the current CBW, for the CSW residue.
    expected_transfer: u32,
    /// Bytes actually moved for the current CBW.
    transferred: u32,
    csw_pending: bool,
    /// Status the SCSI layer decided for the current command.
    command_status: u8,

    /// SCSI sense data (error reporting)
    sense_key: u8,
    sense_asc: u8,
    sense_ascq: u8,

    /// Pending write operation (LBA, transfer length in sectors)
    pending_write: Option<(u32, u32)>,

    /// Write-protect flag
    write_protect: bool,

    /// Where completed transfers are reported for LLM eventing.
    io_tx: Option<mpsc::UnboundedSender<MscIoEvent>>,
}

#[cfg(all(unix, feature = "libusb"))]
impl UsbMscHandler {
    /// Create new MSC handler with disk image
    pub fn new(disk_image: SharedDisk, write_protect: bool) -> Self {
        Self {
            disk_image,
            medium_present: true,
            current_cbw: None,
            pending_data: Vec::new(),
            last_tag: 0,
            expected_transfer: 0,
            transferred: 0,
            csw_pending: false,
            command_status: CommandStatusWrapper::STATUS_PASSED,
            sense_key: scsi_sense_key::NO_SENSE,
            sense_asc: 0,
            sense_ascq: 0,
            pending_write: None,
            write_protect,
            io_tx: None,
        }
    }

    /// Report completed transfers on `io_tx` so the connection task can raise events.
    pub fn with_io_events(mut self, io_tx: mpsc::UnboundedSender<MscIoEvent>) -> Self {
        self.io_tx = Some(io_tx);
        self
    }

    fn report_io(&self, event: MscIoEvent) {
        if let Some(tx) = &self.io_tx {
            // A closed channel means the connection task is gone; the transfer itself already
            // succeeded, so this is not an error for the host.
            let _ = tx.send(event);
        }
    }

    /// Set sense data for error reporting
    fn set_sense(&mut self, key: u8, asc: u8, ascq: u8) {
        self.sense_key = key;
        self.sense_asc = asc;
        self.sense_ascq = ascq;
        debug!(
            "SCSI sense set: key={:#04x}, asc={:#04x}, ascq={:#04x}",
            key, asc, ascq
        );
    }

    /// Clear sense data
    fn clear_sense(&mut self) {
        self.sense_key = scsi_sense_key::NO_SENSE;
        self.sense_asc = 0;
        self.sense_ascq = 0;
    }

    /// Set write-protect flag
    ///
    /// When enabled, WRITE(10) commands will fail with DATA_PROTECT sense.
    pub fn set_write_protect(&mut self, enabled: bool) {
        info!(
            "USB MSC: Write protection {}",
            if enabled { "enabled" } else { "disabled" }
        );
        self.write_protect = enabled;
    }

    /// Get current write-protect status
    pub fn is_write_protected(&self) -> bool {
        self.write_protect
    }

    /// Replace the disk image with a new one
    ///
    /// This allows mounting a different disk image at runtime.
    pub fn mount_disk(&mut self, new_disk: SharedDisk) {
        info!("USB MSC: Mounting new disk image");
        self.disk_image = new_disk;
        self.medium_present = true;
        self.reset_bot_state();
    }

    /// Eject the current disk (simulates media removal)
    ///
    /// After ejection every command that needs the medium fails with NOT_READY until a new
    /// disk is mounted. Setting sense alone was not enough: the very next command cleared it,
    /// so an ejected device kept happily serving sectors.
    pub fn eject_disk(&mut self) {
        info!("USB MSC: Ejecting disk");
        self.medium_present = false;
        self.set_sense(scsi_sense_key::NOT_READY, 0x3A, 0x00); // Medium not present
    }

    /// Whether a medium is currently present.
    pub fn is_medium_present(&self) -> bool {
        self.medium_present
    }

    /// Get disk capacity info as (total_sectors, bytes_per_sector).
    pub fn get_disk_info(&self) -> Option<(u32, u32)> {
        let disk = self.disk_image.lock().ok()?;
        Some((disk.total_sectors(), disk.bytes_per_sector()))
    }

    /// Reset BOT state
    fn reset_bot_state(&mut self) {
        debug!("Resetting BOT state");
        self.current_cbw = None;
        self.pending_data.clear();
        self.csw_pending = false;
        self.pending_write = None;
        self.expected_transfer = 0;
        self.transferred = 0;
        self.command_status = CommandStatusWrapper::STATUS_PASSED;
        self.clear_sense();
    }

    /// Fail the current command because there is no medium.
    fn no_medium(&mut self) -> u8 {
        self.set_sense(scsi_sense_key::NOT_READY, 0x3A, 0x00);
        CommandStatusWrapper::STATUS_FAILED
    }

    /// Fail the current command because the CDB is too short to be the command it claims to be.
    fn malformed_cdb(&mut self, opcode: u8, need: usize, got: usize) -> u8 {
        warn!(
            "SCSI command {:#04x} needs {} CDB bytes, got {}",
            opcode, need, got
        );
        self.set_sense(scsi_sense_key::ILLEGAL_REQUEST, 0x24, 0x00); // Invalid field in CDB
        CommandStatusWrapper::STATUS_FAILED
    }

    /// Handle SCSI command from CBW
    fn handle_scsi_command(&mut self, cmd: &[u8]) -> u8 {
        let Some(&opcode) = cmd.first() else {
            warn!("Empty SCSI command block");
            self.set_sense(scsi_sense_key::ILLEGAL_REQUEST, 0x20, 0x00);
            return CommandStatusWrapper::STATUS_FAILED;
        };
        trace!("SCSI command: opcode={:#04x} ({} bytes)", opcode, cmd.len());

        match opcode {
            scsi_opcode::INQUIRY => self.scsi_inquiry(cmd),
            scsi_opcode::TEST_UNIT_READY => self.scsi_test_unit_ready(),
            scsi_opcode::READ_CAPACITY_10 => self.scsi_read_capacity(),
            scsi_opcode::READ_10 => self.scsi_read10(cmd),
            scsi_opcode::WRITE_10 => self.scsi_write10(cmd),
            scsi_opcode::REQUEST_SENSE => self.scsi_request_sense(),
            scsi_opcode::MODE_SENSE_6 => self.scsi_mode_sense(cmd),
            scsi_opcode::PREVENT_ALLOW_MEDIUM_REMOVAL => self.scsi_prevent_allow_removal(),
            scsi_opcode::READ_FORMAT_CAPACITIES => self.scsi_read_format_capacities(),
            _ => {
                warn!("Unsupported SCSI command: {:#04x}", opcode);
                self.set_sense(scsi_sense_key::ILLEGAL_REQUEST, 0x20, 0x00);
                CommandStatusWrapper::STATUS_FAILED
            }
        }
    }

    /// SCSI INQUIRY command (0x12) - Return device information
    ///
    /// INQUIRY must answer even with no medium loaded; that is how a host learns the device
    /// exists at all.
    fn scsi_inquiry(&mut self, cmd: &[u8]) -> u8 {
        let Some(&alloc_len) = cmd.get(4) else {
            return self.malformed_cdb(scsi_opcode::INQUIRY, 5, cmd.len());
        };
        let alloc_len = alloc_len as usize;
        debug!("SCSI INQUIRY (alloc_len={})", alloc_len);

        let response = crate::server::scsi_common::standard_inquiry(
            &crate::server::scsi_common::Identity {
                vendor: "NetGet".into(),
                product: "Virtual Disk".into(),
                revision: "1.0".into(),
            },
            true, // removable media
            0x05, // SPC-3
            false,
            &[],
        );

        self.pending_data = response[..alloc_len.min(response.len())].to_vec();
        self.clear_sense();
        CommandStatusWrapper::STATUS_PASSED
    }

    /// SCSI TEST_UNIT_READY command (0x00) - Check device readiness
    fn scsi_test_unit_ready(&mut self) -> u8 {
        debug!("SCSI TEST_UNIT_READY");
        if !self.medium_present {
            return self.no_medium();
        }
        self.clear_sense();
        CommandStatusWrapper::STATUS_PASSED
    }

    /// SCSI READ_CAPACITY(10) command (0x25) - Return disk capacity
    fn scsi_read_capacity(&mut self) -> u8 {
        if !self.medium_present {
            return self.no_medium();
        }

        let Some((total_sectors, block_size)) = self.get_disk_info() else {
            error!("READ_CAPACITY: disk image mutex poisoned");
            self.set_sense(scsi_sense_key::HARDWARE_ERROR, 0x44, 0x00);
            return CommandStatusWrapper::STATUS_FAILED;
        };
        let last_lba = total_sectors.saturating_sub(1);

        debug!(
            "SCSI READ_CAPACITY: last_lba={}, block_size={}",
            last_lba, block_size
        );

        self.pending_data =
            crate::server::scsi_common::read_capacity_10(last_lba as u64, block_size).to_vec();
        self.clear_sense();
        CommandStatusWrapper::STATUS_PASSED
    }

    /// SCSI READ(10) command (0x28) - Read sectors from disk
    fn scsi_read10(&mut self, cmd: &[u8]) -> u8 {
        if cmd.len() < 9 {
            return self.malformed_cdb(scsi_opcode::READ_10, 9, cmd.len());
        }
        if !self.medium_present {
            return self.no_medium();
        }

        let lba = u32::from_be_bytes([cmd[2], cmd[3], cmd[4], cmd[5]]);
        let transfer_len = u16::from_be_bytes([cmd[7], cmd[8]]) as u32;

        debug!(
            "SCSI READ(10): lba={}, transfer_len={} sectors",
            lba, transfer_len
        );

        let result = match self.disk_image.lock() {
            Ok(disk) => disk.read_sectors(lba, transfer_len),
            Err(_) => Err(anyhow::anyhow!("disk image mutex poisoned")),
        };

        match result {
            Ok(data) => {
                let bytes = data.len();
                self.pending_data = data;
                self.clear_sense();
                self.report_io(MscIoEvent::Read {
                    lba,
                    sectors: transfer_len,
                    bytes,
                });
                CommandStatusWrapper::STATUS_PASSED
            }
            Err(e) => {
                error!("READ(10) failed: {}", e);
                // Logical block address out of range.
                self.set_sense(scsi_sense_key::ILLEGAL_REQUEST, 0x21, 0x00);
                CommandStatusWrapper::STATUS_FAILED
            }
        }
    }

    /// SCSI WRITE(10) command (0x2A) - Write sectors to disk
    fn scsi_write10(&mut self, cmd: &[u8]) -> u8 {
        if cmd.len() < 9 {
            return self.malformed_cdb(scsi_opcode::WRITE_10, 9, cmd.len());
        }
        if !self.medium_present {
            return self.no_medium();
        }

        let lba = u32::from_be_bytes([cmd[2], cmd[3], cmd[4], cmd[5]]);
        let transfer_len = u16::from_be_bytes([cmd[7], cmd[8]]) as u32;

        debug!(
            "SCSI WRITE(10): lba={}, transfer_len={} sectors (write_protect={})",
            lba, transfer_len, self.write_protect
        );

        if self.write_protect {
            warn!("WRITE(10) blocked: disk is write-protected");
            self.set_sense(scsi_sense_key::DATA_PROTECT, 0x27, 0x00);
            return CommandStatusWrapper::STATUS_FAILED;
        }

        // Store pending write info - data will arrive in separate bulk OUT transfer
        self.pending_write = Some((lba, transfer_len));
        self.clear_sense();
        CommandStatusWrapper::STATUS_PASSED
    }

    /// SCSI REQUEST_SENSE command (0x03) - Return sense data
    fn scsi_request_sense(&mut self) -> u8 {
        debug!(
            "SCSI REQUEST_SENSE: key={:#04x}, asc={:#04x}, ascq={:#04x}",
            self.sense_key, self.sense_asc, self.sense_ascq
        );

        let response = crate::server::scsi_common::fixed_sense(
            self.sense_key,
            self.sense_asc,
            self.sense_ascq,
        )
        .to_vec();

        self.pending_data = response;
        // Reporting the sense consumes it, which is what a host expects. An ejected medium is
        // a standing condition, not a one-shot error, so re-arm it.
        self.clear_sense();
        if !self.medium_present {
            self.set_sense(scsi_sense_key::NOT_READY, 0x3A, 0x00);
        }
        CommandStatusWrapper::STATUS_PASSED
    }

    /// SCSI MODE_SENSE(6) command (0x1A) - Return device parameters
    fn scsi_mode_sense(&mut self, cmd: &[u8]) -> u8 {
        let page_code = cmd.get(2).map(|b| b & 0x3F).unwrap_or(0x3F);
        debug!("SCSI MODE_SENSE(6): page_code={:#04x}", page_code);

        #[rustfmt::skip]
        let response = vec![
            0x03,             // Mode data length
            0x00,             // Medium type
            if self.write_protect { 0x80 } else { 0x00 }, // Device-specific parameter
            0x00,             // Block descriptor length
        ];

        self.pending_data = response;
        self.clear_sense();
        CommandStatusWrapper::STATUS_PASSED
    }

    /// SCSI PREVENT_ALLOW_MEDIUM_REMOVAL command (0x1E)
    fn scsi_prevent_allow_removal(&mut self) -> u8 {
        debug!("SCSI PREVENT_ALLOW_MEDIUM_REMOVAL");
        // We don't enforce this, just acknowledge
        self.clear_sense();
        CommandStatusWrapper::STATUS_PASSED
    }

    /// SCSI READ_FORMAT_CAPACITIES command (0x23)
    fn scsi_read_format_capacities(&mut self) -> u8 {
        if !self.medium_present {
            return self.no_medium();
        }

        let Some((total_sectors, block_size)) = self.get_disk_info() else {
            error!("READ_FORMAT_CAPACITIES: disk image mutex poisoned");
            self.set_sense(scsi_sense_key::HARDWARE_ERROR, 0x44, 0x00);
            return CommandStatusWrapper::STATUS_FAILED;
        };

        debug!("SCSI READ_FORMAT_CAPACITIES: {} sectors", total_sectors);

        #[rustfmt::skip]
        let mut response = vec![
            0x00, 0x00, 0x00, 0x08,  // Capacity list length (8 bytes)
        ];
        response.extend_from_slice(&total_sectors.to_be_bytes());
        response.push(0x02); // Descriptor type: formatted media
        response.extend_from_slice(&block_size.to_be_bytes()[1..]); // Block size (24-bit)

        self.pending_data = response;
        self.clear_sense();
        CommandStatusWrapper::STATUS_PASSED
    }

    /// Handle write data received from bulk OUT endpoint
    fn handle_write_data(&mut self, data: &[u8]) -> Result<()> {
        let Some((lba, transfer_len)) = self.pending_write.take() else {
            warn!("Received write data with no pending WRITE(10) command");
            return Ok(());
        };

        debug!(
            "Writing {} bytes to LBA {} ({} sectors expected)",
            data.len(),
            lba,
            transfer_len
        );

        let result = match self.disk_image.lock() {
            Ok(mut disk) => disk.write_sectors(lba, data),
            Err(_) => Err(anyhow::anyhow!("disk image mutex poisoned")),
        };

        match result {
            Ok(sectors_written) => {
                info!(
                    "WRITE(10) completed: {} sectors written to LBA {}",
                    sectors_written, lba
                );
                self.report_io(MscIoEvent::Write {
                    lba,
                    sectors: sectors_written,
                    bytes: data.len(),
                });
                Ok(())
            }
            Err(e) => {
                error!("WRITE(10) failed: {}", e);
                self.set_sense(scsi_sense_key::MEDIUM_ERROR, 0x03, 0x00);
                Err(e)
            }
        }
    }

    /// Start a new BOT command from a freshly parsed CBW.
    fn begin_command(&mut self, cbw: CommandBlockWrapper) {
        // Copy packed fields out before touching them: taking a reference to a field of a
        // `#[repr(packed)]` struct is undefined behaviour.
        let tag = cbw.tag;
        let lun = cbw.lun;
        let flags = cbw.flags;
        let data_transfer_length = cbw.data_transfer_length;

        debug!(
            "BOT: Received CBW (tag={:#010x}, lun={}, flags={:#04x}, length={})",
            tag, lun, flags, data_transfer_length
        );

        self.last_tag = tag;
        self.expected_transfer = data_transfer_length;
        self.transferred = 0;
        self.pending_data.clear();

        let scsi_cmd = cbw.scsi_command().to_vec();
        self.command_status = self.handle_scsi_command(&scsi_cmd);
        self.current_cbw = Some(cbw);

        // With neither data to send nor data to receive, the CSW is the whole rest of the
        // command.
        if self.pending_data.is_empty() && self.pending_write.is_none() {
            self.csw_pending = true;
        }
    }

    /// Build the CSW that ends the current command.
    fn build_csw(&mut self) -> [u8; CommandStatusWrapper::SIZE] {
        let residue = self.expected_transfer.saturating_sub(self.transferred);
        let csw = CommandStatusWrapper::new(self.last_tag, residue, self.command_status);

        let tag = csw.tag;
        let status = csw.status;
        debug!(
            "BOT: Sending CSW (tag={:#010x}, status={}, residue={})",
            tag, status, residue
        );

        self.csw_pending = false;
        self.current_cbw = None;
        self.expected_transfer = 0;
        self.transferred = 0;
        self.command_status = CommandStatusWrapper::STATUS_PASSED;

        csw.to_bytes()
    }
}

// Implement usbip::UsbInterfaceHandler trait
#[cfg(all(unix, feature = "libusb"))]
impl usbip::UsbInterfaceHandler for UsbMscHandler {
    fn handle_urb(
        &mut self,
        _interface: &usbip::UsbInterface,
        endpoint: usbip::UsbEndpoint,
        // usbip 0.9 passes the host's declared transfer length. The BOT state machine
        // derives its own lengths from the CBW, so this only caps how much of a queued
        // response goes out in one transfer.
        transfer_buffer_length: u32,
        setup: usbip::SetupPacket,
        data: &[u8],
    ) -> std::result::Result<Vec<u8>, std::io::Error> {
        // `is_ep0()`, not `address == 0`: the crate's control IN endpoint is 0x80, so an
        // address comparison sends every class request down the bulk IN path — Get Max LUN
        // would have been answered with whatever the BOT state machine had queued.
        if endpoint.is_ep0() {
            // Control transfer
            trace!(
                "MSC control request: type={:#04x}, request={:#04x}",
                setup.request_type,
                setup.request
            );

            return match (setup.request_type, setup.request) {
                // Bulk-Only Mass Storage Reset (0x21, 0xFF)
                (0x21, 0xFF) => {
                    debug!("BOT: Mass Storage Reset");
                    self.reset_bot_state();
                    Ok(vec![])
                }

                // Get Max LUN (0xA1, 0xFE)
                (0xA1, 0xFE) => {
                    debug!("BOT: Get Max LUN");
                    Ok(vec![0x00]) // Single LUN device
                }

                _ => {
                    warn!(
                        "Unsupported MSC control request: type={:#04x}, request={:#04x}",
                        setup.request_type, setup.request
                    );
                    Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "Unsupported control request",
                    ))
                }
            };
        }

        if matches!(endpoint.direction(), usbip::Direction::Out) {
            // Bulk OUT endpoint (host to device) - receives CBW and write data.
            //
            // Which of the two this is depends on the BOT phase, not on the length. Deciding
            // by `len() == 31` alone misreads a 31-byte data-out payload as a command.
            if self.pending_write.is_some() {
                if let Err(e) = self.handle_write_data(data) {
                    error!("Failed to handle write data: {}", e);
                    self.command_status = CommandStatusWrapper::STATUS_FAILED;
                } else {
                    self.transferred = self
                        .transferred
                        .saturating_add(u32::try_from(data.len()).unwrap_or(u32::MAX));
                }
                self.csw_pending = true;
                return Ok(vec![]);
            }

            if self.csw_pending {
                // The command already failed (write-protected media, say) but the host is
                // still pushing the data phase it promised in the CBW. A real device stalls
                // the endpoint here; there is no stall over USB/IP, so discard the bytes and
                // let the CSW report them as residue.
                debug!(
                    "BOT: discarding {} byte(s) of data for a command that already completed",
                    data.len()
                );
                return Ok(vec![]);
            }

            return match CommandBlockWrapper::parse(data) {
                Some(cbw) => {
                    self.begin_command(cbw);
                    Ok(vec![])
                }
                None => {
                    error!(
                        "Failed to parse CBW: invalid format ({} bytes on the bulk OUT endpoint)",
                        data.len()
                    );
                    Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Invalid CBW format",
                    ))
                }
            };
        }

        // Bulk IN endpoint (device to host) - sends data then CSW.
        if !self.pending_data.is_empty() {
            let take = if transfer_buffer_length == 0 {
                self.pending_data.len()
            } else {
                (transfer_buffer_length as usize).min(self.pending_data.len())
            };
            let chunk: Vec<u8> = self.pending_data.drain(..take).collect();
            debug!(
                "BOT: Sending {} bytes of data ({} still queued)",
                chunk.len(),
                self.pending_data.len()
            );
            self.transferred = self
                .transferred
                .saturating_add(u32::try_from(chunk.len()).unwrap_or(u32::MAX));
            if self.pending_data.is_empty() {
                self.csw_pending = true;
            }
            return Ok(chunk);
        }

        if self.csw_pending {
            return Ok(self.build_csw().to_vec());
        }

        // Nothing queued: an idle bulk IN poll. A zero-length reply is the honest answer.
        Ok(vec![])
    }

    fn get_class_specific_descriptor(&self) -> Vec<u8> {
        // MSC doesn't have class-specific descriptors beyond standard interface descriptor
        vec![]
    }

    fn as_any(&mut self) -> &mut dyn std::any::Any {
        self
    }
}
