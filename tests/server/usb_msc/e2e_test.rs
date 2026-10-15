//! E2E tests for the USB Mass Storage Class server.
//!
//! The question these answer is the concrete one: *pretend to be a USB drive and serve a
//! single file `hello.txt` containing `world`* — does that work?
//!
//! They drive a real USB/IP client over TCP (`tests/helpers/usbip_client.rs`): `OP_REQ_DEVLIST`
//! and `OP_REQ_IMPORT`, then Bulk-Only Transport CBW/CSW pairs carrying real SCSI commands. A
//! FAT16 volume is built in-process (`super::fat16`), handed to the server as
//! `startup_params.disk_image`, and read back sector by sector through `READ(10)`. The
//! assertion is on the bytes the host receives, so a broken SCSI path cannot pass.
//!
//! **What this does not prove.** There is no `vhci-hcd`, no `/dev/sdX`, no kernel filesystem
//! driver — macOS has no USB/IP client at all, which is why the protocol is spoken directly.
//! These tests establish that the *device side* is correct: netget puts the right bytes on the
//! wire for the right SCSI commands. They do not establish that Linux mounts the volume and
//! that `cat /mnt/hello.txt` prints `world`; that still needs a real host with the kernel
//! module and root.
//!
//! The previous version of this file connected a bare `TcpStream` and checked that an event
//! fired. That could not have caught any of what was actually broken: the server exported the
//! device on a second listener bound to the *client's* address and dropped the accepted socket,
//! every SCSI command panicked the moment it ran (`Handle::current().block_on` on a tokio
//! worker), control requests were routed to the bulk IN path, and three of the four events
//! could never fire.

#[cfg(all(unix, feature = "libusb"))]
mod usb_msc_e2e {
    use crate::helpers::usbip_client::{Csw, UsbIpClient};
    use crate::helpers::*;
    use crate::server::usb_msc::fat16::{self, FatFile};

    /// Log line the server emits after each LLM call on an MSC connection.
    ///
    /// Must be the post-call line: the pre-call line is printed before the HTTP request
    /// reaches the mock, so waiting on it races `verify_mocks()` under parallel load.
    /// The same line, narrowed to one event kind.
    const ATTACH_CALL_LOG: &str = "USB MSC LLM call completed (attach)";
    const WRITE_CALL_LOG: &str = "USB MSC LLM call completed (write)";
    const READ_CALL_LOG: &str = "USB MSC LLM call completed (read)";

    /// SCSI sense keys the tests assert on.
    const SENSE_NOT_READY: u8 = 0x02;
    const SENSE_DATA_PROTECT: u8 = 0x07;

    /// Write a FAT16 image containing `hello.txt` -> `world` and return its path.
    ///
    /// The `TempDir` is returned too and must be kept alive: dropping it deletes the image.
    fn hello_world_image() -> E2EResult<(tempfile::TempDir, std::path::PathBuf)> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("hello.img");
        fat16::write_image(
            &path,
            &[FatFile {
                name: "hello.txt",
                data: b"world",
            }],
        )?;
        Ok((dir, path))
    }

    /// A path inside `dir` for an image netget is expected to create itself.
    fn scratch_image(dir: &tempfile::TempDir, name: &str) -> String {
        dir.path().join(name).to_string_lossy().to_string()
    }

    /// Decode the fields of a FAT16 BIOS Parameter Block from a boot sector.
    ///
    /// The test computes the volume geometry from the bytes the *device* served rather than
    /// from constants it shares with the implementation. If netget laid the volume out wrongly,
    /// this walks to the wrong sector and the content assertion fails — which is the point: a
    /// host does exactly this walk, and it is the only thing that makes "the file is on the
    /// drive" mean anything.
    struct Bpb {
        bytes_per_sector: u32,
        sectors_per_cluster: u32,
        root_dir_lba: u32,
        data_start_lba: u32,
    }

    fn parse_bpb(boot: &[u8]) -> Bpb {
        assert_eq!(boot.len(), 512, "a boot sector is one 512-byte sector");
        assert_eq!(
            [boot[510], boot[511]],
            [0x55, 0xAA],
            "boot sector signature missing"
        );
        assert_eq!(&boot[54..62], b"FAT16   ", "volume should be FAT16");

        let bytes_per_sector = u16::from_le_bytes([boot[11], boot[12]]) as u32;
        let sectors_per_cluster = boot[13] as u32;
        let reserved = u16::from_le_bytes([boot[14], boot[15]]) as u32;
        let num_fats = boot[16] as u32;
        let root_entries = u16::from_le_bytes([boot[17], boot[18]]) as u32;
        let fat_sectors = u16::from_le_bytes([boot[22], boot[23]]) as u32;

        let root_dir_lba = reserved + num_fats * fat_sectors;
        let root_dir_sectors = (root_entries * 32).div_ceil(bytes_per_sector);

        Bpb {
            bytes_per_sector,
            sectors_per_cluster,
            root_dir_lba,
            data_start_lba: root_dir_lba + root_dir_sectors,
        }
    }

    impl Bpb {
        fn cluster_lba(&self, cluster: u32) -> u32 {
            self.data_start_lba + (cluster - 2) * self.sectors_per_cluster
        }
    }

    /// Find a file's directory entry in a root-directory sector.
    ///
    /// Returns `(first cluster, size)`.
    fn find_entry(root_dir: &[u8], name_8_3: &[u8; 11]) -> (u32, u32) {
        for entry in root_dir.chunks_exact(32) {
            if entry[0] == 0x00 {
                break; // no more entries
            }
            if &entry[0..11] == name_8_3.as_slice() {
                let first_cluster = u16::from_le_bytes([entry[26], entry[27]]) as u32;
                let size = u32::from_le_bytes([entry[28], entry[29], entry[30], entry[31]]);
                return (first_cluster, size);
            }
        }
        panic!(
            "no root directory entry named {:?}",
            String::from_utf8_lossy(name_8_3)
        );
    }

    /// The headline case: *pretend to be a USB drive serving `hello.txt` containing `world`* —
    /// with the **model** supplying the contents.
    ///
    /// Nothing in this test names a file on disk. The model answers `usb_msc_attached` with
    /// `serve_files`, netget lays that out as a FAT16 volume in memory, and the test walks the
    /// filesystem the way a host would: parse the BPB, find the directory entry, follow it to
    /// its cluster, read the sector. `world` arriving there can only have come from the mock's
    /// response.
    ///
    /// The previous version handed the server a prepared image via `startup_params.disk_image`
    /// and read it back. That passed while the protocol implemented storage — a memory-mapped
    /// file, defaulting to `./tmp/netget_msc_disk.img` — and while the read/write events were
    /// notifications about data the model had never been asked for.
    ///
    /// LLM calls: 3 (startup, attach, read)
    #[tokio::test]
    async fn test_usb_msc_serves_hello_txt() -> E2EResult<()> {
        let config = NetGetConfig::new(
            "Pretend to be a USB drive serving a single file hello.txt.".to_string(),
        )
        .with_mock(|mock| {
            mock.on_event("usb_msc_attached")
                .respond_with_actions(serde_json::json!([{
                    "type": "serve_files",
                    "volume_label": "MODELDATA",
                    "files": [
                        {"name": "hello.txt", "content": "world"},
                        {"name": "notes.txt", "content": "second file"}
                    ]
                }]))
                .expect_calls(1)
                .and()
                // Reads are coalesced, so how many events a burst produces is timing
                // dependent; that at least one fires is the point.
                .on_event("usb_msc_read")
                .respond_with_actions(serde_json::json!([{ "type": "wait_for_more" }]))
                .expect_at_least(1)
                .and()
                .on_event("usb_msc_detached")
                .respond_with_actions(serde_json::json!([
                    { "type": "show_message", "message": "detached" }
                ]))
                .expect_at_least(0)
                .and()
                .on_instruction_containing("USB drive")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "USB-MassStorage",
                    "instruction": "Serve hello.txt"
                }]))
                .expect_calls(1)
                .and()
        });

        let mut server = start_netget_server(config).await?;
        assert!(server.is_running(), "USB MSC server should be running");

        // 1. Enumeration: what would `usbip list -r <host>` show?
        let mut client = UsbIpClient::connect(server.port).await?;
        let devices = client.list_devices().await?;
        assert_eq!(devices.len(), 1, "exactly one device should be exported");
        let device = &devices[0];
        assert_eq!(device.bus_id, "0-0-0");
        assert_eq!(
            device.interfaces,
            vec![(0x08, 0x06, 0x50)],
            "the interface must advertise Mass Storage / SCSI transparent / Bulk-Only"
        );

        // 2. Attach. The attach handler is what puts the model's files on the drive, so
        //    everything below depends on the call having completed.
        let imported = client.import("0-0-0").await?;
        assert_eq!(imported.bus_id, "0-0-0");
        server.wait_for_log(ATTACH_CALL_LOG, 10).await?;

        // 3. Class request on the control endpoint.
        assert_eq!(client.get_max_lun().await?, 0, "single-LUN device");

        // 4. INQUIRY: who are you?
        let inquiry = client.scsi_inquiry().await?;
        assert_eq!(inquiry.len(), 36, "standard INQUIRY data is 36 bytes");
        assert_eq!(inquiry[0], 0x00, "direct-access block device");
        assert_eq!(inquiry[1] & 0x80, 0x80, "removable media");
        assert_eq!(
            &inquiry[8..16],
            b"NetGet  ",
            "vendor id, space padded to 8 bytes"
        );

        // 5. READ CAPACITY(10) and TEST UNIT READY.
        let (last_lba, block_size) = client.scsi_read_capacity_10().await?;
        assert_eq!(block_size, 512);
        assert!(
            last_lba > 0,
            "a mounted volume must report a non-zero capacity"
        );
        assert!(
            client.scsi_test_unit_ready().await?.passed(),
            "a mounted medium must report ready"
        );

        // 6. Boot sector: is this a FAT16 volume, and where is everything?
        let (boot, csw) = client.scsi_read_10(0, 1).await?;
        assert!(csw.passed(), "READ(10) of the boot sector failed");
        let bpb = parse_bpb(&boot);
        assert_eq!(bpb.bytes_per_sector, 512);
        assert_eq!(
            &boot[43..54],
            b"MODELDATA  ",
            "the volume label must be the one the model asked for"
        );
        assert_eq!(
            u16::from_le_bytes([boot[19], boot[20]]) as u32,
            last_lba + 1,
            "the BPB's total-sector count must agree with READ CAPACITY(10)"
        );

        // 7. Root directory: both of the model's files must be listed.
        let (root_dir, csw) = client.scsi_read_10(bpb.root_dir_lba, 1).await?;
        assert!(csw.passed(), "READ(10) of the root directory failed");
        let (hello_cluster, hello_size) = find_entry(&root_dir, b"HELLO   TXT");
        assert_eq!(hello_size, 5, "hello.txt is 5 bytes long");
        let (notes_cluster, notes_size) = find_entry(&root_dir, b"NOTES   TXT");
        assert_eq!(notes_size, 11, "notes.txt is 11 bytes long");
        assert_ne!(
            hello_cluster, notes_cluster,
            "two files must not share a cluster"
        );

        // 8. Follow hello.txt to its own cluster. This is the whole point of the exercise, and
        //    `world` can only have come from the model's serve_files answer.
        let (data, csw) = client
            .scsi_read_10(bpb.cluster_lba(hello_cluster), 1)
            .await?;
        assert!(csw.passed(), "READ(10) of the file data failed");
        assert_eq!(data.len(), 512);
        assert_eq!(
            &data[..5],
            b"world",
            "the sectors the host reads must contain the contents the model supplied; got {:?}",
            String::from_utf8_lossy(&data[..5.min(data.len())])
        );

        // And the second file, at its own cluster.
        let (notes, _) = client
            .scsi_read_10(bpb.cluster_lba(notes_cluster), 1)
            .await?;
        assert_eq!(
            &notes[..11],
            b"second file",
            "every file the model listed must be readable"
        );

        // 9. A drive whose contents the model declared is write-protected: a host write would
        //    be editing the model's answer.
        let csw = client
            .scsi_write_10(bpb.cluster_lba(hello_cluster), &[b'X'; 512])
            .await?;
        assert_eq!(
            csw.status,
            Csw::STATUS_FAILED,
            "WRITE(10) must be refused on a write-protected device"
        );
        assert_eq!(
            csw.residue, 512,
            "a refused write transfers nothing, so the whole request is residue"
        );
        let sense = client.scsi_request_sense().await?;
        assert_eq!(sense.key, SENSE_DATA_PROTECT, "sense key should be 0x07");
        assert_eq!(sense.asc, 0x27, "ASC 0x27 is WRITE PROTECTED");

        // And the refusal really did leave the medium alone.
        let (data, _) = client
            .scsi_read_10(bpb.cluster_lba(hello_cluster), 1)
            .await?;
        assert_eq!(
            &data[..5],
            b"world",
            "the blocked write must not have landed"
        );

        // usb_msc_read fired for those reads.
        server.wait_for_log(READ_CALL_LOG, 10).await?;

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        Ok(())
    }

    /// Turning write protection off lets the host write, `usb_msc_write` fires, and closing
    /// the session raises `usb_msc_detached`.
    ///
    /// LLM calls: 4 (startup, attach, write, detach)
    #[tokio::test]
    async fn test_usb_msc_write_and_detach() -> E2EResult<()> {
        let dir = tempfile::tempdir()?;
        let image = scratch_image(&dir, "writable.img");

        let config = NetGetConfig::new(
            "Create a writable USB mass storage device on port {AVAILABLE_PORT}.".to_string(),
        )
        .with_mock({
            let image = image.clone();
            move |mock| {
                mock.on_event("usb_msc_attached")
                    .respond_with_actions(serde_json::json!([
                        { "type": "set_write_protect", "enabled": false }
                    ]))
                    .expect_calls(1)
                    .and()
                    .on_event("usb_msc_write")
                    .respond_with_actions(serde_json::json!([{ "type": "wait_for_more" }]))
                    .expect_at_least(1)
                    .and()
                    .on_event("usb_msc_detached")
                    .respond_with_actions(serde_json::json!([
                        { "type": "show_message", "message": "Mass storage host detached" }
                    ]))
                    .expect_calls(1)
                    .and()
                    .on_instruction_containing("USB mass storage")
                    .respond_with_actions(serde_json::json!([{
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "USB-MassStorage",
                        "instruction": "Allow writes",
                        // The image lives in a temp dir, so the server's image_dir is the
                        // temp root: every disk_image must sit under it (image_dir_test.rs).
                        "startup_params": { "disk_image": image, "image_dir": std::env::temp_dir() }
                    }]))
                    .expect_calls(1)
                    .and()
            }
        });

        let server = start_netget_server(config).await?;

        let mut client = UsbIpClient::attach(server.port).await?;
        // The attach handler disables write protection; the write below depends on it having
        // run, so wait for the call to complete rather than racing it.
        server.wait_for_log(ATTACH_CALL_LOG, 10).await?;

        let mut payload = vec![0u8; 512];
        payload[..11].copy_from_slice(b"netget-mark");
        let lba = 200;

        let csw = client.scsi_write_10(lba, &payload).await?;
        assert!(
            csw.passed(),
            "WRITE(10) should succeed once write protection is off (CSW status {})",
            csw.status
        );
        assert_eq!(csw.residue, 0, "the whole payload was accepted");

        // Read it back over SCSI.
        let (readback, csw) = client.scsi_read_10(lba, 1).await?;
        assert!(csw.passed(), "READ(10) after WRITE(10) failed");
        assert_eq!(
            &readback[..11],
            b"netget-mark",
            "the host must read back exactly what it wrote"
        );

        // The write raised usb_msc_write. Waiting on the write line specifically, not on a
        // call count: the read-back above may also raise usb_msc_read, which would satisfy a
        // count while the write event was still in flight.
        server.wait_for_log(WRITE_CALL_LOG, 10).await?;

        // Detach: close the USB/IP session.
        drop(client);
        server
            .wait_for_log("USB MSC host detached on connection", 10)
            .await?;

        // The bytes really reached the backing image, not just the handler's memory.
        let on_disk = std::fs::read(&image)?;
        let offset = lba as usize * 512;
        assert!(
            on_disk.len() >= offset + 512,
            "image is {} bytes, too short to hold LBA {}",
            on_disk.len(),
            lba
        );
        assert_eq!(
            &on_disk[offset..offset + 11],
            b"netget-mark",
            "the write must be flushed to the disk image file"
        );

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        Ok(())
    }

    /// `mount_disk` swaps in a different image at runtime, and `eject_disk` takes the medium
    /// away again.
    ///
    /// The server starts on an empty scratch image; the model mounts the FAT16 volume when the
    /// host attaches, and ejects it in response to the read event. LLM calls: 3 (startup,
    /// attach, read).
    #[tokio::test]
    async fn test_usb_msc_mount_then_eject() -> E2EResult<()> {
        let (_dir, image) = hello_world_image()?;
        let scratch_dir = tempfile::tempdir()?;
        let scratch = scratch_image(&scratch_dir, "blank.img");

        let config = NetGetConfig::new(
            "Create a USB mass storage device and mount a disk image when a host attaches."
                .to_string(),
        )
        .with_mock({
            let image = image.to_string_lossy().to_string();
            let scratch = scratch.clone();
            move |mock| {
                mock.on_event("usb_msc_attached")
                    .respond_with_actions(serde_json::json!([{
                        "type": "mount_disk",
                        "disk_image": image,
                        "write_protect": true
                    }]))
                    .expect_calls(1)
                    .and()
                    .on_event("usb_msc_read")
                    .respond_with_actions(serde_json::json!([{ "type": "eject_disk" }]))
                    .expect_at_least(1)
                    .and()
                    .on_instruction_containing("USB mass storage")
                    .respond_with_actions(serde_json::json!([{
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "USB-MassStorage",
                        "instruction": "Mount a disk image on attach",
                        // Both images live in temp dirs, so the server's image_dir is the
                        // temp root: every disk_image must sit under it (image_dir_test.rs).
                        "startup_params": { "disk_image": scratch, "image_dir": std::env::temp_dir() }
                    }]))
                    .expect_calls(1)
                    .and()
            }
        });

        let server = start_netget_server(config).await?;

        let mut client = UsbIpClient::attach(server.port).await?;
        server.wait_for_log(ATTACH_CALL_LOG, 10).await?;

        // The mounted image replaced the blank 10MB default, so capacity follows the FAT
        // volume.
        let (last_lba, block_size) = client.scsi_read_capacity_10().await?;
        assert_eq!(block_size, 512);
        assert_eq!(
            last_lba,
            fat16::TOTAL_SECTORS as u32 - 1,
            "mount_disk must serve the mounted image at its own size"
        );

        let (data, csw) = client.scsi_read_10(fat16::cluster_lba(2), 1).await?;
        assert!(csw.passed(), "READ(10) of the mounted image failed");
        assert_eq!(
            &data[..5],
            b"world",
            "the mounted image must be the one the model named"
        );

        // That read raised usb_msc_read, whose handler ejects the medium.
        server.wait_for_log(READ_CALL_LOG, 10).await?;
        server.wait_for_log("USB MSC: Ejecting disk", 10).await?;

        // An ejected device is not ready, and says so consistently.
        let csw = client.scsi_test_unit_ready().await?;
        assert_eq!(
            csw.status,
            Csw::STATUS_FAILED,
            "TEST UNIT READY must fail with no medium"
        );
        let sense = client.scsi_request_sense().await?;
        assert_eq!(sense.key, SENSE_NOT_READY, "sense key should be 0x02");
        assert_eq!(sense.asc, 0x3A, "ASC 0x3A is MEDIUM NOT PRESENT");

        let (data, csw) = client.scsi_read_10(fat16::cluster_lba(2), 1).await?;
        assert_eq!(
            csw.status,
            Csw::STATUS_FAILED,
            "READ(10) must fail after the medium is ejected"
        );
        assert!(
            data.is_empty(),
            "an ejected device must not hand back sector data, got {} bytes",
            data.len()
        );

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        Ok(())
    }

    /// Sector offsets are computed in `usize`, so a disk past 4 GiB addresses correctly.
    ///
    /// `read_sectors` did `(lba * self.bytes_per_sector) as usize` -- a `u32` multiply that
    /// overflows at exactly 4 GiB, which is well inside what `mount_disk` accepted. In a debug
    /// or test build it panicked inside a URB callback (swallowed, with the server still
    /// reporting `Running`); in release it wrapped to a small offset and served the wrong
    /// sectors as though they were the right ones.
    ///
    /// The image is sparse: `open_or_create` calls `set_len`, so no bytes are written.
    #[tokio::test]
    async fn sector_offsets_do_not_overflow_past_four_gibibytes() {
        use ::netget::server::usb::msc::disk::DiskImage;

        let dir = std::env::temp_dir().join(format!(
            "netget-usb-msc-offset-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let path = dir.join("sparse.img");

        // 5 GiB: the first LBA whose byte offset exceeds u32::MAX is 8388608.
        let mut disk = DiskImage::open_or_create(&path, 5 * 1024).expect("sparse image");
        let first_past_32_bits: u32 = 8_388_608;
        assert!(disk.total_sectors() > first_past_32_bits);

        let sectors = disk
            .read_sectors(first_past_32_bits, 1)
            .expect("a sector past the 32-bit byte boundary must be readable");
        assert_eq!(sectors.len(), 512);

        let payload = vec![0xA5u8; 512];
        assert_eq!(
            disk.write_sectors(first_past_32_bits, &payload)
                .expect("and writable"),
            1
        );
        assert_eq!(
            disk.read_sectors(first_past_32_bits, 1).expect("read back"),
            payload,
            "the bytes must come back from the sector they were written to, not a wrapped one"
        );

        drop(disk);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A drive larger than a 32-bit LBA can address is refused rather than truncated.
    ///
    /// `size_mb` was only checked to fit in `u32`, so 4294967295 was accepted -- a 4 PiB
    /// `set_len` whose sector count then had to be truncated by `as u32` to be stored. The
    /// device advertised a capacity bearing no relation to the mapping behind it.
    #[tokio::test]
    async fn a_drive_larger_than_a_32_bit_lba_is_refused() {
        use ::netget::llm::actions::Server;
        use ::netget::server::usb::msc::UsbMscProtocol;

        let protocol = UsbMscProtocol::new();
        let err = protocol
            .execute_action(serde_json::json!({
                "type": "mount_disk",
                "disk_image": "/nonexistent/netget-must-not-create-this.img",
                "size_mb": u32::MAX as u64
            }))
            .expect_err("a 4 PiB drive must be refused");
        let message = format!("{err}");
        assert!(
            message.contains("size_mb"),
            "the refusal must name the parameter that was out of range: {message}"
        );
        assert!(
            !std::path::Path::new("/nonexistent/netget-must-not-create-this.img").exists(),
            "the size must be checked before anything touches the filesystem"
        );
    }
}
