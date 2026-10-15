//! What a mass-storage host gets when the LLM backend fails.
//!
//! The failure is forced by configuring a mock for the *startup* instruction only. The
//! `usb_msc_attached` event then matches no rule, the mock Ollama server answers HTTP 500, and
//! `call_llm` returns `Err` — the same shape as a real backend outage.
//!
//! `usb_msc_attached` is the one event whose answer the host depends on: it is where the model
//! says what is on the drive (`serve_files`). Before this path existed, a failure there left the
//! device serving its default in-memory FAT16 volume — empty, but perfectly valid. A host would
//! mount it and find nothing, with no way to tell "the model was unreachable" from "the model
//! served an empty disk". That is the fail-open shape the project's OAuth2 post-mortem is about,
//! wearing a filesystem.
//!
//! SCSI already has the right words for a drive with nothing in it, so the device now says them:
//! CHECK CONDITION with sense NOT READY / MEDIUM NOT PRESENT (02/3A/00), which is exactly what
//! `eject_disk` produces for a deliberate ejection. INQUIRY still answers — that is how a host
//! learns the device exists at all, and refusing it would look like a broken device rather than
//! an empty one.
//!
//! Read and write events are deliberately *not* covered by any of this: they are notifications
//! about transfers the image has already served, so there is nothing the host is waiting for and
//! nothing to withdraw. They log at ERROR and stop.

#[cfg(all(unix, feature = "libusb"))]
mod usb_msc_llm_failure {
    use crate::helpers::usbip_client::{Csw, UsbIpClient};
    use crate::helpers::*;

    /// The dual-logged ERROR the LLM-failure path emits.
    const LLM_FAILURE_LOG: &str = "LLM call failed for USB MSC connection";
    /// Emitted *after* the medium has been withdrawn, so waiting on it removes the race between
    /// the log line and the ejection.
    const EJECTED_LOG: &str = "ejected the medium after the attach handler failed";

    /// SCSI sense: NOT READY / MEDIUM NOT PRESENT.
    const SENSE_NOT_READY: u8 = 0x02;
    const ASC_MEDIUM_NOT_PRESENT: u8 = 0x3A;

    #[tokio::test]
    async fn test_usb_msc_reports_medium_not_present_when_llm_fails() -> E2EResult<()> {
        let config = NetGetConfig::new_no_scripts(
            "Pretend to be a USB drive on port {AVAILABLE_PORT}.".to_string(),
        )
        .with_mock(|mock| {
            mock.on_instruction_containing("USB drive")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "USB-MassStorage",
                    "instruction": "Serve whatever the model decides"
                }]))
                .expect_calls(1)
                .and()
            // Deliberately NO rule for usb_msc_attached: the mock answers 500, which is what
            // drives the server down its LLM-failure path.
        });

        let mut server = start_netget_server(config).await?;
        assert!(server.is_running(), "USB MSC server should be running");

        let mut client = UsbIpClient::attach(server.port).await?;

        // The attach handler fails, and the medium is taken away. Wait for the *post*-ejection
        // line: the ERROR is logged first, so waiting on that alone would race the ejection and
        // a TEST UNIT READY could still catch a mounted volume.
        server.wait_for_log(LLM_FAILURE_LOG, 15).await?;
        server.wait_for_log(EJECTED_LOG, 10).await?;

        // 1. The device must still enumerate and identify itself. A host that cannot even run
        //    INQUIRY sees a broken device, not an empty one, and the distinction is the whole
        //    point of answering rather than going quiet.
        let inquiry = client.scsi_inquiry().await?;
        assert_eq!(inquiry.len(), 36, "standard INQUIRY data is 36 bytes");
        assert_eq!(inquiry[0], 0x00, "direct-access block device");
        assert_eq!(&inquiry[8..16], b"NetGet  ", "vendor id, space padded");

        // 2. TEST UNIT READY — the command a host uses to ask exactly this question.
        let csw = client.scsi_test_unit_ready().await?;
        assert_eq!(
            csw.status,
            Csw::STATUS_FAILED,
            "TEST UNIT READY must fail when the model never said what the drive contains; an \
             empty-but-valid volume is indistinguishable from a deliberate one"
        );

        // 3. REQUEST SENSE — *why* it failed. This is the assertion that pins the vocabulary:
        //    any other sense would tell the host something untrue.
        let sense = client.scsi_request_sense().await?;
        assert_eq!(
            sense.key, SENSE_NOT_READY,
            "sense key must be NOT READY (0x02), got {:#04x}",
            sense.key
        );
        assert_eq!(
            sense.asc, ASC_MEDIUM_NOT_PRESENT,
            "ASC must be MEDIUM NOT PRESENT (0x3A), got {:#04x}",
            sense.asc
        );
        assert_eq!(sense.ascq, 0x00, "ASCQ must be 0x00");

        // 4. And the transfer a host would actually attempt must be refused rather than served
        //    from a volume nobody asked for.
        let (data, csw) = client.scsi_read_10(0, 1).await?;
        assert_eq!(
            csw.status,
            Csw::STATUS_FAILED,
            "READ(10) must be refused while no medium is present"
        );
        assert!(
            data.is_empty(),
            "a refused READ(10) must transfer no sectors, got {} byte(s)",
            data.len()
        );
        assert_eq!(
            csw.residue, 512,
            "a refused read transfers nothing, so the whole request is residue"
        );

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        Ok(())
    }
}
