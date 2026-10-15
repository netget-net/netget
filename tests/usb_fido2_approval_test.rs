//! FIDO2 approval manager: concurrency and identity.
//!
//! The single-request contract — approve, deny, unanswered-denies, unknown-id-errors — is
//! asserted in `tests/server/usb_fido2/e2e_test.rs::test_approval_manager_contract`, next to the
//! end-to-end tests that depend on it. What is left here is the part those cannot reach: **more
//! than one request in flight at once**, which is what the approval id exists for.
//!
//! That matters because the model answers by quoting an id back. If ids were not unique per
//! manager, or if resolving one request could satisfy another, an approval meant for one relying
//! party would be applied to a different one — and since an unanswered request denies, the
//! victim would look like a timeout rather than a mix-up.
//!
//! These used to call `list_pending().await`, `approve(id).await` and `deny(id).await`. The
//! whole manager was async, reached from the synchronous USB/IP handler through
//! `tokio::runtime::Handle::current().block_on(...)`, which panics on a tokio worker: *"Cannot
//! block the current thread from within a runtime"*. It is synchronous now, and these tests
//! calling it without `.await` is the visible half of that fix.

#[cfg(all(unix, feature = "libusb"))]
use netget::server::usb::fido2::approval::*;
#[cfg(all(unix, feature = "libusb"))]
use std::time::Duration;

#[cfg(all(unix, feature = "libusb"))]
fn details(rp: &str, operation: OperationType) -> ApprovalDetails {
    ApprovalDetails {
        operation,
        rp_id: rp.to_string(),
        user_name: Some(format!("user@{}", rp)),
        credential_count: 0,
    }
}

/// Two requests open at once are resolved independently, each by its own id.
#[cfg(all(unix, feature = "libusb"))]
#[tokio::test]
async fn concurrent_requests_are_resolved_by_id() {
    let manager = ApprovalManager::new(ApprovalConfig {
        auto_approve: false,
        timeout: Duration::from_secs(5),
        timeout_decision: ApprovalDecision::Denied,
    });

    let (first, first_rx) = manager.open(details("first.example", OperationType::Register), None);
    let (second, second_rx) =
        manager.open(details("second.example", OperationType::Authenticate), None);

    assert_ne!(
        first, second,
        "each open request must get its own id, or the model cannot address them separately"
    );

    let pending = manager.list_pending();
    assert_eq!(pending.len(), 2, "both requests must be listed as pending");
    assert_eq!(
        pending.iter().map(|p| p.id).collect::<Vec<_>>(),
        vec![first, second],
        "list_pending must be ordered by id, so the model sees a stable list"
    );
    assert_eq!(
        pending[1].details.rp_id, "second.example",
        "each entry must carry its own relying party, not the other's"
    );

    // Approve the second and deny the first: crossing them over would be invisible if the
    // manager keyed on anything but the id.
    manager.approve(second).expect("second is pending");
    manager.deny(first).expect("first is pending");

    assert_eq!(
        manager.wait(second, second_rx).await,
        ApprovalDecision::Approved
    );
    assert_eq!(
        manager.wait(first, first_rx).await,
        ApprovalDecision::Denied
    );

    assert!(
        manager.list_pending().is_empty(),
        "resolved requests must leave the pending list"
    );
}

/// Clones share the id counter.
///
/// `Clone` used to build a fresh `AtomicU64` seeded from the original's current value, so two
/// clones would go on to issue the *same* ids from that point. The connection task and the
/// action path hold different clones of the same manager, which is exactly the situation where
/// duplicate ids would let one decision resolve another request.
#[cfg(all(unix, feature = "libusb"))]
#[tokio::test]
async fn cloned_managers_share_one_id_space() {
    let manager = ApprovalManager::new(ApprovalConfig::default());
    let clone = manager.clone();

    let (a, _rx_a) = manager.open(details("a.example", OperationType::Register), None);
    let (b, _rx_b) = clone.open(details("b.example", OperationType::Register), None);

    assert_ne!(
        a, b,
        "a clone must not reissue an id the original handed out"
    );
    assert_eq!(
        clone.list_pending().len(),
        2,
        "a clone must see the same pending requests, not its own copy"
    );

    // And a decision made through the clone reaches a request opened through the original.
    clone
        .approve(a)
        .expect("the clone must find the original's request");
}

/// Auto-approve short-circuits without ever registering a pending request.
#[cfg(all(unix, feature = "libusb"))]
#[tokio::test]
async fn auto_approve_leaves_nothing_pending() {
    let manager = ApprovalManager::new(ApprovalConfig {
        auto_approve: true,
        ..Default::default()
    });

    let (id, decision) = manager
        .request_approval(details("example.com", OperationType::Register), None)
        .await;

    assert_eq!(decision, ApprovalDecision::Approved);
    assert!(id > 0, "approval ids start at 1");
    assert!(
        manager.list_pending().is_empty(),
        "an auto-approved request must not linger in the pending list"
    );
}
