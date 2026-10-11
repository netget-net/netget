//! The Observe and Block-wise tables held directly, for the rules the wire cannot reach.
//!
//! `observe::Observers` and `blockwise::{Transfers, Uploads}` are pure and take `now`, so two
//! kinds of rule are tested here rather than in `observe_blockwise_bounds_test.rs`:
//!
//! - **The shared caps.** `MAX_OBSERVERS` and `MAX_UPLOADS` sit above the per-IP caps, so
//!   reaching them takes more source IPs than loopback offers on every platform the suite
//!   runs on. Here the addresses are just values.
//! - **Rules that need a clock.** A Block2 entry's TTL that a hit does not renew, and an
//!   observer's expiry after `OBSERVER_MAX_AGE` without confirmation, are a minute and a day
//!   long; `now` is passed in instead of waited for.

use netget::server::coap::blockwise::{
    Representation, ResourceKey, Transfers, UploadKey, UploadStep, Uploads, MAX_UPLOADS,
    MAX_UPLOADS_PER_IP, TRANSFER_SERVE_FACTOR, TRANSFER_TTL,
};
use netget::server::coap::codec::{BlockValue, CODE_CONTENT, CODE_PUT, CODE_SERVICE_UNAVAILABLE};
use netget::server::coap::observe::{
    Observer, Observers, Registered, MAX_OBSERVERS, MAX_OBSERVERS_PER_IP, OBSERVER_MAX_AGE,
    RECENT_NOTIFICATIONS,
};
use netget::server::connection::ConnectionId;
use netget::utils::clock::Instant;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

fn addr(ip: u32, port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::from(0x0A00_0000 + ip)), port)
}

fn observer(peer: SocketAddr, token: &[u8]) -> Observer {
    Observer {
        peer,
        token: token.to_vec(),
        path: "/temp".into(),
        query: None,
        block_szx: None,
        connection_id: ConnectionId::new(1),
    }
}

fn hours(h: u64) -> Duration {
    Duration::from_secs(h * 60 * 60)
}

#[test]
fn the_shared_observer_cap_holds_across_ips() {
    let now = Instant::now();
    let mut table = Observers::default();
    let ips = MAX_OBSERVERS / MAX_OBSERVERS_PER_IP;
    for ip in 0..ips as u32 {
        for n in 0..MAX_OBSERVERS_PER_IP {
            let o = observer(addr(ip, 5683 + n as u16), &[n as u8]);
            assert_eq!(table.register(o, now), Registered::Added, "ip {ip} #{n}");
        }
    }
    assert_eq!(table.len(), MAX_OBSERVERS);
    // A new IP, under its own cap, is refused by the shared one.
    assert_eq!(
        table.register(observer(addr(1000, 5683), b"x"), now),
        Registered::Full
    );
    // A full IP is refused by its own cap first.
    assert_eq!(
        table.register(observer(addr(0, 9999), b"x"), now),
        Registered::PeerFull
    );
    // Replacing an existing registration is neither.
    assert_eq!(
        table.register(observer(addr(0, 5683), &[0]), now),
        Registered::Replaced
    );
    assert_eq!(table.len(), MAX_OBSERVERS);
}

#[test]
fn an_unconfirmed_observer_expires_and_an_acknowledged_one_is_renewed() {
    let t0 = Instant::now();
    let mut table = Observers::default();
    let quiet = addr(1, 5683);
    let live = addr(2, 5683);
    table.register(observer(quiet, b"q"), t0);
    table.register(observer(live, b"l"), t0);

    // Unconfirmed for half the maximum age: the next notification must be Confirmable.
    let half = OBSERVER_MAX_AGE / 2;
    assert!(!table.needs_confirmation(quiet, b"q", t0 + half - Duration::from_secs(1)));
    assert!(table.needs_confirmation(quiet, b"q", t0 + half));

    // The live observer acknowledges a Confirmable notification at 13 h.
    let t13 = t0 + hours(13);
    table.record(live, 7, b"l", true);
    assert!(table.awaiting_ack(live, 7));
    assert!(table.acknowledge(live, 7, t13));
    assert!(!table.awaiting_ack(live, 7));
    assert!(!table.needs_confirmation(live, b"l", t13));

    // Just short of the maximum age nothing expires; at it, only the quiet one does.
    assert!(table
        .expire(t0 + OBSERVER_MAX_AGE - Duration::from_secs(1))
        .is_empty());
    let expired = table.expire(t0 + OBSERVER_MAX_AGE);
    assert_eq!(expired.len(), 1);
    assert_eq!(expired[0].peer, quiet);
    assert_eq!(table.all().len(), 1);

    // The acknowledgement renewed the live one for a full maximum age from 13 h.
    assert!(table
        .expire(t13 + OBSERVER_MAX_AGE - Duration::from_secs(1))
        .is_empty());
    assert_eq!(table.expire(t13 + OBSERVER_MAX_AGE).len(), 1);
    assert!(table.is_empty());
}

#[test]
fn an_expired_observer_takes_its_pending_notification_with_it() {
    let t0 = Instant::now();
    let mut table = Observers::default();
    let peer = addr(1, 5683);
    table.register(observer(peer, b"t"), t0);
    table.record(peer, 1, b"t", true);
    assert_eq!(table.pending_len(), 1);
    table.expire(t0 + OBSERVER_MAX_AGE);
    assert_eq!(table.pending_len(), 0);
    assert!(!table.awaiting_ack(peer, 1));
}

#[test]
fn a_pending_confirmable_notification_outlives_the_recent_window() {
    let now = Instant::now();
    let mut table = Observers::default();
    let silent = addr(1, 5683);
    let chatty = addr(2, 5683);
    table.register(observer(silent, b"s"), now);
    table.register(observer(chatty, b"c"), now);
    table.record(silent, 1, b"s", true);
    for mid in 0..=RECENT_NOTIFICATIONS as u16 {
        table.record(chatty, 1000 + mid, b"c", false);
    }
    assert!(
        table.awaiting_ack(silent, 1),
        "out of the RST window, still waited for: not taken as acknowledged"
    );
    assert!(
        table.acknowledge(silent, 1, now),
        "and still matchable by its ACK"
    );
    assert!(!table.awaiting_ack(silent, 1));
    // A RST to a notification still in the pending map ends the observation too.
    table.record(silent, 2, b"s", true);
    for mid in 0..=RECENT_NOTIFICATIONS as u16 {
        table.record(chatty, 3000 + mid, b"c", false);
    }
    assert_eq!(table.reset(silent, 2).map(|o| o.peer), Some(silent));
    assert_eq!(table.pending_len(), 0);
}

#[test]
fn a_newer_confirmable_notification_supersedes_the_older_one() {
    let now = Instant::now();
    let mut table = Observers::default();
    let peer = addr(1, 5683);
    table.register(observer(peer, b"t"), now);
    table.record(peer, 1, b"t", true);
    table.record(peer, 2, b"t", true);
    assert!(
        !table.awaiting_ack(peer, 1),
        "only the newest is retransmitted"
    );
    assert!(table.awaiting_ack(peer, 2));
    assert_eq!(table.pending_len(), 1, "at most one pending per observer");
    table.settle(peer, 2);
    assert_eq!(table.pending_len(), 0);
}

fn key(ip: u32, path: &str) -> ResourceKey {
    ResourceKey {
        peer: addr(ip, 5683),
        path: path.into(),
        query: None,
    }
}

const FIRST_BLOCK: BlockValue = BlockValue {
    num: 0,
    more: true,
    szx: 6,
};

#[test]
fn a_cache_hit_does_not_renew_the_entry_s_age() {
    let t0 = Instant::now();
    let mut cache = Transfers::default();
    let rep = Arc::new(Representation::new(CODE_CONTENT, vec![b'x'; 3000], None));
    cache.insert(key(1, "/big"), rep.clone(), 1024, t0);
    let second = BlockValue {
        num: 1,
        ..FIRST_BLOCK
    };
    let later = t0 + TRANSFER_TTL - Duration::from_secs(1);
    assert!(cache.get(&key(1, "/big"), second, later).is_some());
    // Serving the hit re-inserts the same representation; that must not renew it either.
    assert_eq!(cache.insert(key(1, "/big"), rep, 1024, later), None);
    assert!(
        cache
            .get(&key(1, "/big"), second, t0 + TRANSFER_TTL)
            .is_none(),
        "TRANSFER_TTL after it was cached, the entry is gone however often it was hit"
    );
    assert!(cache.is_empty());
}

#[test]
fn a_cached_entry_serves_at_most_its_budget() {
    let now = Instant::now();
    let mut cache = Transfers::default();
    let len = 2048;
    let rep = Arc::new(Representation::new(CODE_CONTENT, vec![b'x'; len], None));
    cache.insert(key(1, "/big"), rep.clone(), 1024, now);
    let mut served = 1024;
    let second = BlockValue {
        num: 1,
        ..FIRST_BLOCK
    };
    while served + 1024 <= len * TRANSFER_SERVE_FACTOR {
        assert!(cache.get(&key(1, "/big"), second, now).is_some());
        served += 1024;
    }
    assert_eq!(served, len * TRANSFER_SERVE_FACTOR);
    assert!(cache.get(&key(1, "/big"), second, now).is_none());
    assert!(cache.is_empty(), "the spent entry was evicted");

    // A block past the end costs nothing, so it never exhausts an entry: it is a 4.02.
    cache.insert(key(1, "/big"), rep, len * TRANSFER_SERVE_FACTOR, now);
    let past = BlockValue {
        num: 9,
        ..FIRST_BLOCK
    };
    assert!(cache.get(&key(1, "/big"), past, now).is_some());
}

fn upload_key(ip: u32, port: u16, path: &str) -> UploadKey {
    UploadKey {
        resource: ResourceKey {
            peer: addr(ip, port),
            path: path.into(),
            query: None,
        },
        method: CODE_PUT,
    }
}

fn start(table: &mut Uploads, key: UploadKey, now: Instant) -> UploadStep {
    let block = BlockValue {
        num: 0,
        more: true,
        szx: 2,
    };
    table.accept(key, block, &[b'u'; 64], None, now)
}

#[test]
fn the_shared_upload_cap_holds_across_ips_and_one_ip_evicts_only_its_own() {
    let t0 = Instant::now();
    let mut table = Uploads::default();
    let ips = MAX_UPLOADS / MAX_UPLOADS_PER_IP;
    let mut tick = 0u64;
    let mut at = || {
        tick += 1;
        t0 + Duration::from_millis(tick)
    };
    for ip in 0..ips as u32 {
        for n in 0..MAX_UPLOADS_PER_IP {
            let step = start(&mut table, upload_key(ip, 5683, &format!("/u/{n}")), at());
            assert!(matches!(step, UploadStep::Continue(_)), "ip {ip} #{n}");
        }
    }
    assert_eq!(table.len(), MAX_UPLOADS);

    // A new IP is refused by the shared cap.
    match start(&mut table, upload_key(1000, 5683, "/u/0"), at()) {
        UploadStep::Refuse { code, .. } => assert_eq!(code, CODE_SERVICE_UNAVAILABLE),
        other => panic!("expected 5.03, got {other:?}"),
    }

    // An IP at its own cap — from another port — evicts its own oldest, not anyone else's.
    let step = start(&mut table, upload_key(0, 7777, "/u/new"), at());
    assert!(matches!(step, UploadStep::Continue(_)));
    assert_eq!(table.len(), MAX_UPLOADS);
    let next = BlockValue {
        num: 1,
        more: false,
        szx: 2,
    };
    match table.accept(upload_key(0, 5683, "/u/0"), next, b"end", None, at()) {
        UploadStep::Refuse { decision, .. } => {
            assert_eq!(
                decision, "refused_upload_out_of_order",
                "ip 0's oldest is gone"
            )
        }
        other => panic!("expected the evicted upload to be gone, got {other:?}"),
    }
    match table.accept(upload_key(0, 5683, "/u/1"), next, b"end", None, at()) {
        UploadStep::Complete { body, .. } => assert_eq!(body.len(), 67),
        other => panic!("ip 0's newer upload survives, got {other:?}"),
    }
    match table.accept(upload_key(1, 5683, "/u/0"), next, b"end", None, at()) {
        UploadStep::Complete { body, .. } => assert_eq!(body.len(), 67),
        other => panic!("another IP's upload is untouched, got {other:?}"),
    }
}
