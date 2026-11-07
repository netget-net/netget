//! `netget::server::snmp` — the BER depth guard and the `rasn` decoder it guards.
//!
//! This is the same shape as the bencode target and for the same reason: `check_ber_structure`
//! exists because BER is recursive by construction: `rasn` 0.18 counted nothing, so one
//! unauthenticated UDP datagram of nested constructed tags recursed until the guard page, and
//! `rasn` 0.30's own bound (128 levels) is a second line rather than the only one. It also
//! decodes values — integers, OIDs, strings, times — that the guard does not look inside, and a
//! panic there is the other half of what this target searches for.
//! `SnmpServer::parse_snmp_message` runs the guard and then `rasn::ber::decode`
//! in sequence, which is exactly the pair whose contract matters:
//!
//! **anything the guard accepts, the decoder must survive.**
//!
//! Fuzzing the guard alone would prove only that the guard does not crash — which is the
//! easy half, and not the half that killed the process.

#![no_main]

use libfuzzer_sys::fuzz_target;
use netget::server::snmp::{check_ber_structure, SnmpServer, MAX_BER_DEPTH};

fuzz_target!(|data: &[u8]| {
    let verdict = check_ber_structure(data, MAX_BER_DEPTH);

    assert_eq!(
        verdict.is_ok(),
        check_ber_structure(data, MAX_BER_DEPTH).is_ok(),
        "check_ber_structure disagreed with itself"
    );

    // The pair. A stack overflow inside `rasn` here is a SIGSEGV, not a panic, so libFuzzer
    // reports it as a crash — the class nothing else in this suite can observe.
    let _ = SnmpServer::parse_snmp_message(data);
});
