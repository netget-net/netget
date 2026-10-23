//! `netget::server::stratum_v2` — what every Stratum V2 role decodes from a peer once the
//! Noise session is up: every Common, Mining, Job Declaration and Template Distribution message
//! (`wire::Message::decode`), and the Bitcoin structures the template provider and job
//! declarator parse out of them (`bitcoin::Tx::parse` for SubmitSolution's coinbase and every
//! supplied transaction, `bitcoin::parse_output_vector` for a token's required outputs, the
//! job declarator's split of a declared coinbase, BIP 34 heights and compact targets).
//!
//! The first byte is the message type and the rest its payload. What is checked: nothing
//! panics; a decoded message re-encodes and decodes to itself; a parsed transaction
//! re-serialises to exactly the bytes it came from (every CompactSize is canonical, so there is
//! one encoding).
//!
//! Nothing here recurses — a transaction's inputs, outputs and witness items are flat lists —
//! so there is no depth to bound. What a peer can push against is counts: SEQ0_64K and
//! CompactSize counts are checked against the bytes left before anything is allocated. The
//! corpus carries those shapes: `seq_count_bomb` (a DeclareMiningJob whose wtxid list declares
//! 65535 entries in a few bytes), `tx_count_bomb` (a SubmitSolution whose coinbase declares
//! 2^32 inputs) and `transaction_list_bomb` (a RequestTransactionData.Success declaring 65535
//! transactions of 16 MiB each). Work selection adds SetCustomMiningJob, whose output vector the
//! pool parses (`custom_job_outputs_bomb` declares 2^32 - 1 outputs in five bytes) and whose
//! merkle path is a SEQ0_255 (`custom_job_path_bomb` declares 255 hashes and carries one).

#![no_main]

use libfuzzer_sys::fuzz_target;
use netget::server::stratum_v2::bitcoin::{self as btc, Tx};
use netget::server::stratum_v2::job_declarator;
use netget::server::stratum_v2::wire::{Frame, Message};

fuzz_target!(|data: &[u8]| {
    let Some((&msg_type, payload)) = data.split_first() else {
        return;
    };
    let frame = Frame {
        extension_type: 0,
        msg_type,
        payload: payload.to_vec(),
    };
    if let Ok(message) = Message::decode(&frame) {
        let again = Message::decode(&message.encode()).expect("a decoded message re-encodes");
        assert_eq!(again, message);
        match &message {
            Message::SubmitSolution { coinbase_tx, .. } => parse_tx(coinbase_tx),
            Message::ProvideMissingTransactionsSuccess {
                transaction_list, ..
            }
            | Message::RequestTransactionDataSuccess {
                transaction_list, ..
            } => transaction_list.iter().for_each(|t| parse_tx(t)),
            Message::AllocateMiningJobTokenSuccess {
                coinbase_outputs, ..
            } => {
                let _ = btc::parse_output_vector(coinbase_outputs, 16);
            }
            Message::DeclareMiningJob {
                coinbase_tx_prefix,
                coinbase_tx_suffix,
                ..
            } => {
                if let Ok((tx, extranonce)) =
                    job_declarator::split_coinbase(coinbase_tx_prefix, coinbase_tx_suffix)
                {
                    assert!(extranonce <= job_declarator::MAX_EXTRANONCE);
                    let _ = btc::bip34_height(&tx.inputs[0].script_sig);
                }
            }
            Message::TemplateSetNewPrevHash { nbits, .. } | Message::PushSolution { nbits, .. } => {
                let _ = btc::compact_to_target(*nbits);
            }
            Message::SetCustomMiningJob {
                nbits,
                coinbase_tx_outputs,
                ..
            } => {
                let _ = btc::compact_to_target(*nbits);
                // The bound the pool parses a custom job's outputs with.
                let _ = btc::parse_output_vector(coinbase_tx_outputs, 255);
            }
            _ => {}
        }
    }
    parse_tx(data);
    let _ = btc::parse_output_vector(data, 16);
    let _ = btc::bip34_height(data);
});

fn parse_tx(bytes: &[u8]) {
    if let Ok(tx) = Tx::parse(bytes) {
        assert_eq!(tx.serialize(true), bytes, "one encoding per transaction");
        let _ = (tx.txid(), tx.wtxid(), tx.weight());
    }
}
