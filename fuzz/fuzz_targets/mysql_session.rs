//! A MySQL client's byte stream — `opensrv_mysql::AsyncMysqlIntermediary::run_on`, behind
//! NetGet's `PacketLimitReader`.
//!
//! `opensrv-mysql` 0.7.0 owns the whole server-side protocol loop: packet reassembly
//! (`packet()`, whose fragment `assert_eq!`s panic on misnumbered chains), the handshake
//! response parser, `set_seq(seq + 1)` on every packet the client numbers, and command
//! dispatch. NetGet's server puts `PacketLimitReader` beneath it, which decides every packet
//! from its 4-byte header — size and sequence id — before the crate reads the payload.
//!
//! The target replays the input as everything a client sends after the greeting, through the
//! same reader, into the real loop. A shim of its own stands in for NetGet's `MysqlHandler`
//! (which needs a running `AppState` and a model): it accepts every login and answers every
//! command with OK, so the fuzzer reaches the command loop. Its `on_execute` deliberately does
//! not iterate the parameters — that decoder (`params.rs`) panics on malformed input in ways
//! the replacement of NetGet's COM_STMT_EXECUTE path addresses, and finding it again every few
//! seconds would bury everything else.
//!
//! **Anything the reader passes, the crate must survive.** `cargo fuzz` builds with debug
//! assertions, so overflow checks are on, which is exactly the build in which `seq + 1` on a
//! sequence id of 255 panics.

#![no_main]

use libfuzzer_sys::fuzz_target;
use netget::server::mysql::packet_limit::{PacketLimitReader, PacketLimitTrip};
use opensrv_mysql::{
    AsyncMysqlIntermediary, AsyncMysqlShim, Column, OkResponse, ParamParser, QueryResultWriter,
    StatementMetaWriter,
};
use std::io;
use std::sync::Arc;
use tokio::io::AsyncWrite;

struct Shim;

#[async_trait::async_trait]
impl<W: AsyncWrite + Send + Unpin> AsyncMysqlShim<W> for Shim {
    type Error = io::Error;

    async fn on_prepare<'a>(
        &'a mut self,
        _query: &'a str,
        info: StatementMetaWriter<'a, W>,
    ) -> io::Result<()> {
        let none: &[Column] = &[];
        info.reply(1, none, none).await
    }

    async fn on_execute<'a>(
        &'a mut self,
        _id: u32,
        _params: ParamParser<'a>,
        results: QueryResultWriter<'a, W>,
    ) -> io::Result<()> {
        results.completed(OkResponse::default()).await
    }

    async fn on_close<'a>(&'a mut self, _stmt: u32)
    where
        W: 'async_trait,
    {
    }

    async fn on_query<'a>(
        &'a mut self,
        _query: &'a str,
        results: QueryResultWriter<'a, W>,
    ) -> io::Result<()> {
        results.completed(OkResponse::default()).await
    }
}

fuzz_target!(|data: &[u8]| {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("a current-thread runtime");
    runtime.block_on(async {
        let trip = Arc::new(PacketLimitTrip::default());
        let reader = PacketLimitReader::new(data, trip);
        let _ = AsyncMysqlIntermediary::run_on(Shim, reader, tokio::io::sink()).await;
    });
});
