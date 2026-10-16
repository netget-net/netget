# AFP client tests

- `real_server_test.rs` — the evidence: netatalk 4.6's `afpd`, unprivileged in a temporary
  directory with one guest volume, through a recording relay. The client's python policy
  (`TOUR` in `support.rs`) lists, reads (text and bytes), describes, writes, creates and deletes;
  the test asserts each effect on disk and runs tshark over both connections. Fails rather than
  skips without `afpd` (`brew install netatalk`, or `sh scripts/test-peers/build-netatalk.sh`).
- `e2e_test.rs` — against NetGet's own AFP server, a regression only: cleartext login and its
  refusals, the follow-up depth bound, a model that never answers, a silent server and an
  oversized reply.
