mod command_channel_test;
// Both e2e_test and command_channel_test drive NetGet's own MongoDB server, which is behind
// the separate `mongodb-server` feature — see the header of each.
pub mod e2e_test;
