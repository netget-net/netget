//! FUSE local filesystem server tests. `tree_test` runs on every Unix; the rest need Linux,
//! `/dev/fuse` and fusermount3, and fail rather than skip without them.
pub mod tree_test;

#[cfg(target_os = "linux")]
pub mod bounds_test;
#[cfg(target_os = "linux")]
pub mod pjdfstest_test;
#[cfg(target_os = "linux")]
pub mod support;
#[cfg(target_os = "linux")]
pub mod tools_test;
