//! FUSE local filesystem server tests. `tree_test` and `tree_links_test` run on every Unix; the
//! Linux suites need `/dev/fuse` and fusermount3, the macOS ones FUSE-T, and both fail rather
//! than skip without them. The macOS mount tests run only by hand, with
//! `NETGET_FUSE_MACOS_MOUNT=1` (`support::MACOS_MOUNT_GATE`): a FUSE-T mount is an NFS mount, and
//! Apple's NFS client can panic the host.
pub mod tree_links_test;
pub mod tree_test;

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod appledouble_test;

#[cfg(target_os = "linux")]
pub mod bounds_test;
#[cfg(target_os = "linux")]
pub mod links_xattrs_test;
#[cfg(target_os = "macos")]
pub mod macos_bounds_test;
#[cfg(target_os = "macos")]
pub mod macos_tools_test;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod pjdfstest_test;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod support;
#[cfg(target_os = "linux")]
pub mod tools_test;
