//! The AppleDouble sidecar store (`src/server/fuse/appledouble.rs`) without a mount: what macOS
//! writes into `._name` files on a FUSE-T volume is accepted and discarded, and the attributes
//! served for a sidecar never flap. Pure, so it runs wherever the FUSE server builds — no mount,
//! no FUSE-T.
use netget::server::fuse::appledouble::{
    is_appledouble, Sidecars, FIRST_INO, MAX_SIDECARS, MAX_SIDECAR_LEN,
};
use netget::utils::clock::{SystemTime, UNIX_EPOCH};
use std::time::Duration;

fn at(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}

#[test]
fn only_dot_underscore_names_are_sidecars() {
    assert!(is_appledouble(b"._README.txt"));
    assert!(is_appledouble(b"._"));
    assert!(!is_appledouble(b"README.txt"));
    assert!(!is_appledouble(b"_x"));
    assert!(!is_appledouble(b"."));
    assert!(Sidecars::owns(FIRST_INO) && !Sidecars::owns(2) && !Sidecars::owns(FIRST_INO - 1));
}

#[test]
fn a_new_sidecar_is_a_stable_empty_0644_file_of_its_creator() {
    let mut s = Sidecars::new();
    let a = s.create(1, "._a", 501, 20, at(1000)).unwrap();
    assert!(a.ino >= FIRST_INO);
    assert_eq!(
        (a.size, a.perm, a.uid, a.gid, a.nlink),
        (0, 0o644, 501, 20, 1)
    );
    assert_eq!((a.mtime, a.ctime), (at(1000), at(1000)));
    // Asked again, nothing moves.
    assert_eq!(s.attr(a.ino), Some(a.clone()));
    assert_eq!(s.lookup(1, "._a"), Some(a.clone()));
    assert_eq!(s.lookup(2, "._a"), None);
    // Creating it again returns it unchanged.
    assert_eq!(s.create(1, "._a", 0, 0, at(5000)).unwrap(), a);
    assert_eq!(s.count(), 1);
}

#[test]
fn writes_keep_only_the_length_and_move_times_forward() {
    let mut s = Sidecars::new();
    let ino = s.create(1, "._a", 501, 20, at(1000)).unwrap().ino;
    assert_eq!(s.write(ino, 0, 100, at(2000)), Ok(100));
    let a = s.attr(ino).unwrap();
    assert_eq!((a.size, a.mtime, a.ctime), (100, at(2000), at(2000)));
    // A write lower down does not shrink it; reads are zeroes up to the length.
    assert_eq!(s.write(ino, 10, 5, at(3000)), Ok(5));
    assert_eq!(s.attr(ino).unwrap().size, 100);
    assert_eq!(s.read(ino, 0, 4096).unwrap(), vec![0u8; 100]);
    assert_eq!(s.read(ino, 90, 50).unwrap(), vec![0u8; 10]);
    assert!(s.read(ino, 200, 10).unwrap().is_empty());
    // A clock that reads earlier never takes the times backwards.
    s.write(ino, 0, 1, at(10)).unwrap();
    let b = s.attr(ino).unwrap();
    assert!(b.mtime > at(3000) && b.ctime > at(3000));
    // An empty write changes nothing.
    s.write(ino, 0, 0, at(9000)).unwrap();
    assert_eq!(s.attr(ino).unwrap(), b);
}

#[test]
fn length_and_count_are_bounded() {
    let mut s = Sidecars::new();
    let ino = s.create(1, "._a", 501, 20, at(1)).unwrap().ino;
    assert_eq!(s.write(ino, MAX_SIDECAR_LEN - 1, 1, at(2)), Ok(1));
    assert_eq!(s.write(ino, MAX_SIDECAR_LEN, 1, at(3)), Err(libc::EFBIG));
    assert_eq!(s.write(ino, u64::MAX, 1, at(3)), Err(libc::EFBIG));
    assert_eq!(
        s.setattr(ino, Some(MAX_SIDECAR_LEN + 1), at(3)),
        Err(libc::EFBIG)
    );
    assert_eq!(s.attr(ino).unwrap().size, MAX_SIDECAR_LEN);
    for i in 1..MAX_SIDECARS {
        s.create(1, &format!("._{i}"), 501, 20, at(4)).unwrap();
    }
    assert_eq!(s.count(), MAX_SIDECARS);
    assert_eq!(s.create(1, "._one-more", 501, 20, at(5)), Err(libc::ENOSPC));
    // An existing one is still found past the bound.
    assert!(s.create(1, "._a", 501, 20, at(5)).is_ok());
}

#[test]
fn only_a_size_changes_a_sidecar_on_setattr() {
    let mut s = Sidecars::new();
    let ino = s.create(1, "._a", 501, 20, at(1000)).unwrap().ino;
    s.write(ino, 0, 50, at(2000)).unwrap();
    let before = s.attr(ino).unwrap();
    assert_eq!(s.setattr(ino, None, at(3000)).unwrap(), before);
    assert_eq!(s.setattr(ino, Some(50), at(3000)).unwrap(), before);
    let cut = s.setattr(ino, Some(10), at(4000)).unwrap();
    assert_eq!((cut.size, cut.mtime, cut.ctime), (10, at(4000), at(4000)));
    assert_eq!(s.setattr(ino + 1000, Some(1), at(5000)), Err(libc::ENOENT));
}

#[test]
fn inodes_are_never_reused_and_rename_moves_the_inode() {
    let mut s = Sidecars::new();
    let a = s.create(1, "._a", 501, 20, at(1)).unwrap().ino;
    s.unlink(1, "._a").unwrap();
    assert_eq!(s.attr(a), None);
    assert_eq!(s.unlink(1, "._a"), Err(libc::ENOENT));
    let b = s.create(1, "._a", 501, 20, at(2)).unwrap().ino;
    assert_ne!(a, b, "an inode number is never given out twice");
    let c = s.create(1, "._c", 501, 20, at(3)).unwrap().ino;
    // Rename onto another sidecar replaces it; the moved one keeps its inode.
    s.rename(1, "._a", 1, "._c", at(4)).unwrap();
    assert_eq!(s.lookup(1, "._a"), None);
    assert_eq!(s.lookup(1, "._c").unwrap().ino, b);
    assert_eq!(s.attr(c), None);
    s.rename(1, "._c", 7, "._d", at(5)).unwrap();
    assert_eq!(s.lookup(7, "._d").unwrap().ino, b);
    assert_eq!(s.rename(1, "._nope", 1, "._x", at(6)), Err(libc::ENOENT));
    assert_eq!(s.count(), 1);
}
