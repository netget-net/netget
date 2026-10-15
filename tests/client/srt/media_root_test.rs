//! `srt_send_file` and `rtmp_publish` read a local file and stream it to the peer — the peer
//! whose responses the model reads. Without a boundary that was a file-exfiltration
//! primitive one prompt injection away (`{"path": "/home/op/.ssh/id_ed25519"}`; SRT's content
//! gate was one byte). `client::media_root::MediaRoot` is that boundary, shared by both.
//! No peer, no model: the boundary is a pure function of the filesystem.


use netget::client::media_root::{MediaRoot, MEDIA_ROOT_PARAM};

fn scratch(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("netget-media-root-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn files_under_the_root_are_accepted_by_relative_or_absolute_path() {
    let dir = scratch("inside");
    let root = dir.join("media");
    std::fs::create_dir_all(root.join("clips")).unwrap();
    std::fs::write(root.join("clips/a.ts"), b"G").unwrap();
    let media = MediaRoot::new(Some(root.to_str().unwrap())).unwrap();
    let expected = root.join("clips/a.ts").canonicalize().unwrap();
    assert_eq!(media.resolve("clips/a.ts", "path").unwrap(), expected);
    assert_eq!(
        media
            .resolve(root.join("clips/a.ts").to_str().unwrap(), "path")
            .unwrap(),
        expected
    );
    assert_eq!(
        media.resolve("clips/../clips/a.ts", "path").unwrap(),
        expected
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn anything_outside_the_root_is_refused_and_names_the_parameter() {
    let dir = scratch("outside");
    let root = dir.join("media");
    std::fs::create_dir_all(&root).unwrap();
    let secret = dir.join("id_ed25519");
    std::fs::write(&secret, b"G-- not a clip").unwrap();
    let media = MediaRoot::new(Some(root.to_str().unwrap())).unwrap();

    for raw in [
        secret.to_str().unwrap().to_string(),
        "../id_ed25519".to_string(),
        "/etc/hostname".to_string(),
    ] {
        let err = media
            .resolve(&raw, "the srt_send_file 'path'")
            .expect_err(&raw);
        let text = err.to_string();
        assert!(
            text.contains(MEDIA_ROOT_PARAM) || text.contains("does not exist"),
            "{raw}: {text}"
        );
        assert!(
            !text.contains("not a regular file"),
            "{raw}: refused for the right reason"
        );
    }
    assert!(media.resolve("", "path").is_err());
    assert!(
        media.resolve(".", "path").is_err(),
        "the root itself is not a file"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn a_symlink_under_the_root_pointing_outside_is_refused() {
    let dir = scratch("symlink");
    let root = dir.join("media");
    std::fs::create_dir_all(&root).unwrap();
    let secret = dir.join("secret.flv");
    std::fs::write(&secret, b"FLV\x01").unwrap();
    std::os::unix::fs::symlink(&secret, root.join("clip.flv")).unwrap();
    let media = MediaRoot::new(Some(root.to_str().unwrap())).unwrap();
    let err = media
        .resolve("clip.flv", "the rtmp_publish 'flv_file'")
        .expect_err("a symlink out of the root");
    assert!(err.to_string().contains(MEDIA_ROOT_PARAM), "{err}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_default_root_is_neither_home_nor_the_working_directory_and_is_created() {
    let root = netget::client::media_root::default_root();
    let cwd = std::env::current_dir().unwrap();
    assert_ne!(root, cwd);
    if let Some(home) = dirs::home_dir() {
        assert_ne!(root, home);
    }
    let media = MediaRoot::new(None).expect("the default root is usable without preparation");
    assert!(media.root().is_dir());
}
