use netget::server::gnmi::tls::{read_pem, MAX_PEM_BYTES};
#[tokio::test]
async fn regular_file_exact_bound_plus_one_and_directory_refusal() {
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("pem");
    tokio::fs::write(&file, vec![b'x'; MAX_PEM_BYTES])
        .await
        .unwrap();
    assert_eq!(
        read_pem(file.to_string_lossy().into_owned())
            .await
            .unwrap()
            .len(),
        MAX_PEM_BYTES
    );
    tokio::fs::write(&file, vec![b'x'; MAX_PEM_BYTES + 1])
        .await
        .unwrap();
    assert!(read_pem(file.to_string_lossy().into_owned()).await.is_err());
    assert!(read_pem(directory.path().to_string_lossy().into_owned())
        .await
        .is_err());
}
#[cfg(unix)]
#[tokio::test]
async fn fifo_is_refused_before_open_without_a_writer() {
    let directory = tempfile::tempdir().unwrap();
    let fifo = directory.path().join("fifo.pem");
    let path = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
    // Only creates a named pipe in this owned temporary directory.
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    assert!(tokio::time::timeout(
        std::time::Duration::from_secs(1),
        read_pem(fifo.to_string_lossy().into_owned())
    )
    .await
    .unwrap()
    .is_err());
}
