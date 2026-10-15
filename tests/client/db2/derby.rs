//! Derby's own `ij` client (over its own DRDA client driver) to read back what NetGet left
//! behind in Apache Derby's network server, and a recording proxy. The server itself is
//! started by `real_server_test.rs::start_derby`.
//!
//! The jars are fetched and SHA-256-checked by `tests/client/db2/install_derby.py`, which
//! prints the `NETGET_DERBY_LIB` export this module reads. A missing `java` or missing jars
//! fail the test with how to install them; nothing here skips.

use crate::helpers::real_server::{run_tool, InstallHint, RealServer};
use crate::helpers::E2EResult;
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub const DERBY_VERSION: &str = "10.17.1.0";

pub const JAVA: InstallHint = InstallHint {
    brew: "openjdk@21 (Derby 10.17 needs Java 21 or newer)",
    apt: "openjdk-21-jre-headless",
};

/// The directory holding the Derby jars.
pub fn derby_lib() -> E2EResult<PathBuf> {
    let dir = std::env::var_os("NETGET_DERBY_LIB")
        .map(PathBuf::from)
        .ok_or(
            "NETGET_DERBY_LIB is not set. The Db2 client's evidence is Apache Derby's network \
         server, and this test FAILS rather than skipping without it: run \
         `python3 tests/client/db2/install_derby.py /some/dir` and export the \
         NETGET_DERBY_LIB it prints (it also needs Java 21+: `brew install openjdk@21` or \
         `sudo apt-get install openjdk-21-jre-headless`).",
        )?;
    for jar in [
        "derby",
        "derbynet",
        "derbyshared",
        "derbytools",
        "derbyclient",
    ] {
        let path = dir.join(format!("{jar}-{DERBY_VERSION}.jar"));
        if !path.is_file() {
            return Err(format!(
                "{} is missing; run `python3 tests/client/db2/install_derby.py {}`",
                path.display(),
                dir.display()
            )
            .into());
        }
    }
    Ok(dir)
}

pub fn classpath(jars: &[&str]) -> E2EResult<String> {
    let dir = derby_lib()?;
    Ok(jars
        .iter()
        .map(|j| {
            dir.join(format!("{j}-{DERBY_VERSION}.jar"))
                .display()
                .to_string()
        })
        .collect::<Vec<_>>()
        .join(":"))
}

/// Run SQL through Derby's `ij` over Derby's own DRDA client driver, as user `app`.
pub async fn ij(
    server: &RealServer,
    database: &str,
    password: &str,
    sql: &str,
) -> E2EResult<String> {
    let cp = classpath(&["derbytools", "derbyclient", "derbyshared"])?;
    let script = server
        .dir()
        .join(format!("ij-{}.sql", rand::random::<u32>()));
    std::fs::write(
        &script,
        format!(
            "connect 'jdbc:derby://127.0.0.1:{}/{database};user=app;password={password}';\n{sql}\ndisconnect;\nexit;\n",
            server.port
        ),
    )?;
    let mut cmd = Command::new("java");
    cmd.arg("-Dij.driver=org.apache.derby.client.ClientAutoloadedDriver")
        .arg("-cp")
        .arg(cp)
        .arg("org.apache.derby.tools.ij")
        .arg(&script);
    run_tool(cmd, "java", JAVA).await
}

/// Derby's log: connections and every statement text it executed.
pub fn derby_log(server: &RealServer) -> String {
    std::fs::read_to_string(server.dir().join("derby.log")).unwrap_or_default()
}

/// What crossed a [`RecordingProxy`], in order: `(true, bytes)` client to server.
pub type Recording = Arc<Mutex<Vec<(bool, Vec<u8>)>>>;

/// A loopback TCP relay to `target` that records both directions, so the conversation can be
/// handed to tshark's DRDA dissector afterwards.
pub struct RecordingProxy {
    pub addr: String,
    pub recording: Recording,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for RecordingProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl RecordingProxy {
    pub async fn start(target: String) -> E2EResult<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?.to_string();
        let recording: Recording = Arc::default();
        let rec = recording.clone();
        let task = tokio::spawn(async move {
            while let Ok((client, _)) = listener.accept().await {
                let Ok(server) = TcpStream::connect(&target).await else {
                    continue;
                };
                let (mut cr, mut cw) = client.into_split();
                let (mut sr, mut sw) = server.into_split();
                let up = rec.clone();
                let down = rec.clone();
                tokio::spawn(async move {
                    let mut b = vec![0u8; 65536];
                    while let Ok(n) = cr.read(&mut b).await {
                        if n == 0 {
                            break;
                        }
                        up.lock().unwrap().push((true, b[..n].to_vec()));
                        if sw.write_all(&b[..n]).await.is_err() {
                            break;
                        }
                    }
                    let _ = sw.shutdown().await;
                });
                tokio::spawn(async move {
                    let mut b = vec![0u8; 65536];
                    while let Ok(n) = sr.read(&mut b).await {
                        if n == 0 {
                            break;
                        }
                        down.lock().unwrap().push((false, b[..n].to_vec()));
                        if cw.write_all(&b[..n]).await.is_err() {
                            break;
                        }
                    }
                    let _ = cw.shutdown().await;
                });
            }
        });
        Ok(Self {
            addr,
            recording,
            task,
        })
    }
}
