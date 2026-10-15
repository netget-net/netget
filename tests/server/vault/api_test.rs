//! Vault routing and rendering, without a socket.


use netget::server::vault::api::{
    preflight_mount, render_error, render_list, render_metadata, render_secret, render_write_ok,
    resolve, Route,
};
use serde_json::json;

fn mounts() -> Vec<String> {
    vec!["secret".into(), "kv/prod".into()]
}

#[test]
fn the_routing_table() {
    let m = mounts();
    assert_eq!(
        resolve("GET", "/v1/sys/seal-status", false, &m),
        Route::SealStatus
    );
    assert_eq!(resolve("GET", "/v1/sys/health", false, &m), Route::Health);
    assert_eq!(resolve("GET", "/v1/sys/leader", false, &m), Route::Leader);
    assert_eq!(
        resolve("GET", "/v1/sys/internal/ui/mounts/secret/app/db", false, &m),
        Route::MountPreflight("secret/app/db".into())
    );
    assert_eq!(
        resolve("GET", "/v1/secret/data/app/db", false, &m),
        Route::ReadData {
            mount: "secret".into(),
            path: "app/db".into()
        }
    );
    for method in ["PUT", "POST"] {
        assert_eq!(
            resolve(method, "/v1/secret/data/app/db", false, &m),
            Route::WriteData {
                mount: "secret".into(),
                path: "app/db".into()
            }
        );
    }
    assert_eq!(
        resolve("LIST", "/v1/secret/metadata/app", false, &m),
        Route::List {
            mount: "secret".into(),
            path: "app".into()
        }
    );
    assert_eq!(
        resolve("GET", "/v1/secret/metadata/app/", true, &m),
        Route::List {
            mount: "secret".into(),
            path: "app".into()
        }
    );
    assert_eq!(
        resolve("GET", "/v1/secret/metadata/", true, &m),
        Route::List {
            mount: "secret".into(),
            path: String::new()
        },
        "listing the mount's root"
    );
    assert_eq!(
        resolve("GET", "/v1/secret/metadata/app/db", false, &m),
        Route::ReadMetadata {
            mount: "secret".into(),
            path: "app/db".into()
        }
    );
    // The longest mount wins, and a multi-segment mount works.
    assert_eq!(
        resolve("GET", "/v1/kv/prod/data/x", false, &m),
        Route::ReadData {
            mount: "kv/prod".into(),
            path: "x".into()
        }
    );
    assert_eq!(
        resolve("DELETE", "/v1/secret/data/app/db", false, &m),
        Route::Unsupported
    );
    assert_eq!(
        resolve("PATCH", "/v1/secret/data/app/db", false, &m),
        Route::Unsupported
    );
    assert_eq!(
        resolve("GET", "/v1/secret/config", false, &m),
        Route::Unsupported
    );
    // Not under a mount, not /v1, or a mount that is only a prefix of a segment.
    assert_eq!(
        resolve("GET", "/v1/other/data/x", false, &m),
        Route::NotFound
    );
    assert_eq!(
        resolve("GET", "/v1/secretive/data/x", false, &m),
        Route::NotFound
    );
    assert_eq!(resolve("GET", "/secret/data/x", false, &m), Route::NotFound);
    assert_eq!(preflight_mount("secret/app/db", &m), Some("secret".into()));
    assert_eq!(preflight_mount("elsewhere/x", &m), None);
}

#[test]
fn reads_writes_and_metadata_render_the_kv2_envelope() {
    let read = render_secret(&json!({"data": {"k": "v"}, "version": 3,
                                     "created_time": "2026-09-01T12:00:00+02:00"}))
    .unwrap();
    assert_eq!(read["data"]["data"], json!({"k": "v"}));
    assert_eq!(read["data"]["metadata"]["version"], 3);
    assert_eq!(
        read["data"]["metadata"]["created_time"], "2026-09-01T10:00:00.000000Z",
        "normalised to UTC"
    );
    assert_eq!(read["lease_id"], "");
    assert!(read["request_id"].as_str().unwrap().len() == 36);

    let empty = render_secret(&json!({})).unwrap();
    assert_eq!(
        empty["data"]["data"],
        json!({}),
        "an empty secret is still a secret"
    );
    assert_eq!(empty["data"]["metadata"]["version"], 1);

    let write = render_write_ok(&json!({"version": 9})).unwrap();
    assert_eq!(write["data"]["version"], 9);
    assert_eq!(write["data"]["destroyed"], false);

    let meta = render_metadata(&json!({"version": 4})).unwrap();
    assert_eq!(meta["data"]["current_version"], 4);
    assert!(meta["data"]["versions"]["4"].is_object());

    let list = render_list(&json!({"keys": ["a", "b/"]})).unwrap();
    assert_eq!(list["data"]["keys"], json!(["a", "b/"]));
}

#[test]
fn every_malformed_answer_is_refused_with_a_reason() {
    for (answer, needle) in [
        (json!({"data": "password=x"}), "object of key/value"),
        (json!({"version": 0}), "positive integer"),
        (json!({"version": "latest"}), "positive integer"),
        (json!({"created_time": "yesterday"}), "RFC 3339"),
        (json!({"custom_metadata": ["x"]}), "object of strings"),
    ] {
        let reason = render_secret(&answer).expect_err(&answer.to_string());
        assert!(reason.contains(needle), "{answer}: {reason}");
    }
    for (answer, needle) in [
        (json!({}), "array"),
        (json!({"keys": [""]}), "one path segment"),
        (json!({"keys": ["a/b"]}), "one path segment"),
        (json!({"keys": [1]}), "strings"),
    ] {
        let reason = render_list(&answer).expect_err(&answer.to_string());
        assert!(reason.contains(needle), "{answer}: {reason}");
    }
    assert!(
        render_error(&json!({"status": 200})).is_err(),
        "an error is never a 2xx"
    );
    let (status, errors) =
        render_error(&json!({"status": 403, "errors": ["permission\ndenied"]})).unwrap();
    assert_eq!(status, 403);
    assert_eq!(errors, vec!["permission denied"], "one line per error");
}
