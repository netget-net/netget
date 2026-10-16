//! NetGet's AFP server from a raw DSI client: whole sessions with a python policy playing the
//! model, the password check, every bound a peer can push on, and the fail-closed answers when
//! the model fails, refuses, or answers with the wrong thing. No LLM calls: the policy, static
//! rules, or a model that is not there.
use super::support::{self, RawClient, NOTES, README};
use netget::server::afp::dsi;
use netget::server::afp::wire::{self, err, AfpPath, Request};
use serde_json::json;
use std::time::Duration;

fn names(nodes: &[wire::NodeParams]) -> Vec<&str> {
    nodes.iter().map(|n| n.name.as_str()).collect()
}

#[tokio::test]
async fn a_guest_session_lists_reads_and_resolves_what_the_model_described() {
    let s = support::start(support::policy(), json!({"server_name": "Studio"})).await;
    let mut c = RawClient::connect(s.addr()).await;

    // FPGetSrvrInfo through DSIGetStatus, before any session: answered, then closed.
    let r = c.call(dsi::command::GET_STATUS, 0, &[]).await;
    assert!(c.closed_within(Duration::from_secs(10)).await);
    c.oracle().assert_clean();
    let mut c = RawClient::connect(s.addr()).await;
    let info = wire::decode_server_info(&r.body).unwrap();
    assert_eq!(info.server_name, "Studio");
    assert_eq!(info.utf8_server_name.as_deref(), Some("Studio"));
    assert_eq!(info.uams, vec!["No User Authent"]);
    assert!(info.versions.contains(&"AFP3.4".to_string()));
    assert_eq!(
        info.address_strings(),
        vec![format!("127.0.0.1:{}", s.port)]
    );

    assert_eq!(c.open_session().await, dsi::REQUEST_QUANTUM);
    // Nothing but the login before a login.
    assert_eq!(c.afp(&Request::GetSrvrParms).await.code, err::USER_NOT_AUTH);
    assert_eq!(c.login(None).await, 0);

    let r = c.afp(&Request::GetSrvrParms).await;
    assert_eq!(r.code, 0);
    let (_, vols) = wire::decode_srvr_parms(&r.body).unwrap();
    assert_eq!(
        vols.iter().map(|v| v.name.as_str()).collect::<Vec<_>>(),
        ["Share", "Archive"]
    );
    let vol = c.open_vol("share").await;

    let (code, root) = c.enumerate(vol, &[]).await;
    assert_eq!(code, 0, "{}", s.log_text());
    assert_eq!(names(&root), ["README.txt", "secret.txt", "docs"]);
    let readme = &root[0];
    assert!(!readme.is_dir);
    assert_eq!(readme.data_len, 18);
    assert_eq!(readme.parent_id, wire::ROOT_DID);
    assert!(readme.node_id >= wire::FIRST_CNID);
    assert_eq!(
        wire::date_to_text(readme.created).unwrap(),
        "2026-01-02T03:04:05Z"
    );
    assert_eq!(
        wire::date_to_text(readme.modified).unwrap(),
        "2026-02-03T04:05:06Z"
    );
    assert_eq!(readme.unix.mode, 0o100644);
    assert_eq!(root[1].unix.mode, 0o100600);
    assert!(root[2].is_dir);
    assert_eq!(root[2].unix.mode, 0o040755);

    // Paging: the second entry onward, and past the end.
    let r = c
        .afp(&Request::Enumerate {
            kind: wire::EnumerateKind::Classic,
            vol,
            dir: wire::ROOT_DID,
            file_bitmap: wire::file_bit::LONG_NAME,
            dir_bitmap: wire::dir_bit::LONG_NAME,
            req_count: 1,
            start_index: 2,
            max_reply: 8000,
            path: AfpPath::here(),
        })
        .await;
    assert_eq!(r.code, 0);
    let page = wire::decode_enumerate_reply(wire::EnumerateKind::Classic, &r.body).unwrap();
    assert_eq!(names(&page), ["secret.txt"]);
    let r = c
        .afp(&Request::Enumerate {
            kind: wire::EnumerateKind::Ext,
            vol,
            dir: wire::ROOT_DID,
            file_bitmap: wire::file_bit::LONG_NAME,
            dir_bitmap: 0,
            req_count: 10,
            start_index: 3,
            max_reply: 8000,
            path: AfpPath::here(),
        })
        .await;
    assert_eq!(r.code, err::OBJECT_NOT_FOUND, "files only: two of them");

    // A directory by path, then by its ID.
    let r = c
        .afp(&Request::GetFileDirParms {
            vol,
            dir: wire::ROOT_DID,
            file_bitmap: wire::file_bit::SUPPORTED,
            dir_bitmap: wire::dir_bit::SUPPORTED,
            path: AfpPath::names(&["docs"]),
        })
        .await;
    assert_eq!(r.code, 0);
    let docs = wire::decode_file_dir_reply(&r.body).unwrap();
    assert!(docs.is_dir);
    assert_eq!(docs.node_id, root[2].node_id);
    let r = c
        .afp(&Request::Enumerate {
            kind: wire::EnumerateKind::Ext2,
            vol,
            dir: docs.node_id,
            file_bitmap: wire::file_bit::UTF8_NAME | wire::file_bit::NODE_ID,
            dir_bitmap: wire::dir_bit::UTF8_NAME,
            req_count: 10,
            start_index: 1,
            max_reply: 8000,
            path: AfpPath::here(),
        })
        .await;
    assert_eq!(r.code, 0);
    let inside = wire::decode_enumerate_reply(wire::EnumerateKind::Ext2, &r.body).unwrap();
    assert_eq!(names(&inside), ["notes.txt", "empty"]);
    // The root's parent with the volume name is the root; an ascent from docs is too.
    let r = c
        .afp(&Request::GetFileDirParms {
            vol,
            dir: wire::ROOT_PARENT_DID,
            file_bitmap: 0,
            dir_bitmap: wire::dir_bit::NODE_ID | wire::dir_bit::LONG_NAME,
            path: AfpPath::names(&["Share"]),
        })
        .await;
    assert_eq!(r.code, 0);
    let root_dir = wire::decode_file_dir_reply(&r.body).unwrap();
    assert_eq!((root_dir.node_id, root_dir.name.as_str()), (2, "Share"));
    let up = AfpPath {
        kind: 3,
        elements: vec![
            wire::PathElement::Name("docs".into()),
            wire::PathElement::Parent,
            wire::PathElement::Name("README.txt".into()),
        ],
    };
    let r = c
        .afp(&Request::GetFileDirParms {
            vol,
            dir: wire::ROOT_DID,
            file_bitmap: wire::file_bit::NODE_ID,
            dir_bitmap: 0,
            path: up,
        })
        .await;
    assert_eq!(r.code, 0);
    assert_eq!(
        wire::decode_file_dir_reply(&r.body).unwrap().node_id,
        readme.node_id
    );
    let r = c
        .afp(&Request::GetFileDirParms {
            vol,
            dir: wire::ROOT_DID,
            file_bitmap: 1,
            dir_bitmap: 1,
            path: AfpPath::names(&["nothing"]),
        })
        .await;
    assert_eq!(r.code, err::OBJECT_NOT_FOUND);

    // Read the README: open, size, read with EOF, close.
    let (fork, size) = c
        .open_fork(vol, &["README.txt"], wire::open_mode::READ)
        .await
        .unwrap();
    assert_eq!(size, README.len() as u64);
    let r = c
        .afp(&Request::Read {
            ext: true,
            fork,
            offset: 0,
            count: 6,
        })
        .await;
    assert_eq!((r.code, r.body.as_slice()), (0, &b"Hello "[..]));
    let r = c
        .afp(&Request::Read {
            ext: false,
            fork,
            offset: 6,
            count: 100,
        })
        .await;
    assert_eq!(r.code, err::EOF_ERR, "a read past the end says so");
    assert_eq!(r.body, README.as_bytes()[6..]);
    let r = c
        .afp(&Request::Read {
            ext: true,
            fork,
            offset: 100,
            count: 1,
        })
        .await;
    assert_eq!((r.code, r.body.len()), (err::EOF_ERR, 0));
    let r = c
        .afp(&Request::GetForkParms {
            fork,
            bitmap: wire::file_bit::DATA_FORK_LEN | wire::file_bit::NODE_ID,
        })
        .await;
    assert_eq!(r.code, 0);
    let (bm, rest) = wire::be16_prefixed(&r.body).unwrap();
    let n = wire::decode_node_params(bm, false, rest).unwrap();
    assert_eq!((n.data_len, n.node_id), (18, readme.node_id));
    assert_eq!(c.afp(&Request::CloseFork { fork }).await.code, 0);
    assert_eq!(
        c.afp(&Request::CloseFork { fork }).await.code,
        err::PARAM_ERR
    );
    // The same file by its ID.
    let r = c
        .afp(&Request::ResolveId {
            vol,
            id: readme.node_id,
            bitmap: wire::file_bit::LONG_NAME,
        })
        .await;
    assert_eq!(r.code, 0);
    let (bm, rest) = wire::be16_prefixed(&r.body).unwrap();
    assert_eq!(
        wire::decode_node_params(bm, false, rest).unwrap().name,
        "README.txt"
    );
    assert_eq!(
        c.afp(&Request::ResolveId {
            vol,
            id: 0x7fff_0000,
            bitmap: 1
        })
        .await
        .code,
        err::ID_NOT_FOUND
    );

    // A file in a subdirectory, and one the model will not let anyone read.
    let (fork, _) = c
        .open_fork(vol, &["docs", "notes.txt"], wire::open_mode::READ)
        .await
        .unwrap();
    let r = c
        .afp(&Request::Read {
            ext: true,
            fork,
            offset: 0,
            count: 1000,
        })
        .await;
    assert_eq!(r.body, NOTES.as_bytes());
    assert_eq!(
        c.open_fork(vol, &["secret.txt"], wire::open_mode::READ)
            .await,
        Err(err::ACCESS_DENIED)
    );
    assert_eq!(
        c.open_fork(vol, &["docs"], wire::open_mode::READ).await,
        Err(err::OBJECT_TYPE_ERR)
    );
    // Writing a read-only volume is refused without asking.
    let archive = c.open_vol("Archive").await;
    let r = c
        .afp(&Request::CreateFile {
            hard: false,
            vol: archive,
            dir: wire::ROOT_DID,
            path: AfpPath::names(&["x"]),
        })
        .await;
    assert_eq!(r.code, err::VOL_LOCKED);
    // Something NetGet does not implement.
    let mut rename = vec![wire::cmd::RENAME, 0];
    rename.extend_from_slice(&vol.to_be_bytes());
    rename.extend_from_slice(&wire::ROOT_DID.to_be_bytes());
    rename.extend(AfpPath::names(&["README.txt"]).encode());
    rename.extend(AfpPath::names(&["x.txt"]).encode());
    let r = c.call(dsi::command::COMMAND, 0, &rename).await;
    assert_eq!(r.code, err::CALL_NOT_SUPPORTED);
    assert_eq!(c.afp(&Request::Logout).await.code, 0);
    assert_eq!(c.afp(&Request::GetSrvrParms).await.code, err::USER_NOT_AUTH);

    // Each directory was asked about once; the README once; the volumes once.
    assert_eq!(s.events("afp_list_volumes").await.len(), 1);
    let listed: Vec<String> = s
        .events("afp_list_directory")
        .await
        .iter()
        .map(|e| e["path"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(listed, ["", "docs", ""], "the Archive root is the third");
    assert_eq!(s.events("afp_read_file").await.len(), 3);
    c.oracle().assert_clean();
}

#[tokio::test]
async fn writes_creates_and_deletes_are_the_models_decisions_and_change_the_listing() {
    let s = support::start(support::policy(), json!({"volumes": [{"name": "Share"}]})).await;
    let (mut c, vol) = RawClient::guest_volume(s.addr(), "Share").await;
    assert_eq!(
        s.events("afp_list_volumes").await.len(),
        0,
        "volumes are configured"
    );

    let create = |name: &str, hard| Request::CreateFile {
        hard,
        vol,
        dir: wire::ROOT_DID,
        path: AfpPath::names(&[name]),
    };
    assert_eq!(c.afp(&create("upload.txt", false)).await.code, 0);
    assert_eq!(
        c.afp(&create("upload.txt", false)).await.code,
        err::OBJECT_EXISTS
    );
    assert_eq!(
        c.afp(&create("README.txt", false)).await.code,
        err::OBJECT_EXISTS
    );
    assert_eq!(
        c.afp(&create("forbidden.txt", false)).await.code,
        err::ACCESS_DENIED
    );
    let (code, root) = c.enumerate(vol, &[]).await;
    assert_eq!(code, 0);
    assert_eq!(
        names(&root),
        ["README.txt", "secret.txt", "docs", "upload.txt"]
    );

    // A new file opens empty without asking the model, and takes writes it approves.
    let (fork, size) = c
        .open_fork(
            vol,
            &["upload.txt"],
            wire::open_mode::READ | wire::open_mode::WRITE,
        )
        .await
        .unwrap();
    assert_eq!(size, 0);
    assert_eq!(s.events("afp_read_file").await.len(), 0);
    let r = c
        .afp_write(
            &Request::Write {
                ext: true,
                from_end: false,
                fork,
                offset: 0,
                count: 5,
            },
            b"hello",
        )
        .await;
    assert_eq!((r.code, r.body.clone()), (0, 5u64.to_be_bytes().to_vec()));
    let r = c
        .afp_write(
            &Request::Write {
                ext: false,
                from_end: true,
                fork,
                offset: 0,
                count: 3,
            },
            &[0xff, 0x00, 0x01],
        )
        .await;
    assert_eq!((r.code, r.body.clone()), (0, 8u32.to_be_bytes().to_vec()));
    let r = c
        .afp(&Request::Read {
            ext: true,
            fork,
            offset: 0,
            count: 8,
        })
        .await;
    assert_eq!(r.body, b"hello\xff\x00\x01");
    let writes = s.events("afp_write_file").await;
    assert_eq!(writes.len(), 2);
    assert_eq!(writes[0]["data"], "hello");
    assert_eq!(writes[0]["encoding"], "utf8");
    assert_eq!(writes[0]["offset"], 0);
    assert_eq!(writes[1]["data"], "ff0001");
    assert_eq!(writes[1]["encoding"], "hex");
    assert_eq!(writes[1]["offset"], 5);
    // A length change is a write decision too.
    let r = c
        .afp(&Request::SetForkParms {
            fork,
            bitmap: wire::file_bit::EXT_DATA_FORK_LEN,
            length: 2,
        })
        .await;
    assert_eq!(r.code, 0);
    let last = s.events("afp_write_file").await.pop().unwrap();
    assert_eq!(
        (last["operation"].clone(), last["length"].clone()),
        (json!("set_length"), json!(2))
    );
    // A write with fewer bytes than it claims is a parameter error, asked of nobody.
    let r = c
        .afp_write(
            &Request::Write {
                ext: true,
                from_end: false,
                fork,
                offset: 0,
                count: 9,
            },
            b"abc",
        )
        .await;
    assert_eq!(r.code, err::PARAM_ERR);
    assert_eq!(c.afp(&Request::CloseFork { fork }).await.code, 0);
    let (_, root) = c.enumerate(vol, &[]).await;
    assert_eq!(root[3].data_len, 2, "the listing knows the new size");

    // A write the model refuses.
    assert_eq!(c.afp(&create("nope.txt", false)).await.code, 0);
    let (fork, _) = c
        .open_fork(vol, &["nope.txt"], wire::open_mode::WRITE)
        .await
        .unwrap();
    let r = c
        .afp_write(
            &Request::Write {
                ext: true,
                from_end: false,
                fork,
                offset: 0,
                count: 1,
            },
            b"x",
        )
        .await;
    assert_eq!(r.code, err::DISK_FULL);
    // Writing through a fork opened for reading is refused without asking.
    let (rfork, _) = c
        .open_fork(vol, &["README.txt"], wire::open_mode::READ)
        .await
        .unwrap();
    let before = s.events("afp_write_file").await.len();
    let r = c
        .afp_write(
            &Request::Write {
                ext: true,
                from_end: false,
                fork: rfork,
                offset: 0,
                count: 1,
            },
            b"x",
        )
        .await;
    assert_eq!(r.code, err::ACCESS_DENIED);
    assert_eq!(s.events("afp_write_file").await.len(), before);
    // Deleting an open file is busy; deleting what the model protects is refused.
    let del = |p: &[&str]| Request::Delete {
        vol,
        dir: wire::ROOT_DID,
        path: AfpPath::names(p),
    };
    assert_eq!(c.afp(&del(&["nope.txt"])).await.code, err::FILE_BUSY);
    assert_eq!(c.afp(&Request::CloseFork { fork }).await.code, 0);
    assert_eq!(c.afp(&Request::CloseFork { fork: rfork }).await.code, 0);
    assert_eq!(c.afp(&del(&["README.txt"])).await.code, err::OBJECT_LOCKED);
    assert_eq!(c.afp(&del(&["docs"])).await.code, err::DIR_NOT_EMPTY);
    assert_eq!(c.afp(&del(&["nope.txt"])).await.code, 0);
    assert_eq!(c.afp(&del(&["nope.txt"])).await.code, err::OBJECT_NOT_FOUND);

    // A directory: created, its ID returned, empty without asking, then deleted.
    let r = c
        .afp(&Request::CreateDir {
            vol,
            dir: wire::ROOT_DID,
            path: AfpPath::names(&["made"]),
        })
        .await;
    assert_eq!(r.code, 0);
    let id = u32::from_be_bytes(r.body[..4].try_into().unwrap());
    assert!(id >= wire::FIRST_CNID);
    let (code, _) = c.enumerate(vol, &["made"]).await;
    assert_eq!(code, err::OBJECT_NOT_FOUND, "empty");
    assert_eq!(c.afp(&del(&["made"])).await.code, 0);
    let deletes = s.events("afp_delete").await;
    assert_eq!(
        deletes
            .iter()
            .map(|d| (d["path"].as_str().unwrap(), d["kind"].as_str().unwrap()))
            .collect::<Vec<_>>(),
        [
            ("README.txt", "file"),
            ("nope.txt", "file"),
            ("made", "directory")
        ]
    );
    c.oracle().assert_clean();
}

#[tokio::test]
async fn the_password_is_checked_by_netget_and_never_shown_to_the_model() {
    let s = support::start(
        support::policy(),
        json!({"username": "alice", "password": "s3cret-long", "guest_access": false}),
    )
    .await;
    let mut c = RawClient::connect(s.addr()).await;
    let r = c.call(dsi::command::GET_STATUS, 0, &[]).await;
    assert_eq!(
        wire::decode_server_info(&r.body).unwrap().uams,
        vec!["Cleartxt Passwrd"]
    );
    let mut c = RawClient::connect(s.addr()).await;
    c.open_session().await;
    assert_eq!(c.login(None).await, err::BAD_UAM, "no guest access");
    assert_eq!(c.login(Some(("alice", "wrong"))).await, err::USER_NOT_AUTH);
    assert_eq!(c.login(Some(("bob", "s3cret-l"))).await, err::USER_NOT_AUTH);
    // AFP carries eight bytes of password: what fits is what is compared.
    assert_eq!(c.login(Some(("alice", "s3cret-l"))).await, 0);
    let r = c.afp(&Request::GetSrvrParms).await;
    assert_eq!(r.code, 0);
    let ev = s.events("afp_list_volumes").await;
    assert_eq!(ev[0]["user"], "alice");
    let everything = serde_json::to_string(&s.all_events().await).unwrap();
    assert!(!everything.contains("s3cret"), "{everything}");
    assert!(!s.log_text().contains("s3cret"));

    // A wrong version is refused before the password is looked at.
    let mut c = RawClient::connect(s.addr()).await;
    c.open_session().await;
    let r = c
        .afp(&Request::Login(wire::Login {
            ext: true,
            version: "AFP2.2".into(),
            uam: wire::uam::CLEARTXT_PASSWRD.into(),
            user: Some("alice".into()),
            password: Some(b"s3cret-l".to_vec()),
        }))
        .await;
    assert_eq!(r.code, err::BAD_VERS_NUM);
    // FPLoginExt with the right password.
    let r = c
        .afp(&Request::Login(wire::Login {
            ext: true,
            version: "AFP3.3".into(),
            uam: wire::uam::CLEARTXT_PASSWRD.into(),
            user: Some("alice".into()),
            password: Some(b"s3cret-l".to_vec()),
        }))
        .await;
    assert_eq!(r.code, 0);

    // Five wrong passwords and the connection is closed.
    let mut c = RawClient::connect(s.addr()).await;
    c.open_session().await;
    for _ in 0..netget::server::afp::MAX_LOGIN_FAILURES {
        assert_eq!(c.login(Some(("alice", "guess"))).await, err::USER_NOT_AUTH);
    }
    assert!(c.closed_within(Duration::from_secs(10)).await);
    c.oracle().assert_clean();
}

#[tokio::test]
async fn with_no_model_every_question_fails_closed_with_kfpmiscerr() {
    // No handlers and no model: every event's model call fails.
    let s = support::start(None, json!({"volumes": [{"name": "Share"}]})).await;
    let (mut c, vol) = RawClient::guest_volume(s.addr(), "Share").await;
    let (code, entries) = c.enumerate(vol, &[]).await;
    assert_eq!((code, entries.len()), (err::MISC_ERR, 0));
    let r = c
        .afp(&Request::GetFileDirParms {
            vol,
            dir: wire::ROOT_DID,
            file_bitmap: 1,
            dir_bitmap: 1,
            path: AfpPath::names(&["anything"]),
        })
        .await;
    assert_eq!(r.code, err::MISC_ERR);
    let r = c
        .afp(&Request::CreateFile {
            hard: false,
            vol,
            dir: wire::ROOT_DID,
            path: AfpPath::names(&["new.txt"]),
        })
        .await;
    assert_eq!(
        r.code,
        err::MISC_ERR,
        "the root listing cannot be had either"
    );
    assert!(s.wait_for_log("decision=fail_closed_llm_error").await);
    // The volume root itself is NetGet's; its parameters need no model.
    let r = c
        .afp(&Request::GetFileDirParms {
            vol,
            dir: wire::ROOT_DID,
            file_bitmap: 0,
            dir_bitmap: wire::dir_bit::NODE_ID,
            path: AfpPath::here(),
        })
        .await;
    assert_eq!(r.code, 0);

    // Unconfigured volumes need the model too.
    let s = support::start(None, json!({})).await;
    let mut c = RawClient::connect(s.addr()).await;
    c.open_session().await;
    assert_eq!(c.login(None).await, 0);
    assert_eq!(c.afp(&Request::GetSrvrParms).await.code, err::MISC_ERR);
    let r = c
        .afp(&Request::OpenVol {
            bitmap: wire::vol_bit::VOLUME_ID,
            name: "Share".into(),
            has_password: false,
        })
        .await;
    assert_eq!(r.code, err::MISC_ERR);
}

#[tokio::test]
async fn an_answer_that_does_not_answer_the_question_fails_closed() {
    // The model approves everything, including a listing it was asked for.
    let s = support::start(
        support::static_rule(json!([{"type": "afp_allow"}])),
        json!({"volumes": [{"name": "Share"}]}),
    )
    .await;
    let (mut c, vol) = RawClient::guest_volume(s.addr(), "Share").await;
    assert_eq!(c.enumerate(vol, &[]).await.0, err::MISC_ERR);
    assert!(s.wait_for_log("decision=fail_closed_bad_action").await);

    // A listing NetGet cannot use (two entries with one name) is not half-served.
    let s = support::start(
        support::static_rule(json!([{"type": "afp_directory_listing", "entries": [
            {"name": "a", "type": "file"}, {"name": "a", "type": "file"}
        ]}])),
        json!({"volumes": [{"name": "Share"}]}),
    )
    .await;
    let (mut c, vol) = RawClient::guest_volume(s.addr(), "Share").await;
    assert_eq!(c.enumerate(vol, &[]).await.0, err::MISC_ERR);

    // Content that is not the hex it claims to be.
    let s = support::start(
        Some(vec![
            json!({"event_pattern": "afp_list_directory", "handler": {"type": "static", "actions": [
                {"type": "afp_directory_listing", "entries": [{"name": "f", "type": "file", "size": 1}]}
            ]}}),
            json!({"event_pattern": "*", "handler": {"type": "static", "actions": [
                {"type": "afp_file_content", "content": "zz", "encoding": "hex"}
            ]}}),
        ]),
        json!({"volumes": [{"name": "Share"}]}),
    )
    .await;
    let (mut c, vol) = RawClient::guest_volume(s.addr(), "Share").await;
    assert_eq!(
        c.open_fork(vol, &["f"], wire::open_mode::READ).await,
        Err(err::MISC_ERR)
    );

    // An empty answer is not an answer.
    let s = support::start(
        support::static_rule(json!([])),
        json!({"volumes": ["Share"]}),
    )
    .await;
    let (mut c, vol) = RawClient::guest_volume(s.addr(), "Share").await;
    assert_eq!(c.enumerate(vol, &[]).await.0, err::MISC_ERR);
    assert!(s.wait_for_log("decision=model_silent").await);
}

#[tokio::test]
async fn a_message_longer_than_the_bound_is_refused_before_it_is_read() {
    let s = support::start(support::policy(), json!({})).await;
    let mut c = RawClient::connect(s.addr()).await;
    let h = dsi::Header {
        flags: 0,
        command: dsi::command::COMMAND,
        request_id: 1,
        code: 0,
        length: (dsi::MAX_PAYLOAD_LEN + 1) as u32,
        reserved: 0,
    };
    c.send_raw(&h.encode()).await;
    assert!(c.closed_within(Duration::from_secs(10)).await);
    assert!(s.wait_for_log("decision=protocol_error").await);

    // At the bound it is read, and a command block past MAX_COMMAND_LEN is a parameter error.
    let mut c = RawClient::connect(s.addr()).await;
    c.open_session().await;
    let mut big = vec![wire::cmd::GET_SRVR_PARMS];
    big.resize(dsi::MAX_COMMAND_LEN + 1, 0);
    let r = c.call(dsi::command::COMMAND, 0, &big).await;
    assert_eq!(r.code, err::PARAM_ERR);
    // A DSIWrite whose command claims more than the message holds.
    let r = c
        .call(dsi::command::WRITE, 100, &[wire::cmd::WRITE_EXT, 0])
        .await;
    assert_eq!(r.code, err::PARAM_ERR);
    // AFP before DSIOpenSession closes the connection.
    let mut c = RawClient::connect(s.addr()).await;
    c.send_raw(&dsi::message(
        0,
        dsi::command::COMMAND,
        1,
        0,
        &[wire::cmd::GET_SRVR_PARMS, 0],
    ))
    .await;
    assert!(c.closed_within(Duration::from_secs(10)).await);
}

#[tokio::test]
async fn listings_paths_names_and_forks_are_bounded() {
    let many: Vec<_> = (0..netget::server::afp::actions::MAX_DIR_ENTRIES + 1)
        .map(|i| json!({"name": format!("f{i}"), "type": "file"}))
        .collect();
    let just: Vec<_> = many[..netget::server::afp::actions::MAX_DIR_ENTRIES].to_vec();
    let rule = |entries: Vec<serde_json::Value>| {
        Some(vec![
            json!({"event_pattern": "afp_list_directory", "handler": {"type": "static", "actions": [
                {"type": "afp_directory_listing", "entries": entries}
            ]}}),
            json!({"event_pattern": "*", "handler": {"type": "static", "actions": [
                {"type": "afp_file_content", "content": "x"}
            ]}}),
        ])
    };
    // One entry more than the bound: refused whole.
    let s = support::start(rule(many), json!({"volumes": ["Share"]})).await;
    let (mut c, vol) = RawClient::guest_volume(s.addr(), "Share").await;
    assert_eq!(c.enumerate(vol, &[]).await.0, err::MISC_ERR);

    // At the bound: served, a page at a time, never more than MAX_ENUMERATE_ENTRIES or the
    // reply size the client allows.
    let s = support::start(rule(just), json!({"volumes": ["Share"]})).await;
    let (mut c, vol) = RawClient::guest_volume(s.addr(), "Share").await;
    let page = |start: u32, count: u16, max: u32| Request::Enumerate {
        kind: wire::EnumerateKind::Ext2,
        vol,
        dir: wire::ROOT_DID,
        file_bitmap: wire::file_bit::NODE_ID,
        dir_bitmap: 0,
        req_count: count,
        start_index: start,
        max_reply: max,
        path: AfpPath::here(),
    };
    let r = c.afp(&page(1, u16::MAX, u32::MAX)).await;
    assert_eq!(r.code, 0);
    let got = wire::decode_enumerate_reply(wire::EnumerateKind::Ext2, &r.body).unwrap();
    assert_eq!(got.len(), wire::MAX_ENUMERATE_ENTRIES);
    // Each entry is 4 + 4 bytes: 6 + 8 * 10 holds ten.
    let r = c.afp(&page(1, 100, 6 + 80)).await;
    let got = wire::decode_enumerate_reply(wire::EnumerateKind::Ext2, &r.body).unwrap();
    assert_eq!(got.len(), 10);
    assert_eq!(c.afp(&page(1, 100, 10)).await.code, err::PARAM_ERR);
    assert_eq!(c.afp(&page(0, 100, 1000)).await.code, err::PARAM_ERR);
    assert_eq!(c.afp(&page(1, 0, 1000)).await.code, err::PARAM_ERR);
    let r = c
        .afp(&page(
            netget::server::afp::actions::MAX_DIR_ENTRIES as u32,
            5,
            1000,
        ))
        .await;
    assert_eq!(r.code, 0);
    assert_eq!(
        c.afp(&page(
            netget::server::afp::actions::MAX_DIR_ENTRIES as u32 + 1,
            5,
            1000
        ))
        .await
        .code,
        err::OBJECT_NOT_FOUND
    );

    // A path of more elements than the bound, and a name longer than 255 bytes.
    let deep: Vec<String> = (0..wire::MAX_PATH_ELEMENTS + 1)
        .map(|i| format!("d{i}"))
        .collect();
    let r = c
        .afp(&Request::GetFileDirParms {
            vol,
            dir: wire::ROOT_DID,
            file_bitmap: 1,
            dir_bitmap: 1,
            path: AfpPath::names(&deep),
        })
        .await;
    assert_eq!(r.code, err::PARAM_ERR);
    let long = "n".repeat(wire::MAX_NAME_BYTES + 1);
    let r = c
        .afp(&Request::CreateFile {
            hard: false,
            vol,
            dir: wire::ROOT_DID,
            path: AfpPath::names(&[long]),
        })
        .await;
    assert_eq!(r.code, err::PARAM_ERR);

    // Forks: MAX_OPEN_FORKS, then kFPTooManyFilesOpen.
    for i in 0..netget::server::afp::MAX_OPEN_FORKS {
        let name = format!("f{i}");
        c.open_fork(vol, &[&name], wire::open_mode::READ)
            .await
            .unwrap();
    }
    assert_eq!(
        c.open_fork(vol, &["f0"], wire::open_mode::READ).await,
        Err(err::TOO_MANY_FILES_OPEN)
    );
}

#[tokio::test]
async fn an_idle_client_is_tickled_and_then_closed() {
    let s = support::start(support::policy(), json!({"idle_timeout_secs": 2})).await;
    let mut c = RawClient::connect(s.addr()).await;
    c.open_session().await;
    // Nothing more: the server closes after its idle timeout.
    let started = std::time::Instant::now();
    assert!(c.closed_within(Duration::from_secs(15)).await);
    assert!(started.elapsed() >= Duration::from_secs(2));
    assert!(s.wait_for_log("decision=protocol_timeout").await);
}

/// asip-status's request, byte for byte: a 16-byte DSIGetStatus header whose request ID is
/// written as three bytes, so a stray NUL follows it. The server answers the status and closes,
/// which is the only way asip-status knows the reply is complete.
#[tokio::test]
async fn a_status_request_outside_a_session_is_answered_and_closed() {
    let s = support::start(support::policy(), json!({"server_name": "Studio"})).await;
    let mut c = RawClient::connect(s.addr()).await;
    c.send_raw(&[
        0x00, 0x03, 0xde, 0xad, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ])
    .await;
    let (h, body) = c.recv_within(Duration::from_secs(10)).await.unwrap();
    assert_eq!((h.flags, h.command, h.request_id), (1, 3, 0xdead));
    assert_eq!(
        wire::decode_server_info(&body).unwrap().server_name,
        "Studio"
    );
    assert!(c.closed_within(Duration::from_secs(10)).await);
}
