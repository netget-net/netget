//! The history builder behind `hg_repository`: every declared bound, the refusals, and the
//! changegroup's selection logic.
//!
//! Whether the bytes are *Mercurial's* bytes is not decided here — that is
//! `real_client_test.rs`, where `hg verify` recomputes every node. This file pins the parts a
//! real client cannot easily reach: each `MAX_*` refuses one past its limit and accepts the
//! limit itself, and each malformed description is refused rather than served as something
//! else.

use netget::server::mercurial::changegroup::{
    empty_changegroup, hex, ChangegroupError, Repository, MAX_AUTHOR_BYTES, MAX_BRANCH_BYTES,
    MAX_CHANGES_PER_COMMIT, MAX_COMMITS, MAX_FILE_BYTES, MAX_ID_BYTES, MAX_MANIFEST_BYTES,
    MAX_MESSAGE_BYTES, MAX_PATHS, MAX_PATH_BYTES, MAX_TOTAL_CONTENT_BYTES, NULL_NODE,
};
use serde_json::{json, Value};

fn build(commits: Value) -> Result<Repository, String> {
    Repository::from_description(&json!({ "commits": commits })).map_err(|e| e.to_string())
}

fn refused(commits: Value, needle: &str) {
    match build(commits) {
        Ok(_) => panic!("description was accepted; expected a refusal mentioning {needle:?}"),
        Err(e) => assert!(
            e.contains(needle),
            "refusal {e:?} does not mention {needle:?}"
        ),
    }
}

fn commit(message: &str, files: Value) -> Value {
    json!({ "message": message, "files": files })
}

#[test]
fn commit_count_is_bounded() {
    let at_limit: Vec<Value> = (0..MAX_COMMITS)
        .map(|i| {
            commit(
                &format!("c{i}"),
                json!([{"path": "f", "content": format!("{i}\n")}]),
            )
        })
        .collect();
    let repo = build(Value::Array(at_limit.clone())).expect("MAX_COMMITS commits are served");
    assert_eq!(repo.changesets().len(), MAX_COMMITS);

    let mut over = at_limit;
    over.push(commit(
        "one too many",
        json!([{"path": "f", "content": "x\n"}]),
    ));
    refused(Value::Array(over), "commits described");
}

#[test]
fn changes_per_commit_are_bounded() {
    let files: Vec<Value> = (0..MAX_CHANGES_PER_COMMIT)
        .map(|i| json!({"path": format!("f{i}"), "content": ""}))
        .collect();
    build(json!([commit("at limit", Value::Array(files.clone()))])).expect("at the limit");

    let mut over = files;
    over.push(json!({"path": "one-more", "content": ""}));
    refused(
        json!([commit("over", Value::Array(over))]),
        "changes listed",
    );
}

#[test]
fn distinct_paths_are_bounded() {
    let commits_for = |paths: usize| -> Value {
        let files: Vec<Value> = (0..paths)
            .map(|i| json!({"path": format!("p{i}"), "content": ""}))
            .collect();
        Value::Array(
            files
                .chunks(MAX_CHANGES_PER_COMMIT)
                .enumerate()
                .map(|(i, chunk)| commit(&format!("c{i}"), Value::Array(chunk.to_vec())))
                .collect(),
        )
    };
    build(commits_for(MAX_PATHS)).expect("MAX_PATHS paths are served");
    refused(commits_for(MAX_PATHS + 1), "distinct paths");
}

#[test]
fn path_length_is_bounded() {
    let at = "a".repeat(MAX_PATH_BYTES);
    build(json!([commit("ok", json!([{"path": at, "content": ""}]))])).expect("at the limit");
    let over = "a".repeat(MAX_PATH_BYTES + 1);
    refused(
        json!([commit("long", json!([{"path": over, "content": ""}]))]),
        "path must be",
    );
}

#[test]
fn file_size_is_bounded() {
    let at = "x".repeat(MAX_FILE_BYTES);
    build(json!([commit(
        "ok",
        json!([{"path": "big", "content": at}])
    )]))
    .expect("at the limit");
    let over = "x".repeat(MAX_FILE_BYTES + 1);
    refused(
        json!([commit("big", json!([{"path": "big", "content": over}]))]),
        "bytes; at most",
    );
}

#[test]
fn total_content_is_bounded() {
    let files = MAX_TOTAL_CONTENT_BYTES / MAX_FILE_BYTES;
    let chunk = "y".repeat(MAX_FILE_BYTES);
    let commits = |n: usize| -> Value {
        Value::Array(
            (0..n)
                .map(|i| {
                    // Distinct content per commit, so every file is a real revision.
                    let mut content = chunk.clone();
                    content.replace_range(0..8, &format!("{i:08}"));
                    commit(
                        &format!("c{i}"),
                        json!([{"path": "data", "content": content}]),
                    )
                })
                .collect(),
        )
    };
    build(commits(files)).expect("exactly MAX_TOTAL_CONTENT_BYTES of content is served");
    refused(commits(files + 1), "file contents exceed");
}

#[test]
fn manifest_bytes_are_bounded() {
    // Every manifest lists every file, so many commits over many long paths grow the manifests
    // as commits x paths while the description itself stays small.
    let long = |i: usize| format!("{}{i:05}", "m".repeat(MAX_PATH_BYTES - 5));
    let entry = MAX_PATH_BYTES + 1 + 40 + 1;
    let per_manifest = MAX_PATHS * entry;
    let mut commits: Vec<Value> = (0..MAX_PATHS / MAX_CHANGES_PER_COMMIT)
        .map(|c| {
            let files: Vec<Value> = (0..MAX_CHANGES_PER_COMMIT)
                .map(|j| json!({"path": long(c * MAX_CHANGES_PER_COMMIT + j), "content": ""}))
                .collect();
            commit(&format!("add {c}"), Value::Array(files))
        })
        .collect();
    let edits = MAX_MANIFEST_BYTES / per_manifest + 1;
    for e in 0..edits {
        commits.push(commit(
            &format!("edit {e}"),
            json!([{"path": long(0), "content": format!("{e}\n")}]),
        ));
    }
    refused(Value::Array(commits.clone()), "manifests exceed");

    // Under the bound the same shape is served: drop enough edits to fit.
    let fits = commits.len() - 3;
    commits.truncate(fits);
    build(Value::Array(commits)).expect("manifests under MAX_MANIFEST_BYTES are served");
}

#[test]
fn text_fields_are_bounded() {
    build(json!([{"message": "m".repeat(MAX_MESSAGE_BYTES)}])).expect("message at the limit");
    refused(
        json!([{"message": "m".repeat(MAX_MESSAGE_BYTES + 1)}]),
        "`message` must be",
    );

    let author = |n: usize| format!("{} <a@b>", "a".repeat(n - 6));
    build(json!([{"message": "m", "author": author(MAX_AUTHOR_BYTES)}])).expect("author at limit");
    refused(
        json!([{"message": "m", "author": author(MAX_AUTHOR_BYTES + 1)}]),
        "`author` must be",
    );

    build(json!([{"message": "m", "id": "i".repeat(MAX_ID_BYTES)}])).expect("id at limit");
    refused(
        json!([{"message": "m", "id": "i".repeat(MAX_ID_BYTES + 1)}]),
        "`id` must be",
    );

    build(json!([{"message": "m", "branch": "b".repeat(MAX_BRANCH_BYTES)}])).expect("branch");
    refused(
        json!([{"message": "m", "branch": "b".repeat(MAX_BRANCH_BYTES + 1)}]),
        "branch name must be",
    );
}

#[test]
fn malformed_descriptions_are_refused() {
    refused(json!([{"files": []}]), "`message` must be");
    refused(json!([{"message": "   \n  "}]), "`message` must be");
    refused(
        json!([{"message": "a", "author": "two\nlines"}]),
        "`author` must be",
    );
    refused(
        json!([{"id": "x", "message": "a"}, {"id": "x", "message": "b"}]),
        "used twice",
    );
    refused(
        json!([{"message": "a", "parents": ["later"]}, {"id": "later", "message": "b"}]),
        "not an earlier commit",
    );
    refused(
        json!([
            {"id": "a", "message": "a"}, {"id": "b", "parents": [], "message": "b"},
            {"id": "c", "parents": [], "message": "c"},
            {"message": "d", "parents": ["a", "b", "c"]}
        ]),
        "at most two parents",
    );
    refused(
        json!([{"message": "a", "removed": ["nothing-here"]}]),
        "which its parents do not have",
    );
    refused(
        json!([commit(
            "a",
            json!([{"path": "d", "content": ""}, {"path": "d/f", "content": ""}])
        )]),
        "but it is a file",
    );
    refused(
        json!([commit(
            "a",
            json!([{"path": "d/f", "content": ""}, {"path": "d", "content": ""}])
        )]),
        "cannot be a file",
    );
    for bad in [
        "/abs", "a/../b", "a//b", "./a", ".hg/hgrc", "x/.HG/y", "nul\u{0}", "a\\b", "d/",
    ] {
        refused(
            json!([commit("p", json!([{"path": bad, "content": ""}]))]),
            "path",
        );
    }
    refused(
        json!([commit("a", json!([{"path": "f", "content": 5}]))]),
        "text `content`",
    );
    refused(json!([{"message": "a", "branch": "tip"}]), "reserved");
    refused(json!([{"message": "a", "branch": "42"}]), "revision number");
    refused(
        json!([{"message": "a", "branch": "has space"}]),
        "may use only",
    );
    refused(
        json!([{"message": "a", "date": "last tuesday"}]),
        "RFC 3339",
    );
    refused(json!([{"message": "a", "date": 99999999999i64}]), "32 bits");
    refused(
        json!([{"message": "a", "date": "2026-10-31T12:00:00+15:00"}]),
        "beyond 14 hours",
    );
    // Same parents, files, author, date and message: the same node, so the same commit.
    refused(
        json!([
            {"id": "a", "message": "root"},
            {"id": "b", "parents": ["a"], "message": "same"},
            {"id": "c", "parents": ["a"], "message": "same"}
        ]),
        "is identical to commit",
    );
    assert!(Repository::from_description(&json!({})).is_err());
    assert!(Repository::from_description(&json!({"commits": {}})).is_err());
}

#[test]
fn nodes_are_deterministic_and_described_order_is_revision_order() {
    let commits = json!([
        {"id": "a", "message": "one", "files": [{"path": "f", "content": "1\n"}]},
        {"id": "b", "message": "two", "files": [{"path": "f", "content": "2\n"}]}
    ]);
    let first = build(commits.clone()).unwrap();
    let second = build(commits).unwrap();
    assert_eq!(first.heads(), second.heads());
    assert_eq!(first.changesets()[1].p1, first.changesets()[0].node);
    assert_eq!(first.heads(), vec![first.changesets()[1].node]);
}

#[test]
fn lookup_resolves_the_symbols_a_remote_can_mean() {
    let repo = build(json!([
        {"id": "a", "message": "one"},
        {"id": "b", "message": "two", "branch": "stable"},
        {"id": "c", "parents": ["a"], "message": "three"}
    ]))
    .unwrap();
    let node = |i: usize| repo.changesets()[i].node;
    assert_eq!(repo.lookup("tip"), Some(node(2)));
    assert_eq!(repo.lookup("null"), Some(NULL_NODE));
    assert_eq!(repo.lookup("-1"), Some(NULL_NODE));
    assert_eq!(repo.lookup("1"), Some(node(1)));
    assert_eq!(repo.lookup("3"), None);
    assert_eq!(repo.lookup("stable"), Some(node(1)));
    assert_eq!(repo.lookup("default"), Some(node(2)));
    assert_eq!(repo.lookup(&hex(&node(0))), Some(node(0)));
    assert_eq!(repo.lookup(&hex(&node(0))[..12]), Some(node(0)));
    assert_eq!(repo.lookup("nonexistent"), None);
}

#[test]
fn changegroup_selects_what_the_client_lacks() {
    let repo = build(json!([
        {"id": "a", "message": "one", "files": [{"path": "f", "content": "1\n"}]},
        {"id": "b", "message": "two", "files": [{"path": "f", "content": "2\n"}]}
    ]))
    .unwrap();
    let heads = repo.heads();

    // A client that already has every head receives the empty changegroup.
    assert_eq!(
        repo.changegroup(&heads, &heads).unwrap(),
        empty_changegroup()
    );

    // Unknown heads are refused; unknown common nodes are ignored.
    let stranger = [0x5au8; 20];
    assert_eq!(
        repo.changegroup(&[stranger], &[]),
        Err(ChangegroupError::UnknownHead(hex(&stranger)))
    );
    assert_eq!(
        repo.changegroup(&[], &[stranger]).unwrap(),
        repo.changegroup(&[], &[NULL_NODE]).unwrap()
    );

    // A full clone is larger than a pull from the first commit, which is larger than nothing.
    let full = repo.changegroup(&[], &[NULL_NODE]).unwrap();
    let pull = repo.changegroup(&[], &[repo.changesets()[0].node]).unwrap();
    assert!(full.len() > pull.len() && pull.len() > empty_changegroup().len());

    // An empty repository: the null head, and an empty changegroup.
    let empty = build(json!([])).unwrap();
    assert!(empty.is_empty());
    assert_eq!(empty.heads(), vec![NULL_NODE]);
    assert_eq!(empty.changegroup(&[], &[]).unwrap(), empty_changegroup());
}
