//! The LDAP client against a real **`slapd`** — the evidence its maturity rating rests on.
//!
//! NetGet's LDAP client is the `ldap3` crate (Rust). The server here is OpenLDAP's `slapd` (C),
//! started per test on a probed loopback port with a minimal `slapd.conf` in the guard's
//! temporary directory (an `mdb` database for `dc=example,dc=com`, a plaintext `rootpw`, the
//! core/cosine/inetorgperson schemas), seeded with OpenLDAP's `ldapadd` and read back with
//! `ldapsearch`. Nothing on the wire was written by this repository except NetGet.
//!
//! Condition 4 of the client bar — the client acts on the model's answer, asserted on the wire
//! — is asserted from the server's side: `ldapsearch` finds the entry the model added (with an
//! attribute built from the search result it was shown), the value it modified, and the entry
//! it deleted gone. Each response event is matched on the operation and DN it answers, so a
//! response the model never saw cannot satisfy the mock.
//!
//! **No test here skips.** A missing `slapd`, `ldapadd` or `ldapsearch`, or a machine with no
//! OpenLDAP schema directory, fails with the install command.
//!
//! LLM calls: 19 across the file (7 + 7 + 5). All mocked and in-process.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features ldap --test client -- ldap::real_server_test --test-threads=100


use crate::helpers::real_server::{missing_binary, run_tool, InstallHint, RealServer};
use crate::helpers::*;
use serde_json::json;
use std::path::Path;
use std::process::Command;

const SLAPD: InstallHint = InstallHint {
    brew: "openldap",
    apt: "slapd (and, on Ubuntu, unload its AppArmor profile: \
          `sudo apparmor_parser -R /etc/apparmor.d/usr.sbin.slapd`)",
};
const LDAP_UTILS: InstallHint = InstallHint {
    brew: "openldap",
    apt: "ldap-utils",
};

const ADMIN_DN: &str = "cn=admin,dc=example,dc=com";
const ADMIN_PW: &str = "secret";

/// Where the OpenLDAP schema files live: Homebrew on Apple silicon, Homebrew on Intel, Debian.
const SCHEMA_DIRS: &[&str] = &[
    "/opt/homebrew/etc/openldap/schema",
    "/usr/local/etc/openldap/schema",
    "/etc/ldap/schema",
    "/etc/openldap/schema",
];

/// Where a packaged `slapd` keeps its dynamically loaded backends. Debian builds `back_mdb` as
/// a module there; Homebrew's is found without a `modulepath`.
const MODULE_DIRS: &[&str] = &["/usr/lib/ldap", "/usr/lib/openldap", "/usr/lib64/openldap"];

/// The directory the base, a people OU and two people start with.
const SEED: &str = "\
dn: dc=example,dc=com
objectClass: dcObject
objectClass: organization
dc: example
o: Example

dn: ou=people,dc=example,dc=com
objectClass: organizationalUnit
ou: people

dn: uid=ada,ou=people,dc=example,dc=com
objectClass: inetOrgPerson
uid: ada
cn: Ada Lovelace
sn: Lovelace
mail: ada@example.com

dn: uid=grace,ou=people,dc=example,dc=com
objectClass: inetOrgPerson
uid: grace
cn: Grace Hopper
sn: Hopper
";

/// A throwaway `slapd`: an `mdb` database for `dc=example,dc=com` in the guard's temp dir,
/// listening on 127.0.0.1 only, in the foreground with `-d stats` so every operation is in
/// its log. Seeded with [`SEED`] through `ldapadd` as the rootdn.
async fn start_slapd() -> E2EResult<RealServer> {
    let schema = SCHEMA_DIRS
        .iter()
        .find(|d| Path::new(d).join("core.schema").is_file())
        .ok_or_else(|| {
            missing_binary(
                "slapd",
                SLAPD,
                format!("no OpenLDAP schema directory (core.schema) in any of {SCHEMA_DIRS:?}"),
            )
        })?;
    let modulepath = MODULE_DIRS
        .iter()
        .find(|d| Path::new(d).is_dir())
        .map(|d| format!("modulepath {d}\n"))
        .unwrap_or_default();
    let conf = format!(
        "include {schema}/core.schema\n\
         include {schema}/cosine.schema\n\
         include {schema}/inetorgperson.schema\n\
         pidfile {{dir}}/slapd.pid\n\
         argsfile {{dir}}/slapd.args\n\
         {modulepath}\
         moduleload back_mdb\n\
         database mdb\n\
         maxsize 10485760\n\
         suffix \"dc=example,dc=com\"\n\
         rootdn \"{ADMIN_DN}\"\n\
         rootpw {ADMIN_PW}\n\
         directory {{dir}}/db\n"
    );
    let server = RealServer::builder("slapd", SLAPD)
        .config_file("slapd.conf", &conf)
        .config_file("db/.keep", "")
        .config_file("seed.ldif", SEED)
        .args([
            "-h",
            "ldap://127.0.0.1:{port}/",
            "-f",
            "{dir}/slapd.conf",
            "-d",
            "stats",
        ])
        .ready_when_log_matches("slapd starting")
        .start()
        .await?;

    let mut add = Command::new("ldapadd");
    add.args([
        "-x",
        "-H",
        &url(&server),
        "-D",
        ADMIN_DN,
        "-w",
        ADMIN_PW,
        "-f",
    ])
    .arg(server.dir().join("seed.ldif"));
    server.with_log(run_tool(add, "ldapadd", LDAP_UTILS).await.map(|_| ()))?;
    Ok(server)
}

fn url(server: &RealServer) -> String {
    format!("ldap://127.0.0.1:{}", server.port)
}

/// `ldapsearch -x -LLL -o ldif-wrap=no -b <base> -s <scope> <filter> <attrs…>`, anonymous.
async fn ldapsearch(
    server: &RealServer,
    base: &str,
    scope: &str,
    filter: &str,
    attrs: &[&str],
) -> E2EResult<String> {
    let mut cmd = Command::new("ldapsearch");
    cmd.args([
        "-x",
        "-LLL",
        "-o",
        "ldif-wrap=no",
        "-H",
        &url(server),
        "-b",
        base,
        "-s",
        scope,
        filter,
    ])
    .args(attrs);
    run_tool(cmd, "ldapsearch", LDAP_UTILS).await
}

/// Bind, search, and add / modify / delete — every operation the model's, and the add built
/// from what the search returned.
///
/// 1. `ldap_connected` → bind as the rootdn.
/// 2. The bind response (matched on its DN and `success` true) → search `ou=people` for
///    `(uid=ada)`, asking for `cn` and `mail`.
/// 3. The search results (matched on the filter, `count` 1 and the seeded mail) → add
///    `uid=netget` with `description` built from Ada's `cn` and `mail` as slapd returned them.
///    `cn` and `sn` are given as plain strings, the way a model writes a single value.
/// 4. The add's response (matched on `operation` add and the DN) → replace Ada's `mail`.
/// 5. The modify's response → delete `uid=grace`.
/// 6. The delete's response → nothing.
///
/// Then `ldapsearch` must find the added entry with the model's attributes, Ada's new mail, and
/// no Grace.
///
/// LLM calls: 7 (startup, ldap_connected, bind, search and three modify responses).
#[tokio::test]
async fn ldap_client_binds_searches_and_writes_against_slapd() -> E2EResult<()> {
    let server = start_slapd().await?;
    let result = binds_searches_and_writes(&server).await;
    server.with_log(result)
}

async fn binds_searches_and_writes(server: &RealServer) -> E2EResult<()> {
    let addr = server.addr();
    let config = NetGetConfig::new(format!(
        "Connect to LDAP at {addr}. LDAP-REAL-SERVER-STARTUP-TURN."
    ))
    .with_mock(move |mock| {
        mock.on_instruction_containing("LDAP-REAL-SERVER-STARTUP-TURN")
            .respond_with_actions(json!([{
                "type": "open_client",
                "protocol": "LDAP",
                "remote_addr": addr,
                "instruction": "Bind as admin, look Ada up, record what you found as a new \
                                entry, update Ada's mail and remove Grace."
            }]))
            .expect_calls(1)
            .and()
            .on_event("ldap_connected")
            .respond_with_actions(json!([{
                "type": "bind", "dn": ADMIN_DN, "password": ADMIN_PW
            }]))
            .expect_calls(1)
            .and()
            .on_event("ldap_bind_response")
            .and_event_data_contains("dn", ADMIN_DN)
            .and_event_data_contains("success", "true")
            .respond_with_actions(json!([{
                "type": "search",
                "base_dn": "ou=people,dc=example,dc=com",
                "filter": "(uid=ada)",
                "attributes": ["cn", "mail"],
                "scope": "one"
            }]))
            .expect_calls(1)
            .and()
            .on_event("ldap_search_results")
            .and_event_data_contains("filter", "(uid=ada)")
            .and_event_data_contains("success", "true")
            .and_event_data_contains("count", "1")
            .and_event_data_contains("entries", "ada@example.com")
            .respond_with_actions_from_event(|event| {
                let attrs = &event["entries"][0]["attributes"];
                json!([{
                    "type": "add",
                    "dn": "uid=netget,ou=people,dc=example,dc=com",
                    "attributes": {
                        "objectClass": ["inetOrgPerson"],
                        "uid": "netget",
                        "cn": "NetGet Model",
                        "sn": "Model",
                        "description": format!(
                            "the model saw {} at {}",
                            attrs["cn"][0].as_str().unwrap_or(""),
                            attrs["mail"][0].as_str().unwrap_or("")
                        )
                    }
                }])
            })
            .expect_calls(1)
            .and()
            .on_event("ldap_modify_response")
            .and_event_data_contains("operation", "add")
            .and_event_data_contains("dn", "uid=netget,ou=people,dc=example,dc=com")
            .and_event_data_contains("success", "true")
            .respond_with_actions(json!([{
                "type": "modify",
                "dn": "uid=ada,ou=people,dc=example,dc=com",
                "operation": "replace",
                "attribute": "mail",
                "values": ["ada@analytical-engine.example"]
            }]))
            .expect_calls(1)
            .and()
            .on_event("ldap_modify_response")
            .and_event_data_contains("operation", "modify")
            .and_event_data_contains("success", "true")
            .respond_with_actions(json!([{
                "type": "delete",
                "dn": "uid=grace,ou=people,dc=example,dc=com"
            }]))
            .expect_calls(1)
            .and()
            .on_event("ldap_modify_response")
            .and_event_data_contains("operation", "delete")
            .and_event_data_contains("dn", "uid=grace")
            .and_event_data_contains("success", "true")
            .respond_with_actions(json!([]))
            .expect_calls(1)
            .and()
    });

    let client = start_netget_client(config).await?;
    // The last expectation is the delete's response, so once every rule is satisfied slapd has
    // applied everything the model sent.
    client.wait_for_mocks(30).await;
    client.verify_mocks().await?;

    let added = ldapsearch(
        server,
        "uid=netget,ou=people,dc=example,dc=com",
        "base",
        "(objectClass=*)",
        &["cn", "sn", "description"],
    )
    .await?;
    assert!(
        added.contains("cn: NetGet Model")
            && added.contains("sn: Model")
            && added.contains("description: the model saw Ada Lovelace at ada@example.com"),
        "slapd must hold the entry the model added, with the description it built from the \
         search result:\n{added}"
    );

    let ada = ldapsearch(
        server,
        "uid=ada,ou=people,dc=example,dc=com",
        "base",
        "(objectClass=*)",
        &["mail"],
    )
    .await?;
    assert!(
        ada.contains("mail: ada@analytical-engine.example") && !ada.contains("ada@example.com"),
        "slapd must hold the mail the model's modify replaced:\n{ada}"
    );

    let grace = ldapsearch(
        server,
        "ou=people,dc=example,dc=com",
        "one",
        "(uid=grace)",
        &["dn"],
    )
    .await?;
    assert!(
        grace.trim().is_empty(),
        "the entry the model deleted must be gone:\n{grace}"
    );

    client.stop().await?;
    Ok(())
}

/// The follow-up chain is bounded, asserted from slapd's own log.
///
/// The model answers `ldap_connected` with a search and **every** search result with the same
/// search again — the runaway the bound exists for. The search from the connect event runs at
/// depth 0 and each result's answer one level deeper; the result at `MAX_FOLLOWUP_DEPTH` (4) is
/// shown to the model and its answer dropped. So the model sees five results and slapd logs
/// exactly five searches. Without the bound both counts grow until the test gives up.
///
/// LLM calls: 7 (startup, ldap_connected, five ldap_search_results).
#[tokio::test]
async fn ldap_client_follow_up_chain_is_bounded_against_slapd() -> E2EResult<()> {
    let server = start_slapd().await?;
    let result = follow_up_chain_is_bounded(&server).await;
    server.with_log(result)
}

async fn follow_up_chain_is_bounded(server: &RealServer) -> E2EResult<()> {
    let addr = server.addr();
    let search = json!([{
        "type": "search",
        "base_dn": "ou=people,dc=example,dc=com",
        "filter": "(objectClass=inetOrgPerson)",
        "attributes": ["uid"],
        "scope": "one"
    }]);
    let search_again = search.clone();
    let config = NetGetConfig::new(format!(
        "Connect to LDAP at {addr}. LDAP-BOUND-STARTUP-TURN."
    ))
    .with_mock(move |mock| {
        mock.on_instruction_containing("LDAP-BOUND-STARTUP-TURN")
            .respond_with_actions(json!([{
                "type": "open_client",
                "protocol": "LDAP",
                "remote_addr": addr,
                "instruction": "List the people, over and over."
            }]))
            .expect_calls(1)
            .and()
            .on_event("ldap_connected")
            .respond_with_actions(search)
            .expect_calls(1)
            .and()
            .on_event("ldap_search_results")
            .and_event_data_contains("count", "2")
            .respond_with_actions(search_again)
            .expect_calls(5)
            .and()
    });

    let client = start_netget_client(config).await?;
    client.wait_for_mocks(30).await;
    client.verify_mocks().await?;

    let searches = server
        .log()
        .matches("SRCH base=\"ou=people,dc=example,dc=com\"")
        .count();
    assert_eq!(
        searches, 5,
        "slapd must have served exactly the connect event's search plus four bounded follow-ups"
    );

    client.stop().await?;
    Ok(())
}

/// A search slapd refuses reaches the model as a result, and the model can act on it.
///
/// The model searches a base that does not exist. slapd answers `noSuchObject` (result code
/// 32), which `ldap3` surfaces as an error; the client reports it as `ldap_search_results`
/// with `success` false and the server's result in `message`, rather than ending the chain with
/// nothing raised. The model answers by creating the missing OU as the rootdn, and
/// `ldapsearch` must find it.
///
/// LLM calls: 5 (startup, ldap_connected, bind, the refused search, the add's response).
#[tokio::test]
async fn ldap_client_reports_a_refused_search_to_the_model_against_slapd() -> E2EResult<()> {
    let server = start_slapd().await?;
    let result = reports_a_refused_search(&server).await;
    server.with_log(result)
}

async fn reports_a_refused_search(server: &RealServer) -> E2EResult<()> {
    let addr = server.addr();
    let config = NetGetConfig::new(format!(
        "Connect to LDAP at {addr}. LDAP-REFUSED-SEARCH-STARTUP-TURN."
    ))
    .with_mock(move |mock| {
        mock.on_instruction_containing("LDAP-REFUSED-SEARCH-STARTUP-TURN")
            .respond_with_actions(json!([{
                "type": "open_client",
                "protocol": "LDAP",
                "remote_addr": addr,
                "instruction": "Look in ou=staff; create it if it is missing."
            }]))
            .expect_calls(1)
            .and()
            .on_event("ldap_connected")
            .respond_with_actions(json!([{
                "type": "bind", "dn": ADMIN_DN, "password": ADMIN_PW
            }]))
            .expect_calls(1)
            .and()
            .on_event("ldap_bind_response")
            .and_event_data_contains("success", "true")
            .respond_with_actions(json!([{
                "type": "search",
                "base_dn": "ou=staff,dc=example,dc=com",
                "filter": "(objectClass=*)",
                "scope": "one"
            }]))
            .expect_calls(1)
            .and()
            .on_event("ldap_search_results")
            .and_event_data_contains("base_dn", "ou=staff,dc=example,dc=com")
            .and_event_data_contains("success", "false")
            .and_event_data_contains("message", "rc: 32")
            .respond_with_actions(json!([{
                "type": "add",
                "dn": "ou=staff,dc=example,dc=com",
                "attributes": {"objectClass": ["organizationalUnit"], "ou": "staff"}
            }]))
            .expect_calls(1)
            .and()
            .on_event("ldap_modify_response")
            .and_event_data_contains("operation", "add")
            .and_event_data_contains("success", "true")
            .respond_with_actions(json!([]))
            .expect_calls(1)
            .and()
    });

    let client = start_netget_client(config).await?;
    client.wait_for_mocks(30).await;
    client.verify_mocks().await?;

    let staff = ldapsearch(
        server,
        "ou=staff,dc=example,dc=com",
        "base",
        "(objectClass=organizationalUnit)",
        &["ou"],
    )
    .await?;
    assert!(
        staff.contains("ou: staff"),
        "slapd must hold the OU the model created after its search was refused:\n{staff}"
    );

    client.stop().await?;
    Ok(())
}
