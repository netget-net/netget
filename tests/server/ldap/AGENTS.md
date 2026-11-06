# LDAP Protocol E2E Tests

## Test Overview

Tests the LDAP server with **two** real third-party clients, neither of which is the crate the
server frames with:

- `ldap3` 0.11 (Rust) drives bind, search, add, modify and delete, parsing entries back through
  its own `SearchEntry::construct` — so a reply it rejected would fail rather than be counted as
  bytes on a socket.
- OpenLDAP's `ldapsearch` (C, from the project that wrote the RFC) completes a bind and a search
  and *renders* the result, which is the half a deserialiser cannot check.

**`ldap3` used to be the only one, and the protocol's `e2e_testing` said so.** That field once
claimed "the ldapsearch/ldapadd command-line tools" as well while nothing asserting drove them:
`ldapsearch` appeared only in `tests/eval/`, the real-model harness, which skips unless
`NETGET_USE_OLLAMA=1` and reports rather than asserts. An eval probe is a useful signal and is
not maturity evidence. `real_client_test.rs` is what that claim always should have been.
`ldapadd` is still driven by nothing.

## The six files, and what each is for

This doc described `e2e_test.rs` alone until 22 September 2026 — the files beside it went
unmentioned, including the two that exist because of real defects. A test nothing points at is a
test nobody re-reads.

| file | what it holds |
|---|---|
| `e2e_test.rs` | the maturity evidence: `ldap3` binds, searches and parses entries through its own `SearchEntry::construct` |
| `llm_failure_test.rs` | what a client gets when the backend fails — `unavailable` (52) |
| `result_code_range_test.rs` | a narrowing cast that encoded LDAP **success** |
| `answer_with_test.rs` | the `ldap_bind` hint names the kind of bind (anonymous, a DN with or without a password, SASL), and the bind is offered `ldap_bind_response` alone |
| `connection_bounds_test.rs` | the read deadlines and the connection cap, driven from the wire |
| `real_client_test.rs` | the **second** client: OpenLDAP's `ldapsearch`, asserted on the LDIF it rendered |

**`result_code_range_test.rs` is the one to read first.** A model-supplied `result_code` was
narrowed with `as u8`, and the wrap lands on the worst possible value: `256 as u8` is `0`, and
resultCode `0` is `success`. Every refusal the model could express sat a multiple of 256 away
from telling the client that a bind, a write or a search had completed — fail-open by
arithmetic, and silent, because the encoder produced a perfectly well-formed success.

**`llm_failure_test.rs` is the same shape one level up.** LDAP always answered *something* on
that path, but it answered the per-operation default: `invalidCredentials` for a bind, and an
empty **successful** result set for a search. Both report an outage as a decision the directory
made, and the search case is the dangerous one — resultCode 0 with no entries is a valid answer
meaning "nothing matched".

**`connection_bounds_test.rs`**: before September 2026 this server accepted without limit and
bounded no read, so a peer that connected and said nothing held a socket, a connection task and
an `AppState` entry forever — pre-authentication, which for LDAP means before any bind at all.

It drives the first-message bound through the **`first_byte_timeout_secs` startup parameter**
rather than waiting out the default, which is 300 seconds. That default is the window a `manual`
rule gives a human, and it is 300 rather than 30 because the peer this server usually has is
NetGet's own LDAP client: it opens the socket and sends nothing until the model or a person
supplies an operation, so at 30 seconds the server dropped the operator's own client while they
were still composing a bind. What the test asserts is that the deadline is applied to the
`read()` and to nothing else — the *value* is the operator's to choose, and is argued beside the
constant in `src/server/ldap/mod.rs`.

## Test Strategy

- **Consolidated per operation** - Each test focuses on a specific LDAP operation
- **Multiple server instances** - 6 separate servers (one per test)
- **Real LDAP client** - Uses `ldap3` Rust library for protocol correctness
- **No scripting** - Action-based responses only

## LLM Call Budget

- `test_ldap_bind_success()`: 1 startup call + 1 bind operation
- `test_ldap_bind_failure()`: 1 startup call + 1 bind operation
- `test_ldap_search()`: 1 startup call + 2 operations (bind, search)
- `test_ldap_search_filter()`: 1 startup call + 2 operations (anonymous bind, search)
- `test_ldap_add_entry()`: 1 startup call + 2 operations (bind, add)
- `test_ldap_modify_entry()`: 1 startup call + 2 operations (bind, modify)
- `test_ldap_delete_entry()`: 1 startup call + 2 operations (bind, delete)
- `ldapsearch_completes_a_session_against_the_ldap_server()`: 1 startup + 2 binds + 2 searches
  + up to 2 unbinds = **7** (one server, two `ldapsearch` invocations against it)
- **Total: 26 LLM calls** (8 startups + 18 operations)

The unbind calls are why the `ldap_unbind` rule is `expect_at_most(2)` rather than
`expect_calls`: RFC 4511 forbids a response to an unbind and the event declares no actions, so
the server raises it on a tracked task whose result is discarded — and that task races the
test's own teardown. The rule exists so the mock is not asked to answer a request it has no rule
for (an unmatched request is an HTTP 500), not because anything asserts on it.

**Note**: Target was <10 calls but LDAP test coverage prioritizes completeness.

## Scripting Usage

**Scripting Disabled** (`ServerConfig::new_no_scripts()`)

- LDAP protocol requires context-aware responses (authentication state, directory contents)
- Script generation not beneficial for stateful operations
- LLM interprets each operation with full session context

## Client Libraries

### `ldapsearch` — the second client (`real_client_test.rs`)

OpenLDAP's command-line tool, located by searching `PATH` first and then the places the
OpenLDAP tools hide when a distribution keeps them out of it (Homebrew's keg-only `openldap`,
`/usr/lib/openldap`, `/usr/libexec/openldap`). **The test fails rather than skips** when none is
found, naming `brew install openldap` / `apt-get install -y ldap-utils`: a
`println!("SKIP")` + `Ok(())` is a silent pass on every runner without the binary, and a
maturity rating resting on a test like that rests on nothing wherever the suite actually runs.

It asserts on what `ldapsearch` *rendered*, parsed back out of the LDIF rather than
substring-matched:

- one `dn:` per entry, in the order the `SearchResultEntry` messages were written
- every value of each multi-valued `SET OF` — the break that made this assertion fail was
  `for val in arr.iter().take(1)`, after which `ldapsearch` printed `objectClass: person` alone
- a `description` long enough that the entry's BER length needs the long form. Forcing
  `encode_ber_length` to the short form made `ldapsearch` print no LDIF at all and exit 254
  with `ldap_result: Local error (-2)`
- the bind `diagnosticMessage`, which `ldapsearch` prints as `ldap_bind: Success (0)` plus
  `additional info:`
- `noSuchObject` (32), read off `ldapsearch`'s own exit status — it exits with the resultCode

LDIF folding at 78 columns is real here (the long `description` folds), so the parser
reassembles continuation lines; a parser that ignored them would silently truncate.

### `ldap3` v0.11+ — Async LDAP client (`e2e_test.rs`)

- `LdapConnAsync::new()` - Connect to server
- `simple_bind()` - Authenticate with DN and password
- `search()` - Search directory with filters
- `add()` - Add new entry
- `modify()` - Modify existing entry
- `delete()` - Delete entry
- `unbind()` - Close connection
- Real LDAP library ensures protocol correctness

## Expected Runtime

- Model: qwen3-coder:30b
- Runtime: ~80-120 seconds for full test suite
- Moderate speed due to 19 LLM calls

## Failure Rate

- **Medium-High** (15-25%) - LLM struggles with ASN.1 BER encoding expectations
- Common issues:
    - LLM returns prose instead of LDAP response actions
    - Search response format errors (missing entries or malformed attributes)
    - Result code inconsistencies
    - LLM forgets to include `message_id` in responses

## Test Cases

1. **test_ldap_bind_success** - Tests successful bind with correct credentials
2. **test_ldap_bind_failure** - Tests bind rejection with wrong credentials
3. **test_ldap_search** - Tests search returning multiple entries with attributes
4. **test_ldap_search_filter** - Tests filtered search with specific criteria
5. **test_ldap_add_entry** - Tests adding new directory entry
6. **test_ldap_modify_entry** - Tests modifying existing entry attributes
7. **test_ldap_delete_entry** - Tests deleting directory entry

## Known Issues

- **Binary protocol complexity** - LLM must understand BER encoding indirectly
- Tests sleep 2 seconds after server start for initialization
- Some tests check result codes loosely (any success vs specific code)
- Anonymous bind test assumes LLM accepts empty DN/password
- No verification of entry persistence across operations

## Example Test Pattern

```rust
// Start server with --no-scripts flag
let server = start_netget_server(ServerConfig::new_no_scripts(prompt)).await?;
sleep(Duration::from_secs(2)).await;

// Connect to LDAP server
let ldap_url = format!("ldap://127.0.0.1:{}", server.port);
let (conn, mut ldap) = LdapConnAsync::new(&ldap_url).await?;
ldap3::drive!(conn);

// Bind (authenticate)
let bind_result = ldap.simple_bind("cn=admin,dc=example,dc=com", "secret").await?;
assert_eq!(bind_result.rc, 0, "Bind should succeed");

// Perform operation (search example)
let (rs, _res) = ldap.search(
    "dc=example,dc=com",
    Scope::Subtree,
    "(objectClass=*)",
    vec!["cn", "mail"]
).await?.success()?;

// Validate results
assert!(rs.len() >= 2, "Should find at least 2 entries");

// Unbind
ldap.unbind().await?;
server.stop().await?;
```

## LDAP Protocol Notes

- **DN format**: `cn=username,dc=example,dc=com`
- **Bind types**: Simple (username/password), anonymous (empty DN)
- **Search scopes**: Base, OneLevel, Subtree
- **Result codes**: 0 = success, 49 = invalidCredentials, 32 = noSuchObject, 68 = entryAlreadyExists
- **Object classes**: person, inetOrgPerson, organizationalUnit, etc.

## Performance Considerations

- LDAP client connection has ~1-2 second overhead
- LLM must generate BER-encoded binary responses correctly
- Test suite slower than protocols with simpler text-based formats
