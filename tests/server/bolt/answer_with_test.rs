//! The `answer_with` hint `bolt_authenticate` carries.
//!
//! Told "accepts any login. Reject any query that is not valid Cypher", llama3.1:8b rejected the
//! login five runs in five - "Reject" was the operative verb and nothing said that no query was
//! being decided yet. The hint says what the login turns on and that query rules wait.

use netget::server::bolt::actions::login_answer_with;

#[test]
fn the_login_hint_names_the_user_and_sets_query_rules_aside() {
    let hint = login_answer_with("neo4j", "basic", true);
    assert!(
        hint.starts_with(
            "decide only whether user \"neo4j\" (scheme basic, a credential) may log in"
        ),
        "{hint}"
    );
    assert!(hint.contains("accept_bolt_login unless"), "{hint}");
    assert!(hint.contains("No query has been sent yet"), "{hint}");
    assert!(hint.contains("never to the login"), "{hint}");

    let anonymous = login_answer_with("", "none", false);
    assert!(
        anonymous.contains("no user name (scheme none, no credential)"),
        "{anonymous}"
    );
}

/// The query hint names the query's first word and whether it is a Cypher clause - the fact
/// that turned `SELECT name FROM people` from invented rows into the syntax error.
#[test]
fn the_query_hint_says_whether_the_query_begins_like_cypher() {
    use netget::server::bolt::actions::query_answer_with;
    let sql = query_answer_with("SELECT name FROM people");
    assert!(
        sql.contains("This query begins with SELECT, which is not a Cypher clause."),
        "{sql}"
    );
    assert!(
        sql.contains("Neo.ClientError.Statement.SyntaxError"),
        "{sql}"
    );
    // cypher-shell asks for write mode on every query; an example refusal naming writes made
    // the model refuse SELECT as Forbidden, so the hint says what `mode` is.
    assert!(!sql.contains("a write they forbid"), "{sql}");
    assert!(
        sql.contains("never a reason to refuse unless your instructions forbid writes"),
        "{sql}"
    );
    let cypher = query_answer_with("  match (m:Movie) RETURN count(m) AS movies");
    assert!(
        cypher.contains("This query begins with MATCH, a Cypher clause."),
        "{cypher}"
    );
    let call = query_answer_with("CALL(x) { RETURN 1 }");
    assert!(call.contains("begins with CALL, a Cypher clause"), "{call}");
    assert!(query_answer_with("   ").contains("This query is empty."));
}

/// A record written as an object keyed by exactly the field names is the same row, in field
/// order; anything else that is not an array is still refused.
#[test]
fn a_record_keyed_by_its_field_names_is_read_in_field_order() {
    use netget::server::bolt::{packstream::Value, values::query_answer};
    let answer = query_answer(&serde_json::json!({
        "type": "send_bolt_records",
        "fields": ["name", "born"],
        "records": [{"born": 1815, "name": "Ada"}, ["Grace", 1906]]
    }))
    .expect("an object row keyed by the fields is accepted");
    assert_eq!(answer.records.len(), 2);
    assert_eq!(
        answer.records[0],
        vec![Value::String("Ada".into()), Value::Int(1815)]
    );
    for bad in [
        serde_json::json!({"name": "Ada"}),
        serde_json::json!({"name": "Ada", "born": 1815, "died": 1852}),
        serde_json::json!({"name": "Ada", "year": 1815}),
        serde_json::json!("Ada"),
    ] {
        let refused = query_answer(&serde_json::json!({
            "type": "send_bolt_records",
            "fields": ["name", "born"],
            "records": [bad.clone()]
        }));
        assert!(refused.is_err(), "{bad} must be refused");
    }
}

/// The query hint names the result's columns as Neo4j names them, read off the final RETURN:
/// the alias where there is one, the item's text otherwise. Told only "the names after RETURN",
/// llama3.1:8b named `RETURN count(m) AS movies`'s column `count(m)` or `count` on 13 replayed
/// seeds in 20; named exactly, on none.
#[test]
fn the_query_hint_names_the_columns_of_the_final_return() {
    use netget::server::bolt::actions::{query_answer_with, return_columns};
    let hint = query_answer_with("MATCH (m:Movie) RETURN count(m) AS movies");
    assert!(
        hint.contains(
            "send_bolt_records whose fields are exactly [\"movies\"] - the column names after \
             RETURN, an AS alias where there is one - and whose rows"
        ),
        "{hint}"
    );

    let cols = |q: &str| return_columns(q).map(|c| c.join("|"));
    assert_eq!(
        cols("MATCH (p:Person) RETURN p.name AS name").as_deref(),
        Some("name")
    );
    assert_eq!(
        cols("match (p) return distinct p.name, p.born as Born order by p.name limit 3").as_deref(),
        Some("p.name|Born")
    );
    // Commas and keywords inside brackets and strings belong to the item.
    assert_eq!(
        cols("MATCH (n) RETURN coalesce(n.a, 'x, AS y') AS `the value`, [1, 2] AS l").as_deref(),
        Some("the value|l")
    );
    assert_eq!(
        cols("MATCH (n) RETURN count(n)").as_deref(),
        Some("count(n)")
    );
    // The final RETURN is the result's, not a subquery's.
    assert_eq!(
        cols("CALL { MATCH (n) RETURN n AS inner } RETURN inner.name AS outer").as_deref(),
        Some("outer")
    );
    // No plain answer: the hint keeps the general wording.
    for q in [
        "CREATE (n:Movie)",
        "MATCH (n) RETURN *",
        "MATCH (n RETURN n",
        "RETURN 'open",
    ] {
        assert_eq!(return_columns(q), None, "{q}");
        assert!(
            query_answer_with(q).contains("whose fields are the names after RETURN"),
            "{q}"
        );
    }
}
