//! What a hostile query answer can make the InfluxDB client allocate, and what it can make
//! the model read.
//!
//! The answer body is capped at `MAX_QUERY_RESPONSE_BYTES` (4 MiB), but the Flux reader used
//! to multiply it: every row cloned every header name, and every new `table` value stored a
//! new table carrying a copy of the column descriptors, with the 64-table cap applied only
//! after the whole answer was read. A 1.5 MiB header and ~9 000 rows with distinct `table`
//! values fit under the body cap and asked for ~14 GB. These tests serve such answers from a
//! fake HTTP server on 127.0.0.1 to `query()` itself, and to `read_flux` directly, and assert
//! that what comes back is bounded and comes back promptly.
use netget::client::influxdb::query::{
    query, read_flux, CsvRecords, Language, QueryResponse, QuerySpec, MAX_COLUMNS,
    MAX_ERROR_TEXT_BYTES, MAX_HEADER_BYTES, MAX_QUERY_RESPONSE_BYTES, MAX_REPORTED_ROWS,
    MAX_REPORTED_TABLES,
};
use netget::client::influxdb::transport::Origin;
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

/// The bound on a whole exchange in these tests: an answer that takes longer is a hang.
const PROMPT: Duration = Duration::from_secs(20);

/// Serve one HTTP answer to whatever arrives, then close.
async fn serve_once(status: &'static str, content_type: &'static str, body: Vec<u8>) -> Origin {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut peer, _) = listener.accept().await.unwrap();
        let mut seen = Vec::new();
        let mut buf = [0u8; 8192];
        // The request: headers, then the Content-Length body if any.
        loop {
            let n = peer.read(&mut buf).await.unwrap();
            if n == 0 {
                return;
            }
            seen.extend_from_slice(&buf[..n]);
            if let Some(at) = seen.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&seen[..at]).to_ascii_lowercase();
                let len = head
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length: "))
                    .map_or(0, |n| n.trim().parse::<usize>().unwrap());
                if seen.len() >= at + 4 + len {
                    break;
                }
            }
        }
        let head = format!(
            "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n",
            body.len()
        );
        let _ = peer.write_all(head.as_bytes()).await;
        let _ = peer.write_all(&body).await;
        let _ = peer.shutdown().await;
    });
    Origin {
        authority: addr.to_string(),
        connect_addr: addr.to_string(),
    }
}

fn flux() -> QuerySpec {
    QuerySpec {
        language: Language::Flux,
        query: "from(bucket: \"b\")".into(),
        org: Some("o".into()),
        db: None,
        rp: None,
        epoch: None,
    }
}

async fn ask(origin: Origin, spec: QuerySpec) -> QueryResponse {
    tokio::time::timeout(PROMPT, query(origin, None, spec))
        .await
        .expect("the client answered promptly")
        .expect("the exchange itself succeeded")
}

/// `rows` rows under one header of `columns` value columns, each row in a table of its own.
fn many_tables(columns: usize, name_len: usize, rows: usize) -> String {
    let names: Vec<String> = (0..columns)
        .map(|c| format!("{c:0>width$}", width = name_len))
        .collect();
    let mut text = String::new();
    text.push_str("#datatype,string,long");
    text.push_str(&",string".repeat(columns));
    text.push_str("\r\n#group,false,false");
    text.push_str(&",false".repeat(columns));
    text.push_str("\r\n#default,_result,");
    text.push_str(&",".repeat(columns));
    text.push_str("\r\n,result,table,");
    text.push_str(&names.join(","));
    text.push_str("\r\n");
    let empties = ",".repeat(columns);
    for n in 0..rows {
        text.push_str(&format!(",,{n}{empties}\r\n"));
    }
    text
}

#[test]
fn distinct_tables_past_the_cap_are_counted_not_stored() {
    // Names as long as the header bound allows, and as many distinct tables as fit the body.
    let columns = MAX_COLUMNS - 2;
    let name_len = MAX_HEADER_BYTES / columns - 16;
    let rows = 9_000;
    let text = many_tables(columns, name_len, rows);
    assert!(
        text.len() < MAX_QUERY_RESPONSE_BYTES,
        "{} bytes",
        text.len()
    );

    let answer = read_flux(&text).unwrap();
    assert_eq!(answer.table_count, rows);
    assert_eq!(answer.row_count, rows);
    assert_eq!(
        answer.tables.len(),
        MAX_REPORTED_TABLES,
        "the rest were counted"
    );
    let kept: usize = answer.tables.iter().map(|t| t.rows.len()).sum();
    assert_eq!(kept, MAX_REPORTED_TABLES, "one row in each kept table");
    assert_eq!(answer.tables[0].columns.len(), columns);
    assert_eq!(
        answer.tables[MAX_REPORTED_TABLES - 1].table,
        MAX_REPORTED_TABLES as i64 - 1
    );
}

#[test]
fn rows_past_the_reporting_bound_are_counted_not_stored() {
    let text = format!(
        "#datatype,string,long,long\r\n#group,false,false,false\r\n#default,_result,,\r\n\
         ,result,table,n\r\n{}",
        (0..MAX_REPORTED_ROWS * 3)
            .map(|n| format!(",,0,{n}\r\n"))
            .collect::<String>()
    );
    let answer = read_flux(&text).unwrap();
    assert_eq!(answer.row_count, MAX_REPORTED_ROWS * 3);
    assert_eq!(answer.table_count, 1);
    assert_eq!(answer.tables[0].rows.len(), MAX_REPORTED_ROWS);
}

#[test]
fn a_header_or_annotation_past_the_byte_bound_is_refused() {
    // The header the finding used: under MAX_COLUMNS, 1.5 MiB of names.
    let name = "n".repeat(6 * 1024);
    let header = vec![name.as_str(); MAX_COLUMNS - 2].join(",");
    let datatypes = ",string".repeat(MAX_COLUMNS - 2);
    let text = format!(
        "#datatype,string,long{datatypes}\r\n,result,table,{header}\r\n,,0{}\r\n",
        ",".repeat(MAX_COLUMNS - 2)
    );
    let err = read_flux(&text).unwrap_err().to_string();
    assert!(err.contains("bytes of column names"), "{err}");

    let default = "d".repeat(MAX_HEADER_BYTES + 1);
    let text = format!("#datatype,string,long,string\r\n#default,_result,,{default}\r\n");
    let err = read_flux(&text).unwrap_err().to_string();
    assert!(err.contains("annotation row passes"), "{err}");

    // Exactly at the bound is taken.
    let name = "n".repeat(MAX_HEADER_BYTES - "resulttable".len());
    let text = format!("#datatype,string,long,string\r\n,result,table,{name}\r\n,,0,v\r\n");
    assert_eq!(read_flux(&text).unwrap().row_count, 1);
}

#[test]
fn a_record_with_too_many_fields_is_refused_at_the_comma() {
    let text = ",".repeat(MAX_QUERY_RESPONSE_BYTES - 1);
    let mut records = CsvRecords::new(&text, MAX_COLUMNS + 1);
    let first = records.next().unwrap();
    assert!(first.unwrap_err().to_string().contains("more than"));
    assert!(records.next().is_none(), "nothing after the refusal");
    assert!(read_flux(&text).is_err());
    // At the bound: MAX_COLUMNS + 1 fields is one record.
    let at = ",".repeat(MAX_COLUMNS);
    let record = CsvRecords::new(&at, MAX_COLUMNS + 1)
        .next()
        .unwrap()
        .unwrap();
    assert_eq!(record.len(), MAX_COLUMNS + 1);
}

#[tokio::test]
async fn a_hostile_flux_answer_over_http_is_bounded_and_prompt() {
    let columns = MAX_COLUMNS - 2;
    let text = many_tables(columns, MAX_HEADER_BYTES / columns - 16, 9_000);
    let origin = serve_once("200 OK", "text/csv", text.into_bytes()).await;
    let response = ask(origin, flux()).await;
    assert!(response.error.is_none(), "{:?}", response.error);
    let tables = response.tables.expect("tables");
    assert_eq!(tables.len(), MAX_REPORTED_TABLES);
    assert_eq!(response.row_count, 9_000);
    assert_eq!(response.reported_rows, MAX_REPORTED_TABLES);
    assert!(response.truncated);

    // The finding's own shape, a 1.5 MiB header: an error event, with its text bounded.
    let name = "n".repeat(6 * 1024);
    let header = vec![name.as_str(); columns].join(",");
    let rows: String = (0..9_000)
        .map(|n| format!(",,{n}{}\r\n", ",".repeat(columns)))
        .collect();
    let text = format!(
        "#datatype,string,long{}\r\n,result,table,{header}\r\n{rows}",
        ",string".repeat(columns)
    );
    assert!(text.len() < MAX_QUERY_RESPONSE_BYTES);
    let origin = serve_once("200 OK", "text/csv", text.into_bytes()).await;
    let response = ask(origin, flux()).await;
    let error = response.error.expect("refused");
    assert_eq!(error["code"], "unreadable_answer");
    assert!(response.tables.is_none());
}

fn message_len(response: &QueryResponse) -> usize {
    let error = response.error.as_ref().expect("an error");
    error["message"].as_str().expect("a string message").len()
}

#[tokio::test]
async fn server_error_text_reaches_the_model_bounded() {
    // Within the bound plus the "..." marker, on a char boundary: '名' is three bytes.
    let limit = MAX_ERROR_TEXT_BYTES + "...".len();
    let huge = "名".repeat(MAX_QUERY_RESPONSE_BYTES / 8);

    // v2's {code, message}.
    let body = serde_json::json!({"code": huge, "message": huge}).to_string();
    let response = ask(
        serve_once("400 Bad Request", "application/json", body.into_bytes()).await,
        flux(),
    )
    .await;
    assert_eq!(response.status, 400);
    assert!(
        message_len(&response) <= limit,
        "{}",
        message_len(&response)
    );
    let code = response.error.as_ref().unwrap()["code"].as_str().unwrap();
    assert!(code.len() <= limit);
    assert!(code.starts_with('名'));

    // v1's {error}, here as an object rather than a string.
    let body = serde_json::json!({"error": {"detail": huge}}).to_string();
    let response = ask(
        serve_once(
            "500 Internal Server Error",
            "application/json",
            body.into_bytes(),
        )
        .await,
        flux(),
    )
    .await;
    assert!(message_len(&response) <= limit);

    // A small structured message is passed through as it is.
    let body = serde_json::json!({"code": "invalid", "message": "bad query"}).to_string();
    let response = ask(
        serve_once("400 Bad Request", "application/json", body.into_bytes()).await,
        flux(),
    )
    .await;
    assert_eq!(
        response.error,
        Some(serde_json::json!({"code": "invalid", "message": "bad query"}))
    );

    // Flux's in-band failure after a 200: the error table's text.
    let body = format!(
        "#datatype,string,string\r\n#group,true,true\r\n#default,,\r\n,error,reference\r\n,\"{huge}\",897\r\n"
    );
    let response = ask(
        serve_once("200 OK", "text/csv", body.into_bytes()).await,
        flux(),
    )
    .await;
    assert_eq!(
        response.error.as_ref().unwrap()["code"],
        "unreadable_answer"
    );
    assert!(
        message_len(&response) <= limit,
        "{}",
        message_len(&response)
    );
    assert!(response.error.as_ref().unwrap()["message"]
        .as_str()
        .unwrap()
        .starts_with("the query failed: 名"));

    // A cell that does not parse as its datatype names the cell in the error: bounded too.
    let body = format!(
        "#datatype,string,long,long\r\n,result,table,n\r\n,,0,{}\r\n",
        "9".repeat(MAX_QUERY_RESPONSE_BYTES / 2)
    );
    let response = ask(
        serve_once("200 OK", "text/csv", body.into_bytes()).await,
        flux(),
    )
    .await;
    assert!(
        message_len(&response) <= limit,
        "{}",
        message_len(&response)
    );

    // InfluxQL's per-statement error inside a 200.
    let body = serde_json::json!({"results": [{"statement_id": 0, "error": huge}]}).to_string();
    let spec = QuerySpec {
        language: Language::Influxql,
        query: "SELECT 1".into(),
        org: None,
        db: Some("b".into()),
        rp: None,
        epoch: None,
    };
    let response = ask(
        serve_once("200 OK", "application/json", body.into_bytes()).await,
        spec,
    )
    .await;
    let statements = response.statements.expect("statements");
    let error = statements[0]["error"].as_str().unwrap();
    assert!(error.len() <= limit, "{}", error.len());
}
