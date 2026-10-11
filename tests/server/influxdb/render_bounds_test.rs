//! What the model's tables can make the Flux renderer build.
//!
//! `render_flux` repeats a table's measurement and every tag on every row, so a table's size
//! is rows × (cells + tags). It is measured line by line, before each line is appended: the
//! answer is refused at the line that would pass `MAX_RESPONSE_BYTES`, and a table's tags are
//! capped at `MAX_RESULT_COLUMNS` where the model's tables are read.
use netget::server::influxdb::query::{
    render_flux, tables_from_json, Cell, Column, ColumnType, Table, MAX_CELL_BYTES,
    MAX_RESPONSE_BYTES, MAX_RESULT_COLUMNS,
};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

fn tagged(tags: usize) -> Value {
    let tags: Map<String, Value> = (0..tags).map(|i| (format!("t{i}"), json!("v"))).collect();
    json!([{"tags": tags, "columns": [{"name": "v", "type": "long"}], "rows": [[1]]}])
}

#[test]
fn a_table_s_tags_are_capped_like_its_columns() {
    assert!(tables_from_json(&tagged(MAX_RESULT_COLUMNS), &mut 0, &mut 0).is_ok());
    let err = tables_from_json(&tagged(MAX_RESULT_COLUMNS + 1), &mut 0, &mut 0)
        .unwrap_err()
        .to_string();
    assert!(err.contains("tags"), "{err}");
}

fn one_column(rows: Vec<Vec<Cell>>, tags: BTreeMap<String, String>) -> Table {
    Table {
        measurement: None,
        tags,
        columns: vec![Column {
            name: "s".into(),
            kind: ColumnType::String,
            group: false,
        }],
        rows,
    }
}

#[test]
fn the_rendered_answer_may_reach_the_bound_and_not_pass_it() {
    // The size of everything but the one row, then a row that fills the rest exactly. A row
    // line is ",," + "0" + "," + cell + "\r\n": the cell plus 6.
    let head = render_flux(&[one_column(Vec::new(), BTreeMap::new())])
        .unwrap()
        .len();
    let fill = MAX_RESPONSE_BYTES - head - 6;
    let exact = one_column(vec![vec![Cell::Text("x".repeat(fill))]], BTreeMap::new());
    let rendered = render_flux(&[exact]).unwrap();
    assert_eq!(rendered.len(), MAX_RESPONSE_BYTES);

    let over = one_column(
        vec![vec![Cell::Text("x".repeat(fill + 1))]],
        BTreeMap::new(),
    );
    assert!(render_flux(&[over]).is_err());
}

#[test]
fn rows_repeating_large_tags_are_refused_at_the_first_row_that_passes_the_bound() {
    // Every tag at its largest, on every row: each row is MAX_RESULT_COLUMNS × MAX_CELL_BYTES,
    // already at MAX_RESPONSE_BYTES, so the first row is the one refused. Checking only after
    // a whole table would have built all of them first.
    let tags: BTreeMap<String, String> = (0..MAX_RESULT_COLUMNS)
        .map(|i| (format!("t{i}"), "v".repeat(MAX_CELL_BYTES)))
        .collect();
    let rows = vec![vec![Cell::Text("x".into())]; 200];
    let err = render_flux(&[one_column(rows, tags)])
        .unwrap_err()
        .to_string();
    assert!(err.contains("passes"), "{err}");

    // Many small tables whose sum passes the bound are refused too.
    let table = one_column(
        vec![vec![Cell::Text("x".repeat(MAX_CELL_BYTES))]; 8],
        BTreeMap::new(),
    );
    let tables = vec![table; MAX_RESPONSE_BYTES / (8 * MAX_CELL_BYTES) + 1];
    assert!(render_flux(&tables).is_err());
}
