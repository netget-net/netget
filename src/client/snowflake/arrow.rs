//! A bounded reader for the Arrow IPC **stream** a Snowflake server sends as `rowsetBase64`.
//!
//! Snowflake answers a query in one of two result formats: JSON (`rowset`, every cell a
//! string) or Arrow (`rowsetBase64`, an Arrow IPC stream). A client can ask for JSON, but a
//! server is free to answer Arrow, and fakesnow answers every SELECT in Arrow whatever it was
//! asked. So this reads the subset of Arrow a Snowflake result uses — no more:
//!
//! * the stream framing (`0xFFFFFFFF`, metadata length, flatbuffer `Message`, body), with the
//!   pre-0.15 framing (no continuation marker) accepted too;
//! * a `Schema` of flat columns, where a column may be a `Struct` of flat children (Snowflake
//!   sends timestamps as `{epoch, fraction[, timezone]}`) — and no deeper;
//! * `RecordBatch`es of Int (8–64 bit), FloatingPoint (32/64), Bool, Utf8, Binary, Decimal128,
//!   Date, Time, Timestamp, Null and that one level of Struct.
//!
//! Everything else is refused by name: dictionaries, compression, big-endian data, lists,
//! maps, unions, views, 64-bit offsets, Decimal256. The flatbuffers are read by hand with every
//! offset checked against the buffer, and nothing here recurses — a nested field is read in a
//! second loop, and a field nested deeper than [`MAX_FIELD_NESTING`] is refused.

use anyhow::{bail, ensure, Context, Result};

/// Messages (schema, batches) in one stream.
pub const MAX_MESSAGES: usize = 4096;
/// Columns in one schema, counting a struct's children.
pub const MAX_FIELDS: usize = 2048;
/// How deep a field may sit inside another. Snowflake's timestamp structs are one level deep.
pub const MAX_FIELD_NESTING: usize = 1;

/// A column's physical type, as the schema declares it.
#[derive(Debug, Clone, PartialEq)]
pub enum ArrowType {
    Null,
    Int {
        bits: u8,
        signed: bool,
    },
    Float {
        bits: u8,
    },
    Bool,
    Utf8,
    Binary,
    Decimal {
        precision: i32,
        scale: i32,
    },
    /// `day`: Date32 in days, else Date64 in milliseconds.
    Date {
        day: bool,
    },
    /// The unit as a power of ten below a second (0, 3, 6, 9) and the width.
    Time {
        scale: u32,
        bits: u8,
    },
    Timestamp {
        scale: u32,
        tz: Option<String>,
    },
    Struct,
}

/// One column of the schema, with its children if it is a struct.
#[derive(Debug, Clone)]
pub struct Field {
    pub name: String,
    pub data_type: ArrowType,
    /// Snowflake's per-field metadata: `logicalType`, `scale`, `precision`, ...
    pub metadata: Vec<(String, String)>,
    pub children: Vec<Field>,
}

impl Field {
    pub fn meta(&self, key: &str) -> Option<&str> {
        self.metadata
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
}

/// One cell, as the physical type holds it.
#[derive(Debug, Clone, PartialEq)]
pub enum Cell {
    Null,
    Int(i128),
    Float(f64),
    Bool(bool),
    Text(String),
    /// Binary data is never handed on as bytes; only its length.
    Bytes(usize),
    /// A struct's children, in schema order.
    Struct(Vec<Cell>),
}

/// The decoded stream: the schema and up to `max_rows` rows.
#[derive(Debug, Clone)]
pub struct Decoded {
    pub fields: Vec<Field>,
    pub rows: Vec<Vec<Cell>>,
    /// Rows the stream held, including those past `max_rows`.
    pub total_rows: u64,
}

// ---------------------------------------------------------------------------------------------
// Flatbuffers, by hand.

#[derive(Clone, Copy)]
struct Fb<'a> {
    buf: &'a [u8],
}

impl<'a> Fb<'a> {
    fn bytes(&self, pos: usize, n: usize) -> Result<&'a [u8]> {
        let end = pos.checked_add(n).context("flatbuffer offset overflows")?;
        self.buf
            .get(pos..end)
            .with_context(|| format!("flatbuffer read of {n} bytes at {pos} runs past its end"))
    }
    fn u8(&self, pos: usize) -> Result<u8> {
        Ok(self.bytes(pos, 1)?[0])
    }
    fn u16(&self, pos: usize) -> Result<u16> {
        let b = self.bytes(pos, 2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }
    fn i32(&self, pos: usize) -> Result<i32> {
        let b = self.bytes(pos, 4)?;
        Ok(i32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn u32(&self, pos: usize) -> Result<u32> {
        Ok(self.i32(pos)? as u32)
    }
    fn i64(&self, pos: usize) -> Result<i64> {
        let b = self.bytes(pos, 8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(i64::from_le_bytes(a))
    }
    /// The position an unsigned offset stored at `pos` points to.
    fn follow(&self, pos: usize) -> Result<usize> {
        let target = pos
            .checked_add(self.u32(pos)? as usize)
            .context("flatbuffer offset overflows")?;
        ensure!(
            target < self.buf.len(),
            "flatbuffer offset points past its end"
        );
        Ok(target)
    }
    fn table(&self, pos: usize) -> Result<Table<'a>> {
        let soffset = self.i32(pos)? as i64;
        let vt = pos as i64 - soffset;
        ensure!(
            vt >= 0 && (vt as usize) < self.buf.len(),
            "flatbuffer vtable out of range"
        );
        let vt = vt as usize;
        let vt_len = self.u16(vt)? as usize;
        ensure!(
            vt_len >= 4 && vt_len.is_multiple_of(2),
            "malformed flatbuffer vtable"
        );
        self.bytes(vt, vt_len)?;
        Ok(Table {
            fb: *self,
            pos,
            vt,
            vt_len,
        })
    }
}

#[derive(Clone, Copy)]
struct Table<'a> {
    fb: Fb<'a>,
    pos: usize,
    vt: usize,
    vt_len: usize,
}

impl<'a> Table<'a> {
    fn field(&self, slot: usize) -> Result<Option<usize>> {
        let at = 4 + 2 * slot;
        if at + 2 > self.vt_len {
            return Ok(None);
        }
        match self.fb.u16(self.vt + at)? {
            0 => Ok(None),
            off => Ok(Some(self.pos + off as usize)),
        }
    }
    fn u8_or(&self, slot: usize, default: u8) -> Result<u8> {
        self.field(slot)?.map_or(Ok(default), |p| self.fb.u8(p))
    }
    fn i16_or(&self, slot: usize, default: i16) -> Result<i16> {
        self.field(slot)?
            .map_or(Ok(default), |p| self.fb.u16(p).map(|v| v as i16))
    }
    fn i32_or(&self, slot: usize, default: i32) -> Result<i32> {
        self.field(slot)?.map_or(Ok(default), |p| self.fb.i32(p))
    }
    fn i64_or(&self, slot: usize, default: i64) -> Result<i64> {
        self.field(slot)?.map_or(Ok(default), |p| self.fb.i64(p))
    }
    fn table(&self, slot: usize) -> Result<Option<Table<'a>>> {
        match self.field(slot)? {
            None => Ok(None),
            Some(p) => Ok(Some(self.fb.table(self.fb.follow(p)?)?)),
        }
    }
    /// A vector's element start and count, each element `elem` bytes wide.
    fn vector(&self, slot: usize, elem: usize) -> Result<Option<(usize, usize)>> {
        let Some(p) = self.field(slot)? else {
            return Ok(None);
        };
        let at = self.fb.follow(p)?;
        let n = self.fb.u32(at)? as usize;
        let start = at + 4;
        let len = n.checked_mul(elem).context("flatbuffer vector overflows")?;
        self.fb.bytes(start, len)?;
        Ok(Some((start, n)))
    }
    fn string(&self, slot: usize) -> Result<Option<String>> {
        let Some((start, n)) = self.vector(slot, 1)? else {
            return Ok(None);
        };
        let b = self.fb.bytes(start, n)?;
        Ok(Some(
            std::str::from_utf8(b)
                .context("a flatbuffer string is not UTF-8")?
                .to_string(),
        ))
    }
    /// The tables of a vector of tables.
    fn tables(&self, slot: usize, max: usize) -> Result<Vec<Table<'a>>> {
        let Some((start, n)) = self.vector(slot, 4)? else {
            return Ok(Vec::new());
        };
        ensure!(n <= max, "{n} entries where at most {max} are read");
        (0..n)
            .map(|i| self.fb.table(self.fb.follow(start + 4 * i)?))
            .collect()
    }
}

// ---------------------------------------------------------------------------------------------
// Schema.

const MESSAGE_SCHEMA: u8 = 1;
const MESSAGE_DICTIONARY_BATCH: u8 = 2;
const MESSAGE_RECORD_BATCH: u8 = 3;

fn type_name(code: u8) -> &'static str {
    match code {
        1 => "Null",
        2 => "Int",
        3 => "FloatingPoint",
        4 => "Binary",
        5 => "Utf8",
        6 => "Bool",
        7 => "Decimal",
        8 => "Date",
        9 => "Time",
        10 => "Timestamp",
        11 => "Interval",
        12 => "List",
        13 => "Struct",
        14 => "Union",
        15 => "FixedSizeBinary",
        16 => "FixedSizeList",
        17 => "Map",
        18 => "Duration",
        19 => "LargeBinary",
        20 => "LargeUtf8",
        21 => "LargeList",
        22 => "RunEndEncoded",
        23 => "BinaryView",
        24 => "Utf8View",
        _ => "an unknown type",
    }
}

fn unit_scale(unit: i16) -> Result<u32> {
    Ok(match unit {
        0 => 0,
        1 => 3,
        2 => 6,
        3 => 9,
        other => bail!("time unit {other} is not one Arrow defines"),
    })
}

/// One field of the schema, without its children.
fn read_field<'a>(t: &Table<'a>) -> Result<(Field, Vec<Table<'a>>)> {
    let name = t.string(0)?.unwrap_or_default();
    let type_code = t.u8_or(2, 0)?;
    ensure!(
        t.field(4)?.is_none(),
        "column {name:?} is dictionary-encoded, which this client does not read"
    );
    let ty = t.table(3)?;
    let data_type = match type_code {
        1 => ArrowType::Null,
        2 => {
            let ty = ty.context("an Int type with no parameters")?;
            let bits = ty.i32_or(0, 0)?;
            ensure!(
                matches!(bits, 8 | 16 | 32 | 64),
                "column {name:?}: Int of {bits} bits"
            );
            ArrowType::Int {
                bits: bits as u8,
                signed: ty.u8_or(1, 0)? != 0,
            }
        }
        3 => {
            let precision = ty.map_or(Ok(0), |ty| ty.i16_or(0, 0))?;
            ArrowType::Float {
                bits: match precision {
                    1 => 32,
                    2 => 64,
                    _ => bail!("column {name:?}: half-precision floats are not read"),
                },
            }
        }
        4 => ArrowType::Binary,
        5 => ArrowType::Utf8,
        6 => ArrowType::Bool,
        7 => {
            let ty = ty.context("a Decimal type with no parameters")?;
            let bits = ty.i32_or(2, 128)?;
            ensure!(
                bits == 128,
                "column {name:?}: Decimal{bits} is not read (Decimal128 is)"
            );
            ArrowType::Decimal {
                precision: ty.i32_or(0, 0)?,
                scale: ty.i32_or(1, 0)?,
            }
        }
        8 => ArrowType::Date {
            day: ty.map_or(Ok(1), |ty| ty.i16_or(0, 1))? == 0,
        },
        9 => {
            let (unit, bits) = match ty {
                Some(ty) => (ty.i16_or(0, 1)?, ty.i32_or(1, 32)?),
                None => (1, 32),
            };
            ensure!(
                matches!(bits, 32 | 64),
                "column {name:?}: Time of {bits} bits"
            );
            ArrowType::Time {
                scale: unit_scale(unit)?,
                bits: bits as u8,
            }
        }
        10 => {
            let ty = ty.context("a Timestamp type with no parameters")?;
            ArrowType::Timestamp {
                scale: unit_scale(ty.i16_or(0, 0)?)?,
                tz: ty.string(1)?,
            }
        }
        13 => ArrowType::Struct,
        other => bail!(
            "column {name:?} is an Arrow {}, which this client does not read",
            type_name(other)
        ),
    };
    let mut metadata = Vec::new();
    for kv in t.tables(6, 64)? {
        metadata.push((
            kv.string(0)?.unwrap_or_default(),
            kv.string(1)?.unwrap_or_default(),
        ));
    }
    let children = t.tables(5, MAX_FIELDS)?;
    if data_type != ArrowType::Struct {
        ensure!(
            children.is_empty(),
            "column {name:?} is not a struct but has children"
        );
    }
    Ok((
        Field {
            name,
            data_type,
            metadata,
            children: Vec::new(),
        },
        children,
    ))
}

fn read_schema(schema: &Table<'_>) -> Result<Vec<Field>> {
    ensure!(
        schema.i16_or(0, 0)? == 0,
        "the result is big-endian Arrow, which this client does not read"
    );
    let mut fields = Vec::new();
    let mut count = 0usize;
    for t in schema.tables(1, MAX_FIELDS)? {
        let (mut field, children) = read_field(&t)?;
        count += 1;
        // One level of nesting, read in this loop rather than by recursion.
        for child in children {
            let (child, grandchildren) = read_field(&child)?;
            ensure!(
                grandchildren.is_empty() && child.data_type != ArrowType::Struct,
                "column {:?} nests deeper than {MAX_FIELD_NESTING} level",
                field.name
            );
            count += 1;
            field.children.push(child);
        }
        ensure!(
            count <= MAX_FIELDS,
            "the schema has more than {MAX_FIELDS} fields"
        );
        fields.push(field);
    }
    Ok(fields)
}

// ---------------------------------------------------------------------------------------------
// Record batches.

struct Node {
    length: usize,
    null_count: usize,
}

struct BatchReader<'a> {
    body: &'a [u8],
    nodes: Vec<Node>,
    buffers: Vec<(usize, usize)>,
    next_node: usize,
    next_buffer: usize,
}

impl<'a> BatchReader<'a> {
    fn node(&mut self) -> Result<&Node> {
        let n = self
            .nodes
            .get(self.next_node)
            .context("the batch has fewer field nodes than the schema has fields")?;
        self.next_node += 1;
        Ok(n)
    }
    fn buffer(&mut self) -> Result<&'a [u8]> {
        let (offset, length) = *self
            .buffers
            .get(self.next_buffer)
            .context("the batch has fewer buffers than its columns need")?;
        self.next_buffer += 1;
        let end = offset
            .checked_add(length)
            .context("a buffer's extent overflows")?;
        self.body
            .get(offset..end)
            .context("a buffer runs past the message body")
    }
}

fn valid(bitmap: &[u8], null_count: usize, i: usize) -> Result<bool> {
    if bitmap.is_empty() {
        ensure!(
            null_count == 0,
            "a column with nulls has no validity bitmap"
        );
        return Ok(true);
    }
    let byte = bitmap
        .get(i / 8)
        .context("the validity bitmap is shorter than the column")?;
    Ok(byte & (1 << (i % 8)) != 0)
}

fn fixed(values: &[u8], width: usize, i: usize) -> Result<&[u8]> {
    values
        .get(i * width..(i + 1) * width)
        .context("a value buffer is shorter than the column")
}

fn read_int(b: &[u8], signed: bool) -> i128 {
    let mut a = [0u8; 16];
    a[..b.len()].copy_from_slice(b);
    if signed && b.last().is_some_and(|x| x & 0x80 != 0) {
        for x in &mut a[b.len()..] {
            *x = 0xFF;
        }
    }
    i128::from_le_bytes(a)
}

/// Read `take` rows of one flat (non-struct) column.
fn read_flat(
    r: &mut BatchReader<'_>,
    ty: &ArrowType,
    len: usize,
    take: usize,
) -> Result<Vec<Cell>> {
    let node = r.node()?;
    let (nlen, nulls) = (node.length, node.null_count);
    ensure!(
        nlen == len,
        "a column holds {nlen} values in a batch of {len} rows"
    );
    ensure!(nulls <= nlen, "a column claims more nulls than values");
    if *ty == ArrowType::Null {
        return Ok(vec![Cell::Null; take]);
    }
    let bitmap = r.buffer()?;
    let mut out = Vec::with_capacity(take);
    match ty {
        ArrowType::Utf8 | ArrowType::Binary => {
            let offsets = r.buffer()?;
            let data = r.buffer()?;
            ensure!(
                offsets.len() >= (len + 1) * 4,
                "an offsets buffer is shorter than the column"
            );
            let at = |i: usize| -> Result<usize> {
                let v = i32::from_le_bytes(fixed(offsets, 4, i)?.try_into()?);
                ensure!(v >= 0, "a negative string offset");
                Ok(v as usize)
            };
            for i in 0..take {
                if !valid(bitmap, nulls, i)? {
                    out.push(Cell::Null);
                    continue;
                }
                let (s, e) = (at(i)?, at(i + 1)?);
                ensure!(s <= e, "string offsets run backwards");
                let bytes = data
                    .get(s..e)
                    .context("a string runs past its data buffer")?;
                out.push(if *ty == ArrowType::Utf8 {
                    Cell::Text(
                        std::str::from_utf8(bytes)
                            .context("a Utf8 value is not UTF-8")?
                            .to_string(),
                    )
                } else {
                    Cell::Bytes(bytes.len())
                });
            }
        }
        ArrowType::Bool => {
            let values = r.buffer()?;
            for i in 0..take {
                if !valid(bitmap, nulls, i)? {
                    out.push(Cell::Null);
                    continue;
                }
                out.push(Cell::Bool(valid(values, 0, i)?));
            }
        }
        _ => {
            let values = r.buffer()?;
            let (width, signed) = match ty {
                ArrowType::Int { bits, signed } => (*bits as usize / 8, *signed),
                ArrowType::Float { bits } => (*bits as usize / 8, true),
                ArrowType::Decimal { .. } => (16, true),
                ArrowType::Date { day } => (if *day { 4 } else { 8 }, true),
                ArrowType::Time { bits, .. } => (*bits as usize / 8, true),
                ArrowType::Timestamp { .. } => (8, true),
                _ => bail!("unexpected column type"),
            };
            for i in 0..take {
                if !valid(bitmap, nulls, i)? {
                    out.push(Cell::Null);
                    continue;
                }
                let b = fixed(values, width, i)?;
                out.push(match ty {
                    ArrowType::Float { bits: 32 } => {
                        Cell::Float(f32::from_le_bytes(b.try_into()?) as f64)
                    }
                    ArrowType::Float { .. } => Cell::Float(f64::from_le_bytes(b.try_into()?)),
                    _ => Cell::Int(read_int(b, signed)),
                });
            }
        }
    }
    Ok(out)
}

fn read_batch(
    batch: &Table<'_>,
    body: &[u8],
    fields: &[Field],
    take: usize,
) -> Result<(usize, Vec<Vec<Cell>>)> {
    ensure!(
        batch.field(3)?.is_none(),
        "the result is compressed Arrow, which this client does not read"
    );
    let length = batch.i64_or(0, 0)?;
    ensure!(length >= 0, "a batch with a negative length");
    let length = length as usize;
    let fb = batch.fb;
    let (nstart, ncount) = batch.vector(1, 16)?.unwrap_or((0, 0));
    let (bstart, bcount) = batch.vector(2, 16)?.unwrap_or((0, 0));
    ensure!(
        ncount <= MAX_FIELDS && bcount <= 3 * MAX_FIELDS,
        "a batch with {ncount} nodes and {bcount} buffers"
    );
    let mut nodes = Vec::with_capacity(ncount);
    for i in 0..ncount {
        let (l, n) = (fb.i64(nstart + 16 * i)?, fb.i64(nstart + 16 * i + 8)?);
        ensure!(l >= 0 && n >= 0, "a field node with a negative count");
        nodes.push(Node {
            length: l as usize,
            null_count: n as usize,
        });
    }
    let mut buffers = Vec::with_capacity(bcount);
    for i in 0..bcount {
        let (o, l) = (fb.i64(bstart + 16 * i)?, fb.i64(bstart + 16 * i + 8)?);
        ensure!(o >= 0 && l >= 0, "a buffer with a negative extent");
        buffers.push((o as usize, l as usize));
    }
    let mut r = BatchReader {
        body,
        nodes,
        buffers,
        next_node: 0,
        next_buffer: 0,
    };
    let take = take.min(length);
    let mut columns: Vec<Vec<Cell>> = Vec::with_capacity(fields.len());
    for field in fields {
        if field.data_type == ArrowType::Struct {
            let node = r.node()?;
            let (nlen, nulls) = (node.length, node.null_count);
            ensure!(
                nlen == length,
                "a struct column holds {nlen} values in a batch of {length} rows"
            );
            let bitmap = r.buffer()?;
            let mut children = Vec::with_capacity(field.children.len());
            for child in &field.children {
                children.push(read_flat(&mut r, &child.data_type, length, take)?);
            }
            let mut col = Vec::with_capacity(take);
            for i in 0..take {
                col.push(if valid(bitmap, nulls, i)? {
                    Cell::Struct(children.iter().map(|c| c[i].clone()).collect())
                } else {
                    Cell::Null
                });
            }
            columns.push(col);
        } else {
            columns.push(read_flat(&mut r, &field.data_type, length, take)?);
        }
    }
    let rows = (0..take)
        .map(|i| columns.iter().map(|c| c[i].clone()).collect())
        .collect();
    Ok((length, rows))
}

/// Decode an Arrow IPC stream, keeping at most `max_rows` rows.
pub fn decode_stream(stream: &[u8], max_rows: usize) -> Result<Decoded> {
    let mut pos = 0usize;
    let mut fields: Option<Vec<Field>> = None;
    let mut rows = Vec::new();
    let mut total_rows = 0u64;
    for message in 0.. {
        ensure!(
            message < MAX_MESSAGES,
            "the stream has more than {MAX_MESSAGES} messages"
        );
        if stream.len() < pos + 4 {
            break;
        }
        let word = |at: usize| -> Result<u32> {
            let b = stream
                .get(at..at + 4)
                .context("the stream ends inside a message header")?;
            Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        };
        let mut meta_len = word(pos)?;
        pos += 4;
        if meta_len == 0xFFFF_FFFF {
            meta_len = word(pos)?;
            pos += 4;
        }
        if meta_len == 0 {
            break;
        }
        let meta_len = meta_len as usize;
        ensure!(
            meta_len <= stream.len() - pos.min(stream.len()),
            "a message's metadata runs past the stream"
        );
        let meta = Fb {
            buf: &stream[pos..pos + meta_len],
        };
        pos += meta_len;
        let msg = meta.table(meta.follow(0)?)?;
        let header_type = msg.u8_or(1, 0)?;
        let body_len = msg.i64_or(3, 0)?;
        ensure!(
            body_len >= 0 && body_len as usize <= stream.len() - pos,
            "a message body runs past the stream"
        );
        let body = &stream[pos..pos + body_len as usize];
        pos += body_len as usize;
        let header = msg.table(2)?.context("a message with no header")?;
        match header_type {
            MESSAGE_SCHEMA => {
                ensure!(fields.is_none(), "the stream carries a second schema");
                fields = Some(read_schema(&header)?);
            }
            MESSAGE_RECORD_BATCH => {
                let schema = fields
                    .as_ref()
                    .context("a record batch before the schema")?;
                let take = max_rows.saturating_sub(rows.len());
                let (length, batch_rows) = read_batch(&header, body, schema, take)?;
                total_rows += length as u64;
                rows.extend(batch_rows);
            }
            MESSAGE_DICTIONARY_BATCH => {
                bail!("the result carries an Arrow dictionary, which this client does not read")
            }
            other => bail!("an Arrow message of type {other}, which a result never carries"),
        }
    }
    Ok(Decoded {
        fields: fields.context("the Arrow stream has no schema")?,
        rows,
        total_rows,
    })
}
