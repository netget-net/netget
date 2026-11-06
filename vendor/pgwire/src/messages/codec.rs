use std::str;

use bytes::{Buf, BufMut, BytesMut};

use crate::error::{PgWireError, PgWireResult};

/// Get null-terminated string, returns None when empty cstring read.
///
/// Note that this implementation will also advance cursor by 1 after reading
/// empty cstring. This behaviour works for how postgres wire protocol handling
/// key-value pairs, which is ended by a single `\0`
pub(crate) fn get_cstring(buf: &mut BytesMut) -> Option<String> {
    let mut i = 0;

    if buf.remaining() == 0 {
        return None;
    }

    // with bound check to prevent invalid format
    while i < buf.remaining() && buf[i] != b'\0' {
        i += 1;
    }

    // NetGet patch (vendor/pgwire/README.md): no NUL before the end of the
    // message. `split_to(i + 1)` would be one past the end and panic; leave the
    // bytes unconsumed instead, so the message's end check refuses it.
    if i == buf.remaining() {
        return None;
    }

    // i+1: include the '\0'
    // move cursor to the end of cstring
    let string_buf = buf.split_to(i + 1);

    if i == 0 {
        None
    } else {
        Some(String::from_utf8_lossy(&string_buf[..i]).into_owned())
    }
}

/// Put null-termianted string
///
/// You can put empty string by giving `""` as input.
pub(crate) fn put_cstring(buf: &mut BytesMut, input: &str) {
    buf.put_slice(input.as_bytes());
    buf.put_u8(b'\0');
}

pub(crate) fn put_option_cstring(buf: &mut BytesMut, input: &Option<String>) {
    if let Some(input) = input {
        put_cstring(buf, input);
    } else {
        buf.put_u8(b'\0');
    }
}

/// Try to read message length from buf, without actually move the cursor
pub(crate) fn get_length(buf: &BytesMut, offset: usize) -> Option<usize> {
    if buf.remaining() >= 4 + offset {
        Some((&buf[offset..4 + offset]).get_i32() as usize)
    } else {
        None
    }
}

/// Check if message_length matches and move the cursor to right position then
/// call the `decode_fn` for the body
pub(crate) fn decode_packet<T, F>(
    buf: &mut BytesMut,
    offset: usize,
    max_size: usize,
    decode_fn: F,
) -> PgWireResult<Option<T>>
where
    F: Fn(&mut BytesMut, usize) -> PgWireResult<T>,
{
    if let Some(msg_len) = get_length(buf, offset) {
        if msg_len > max_size {
            return Err(PgWireError::MessageTooLarge(msg_len, max_size));
        }

        // NetGet patch (vendor/pgwire/README.md): the length counts itself, so
        // anything under 4 cannot be a message, and `msg_len - 4` in a body
        // decoder would underflow.
        if msg_len < 4 {
            return Err(PgWireError::InvalidMessageFormat(
                "declared message length is shorter than the length field",
            ));
        }

        if buf.remaining() >= msg_len + offset {
            // NetGet patch (vendor/pgwire/README.md): hand the body decoder this
            // message and nothing after it. Upstream passes the whole remaining
            // buffer, so a decoder could read into the next message, or past
            // the end of the buffer and panic.
            let mut message = buf.split_to(offset + msg_len);
            message.advance(offset + 4);
            return decode_fn(&mut message, msg_len).map(|r| Some(r));
        }
    }

    Ok(None)
}

/// NetGet patch (vendor/pgwire/README.md): [`decode_packet`] for a message a
/// client sends, which must also be consumed exactly. PostgreSQL itself
/// refuses a message with bytes left over ("invalid message format"); this is
/// also what catches a string that runs to the end of the message without its
/// NUL, which [`get_cstring`] leaves unconsumed.
pub(crate) fn decode_frontend_packet<T, F>(
    buf: &mut BytesMut,
    offset: usize,
    max_size: usize,
    decode_fn: F,
) -> PgWireResult<Option<T>>
where
    F: Fn(&mut BytesMut, usize) -> PgWireResult<T>,
{
    decode_packet(buf, offset, max_size, |body, msg_len| {
        let decoded = decode_fn(body, msg_len)?;
        if body.has_remaining() {
            return Err(PgWireError::InvalidMessageFormat(
                "message has bytes left over after its last field",
            ));
        }
        Ok(decoded)
    })
}

/// NetGet patch (vendor/pgwire/README.md): `split_to(len)` for a length the
/// peer declared, refused rather than panicking when the message is shorter.
pub(crate) fn split_declared(buf: &mut BytesMut, len: usize) -> PgWireResult<BytesMut> {
    if len > buf.remaining() {
        return Err(PgWireError::InvalidMessageFormat(
            "declared field length runs past the end of the message",
        ));
    }
    Ok(buf.split_to(len))
}

// pub(crate) fn get_and_ensure_message_type(buf: &mut BytesMut, t: u8) -> PgWireResult<()> {
//     let msg_type = buf[0];
//     // ensure the type is corrent
//     if msg_type != t {
//         return Err(PgWireError::InvalidMessageType(t, msg_type));
//     }

//     Ok(())
// }

pub(crate) fn option_string_len(s: &Option<String>) -> usize {
    1 + s.as_ref().map(|s| s.len()).unwrap_or(0)
}

#[cfg(test)]
mod test {
    use super::get_cstring;
    use bytes::{BufMut, BytesMut};

    #[test]
    fn get_cstring_valid() {
        let mut buf = BytesMut::new();
        buf.put(&b"a cstring\0"[..]);
        buf.put(&b"\0"[..]);

        assert_eq!(Some("a cstring".into()), get_cstring(&mut buf));
        assert_eq!(None, get_cstring(&mut buf));
    }

    #[test]
    fn get_cstring_empty() {
        let mut buf = BytesMut::new();

        assert_eq!(None, get_cstring(&mut buf));
    }
}
