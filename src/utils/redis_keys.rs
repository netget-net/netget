//! Redis mechanics shared by NetGet's Redis server and client: the cluster hash slot of a key,
//! which arguments of a command are keys, and the glob matcher pub/sub patterns use.
//!
//! None of this is storage and none of it is a decision a model should make. A hash slot is
//! arithmetic both ends must agree on byte for byte, the key positions of a command are part
//! of the command's definition, and a pattern either matches a channel or it does not. Each
//! is written against Redis's own source so a real cluster client and a real Redis cluster
//! agree with it; `tests/server/redis/hash_slot_test.rs` checks the slot arithmetic against a
//! real `redis-server`'s `CLUSTER KEYSLOT`, and `tests/server/redis/glob_match_test.rs` pins
//! the matcher to `stringmatchlen`'s cases.

/// The number of hash slots in a Redis Cluster.
pub const CLUSTER_SLOTS: u16 = 16384;

/// CRC16-CCITT (XMODEM): polynomial 0x1021, initial value 0, no reflection — the variant
/// Redis Cluster uses (`src/crc16.c`). `crc16(b"123456789") == 0x31C3`.
pub fn crc16(bytes: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &byte in bytes {
        crc ^= u16::from(byte) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    crc
}

/// The part of a key that is hashed: the bytes between the first `{` and the first `}` after
/// it, when that is non-empty; otherwise the whole key (`keyHashSlot` in `src/cluster.c`).
///
/// So `{user1000}.following` and `{user1000}.followers` share a slot, `foo{}{bar}` hashes the
/// whole key (the first braces are empty), and `foo{{bar}}` hashes `{bar`.
pub fn hash_tag(key: &[u8]) -> &[u8] {
    if let Some(open) = key.iter().position(|&b| b == b'{') {
        if let Some(len) = key[open + 1..].iter().position(|&b| b == b'}') {
            if len > 0 {
                return &key[open + 1..open + 1 + len];
            }
        }
    }
    key
}

/// The cluster hash slot of `key`: `crc16(hash_tag(key)) mod 16384`.
pub fn key_hash_slot(key: &[u8]) -> u16 {
    crc16(hash_tag(key)) & (CLUSTER_SLOTS - 1)
}

/// The arguments of `args` (command name first) that are keys, in order.
///
/// Written from the key specs Redis publishes in `COMMAND INFO`, for every command a cluster
/// client routes by key. Commands that carry no key (`PING`, `INFO`, `CLUSTER …`, `PUBLISH`,
/// the pub/sub family, transactions and administration) return nothing and are served by
/// whichever node receives them. A command this table does not know is assumed to take its
/// key as its first argument, which is the shape of the great majority of Redis commands —
/// and the only shape an unknown command can be routed by at all.
pub fn command_keys(args: &[Vec<u8>]) -> Vec<&[u8]> {
    let Some(name) = args.first() else {
        return Vec::new();
    };
    let name = String::from_utf8_lossy(name).to_ascii_uppercase();
    let rest = &args[1..];
    let at = |i: usize| rest.get(i).map(|a| a.as_slice());
    let all = |from: usize| rest.iter().skip(from).map(|a| a.as_slice()).collect();
    // `numkeys` at `count_at`, then that many keys.
    let counted = |count_at: usize| -> Vec<&[u8]> {
        let n = rest
            .get(count_at)
            .and_then(|a| std::str::from_utf8(a).ok())
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(0);
        rest.iter()
            .skip(count_at + 1)
            .take(n)
            .map(|a| a.as_slice())
            .collect()
    };
    let sub = || {
        rest.first()
            .map(|s| String::from_utf8_lossy(s).to_ascii_uppercase())
            .unwrap_or_default()
    };
    match name.as_str() {
        // No key at all.
        "PING" | "ECHO" | "INFO" | "CLUSTER" | "COMMAND" | "CLIENT" | "CONFIG" | "HELLO"
        | "AUTH" | "SELECT" | "DBSIZE" | "FLUSHALL" | "FLUSHDB" | "KEYS" | "SCAN" | "RANDOMKEY"
        | "TIME" | "PUBLISH" | "SPUBLISH" | "SUBSCRIBE" | "PSUBSCRIBE" | "SSUBSCRIBE"
        | "UNSUBSCRIBE" | "PUNSUBSCRIBE" | "SUNSUBSCRIBE" | "PUBSUB" | "MULTI" | "EXEC"
        | "DISCARD" | "UNWATCH" | "SCRIPT" | "FUNCTION" | "ASKING" | "READONLY" | "READWRITE"
        | "QUIT" | "RESET" | "WAIT" | "WAITAOF" | "LASTSAVE" | "SAVE" | "BGSAVE"
        | "BGREWRITEAOF" | "SHUTDOWN" | "MONITOR" | "SLOWLOG" | "LATENCY" | "DEBUG" | "ACL"
        | "ROLE" | "REPLICAOF" | "SLAVEOF" | "SWAPDB" | "FAILOVER" | "MODULE" | "LOLWUT"
        | "SYNC" | "PSYNC" | "REPLCONF" | "MIGRATE" => Vec::new(),
        // A subcommand, then the key.
        "OBJECT" | "XINFO" => at(1).into_iter().collect(),
        "MEMORY" if sub() == "USAGE" => at(1).into_iter().collect(),
        "MEMORY" => Vec::new(),
        "XGROUP" if sub() != "HELP" => at(1).into_iter().collect(),
        "XGROUP" => Vec::new(),
        // Every argument is a key.
        "DEL" | "EXISTS" | "UNLINK" | "TOUCH" | "MGET" | "WATCH" | "SINTER" | "SUNION"
        | "SDIFF" | "PFCOUNT" | "PFMERGE" | "SINTERSTORE" | "SUNIONSTORE" | "SDIFFSTORE" => all(0),
        // Two keys, then other arguments.
        "RENAME" | "RENAMENX" | "SMOVE" | "RPOPLPUSH" | "BRPOPLPUSH" | "LMOVE" | "BLMOVE"
        | "COPY" | "GEOSEARCHSTORE" | "ZRANGESTORE" => {
            rest.iter().take(2).map(|a| a.as_slice()).collect()
        }
        // An operation, then a destination and its sources.
        "BITOP" => all(1),
        // Every argument but the trailing timeout.
        "BLPOP" | "BRPOP" | "BZPOPMIN" | "BZPOPMAX" => rest
            .iter()
            .take(rest.len().saturating_sub(1))
            .map(|a| a.as_slice())
            .collect(),
        // key value key value …
        "MSET" | "MSETNX" => rest.iter().step_by(2).map(|a| a.as_slice()).collect(),
        // script/function, numkeys, keys…
        "EVAL" | "EVALSHA" | "EVAL_RO" | "EVALSHA_RO" | "FCALL" | "FCALL_RO" => counted(1),
        // destination, numkeys, keys…
        "ZUNIONSTORE" | "ZINTERSTORE" | "ZDIFFSTORE" => {
            let mut keys: Vec<&[u8]> = at(0).into_iter().collect();
            keys.extend(counted(1));
            keys
        }
        // numkeys, keys…
        "ZUNION" | "ZINTER" | "ZDIFF" | "ZINTERCARD" | "SINTERCARD" | "LMPOP" | "ZMPOP" => {
            counted(0)
        }
        // timeout, numkeys, keys…
        "BLMPOP" | "BZMPOP" => counted(1),
        // … STREAMS key… id… — the first half of what follows STREAMS.
        "XREAD" | "XREADGROUP" => {
            let Some(pos) = rest.iter().position(|a| a.eq_ignore_ascii_case(b"STREAMS")) else {
                return Vec::new();
            };
            let tail = &rest[pos + 1..];
            tail.iter()
                .take(tail.len() / 2)
                .map(|a| a.as_slice())
                .collect()
        }
        _ => at(0).into_iter().collect(),
    }
}

/// The arguments a cluster routes `args` by: [`command_keys`], except that the shard pub/sub
/// commands (`SPUBLISH`, `SSUBSCRIBE`, `SUNSUBSCRIBE`) route by their channel names, which
/// hash to slots exactly as keys do.
pub fn slot_keys(args: &[Vec<u8>]) -> Vec<&[u8]> {
    let name = args
        .first()
        .map(|n| String::from_utf8_lossy(n).to_ascii_uppercase())
        .unwrap_or_default();
    match name.as_str() {
        "SPUBLISH" => args.get(1).map(|a| a.as_slice()).into_iter().collect(),
        "SSUBSCRIBE" | "SUNSUBSCRIBE" => args.iter().skip(1).map(|a| a.as_slice()).collect(),
        _ => command_keys(args),
    }
}

/// One element of a parsed glob pattern.
#[derive(Debug, Clone, PartialEq)]
enum Token {
    /// `*`: any run of bytes (consecutive stars are one).
    Star,
    /// `?`: exactly one byte.
    Any,
    /// A byte, possibly `\`-escaped.
    Byte(u8),
    /// `[…]`: one byte in (or, negated, not in) the class.
    Class { negate: bool, items: Vec<ClassItem> },
}

#[derive(Debug, Clone, PartialEq)]
enum ClassItem {
    Byte(u8),
    Range(u8, u8),
}

/// Parse a pattern exactly the way `stringmatchlen` consumes it (`src/util.c`). How Redis
/// advances through the pattern never depends on the string being matched, so the pattern can
/// be tokenised once, ahead of the match. The quirks are Redis's own: an unterminated `[`
/// class ends at the end of the pattern with whatever it has collected, a range's ends are
/// swapped when written backwards, and a lone trailing `\` is a literal backslash.
fn tokenize(pattern: &[u8]) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut i = 0;
    while i < pattern.len() {
        match pattern[i] {
            b'*' => {
                if tokens.last() != Some(&Token::Star) {
                    tokens.push(Token::Star);
                }
                i += 1;
            }
            b'?' => {
                tokens.push(Token::Any);
                i += 1;
            }
            b'[' => {
                i += 1;
                let negate = pattern.get(i) == Some(&b'^');
                if negate {
                    i += 1;
                }
                let mut items = Vec::new();
                loop {
                    let left = pattern.len() - i;
                    if left == 0 {
                        break;
                    }
                    let c = pattern[i];
                    if c == b'\\' && left >= 2 {
                        items.push(ClassItem::Byte(pattern[i + 1]));
                        i += 2;
                    } else if c == b']' {
                        i += 1;
                        break;
                    } else if left >= 3 && pattern[i + 1] == b'-' {
                        let (a, b) = (pattern[i], pattern[i + 2]);
                        items.push(ClassItem::Range(a.min(b), a.max(b)));
                        i += 3;
                    } else {
                        items.push(ClassItem::Byte(c));
                        i += 1;
                    }
                }
                tokens.push(Token::Class { negate, items });
            }
            b'\\' if i + 1 < pattern.len() => {
                tokens.push(Token::Byte(pattern[i + 1]));
                i += 2;
            }
            other => {
                tokens.push(Token::Byte(other));
                i += 1;
            }
        }
    }
    tokens
}

fn token_matches(token: &Token, byte: u8) -> bool {
    match token {
        Token::Star => true,
        Token::Any => true,
        Token::Byte(b) => *b == byte,
        Token::Class { negate, items } => {
            let hit = items.iter().any(|item| match item {
                ClassItem::Byte(b) => *b == byte,
                ClassItem::Range(lo, hi) => (*lo..=*hi).contains(&byte),
            });
            hit != *negate
        }
    }
}

/// Whether `pattern` matches `string`, with Redis's glob semantics (`stringmatchlen`,
/// case-sensitive): `*`, `?`, `[abc]`, `[^a]`, `[a-z]` and `\` escapes.
///
/// **Not backtracking-explosive.** Redis's own matcher recurses once per `*` and protects
/// itself with a nesting limit and its `skipLongerMatches` cut. This one is iterative: only
/// the most recent `*` is ever a backtrack point, which is enough for glob (a later star can
/// absorb anything an earlier one could), so a match costs at most
/// `pattern tokens × string bytes` steps with no recursion and no allocation beyond the
/// tokens. Callers still bound both lengths, because that product is the cost of a publish.
///
/// One Redis quirk is kept deliberately: the empty string matches only the empty pattern, so
/// `*` does not match a zero-length channel name — `stringmatchlen` never enters its loop when
/// the string is empty.
pub fn glob_match(pattern: &[u8], string: &[u8]) -> bool {
    if string.is_empty() {
        return pattern.is_empty();
    }
    let tokens = tokenize(pattern);
    let (mut t, mut s) = (0usize, 0usize);
    // Where the last star was, and how far into the string it has been stretched.
    let mut star: Option<(usize, usize)> = None;
    while s < string.len() {
        if t < tokens.len() && tokens[t] == Token::Star {
            star = Some((t, s));
            t += 1;
        } else if t < tokens.len() && token_matches(&tokens[t], string[s]) {
            t += 1;
            s += 1;
        } else if let Some((star_t, star_s)) = star {
            t = star_t + 1;
            s = star_s + 1;
            star = Some((star_t, star_s + 1));
        } else {
            return false;
        }
    }
    tokens[t..].iter().all(|token| *token == Token::Star)
}
