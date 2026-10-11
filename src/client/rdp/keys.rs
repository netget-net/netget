//! Keys as RDP scancodes (set 1, as the server's keyboard driver reads them), US layout.
use anyhow::{bail, Result};
use ironrdp_input::{Operation, Scancode};

pub const SHIFT: Scancode = Scancode::from_u8(false, 0x2A);
pub const CTRL: Scancode = Scancode::from_u8(false, 0x1D);
pub const ALT: Scancode = Scancode::from_u8(false, 0x38);
pub const WIN: Scancode = Scancode::from_u8(true, 0x5B);
pub const ENTER: Scancode = Scancode::from_u8(false, 0x1C);

/// The key that types `c` on a US keyboard, and whether shift is held for it.
pub fn for_char(c: char) -> Option<(Scancode, bool)> {
    const ROWS: [(&str, &str, u8); 4] = [
        ("1234567890-=", "!@#$%^&*()_+", 0x02),
        ("qwertyuiop[]", "QWERTYUIOP{}", 0x10),
        ("asdfghjkl;'`", "ASDFGHJKL:\"~", 0x1E),
        ("\\zxcvbnm,./", "|ZXCVBNM<>?", 0x2B),
    ];
    match c {
        ' ' => return Some((Scancode::from_u8(false, 0x39), false)),
        '\n' => return Some((ENTER, false)),
        '\t' => return Some((Scancode::from_u8(false, 0x0F), false)),
        _ => {}
    }
    for (plain, shifted, first) in ROWS {
        for (set, shift) in [(plain, false), (shifted, true)] {
            if let Some(i) = set.chars().position(|k| k == c) {
                return Some((Scancode::from_u8(false, first + i as u8), shift));
            }
        }
    }
    None
}

/// A named key, or a single character's key.
pub fn named(name: &str) -> Option<Scancode> {
    let ext = |c| Some(Scancode::from_u8(true, c));
    let key = |c| Some(Scancode::from_u8(false, c));
    match name {
        "enter" | "return" => Some(ENTER),
        "tab" => key(0x0F),
        "esc" | "escape" => key(0x01),
        "backspace" => key(0x0E),
        "space" => key(0x39),
        "shift" => Some(SHIFT),
        "ctrl" | "control" => Some(CTRL),
        "alt" => Some(ALT),
        "win" | "super" | "meta" => Some(WIN),
        "capslock" => key(0x3A),
        "up" => ext(0x48),
        "down" => ext(0x50),
        "left" => ext(0x4B),
        "right" => ext(0x4D),
        "home" => ext(0x47),
        "end" => ext(0x4F),
        "pageup" => ext(0x49),
        "pagedown" => ext(0x51),
        "insert" => ext(0x52),
        "delete" | "del" => ext(0x53),
        "f11" => key(0x57),
        "f12" => key(0x58),
        f if f.len() >= 2 && f.starts_with('f') => match f[1..].parse::<u8>() {
            Ok(n @ 1..=10) => key(0x3A + n),
            _ => None,
        },
        single => {
            let mut chars = single.chars();
            match (chars.next(), chars.next()) {
                (Some(c), None) => for_char(c).filter(|(_, shift)| !shift).map(|(k, _)| k),
                _ => None,
            }
        }
    }
}

/// `ctrl+alt+delete` → the keys to hold, in order.
pub fn combo(spec: &str) -> Result<Vec<Scancode>> {
    let spec = spec.trim().to_ascii_lowercase();
    // "ctrl++" names the plus key.
    let parts: Vec<&str> = if let Some(head) = spec.strip_suffix("++") {
        head.split('+').chain(["="]).collect()
    } else {
        spec.split('+').collect()
    };
    let mut keys = Vec::new();
    for part in parts {
        match named(part.trim()) {
            Some(k) => keys.push(k),
            None => bail!("unknown key {part:?} in {spec:?}"),
        }
    }
    Ok(keys)
}

/// Press each key in order, then release them in reverse.
pub fn press(keys: &[Scancode]) -> Vec<Operation> {
    let mut ops: Vec<Operation> = keys.iter().map(|&k| Operation::KeyPressed(k)).collect();
    ops.extend(keys.iter().rev().map(|&k| Operation::KeyReleased(k)));
    ops
}

/// Keystrokes for `text`: scancodes where the US layout has the character, Unicode key
/// events where it does not.
pub fn type_text(text: &str) -> Vec<Operation> {
    let mut ops = Vec::new();
    for c in text.chars() {
        match for_char(c) {
            Some((k, true)) => ops.extend(press(&[SHIFT, k])),
            Some((k, false)) => ops.extend(press(&[k])),
            None => {
                ops.push(Operation::UnicodeKeyPressed(c));
                ops.push(Operation::UnicodeKeyReleased(c));
            }
        }
    }
    ops
}
