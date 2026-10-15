//! PC/AT scancode set 1, as SPICE's inputs channel carries keys, in both directions: the
//! server decodes what a client pressed into a key name and the character it types (US
//! layout), and the client turns the model's text and key names back into scancodes.
//!
//! On the wire a key is a sequence of scancode bytes: `0xE0` prefixes an extended key, and bit
//! 7 marks a release. `SPICE_MSGC_INPUTS_KEY_DOWN`/`KEY_UP` pack the sequence into a `u32`,
//! first byte lowest (spice-server pushes `code & 0xff` and shifts until nothing is left);
//! `SPICE_MSGC_INPUTS_KEY_SCANCODE` carries the bytes as they are.

/// One decoded key transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stroke {
    pub scancode: u8,
    pub extended: bool,
    pub released: bool,
}

/// Turns scancode bytes into [`Stroke`]s. `0xE1` (Pause's prefix) and the bytes of its
/// sequence are dropped: Pause is the one key with no release and an eight-byte make code.
#[derive(Debug, Default)]
pub struct Decoder {
    extended: bool,
    pause_bytes: u8,
}

impl Decoder {
    pub fn feed(&mut self, byte: u8) -> Option<Stroke> {
        if self.pause_bytes > 0 {
            self.pause_bytes -= 1;
            return None;
        }
        match byte {
            0xE0 => {
                self.extended = true;
                None
            }
            0xE1 => {
                self.pause_bytes = 5;
                None
            }
            0 => None,
            b => {
                let stroke = Stroke {
                    scancode: b & 0x7F,
                    extended: std::mem::take(&mut self.extended),
                    released: b & 0x80 != 0,
                };
                Some(stroke)
            }
        }
    }

    /// The bytes of a `KEY_DOWN`/`KEY_UP` code, lowest first, until a zero byte.
    pub fn feed_code(&mut self, code: u32) -> Vec<Stroke> {
        let mut out = Vec::new();
        for b in code.to_le_bytes() {
            if b == 0 {
                break;
            }
            out.extend(self.feed(b));
        }
        out
    }
}

/// The `KEY_DOWN` / `KEY_UP` code for a key: `0xE0` first for an extended key.
pub fn key_code(scancode: u8, extended: bool, release: bool) -> u32 {
    let sc = u32::from(scancode & 0x7F) | if release { 0x80 } else { 0 };
    if extended {
        0xE0 | (sc << 8)
    } else {
        sc
    }
}

/// (scancode, unshifted, shifted) for every key that types a character on a US keyboard.
const CHARS: &[(u8, char, char)] = &[
    (0x02, '1', '!'),
    (0x03, '2', '@'),
    (0x04, '3', '#'),
    (0x05, '4', '$'),
    (0x06, '5', '%'),
    (0x07, '6', '^'),
    (0x08, '7', '&'),
    (0x09, '8', '*'),
    (0x0A, '9', '('),
    (0x0B, '0', ')'),
    (0x0C, '-', '_'),
    (0x0D, '=', '+'),
    (0x0F, '\t', '\t'),
    (0x10, 'q', 'Q'),
    (0x11, 'w', 'W'),
    (0x12, 'e', 'E'),
    (0x13, 'r', 'R'),
    (0x14, 't', 'T'),
    (0x15, 'y', 'Y'),
    (0x16, 'u', 'U'),
    (0x17, 'i', 'I'),
    (0x18, 'o', 'O'),
    (0x19, 'p', 'P'),
    (0x1A, '[', '{'),
    (0x1B, ']', '}'),
    (0x1C, '\n', '\n'),
    (0x1E, 'a', 'A'),
    (0x1F, 's', 'S'),
    (0x20, 'd', 'D'),
    (0x21, 'f', 'F'),
    (0x22, 'g', 'G'),
    (0x23, 'h', 'H'),
    (0x24, 'j', 'J'),
    (0x25, 'k', 'K'),
    (0x26, 'l', 'L'),
    (0x27, ';', ':'),
    (0x28, '\'', '"'),
    (0x29, '`', '~'),
    (0x2B, '\\', '|'),
    (0x2C, 'z', 'Z'),
    (0x2D, 'x', 'X'),
    (0x2E, 'c', 'C'),
    (0x2F, 'v', 'V'),
    (0x30, 'b', 'B'),
    (0x31, 'n', 'N'),
    (0x32, 'm', 'M'),
    (0x33, ',', '<'),
    (0x34, '.', '>'),
    (0x35, '/', '?'),
    (0x39, ' ', ' '),
];

/// (scancode, extended, name) for keys with a name rather than a character. The names are the
/// X11 keysym names a VNC event uses, so a model sees one vocabulary across both servers.
const NAMED: &[(u8, bool, &str)] = &[
    (0x01, false, "Escape"),
    (0x0E, false, "BackSpace"),
    (0x0F, false, "Tab"),
    (0x1C, false, "Return"),
    (0x1D, false, "Control_L"),
    (0x2A, false, "Shift_L"),
    (0x36, false, "Shift_R"),
    (0x37, false, "KP_Multiply"),
    (0x38, false, "Alt_L"),
    (0x39, false, "space"),
    (0x3A, false, "Caps_Lock"),
    (0x3B, false, "F1"),
    (0x3C, false, "F2"),
    (0x3D, false, "F3"),
    (0x3E, false, "F4"),
    (0x3F, false, "F5"),
    (0x40, false, "F6"),
    (0x41, false, "F7"),
    (0x42, false, "F8"),
    (0x43, false, "F9"),
    (0x44, false, "F10"),
    (0x45, false, "Num_Lock"),
    (0x46, false, "Scroll_Lock"),
    (0x47, false, "KP_7"),
    (0x48, false, "KP_8"),
    (0x49, false, "KP_9"),
    (0x4A, false, "KP_Subtract"),
    (0x4B, false, "KP_4"),
    (0x4C, false, "KP_5"),
    (0x4D, false, "KP_6"),
    (0x4E, false, "KP_Add"),
    (0x4F, false, "KP_1"),
    (0x50, false, "KP_2"),
    (0x51, false, "KP_3"),
    (0x52, false, "KP_0"),
    (0x53, false, "KP_Decimal"),
    (0x57, false, "F11"),
    (0x58, false, "F12"),
    (0x1C, true, "KP_Enter"),
    (0x1D, true, "Control_R"),
    (0x35, true, "KP_Divide"),
    (0x38, true, "Alt_R"),
    (0x47, true, "Home"),
    (0x48, true, "Up"),
    (0x49, true, "Page_Up"),
    (0x4B, true, "Left"),
    (0x4D, true, "Right"),
    (0x4F, true, "End"),
    (0x50, true, "Down"),
    (0x51, true, "Page_Down"),
    (0x52, true, "Insert"),
    (0x53, true, "Delete"),
    (0x5B, true, "Super_L"),
    (0x5C, true, "Super_R"),
    (0x5D, true, "Menu"),
];

/// Modifier keys, which change the state rather than type anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Modifier {
    Shift,
    Ctrl,
    Alt,
    Super,
}

pub fn modifier(scancode: u8, extended: bool) -> Option<Modifier> {
    match (scancode, extended) {
        (0x2A, false) | (0x36, false) => Some(Modifier::Shift),
        (0x1D, _) => Some(Modifier::Ctrl),
        (0x38, _) => Some(Modifier::Alt),
        (0x5B, true) | (0x5C, true) => Some(Modifier::Super),
        _ => None,
    }
}

/// The key's name: its character for a printable key (shifted when `shift`), otherwise its
/// keysym name, otherwise `scancode_0x..`.
pub fn key_name(scancode: u8, extended: bool, shift: bool) -> String {
    if let Some((_, _, name)) = NAMED
        .iter()
        .find(|(s, e, _)| *s == scancode && *e == extended)
    {
        return (*name).to_string();
    }
    if !extended {
        if let Some(c) = char_for(scancode, shift) {
            return c.to_string();
        }
    }
    format!(
        "scancode_{}{scancode:#04x}",
        if extended { "e0_" } else { "" }
    )
}

/// The character a non-extended key types on a US keyboard.
pub fn char_for(scancode: u8, shift: bool) -> Option<char> {
    CHARS
        .iter()
        .find(|(s, _, _)| *s == scancode)
        .map(|(_, plain, shifted)| if shift { *shifted } else { *plain })
}

/// The key and shift state that type `c` on a US keyboard.
pub fn scancode_for_char(c: char) -> Option<(u8, bool)> {
    CHARS.iter().find_map(|(s, plain, shifted)| {
        if *plain == c {
            Some((*s, false))
        } else if *shifted == c {
            Some((*s, true))
        } else {
            None
        }
    })
}

/// A key named by the model: `enter`, `esc`, `ctrl`, `f5`, `page_down`, `a`, `Return`, ….
/// Returns (scancode, extended).
pub fn named_key(name: &str) -> Option<(u8, bool)> {
    let lower = name.trim().to_ascii_lowercase();
    let alias = match lower.as_str() {
        "enter" | "return" => Some((0x1C, false)),
        "esc" | "escape" => Some((0x01, false)),
        "tab" => Some((0x0F, false)),
        "backspace" => Some((0x0E, false)),
        "space" => Some((0x39, false)),
        "ctrl" | "control" | "control_l" => Some((0x1D, false)),
        "shift" | "shift_l" => Some((0x2A, false)),
        "alt" | "alt_l" => Some((0x38, false)),
        "win" | "super" | "meta" | "super_l" => Some((0x5B, true)),
        "delete" | "del" => Some((0x53, true)),
        "insert" | "ins" => Some((0x52, true)),
        "home" => Some((0x47, true)),
        "end" => Some((0x4F, true)),
        "pageup" | "page_up" | "pgup" => Some((0x49, true)),
        "pagedown" | "page_down" | "pgdn" => Some((0x51, true)),
        "up" => Some((0x48, true)),
        "down" => Some((0x50, true)),
        "left" => Some((0x4B, true)),
        "right" => Some((0x4D, true)),
        "capslock" | "caps_lock" => Some((0x3A, false)),
        "menu" => Some((0x5D, true)),
        _ => None,
    };
    if alias.is_some() {
        return alias;
    }
    if let Some(n) = lower.strip_prefix('f').and_then(|n| n.parse::<u8>().ok()) {
        return match n {
            1..=10 => Some((0x3A + n, false)),
            11 => Some((0x57, false)),
            12 => Some((0x58, false)),
            _ => None,
        };
    }
    if let Some((s, e, _)) = NAMED
        .iter()
        .find(|(_, _, n)| n.eq_ignore_ascii_case(name.trim()))
    {
        return Some((*s, *e));
    }
    let mut chars = name.chars();
    match (chars.next(), chars.next()) {
        (Some(c), None) => scancode_for_char(c.to_ascii_lowercase()).map(|(s, _)| (s, false)),
        _ => None,
    }
}
