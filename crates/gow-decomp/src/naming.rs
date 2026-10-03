//! Symbol naming: what a recovered function/global is called, and where that
//! name came from.
//!
//! Priority order (highest wins), which is the convention in matching-style
//! decompilation projects:
//!
//! 1. an entry in a user-supplied `.syms.txt` symbol map (see [`SymbolMap`])
//! 2. `.mdebug` names from the executable itself
//! 3. ELF `.symtab`
//! 4. `f_<address>` / `data_<address>` placeholders
//!
//! Names are the single highest-leverage artifact of a decompilation: they are
//! what makes a 4000-function executable tractable, so they live in a plain
//! text file that is reviewed in pull requests and never regenerated wholesale.

use std::collections::BTreeMap;
use std::path::Path;

use ps2_elf::sanitize_ident;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Function,
    Data,
}

impl Kind {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Function => "function",
            Kind::Data => "data",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Entry {
    pub name: String,
    pub kind: Kind,
    /// `true` when the name came from the binary rather than a human edit.
    pub auto: bool,
    /// Optional note shown in listings ("getter for X", "referenced by ...").
    pub note: Option<String>,
}

/// A plain-text symbol map. Format, one entry per line:
///
/// ```text
/// # comment
/// 0x001129b0 function _ScrMatch_0_1129b0
/// 0x00216a40 data g_GameState
/// 0x0010aef4 function do_fade # fades the screen in/out
/// ```
///
/// Addresses accept `0x..` or decimal, fields are whitespace separated, and a
/// trailing `#` starts a comment. Unknown fields (a fourth `type=` kwarg) are
/// ignored so the format can grow.
#[derive(Clone, Default)]
pub struct SymbolMap {
    entries: BTreeMap<u32, Entry>,
}

impl SymbolMap {
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        Ok(Self::parse(&text))
    }

    #[must_use]
    pub fn parse(text: &str) -> Self {
        let mut map = BTreeMap::new();
        for (lineno, line) in text.lines().enumerate() {
            let (body, comment) = match line.split_once('#') {
                Some((a, b)) => (a, b.trim()),
                None => (line, ""),
            };
            let line = body.trim();
            if line.is_empty() {
                continue;
            }
            let mut it = line.split_whitespace();
            let (Some(addr), Some(kind), Some(name)) = (it.next(), it.next(), it.next()) else {
                eprintln!(
                    "syms:{}: expected `<addr> <function|data> <name>`, got {line:?}",
                    lineno + 1
                );
                continue;
            };
            let Some(addr) = parse_addr(addr) else {
                eprintln!("syms:{}: bad address {addr:?}", lineno + 1);
                continue;
            };
            let kind = match kind {
                "function" | "func" | "fn" => Kind::Function,
                "data" | "object" | "var" => Kind::Data,
                other => {
                    eprintln!(
                        "syms:{}: unknown kind {other:?} (want function|data)",
                        lineno + 1
                    );
                    continue;
                }
            };
            // A `# note` wins over trailing words, which is the friendlier form
            // to write by hand and what `to_text` emits back.
            let note = if !comment.is_empty() {
                comment.to_string()
            } else {
                it.collect::<Vec<_>>().join(" ")
            };
            map.insert(
                addr,
                Entry {
                    name: name.to_string(),
                    kind,
                    auto: false,
                    note: (!note.is_empty()).then(|| note.to_string()),
                },
            );
        }
        Self { entries: map }
    }

    /// Write back in canonical sorted order. Used to normalise a hand-edited
    /// map, not to regenerate it from the binary (that would throw away names).
    #[must_use]
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        out.push_str("# gow1-rust symbol map\n");
        out.push_str("# <address> <function|data> <name> [# note]\n");
        for (addr, e) in &self.entries {
            if e.auto {
                continue;
            }
            out.push_str(&format!("{addr:#010x} {} {}", e.kind.as_str(), e.name));
            if let Some(n) = &e.note {
                out.push_str(&format!(" # {n}"));
            }
            out.push('\n');
        }
        out
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        std::fs::write(path, self.to_text()).map_err(|e| format!("{}: {e}", path.display()))
    }

    #[must_use]
    pub fn get(&self, addr: u32) -> Option<&Entry> {
        self.entries.get(&addr)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    pub fn iter(&self) -> impl Iterator<Item = (u32, &Entry)> {
        self.entries.iter().map(|(a, e)| (*a, e))
    }

    /// Fold in names discovered by the binary parser. Existing human entries
    /// always win, so re-running `gowd gen` never clobbers work.
    pub fn merge_auto(&mut self, exe: &ps2_elf::Executable<'_>) -> usize {
        let mut added = 0;
        if let Some(m) = &exe.mdebug {
            for f in &m.functions {
                if self.entries.contains_key(&f.address) {
                    continue;
                }
                self.entries.insert(
                    f.address,
                    Entry {
                        name: f.name.clone(),
                        kind: Kind::Function,
                        auto: true,
                        note: None,
                    },
                );
                added += 1;
            }
            for g in &m.globals {
                if self.entries.contains_key(&g.address) || g.name.is_empty() {
                    continue;
                }
                self.entries.insert(
                    g.address,
                    Entry {
                        name: g.name.clone(),
                        kind: Kind::Data,
                        auto: true,
                        note: None,
                    },
                );
                added += 1;
            }
        }
        for s in &exe.symtab {
            if s.name.is_empty() || s.value == 0 || self.entries.contains_key(&s.value) {
                continue;
            }
            self.entries.insert(
                s.value,
                Entry {
                    name: s.name.clone(),
                    kind: if s.is_func() {
                        Kind::Function
                    } else {
                        Kind::Data
                    },
                    auto: true,
                    note: None,
                },
            );
            added += 1;
        }
        added
    }

    /// Best name for an address, as used by the disassembler and emitter.
    #[must_use]
    pub fn name_for(&self, addr: u32, exe: &ps2_elf::Executable<'_>) -> (String, bool) {
        if let Some(e) = self.entries.get(&addr) {
            return (e.name.clone(), false);
        }
        if let Some(n) = exe.name_for_address(addr) {
            return (n, true);
        }
        (format!("f_{addr:08x}"), true)
    }
}

fn parse_addr(s: &str) -> Option<u32> {
    let s = s.trim().trim_start_matches('@');
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).ok()
    } else if s.chars().all(|c| c.is_ascii_hexdigit()) && s.chars().any(|c| c.is_ascii_alphabetic())
    {
        u32::from_str_radix(s, 16).ok()
    } else {
        s.parse::<u32>().ok()
    }
}

/// A valid, stable Rust identifier for a recovered symbol.
///
/// The original spelling is preserved on purpose (only made legal): a name like
/// `_ScrMatch_0_1129b0` has to stay greppable against the executable's string
/// table and the PS2 SDK, and renaming it to snake_case would break the link
/// between the Rust source, the symbol map, and the disassembly. Rust's
/// `non_snake_case` lint is silenced per-module instead of mangling names.
#[must_use]
pub fn rust_fn_name(original: &str) -> String {
    sanitize_ident(original)
}

/// Field/variable name in `SCREAMING_SNAKE` when it came from C, else left
/// alone, so globals read as globals.
#[must_use]
pub fn rust_global_name(original: &str) -> String {
    let ident = sanitize_ident(original);
    if ident.starts_with("g_") || ident.starts_with("s_") {
        ident.to_ascii_uppercase()
    } else {
        ident
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_round_trips() {
        let text = "\
# header
0x001129b0 function _ScrMatch_0_1129b0
0x00216a40 data g_GameState # main game state block

  1110484  fn  do_fade   # trailing words are a note
";
        let m = SymbolMap::parse(text);
        assert_eq!(m.len(), 3);
        assert_eq!(m.get(0x001129b0).unwrap().name, "_ScrMatch_0_1129b0");
        assert_eq!(m.get(0x001129b0).unwrap().kind, Kind::Function);
        assert_eq!(m.get(0x00216a40).unwrap().kind, Kind::Data);
        // A decimal address is accepted, and trailing words become the note.
        assert_eq!(m.get(1110484).map(|e| e.name.as_str()), Some("do_fade"));
        assert_eq!(
            m.get(1110484).unwrap().note.as_deref(),
            Some("trailing words are a note")
        );
        let out = m.to_text();
        assert!(out.contains("0x00216a40 data g_GameState"));
        assert!(out.contains("# main game state block"));
        assert_eq!(SymbolMap::parse(&out).len(), 3, "round trip must be stable");
    }

    #[test]
    fn addresses_accept_hex_or_decimal() {
        assert_eq!(parse_addr("0x10"), Some(16));
        assert_eq!(parse_addr("16"), Some(16));
        assert_eq!(parse_addr("0010aef4"), Some(0x0010_aef4));
        assert_eq!(parse_addr("not-hex"), None);
    }

    #[test]
    fn rust_names() {
        assert_eq!(rust_fn_name("_ScrMatch_0_1129b0"), "_ScrMatch_0_1129b0");
        assert_eq!(rust_fn_name("if"), "if_");
        assert_eq!(rust_global_name("g_pPlayer"), "G_PPLAYER");
    }
}
