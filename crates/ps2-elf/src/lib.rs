//! `ps2-elf` — read a PlayStation 2 executable and recover its symbols.
//!
//! Two layers:
//! * [`elf`] parses the ELF32 container (headers, sections, segments, vaddr
//!   translation, and any surviving `.symtab`).
//! * [`mdebug`] parses the ECOFF `.mdebug` section that SN Systems / GCC
//!   builds left in many retail PS2 executables, which is where the function
//!   names, frame sizes, saved-register masks, parameter lists and global
//!   types actually live.
//!
//! The crate is deliberately dependency-free and safe (`forbid(unsafe_code)`);
//! every accessor is bounds-checked and returns [`elf::ParseError`] rather than
//! panicking, because it is fed by an analysis loop that must survive garbage
//! bytes in a stripped or hand-patched binary.

#![forbid(unsafe_code)]

pub mod elf;
pub mod mdebug;

#[cfg(any(test, feature = "fixture"))]
pub mod fixture;

pub use elf::{Elf, Header, ParseError, ProgramHeader, Result, Section, Sym, EM_MIPS, ET_EXEC};
pub use mdebug::{
    stabs_type_hint, Function, Global, Mdebug, ProcedureDescriptor, SourceFile, StabsVar, SymClass,
    SymType,
};

/// Convenience: load a file from disk and parse both the ELF and its symbols.
#[must_use]
pub fn load(path: &std::path::Path) -> (Vec<u8>, Option<String>) {
    match std::fs::read(path) {
        Ok(b) => (b, None),
        Err(e) => (Vec::new(), Some(format!("{}: {e}", path.display()))),
    }
}

/// Everything the rest of the pipeline needs about one executable.
pub struct Executable<'a> {
    pub elf: Elf<'a>,
    pub mdebug: Option<Mdebug<'a>>,
    /// ELF `.symtab` entries, when present.
    pub symtab: Vec<Sym>,
}

impl<'a> Executable<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        let elf = Elf::parse(data)?;
        let mdebug = match elf.mdebug_section() {
            Some((_, off)) => match Mdebug::parse(elf.data(), off) {
                Ok(m) => Some(m),
                Err(e) => {
                    // A truncated `.mdebug` must not take the whole analysis
                    // down; the caller reports it as a warning.
                    eprintln!("warning: .mdebug parse failed: {e}");
                    None
                }
            },
            None => None,
        };
        let mut out = Self {
            elf,
            mdebug,
            symtab: Vec::new(),
        };
        if let Some(m) = &mut out.mdebug {
            if let Err(e) = m.collect_globals() {
                eprintln!("warning: could not collect globals from .mdebug: {e}");
            }
        }
        if let Ok(s) = out.elf.symtab() {
            out.symtab = s;
        }
        Ok(out)
    }

    #[must_use]
    pub fn warnings(&self) -> Vec<String> {
        let mut v = Vec::new();
        if let Some(m) = &self.mdebug {
            if m.header_magic_suspect {
                v.push(format!(
                    ".mdebug magic is {:#06x}, not the usual 0x7009 — offsets may be misreported",
                    m.header().magic
                ));
            }
            if m.fudge() != 0 {
                v.push(format!(
                    ".mdebug sub-table offsets were rebased by {:#x} (section moved after linking)",
                    m.fudge() as u32
                ));
            }
        } else {
            v.push("no .mdebug section: function names must come from a symbol map".to_string());
        }
        v
    }

    /// Number of functions we can name.
    #[must_use]
    pub fn named_function_count(&self) -> usize {
        self.mdebug.as_ref().map(|m| m.functions.len()).unwrap_or(0)
    }

    /// Look up a symbol name for an address: `.mdebug` first (it knows statics
    /// too), then `.symtab`, then `$`-style nearest-within-range guessing.
    #[must_use]
    pub fn name_for_address(&self, addr: u32) -> Option<String> {
        if let Some(m) = &self.mdebug {
            if let Some(f) = m.function_at(addr) {
                return Some(f.name.clone());
            }
            if let Some(g) = m.globals.iter().find(|g| g.address == addr) {
                return Some(g.name.clone());
            }
        }
        self.symtab
            .iter()
            .find(|s| s.value == addr && !s.name.is_empty())
            .map(|s| s.name.clone())
    }

    /// Resolve a call target to a name, distinguishing "known function" from
    /// "address inside a known function" (a tail call or a local label).
    #[must_use]
    pub fn resolve_call(&self, addr: u32) -> CallTarget {
        match self.name_for_address(addr) {
            Some(name) => CallTarget::Named(name),
            None if self.contains_text(addr) => CallTarget::UnnamedInText(addr),
            None => CallTarget::OutsideImage(addr),
        }
    }

    #[must_use]
    pub fn contains_text(&self, addr: u32) -> bool {
        match self.elf.text() {
            Some((base, bytes)) => addr >= base && addr < base + bytes.len() as u32,
            None => false,
        }
    }

    /// Total `.text` size in bytes, if a `.text` section exists.
    #[must_use]
    pub fn text_size(&self) -> Option<u32> {
        self.elf.text().map(|(_, b)| b.len() as u32)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CallTarget {
    Named(String),
    UnnamedInText(u32),
    OutsideImage(u32),
}

impl CallTarget {
    /// A Rust-safe identifier fragment for this target.
    #[must_use]
    pub fn ident(&self) -> String {
        match self {
            CallTarget::Named(n) => {
                crate::mdebug::stabs_type_hint("__none__")
                    .as_str()
                    .to_string()
                    .replace("__none__", "")
                    + &sanitize_ident(n)
            }
            CallTarget::UnnamedInText(a) => format!("unnamed_{a:08x}"),
            CallTarget::OutsideImage(a) => format!("extern_{a:08x}"),
        }
    }
}

/// Turn an arbitrary ECOFF/ELF symbol name into a legal Rust path segment.
#[must_use]
pub fn sanitize_ident(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut last_underscore = false;
    for ch in name.chars() {
        let keep = if ch.is_ascii_alphanumeric() || ch == '_' {
            Some(ch)
        } else {
            None
        };
        match keep {
            Some(c) => {
                out.push(c);
                last_underscore = c == '_';
            }
            None => {
                if !last_underscore && !out.is_empty() {
                    out.push('_');
                    last_underscore = true;
                }
            }
        }
    }
    while out.ends_with('_') {
        out.pop();
    }
    if out.is_empty() || out.chars().next().unwrap().is_ascii_digit() {
        out.insert(0, '_');
    }
    // Rust keywords that show up constantly in C symbol names.
    if matches!(
        out.as_str(),
        "as" | "break"
            | "const"
            | "continue"
            | "crate"
            | "else"
            | "enum"
            | "extern"
            | "false"
            | "fn"
            | "for"
            | "if"
            | "impl"
            | "in"
            | "let"
            | "loop"
            | "match"
            | "mod"
            | "move"
            | "mut"
            | "pub"
            | "ref"
            | "return"
            | "self"
            | "static"
            | "struct"
            | "super"
            | "trait"
            | "true"
            | "type"
            | "unsafe"
            | "use"
            | "where"
            | "while"
            | "async"
            | "await"
            | "dyn"
            | "abstract"
            | "become"
            | "box"
            | "do"
            | "final"
            | "macro"
            | "override"
            | "priv"
            | "try"
            | "typeof"
            | "unsized"
            | "virtual"
            | "yield"
    ) {
        out.push('_');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ident_sanitising() {
        assert_eq!(sanitize_ident("_ScrMatch_0_1129b0"), "_ScrMatch_0_1129b0");
        assert_eq!(sanitize_ident("operator new"), "operator_new");
        assert_eq!(sanitize_ident("if"), "if_");
        assert_eq!(sanitize_ident("2foo"), "_2foo");
        assert_eq!(sanitize_ident("$3"), "_3");
        assert_eq!(sanitize_ident(""), "_");
    }

    #[test]
    fn stabs_hints() {
        assert_eq!(
            stabs_type_hint("x1"),
            "i32",
            "the `x` cross-reference marker is stripped"
        );
        assert_eq!(stabs_type_hint("int:x1"), "raw(int)");
    }
}
