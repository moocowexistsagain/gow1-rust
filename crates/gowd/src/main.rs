//! `gowd` — the God of War (PS2) decompilation driver.
//!
//! Everything is driven off a path to an executable the user extracted from a
//! disc they own; nothing in this repository contains game data. Run
//! `gowd help` for the command list, or `gowd selftest` to check the toolchain
//! works on this machine without any ROM at all.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

use ee_isa::DecodeOptions;
use gow_decomp::{naming::SymbolMap, status::StatusFile, Layout};
use ps2_elf::{Executable, Mdebug};

/// Default location for user-supplied extracts (gitignored, see docs/LEGAL.md).
/// `SCUS_973.99` is the NTSC-U disc's boot executable (serial SCUS-97399);
/// other regions use other names, which is why every command takes a path.
const DEFAULT_ELF: &str = "extracted/SCUS_973.99";

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let code = match run(&argv) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    };
    std::process::exit(code);
}

fn run(argv: &[String]) -> Result<(), String> {
    let Some(cmd) = argv.first().map(|s| s.as_str()) else {
        print_usage();
        return Ok(());
    };
    match cmd {
        "help" | "--help" | "-h" => {
            print_usage();
            Ok(())
        }
        "version" | "--version" => {
            println!("gowd {}", env!("CARGO_PKG_VERSION"));
            println!("  ee-isa tables: base MIPS + EE MMI/COP0/COP1 (VU0 CT space partial)");
            Ok(())
        }
        "selftest" => selftest(flags(argv)),
        "info" => info(argv),
        "sections" => sections(argv),
        "funcs" => funcs(argv),
        "globals" => globals(argv),
        "disasm" => disasm(argv),
        "gen" => gen(argv),
        "status" => status_cmd(argv),
        "raw" => raw_stdin(),
        "fixture" => write_fixture(argv),
        other => Err(format!("unknown command {other:?} (try `gowd help`)")),
    }
}

fn print_usage() {
    let usage = "\
gowd — God of War (PS2) decompilation driver

  gowd selftest                     verify the toolchain end to end (needs no ROM)
  gowd info   [ELF]                 ELF header, sections, symbol availability
  gowd sections [ELF]               section table
  gowd funcs  [ELF] [--filter s]    list recovered functions (scans a stripped binary)
  gowd globals [ELF]                list recovered data symbols
  gowd disasm [ELF] [TARGET]        disassemble: --all | --addr 0x.. | --entry
                                    | --name sym | --range a:b  (--count = instructions)
  gowd gen    [ELF] [--out DIR]     emit Rust stubs + sketches + report
  gowd status [ELF]                 coverage numbers
  gowd raw                          read 'ADDR HEX' lines on stdin, write listings (for tests)

  gowd fixture [PATH] [--stripped]  write the synthetic test executable (needs no ROM)

ELF defaults to extracted/SCUS_973.99 (NTSC-U). Put files you extracted from your own disc in
extracted/ — it is gitignored, and copyrighted data must never be committed
(see docs/LEGAL.md).

funcs flags:
  --limit N        stop after N rows (default 200)
  --filter SUBSTR  only names containing SUBSTR
  --symbols FILE   overlay a .syms.txt name map
  --no-scan        symbols only; do not recover entry points from .text

gen flags:
  --limit N        stop after N functions
  --filter SUBSTR  only functions whose name contains SUBSTR
  --force          rewrite files that a human has edited
  --no-anon        only emit functions that have a symbol
  --symbols FILE   overlay a .syms.txt name map (wins over .mdebug)
";
    println!("{usage}");
}

fn flags(argv: &[String]) -> FlagSet {
    FlagSet::parse(argv)
}

#[derive(Default, Clone)]
struct FlagSet {
    positional: Vec<String>,
    named: Vec<(String, String)>,
}

impl FlagSet {
    fn parse(argv: &[String]) -> Self {
        let mut out = Self::default();
        let mut it = argv.iter().peekable();
        // Skip the command word (already consumed by the caller in some paths;
        // parse() is called with the full argv, so drop index 0).
        it.next();
        while let Some(a) = it.next() {
            if let Some(rest) = a.strip_prefix("--") {
                let (k, v) = match rest.split_once('=') {
                    Some((k, v)) => (k.to_string(), v.to_string()),
                    None => {
                        let k = rest.to_string();
                        let v = match it.peek() {
                            Some(n) if !n.starts_with("--") => it.next().unwrap().clone(),
                            _ => "1".to_string(),
                        };
                        (k, v)
                    }
                };
                out.named.push((k, v));
            } else {
                out.positional.push(a.clone());
            }
        }
        out
    }
    fn get(&self, k: &str) -> Option<&str> {
        self.named
            .iter()
            .rev()
            .find(|(n, _)| n == k)
            .map(|(_, v)| v.as_str())
    }
    fn has(&self, k: &str) -> bool {
        self.named.iter().any(|(n, _)| n == k)
    }
    fn usize(&self, k: &str) -> Result<Option<usize>, String> {
        match self.get(k) {
            None => Ok(None),
            Some(v) => v
                .parse::<usize>()
                .map(Some)
                .map_err(|_| format!("--{k} wants a number, got {v:?}")),
        }
    }
    fn path(&self) -> PathBuf {
        self.positional
            .first()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_ELF))
    }
}

/// Load bytes + parse, with a helpful message when the user has not dropped a
/// file in yet.
fn open_exe(path: &Path) -> Result<(Vec<u8>, usize), String> {
    let bytes = std::fs::read(path).map_err(|e| {
        let mut msg = format!(
            "cannot read {} ({e})\n\
             Put the executable you extracted from your own disc there, or pass\n\
             a path explicitly. `gowd selftest` checks the toolchain with no ROM.",
            path.display()
        );
        // The default path names the NTSC-U disc's executable; other regions
        // and the demo use other names, so show what is actually sitting there.
        let dir = path.parent().filter(|d| !d.as_os_str().is_empty());
        if let Some(entries) = dir.and_then(|d| std::fs::read_dir(d).ok()) {
            let mut found: Vec<String> = entries
                .flatten()
                .filter(|e| e.path().is_file())
                .map(|e| e.path().display().to_string())
                .collect();
            found.sort();
            if !found.is_empty() {
                msg.push_str("\nfiles already there:");
                for f in found.iter().take(12) {
                    msg.push_str(&format!("\n  {f}"));
                }
            }
        }
        msg
    })?;
    let len = bytes.len();
    Ok((bytes, len))
}

fn with_elf<T>(
    argv: &[String],
    f: impl FnOnce(&Path, &Executable<'_>, usize) -> Result<T, String>,
) -> Result<T, String> {
    let fl = flags(argv);
    let path = fl.path();
    let (bytes, len) = open_exe(&path)?;
    let exe = Executable::parse(&bytes).map_err(|e| format!("{}: {e}", path.display()))?;
    f(&path, &exe, len)
}

fn info(argv: &[String]) -> Result<(), String> {
    with_elf(argv, |path, exe, len| {
        let h = exe.elf.header();
        println!("{} ({len} bytes)", path.display());
        println!(
            "  type {}  machine {}  entry {:#010x}  flags {:#010x}",
            h.kind, h.machine, h.entry, h.flags
        );
        println!(
            "  sections {}   segments {}   shstrtab {:#08x}",
            exe.elf.sections().len(),
            exe.elf.segments().len(),
            h.shstrndx
        );
        println!(
            "  .text {}",
            match exe.text_size() {
                Some(sz) => format!("{:#x} bytes", sz),
                None => "not found".to_string(),
            }
        );
        println!("  symbols");
        match &exe.mdebug {
            Some(m) => {
                let mh: &Mdebug<'_> = m;
                println!(
                    "    .mdebug: magic {:#06x} version {:#06x}, {} files, {} procedures, {} functions recovered, {} globals, {} externals",
                    mh.header().magic,
                    mh.header().version_stamp,
                    mh.files.len(),
                    mh.procedures.len(),
                    mh.functions.len(),
                    mh.globals.len(),
                    mh.externals.len()
                );
                for f in mh.files.iter().take(12) {
                    println!(
                        "      file {:#010x}  {}  ({} syms)",
                        f.address, f.path, f.symbol_count
                    );
                }
            }
            None => println!("    .mdebug: absent — names must come from a symbol map"),
        }
        println!(
            "    .symtab: {} entries ({} functions)",
            exe.symtab.len(),
            exe.symtab.iter().filter(|s| s.is_func()).count()
        );
        let named = exe.named_function_count() + exe.symtab.iter().filter(|s| s.is_func()).count();
        if named == 0 && exe.elf.text().is_some() {
            // Stripped: say what can still be recovered instead of stopping at
            // "no symbols", which is where this tool used to leave the user.
            let scanned = gow_decomp::report::discover_functions(exe, true);
            let called = scanned.iter().filter(|s| s.call_sites > 0).count();
            println!(
                "    scan: {} entry points recovered from .text ({called} are call targets)",
                scanned.len()
            );
            println!("  this executable is stripped; the pipeline still works, by address:");
            println!("    gowd funcs  {p}", p = path.display());
            println!("    gowd disasm {p} --entry --count 40", p = path.display());
            println!("    gowd gen    {p} --out out/rust", p = path.display());
        }
        for w in exe.warnings() {
            println!("  warning: {w}");
        }
        Ok(())
    })
}

fn sections(argv: &[String]) -> Result<(), String> {
    with_elf(argv, |_path, exe, _len| {
        println!(
            "{:<16} {:<10} {:>10} {:>10} {:>10} {:>6}",
            "name", "type", "addr", "off", "size", "flags"
        );
        for s in exe.elf.sections() {
            // An unknown section type is information, not an error: real
            // executables carry linker- and SDK-specific sections, and a dump
            // command that refuses to dump is useless for finding out what is
            // in the file.
            let ty = section_type_name(s.sh_type);
            println!(
                "{:<16} {:<10} {:>10x} {:>10x} {:>10x} {:>6x}",
                s.name, ty, s.addr, s.offset, s.size, s.flags
            );
        }
        Ok(())
    })
}

/// ELF section types, including the MIPS-specific range PS2 executables use.
fn section_type_name(ty: u32) -> String {
    match ty {
        0 => "NULL".into(),
        1 => "PROGBITS".into(),
        2 => "SYMTAB".into(),
        3 => "STRTAB".into(),
        4 => "RELA".into(),
        5 => "HASH".into(),
        6 => "DYNAMIC".into(),
        7 => "NOTE".into(),
        8 => "NOBITS".into(),
        9 => "REL".into(),
        10 => "SHLIB".into(),
        11 => "DYNSYM".into(),
        0x7000_0000 => "MIPS_LIBLIST".into(),
        0x7000_0002 => "MIPS_CONFLICT".into(),
        0x7000_0003 => "MIPS_GPTAB".into(),
        0x7000_0004 => "MIPS_UCODE".into(),
        0x7000_0005 => "MIPS_DEBUG".into(),
        0x7000_0006 => "MIPS_REGINFO".into(),
        0x7000_002a => "REGINFO".into(),
        other => format!("{other:#x}"),
    }
}

fn funcs(argv: &[String]) -> Result<(), String> {
    let fl = flags(argv);
    let filter = fl.get("filter").map(|s| s.to_lowercase());
    let limit = fl.usize("limit")?.unwrap_or(200);
    // The scan is what makes this command useful on a stripped retail
    // executable, so it is on unless the user asks for symbols only.
    let scan = !(fl.has("no-scan") || fl.has("no-anon") || fl.has("symbols-only"));
    let map = load_symbol_map(&fl)?;
    with_elf(argv, |path, exe, _len| {
        let starts = gow_decomp::report::discover_functions(exe, scan);
        let text_end = exe.elf.text().map(|(b, t)| b + t.len() as u32).unwrap_or(0);
        println!(
            "{:>12} {:>9} {:<8} {:<28} source file / evidence",
            "addr", "size", "kind", "name"
        );
        let (mut shown, mut matched) = (0usize, 0usize);
        for (i, st) in starts.iter().enumerate() {
            let addr = st.addr;
            let name = map
                .get(addr)
                .map(|e| e.name.clone())
                .or_else(|| exe.name_for_address(addr))
                .unwrap_or_else(|| format!("f_{addr:08x}"));
            if let Some(f) = &filter {
                if !name.to_lowercase().contains(f) {
                    continue;
                }
            }
            matched += 1;
            if shown >= limit {
                continue;
            }
            let mdf = st
                .source
                .mdebug_index()
                .and_then(|i| exe.mdebug.as_ref().and_then(|m| m.functions.get(i)));
            let (size, kind, extra) = match mdf {
                Some(f) => (
                    f.size,
                    if f.is_static { "static" } else { "global" },
                    f.source_file.clone().unwrap_or_default(),
                ),
                None => {
                    let next = starts.get(i + 1).map(|s| s.addr).unwrap_or(text_end);
                    (
                        next.saturating_sub(addr),
                        st.source.label(),
                        match st.call_sites {
                            0 => String::new(),
                            1 => "1 call site".to_string(),
                            n => format!("{n} call sites"),
                        },
                    )
                }
            };
            // `~` marks a size we inferred from the next entry point rather
            // than read out of a symbol table.
            let mark = if mdf.is_some() { ' ' } else { '~' };
            println!("{addr:>12x} {mark}{size:>8x} {kind:<8} {name:<28} {extra}");
            shown += 1;
        }
        if matched > shown {
            println!("... ({} more; --limit N)", matched - shown);
        }

        let from_symbols = starts.iter().filter(|s| s.source.is_symbol()).count();
        let scanned = starts.len() - from_symbols;
        let called = starts.iter().filter(|s| s.call_sites > 0).count();
        println!();
        if starts.is_empty() {
            println!("no functions found.");
            if !scan {
                println!("  the scan is disabled (--no-scan); drop that flag to recover entry");
                println!("  points from the instruction stream.");
            } else if exe.elf.text().is_none() {
                println!("  this file has no .text section — is it really the main executable?");
            } else {
                println!("  nothing in .text looked like a call target, a return boundary or a");
                println!("  prologue. If the executable is compressed or encrypted, decompress it");
                println!("  first; `gowd sections` shows what the container actually holds.");
            }
            return Ok(());
        }
        println!(
            "{} function(s): {from_symbols} from symbols, {scanned} recovered by scanning \
             ({called} of them proven call targets).",
            starts.len()
        );
        if from_symbols == 0 {
            println!(
                "This executable is stripped (no .mdebug, no .symtab function symbols), so the"
            );
            println!("names above are addresses. Next steps:");
            let first = starts[0].addr;
            println!(
                "  gowd disasm {} --name f_{first:08x} --count 40",
                path.display()
            );
            println!(
                "  gowd disasm {} --addr {first:#010x} --count 40",
                path.display()
            );
            println!(
                "  gowd gen {} --out out/rust          # stubs + sketches for all of them",
                path.display()
            );
            println!("  then put real names in out/rust/symbols.syms.txt and re-run with");
            println!("  --symbols out/rust/symbols.syms.txt (format: docs/FORMATS.md).");
        }
        Ok(())
    })
}

/// Load the name overlay for commands that display names: `--symbols FILE`
/// when given, otherwise `out/rust/symbols.syms.txt` if a `gen` run made one.
fn load_symbol_map(fl: &FlagSet) -> Result<SymbolMap, String> {
    if let Some(p) = fl.get("symbols") {
        return SymbolMap::load(Path::new(p));
    }
    let default = Layout {
        out_dir: fl
            .get("out")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("out/rust")),
    }
    .symbols_path();
    if default.exists() {
        return SymbolMap::load(&default);
    }
    Ok(SymbolMap::default())
}

fn globals(argv: &[String]) -> Result<(), String> {
    with_elf(argv, |_path, exe, _len| {
        match &exe.mdebug {
            Some(m) if !m.globals.is_empty() => {
                println!(
                    "{:>12} {:<8} {:<28} type (raw stabs)",
                    "addr", "section", "name"
                );
                for g in &m.globals {
                    println!(
                        "{:>12x} {:<8} {:<28} {}",
                        g.address,
                        format!("{:?}", g.section),
                        g.name,
                        g.raw_type.clone().unwrap_or_default()
                    );
                }
            }
            _ => {
                println!("no data symbols recovered from .mdebug; .symtab:");
                for s in exe.symtab.iter().filter(|s| !s.is_func()) {
                    println!("  {:#010x} {} (size {:#x})", s.value, s.name, s.size);
                }
            }
        }
        Ok(())
    })
}

fn disasm(argv: &[String]) -> Result<(), String> {
    let fl = flags(argv);
    let opts = DecodeOptions {
        numeric_gprs: fl.has("numeric"),
        hex_imms: !fl.has("decimal"),
        collapse_aliases: !fl.has("raw-encodings"),
    };
    with_elf(argv, |_path, exe, _len| {
        let (base, text) = exe.elf.text().ok_or("binary has no .text section")?;
        let (start, count) = resolve_range(exe, &fl, base, text.len() as u32)?;
        if start < base || start >= base + text.len() as u32 {
            return Err(format!(
                "{start:#010x} is outside .text ({base:#010x}..{:#010x})",
                base + text.len() as u32
            ));
        }
        if start % 4 != 0 {
            return Err(format!("{start:#010x} is not 4-byte aligned"));
        }
        if count < 4 {
            return Err(format!(
                "nothing to disassemble at {start:#010x} (.text ends at {:#010x})",
                base + text.len() as u32
            ));
        }
        let off = (start - base) as usize;
        let end_off = ((start + count) - base) as usize;
        let insns = ee_isa::decode_all(start, &text[off..end_off], &opts);
        let map = load_symbol_map(&fl)?;
        let mut unknown = 0usize;
        let mut out = String::new();
        let mut name_cache: std::collections::HashMap<u32, String> = Default::default();
        for ins in &insns {
            if ins.is_unknown() {
                unknown += 1;
            }
            // Annotate with symbol names at the left margin when known.
            let mark = if let Some(n) = name_cache.get(&ins.addr) {
                format!("; {n}")
            } else {
                let n = map
                    .get(ins.addr)
                    .map(|e| e.name.clone())
                    .or_else(|| exe.name_for_address(ins.addr));
                match n {
                    Some(n) => {
                        name_cache.insert(ins.addr, n.clone());
                        format!("; {n}")
                    }
                    None => String::new(),
                }
            };
            out.push_str(&format!(
                "{:08x}: {:08x}  {:<36}{}\n",
                ins.addr,
                ins.raw,
                ins.text(&opts),
                mark
            ));
        }
        print!("{out}");
        if unknown > 0 {
            eprintln!(
                "({unknown} undecoded word(s) in {} instructions)",
                insns.len()
            );
        }
        Ok(())
    })
}

fn resolve_range(
    exe: &Executable<'_>,
    fl: &FlagSet,
    base: u32,
    size: u32,
) -> Result<(u32, u32), String> {
    let text_end = base + size;
    // `--count` is a number of *instructions*; everything below works in bytes.
    let count_bytes = || -> Result<u32, String> {
        let n = fl.usize("count")?.unwrap_or(64);
        Ok((n.min(u32::MAX as usize / 4) as u32) * 4)
    };
    let clamp = |start: u32, bytes: u32| -> (u32, u32) {
        (start, bytes.min(text_end.saturating_sub(start)))
    };

    if let Some(v) = fl.get("addr") {
        return Ok(clamp(parse_hex(v)?, count_bytes()?));
    }
    if fl.has("entry") {
        return Ok(clamp(exe.elf.entry(), count_bytes()?));
    }
    if let Some(v) = fl.get("name") {
        let map = load_symbol_map(fl)?;
        let (start, known_size) = lookup_function(exe, &map, v)?;
        let bytes = match known_size {
            0 => inferred_extent(exe, start).unwrap_or(count_bytes()?),
            n => n,
        };
        return Ok(clamp(start, bytes));
    }
    if let Some(v) = fl.get("range") {
        let (a, b) = v
            .split_once(':')
            .ok_or_else(|| "--range wants start:end".to_string())?;
        let (a, b) = (parse_hex(a)?, parse_hex(b)?);
        if b <= a {
            return Err("--range end must be after start".to_string());
        }
        return Ok(clamp(a, b - a));
    }
    if fl.has("all") {
        return Ok((base, size));
    }
    // Positional target: a bare hex address as the second positional argument.
    if let Some(t) = fl.positional.get(1) {
        return Ok(clamp(parse_hex(t)?, count_bytes()?));
    }
    Ok(clamp(base, count_bytes()?))
}

/// Resolve `--name` against everything that can carry a name, in order of
/// authority: `.mdebug`, `.symtab`, the user's symbol map, and finally the
/// `f_<addr>` placeholders this tool itself prints for a stripped binary.
/// Returns the address and the size the symbol claims (0 = unknown).
fn lookup_function(
    exe: &Executable<'_>,
    map: &SymbolMap,
    want: &str,
) -> Result<(u32, u32), String> {
    if let Some(f) = exe.mdebug.as_ref().and_then(|m| m.function_by_name(want)) {
        return Ok((f.address, if f.size >= 4 { f.size } else { 0 }));
    }
    if let Some(s) = exe
        .symtab
        .iter()
        .find(|s| s.is_func() && !s.name.is_empty() && s.name == want)
    {
        return Ok((s.value, s.size));
    }
    if let Some((addr, _)) = map.iter().find(|(_, e)| e.name == want) {
        return Ok((addr, 0));
    }
    if let Some(addr) = placeholder_address(want) {
        if exe.contains_text(addr) {
            return Ok((addr, 0));
        }
        return Err(format!(
            "{want:?} parses as {addr:#010x}, which is outside .text"
        ));
    }
    Err(no_such_name(exe, map, want))
}

/// `f_001234ab` / `sub_001234ab` / `func_001234ab` / a bare hex address.
///
/// A bare string must be at least 6 hex digits, so that a mistyped symbol name
/// that happens to be hex (`face`, `added`) is reported as a missing name
/// rather than silently disassembling address `0xface`.
fn placeholder_address(want: &str) -> Option<u32> {
    let prefixed = want
        .strip_prefix("f_")
        .or_else(|| want.strip_prefix("sub_"))
        .or_else(|| want.strip_prefix("func_"))
        .or_else(|| want.strip_prefix("0x"));
    let (hex, min_len) = match prefixed {
        Some(h) => (h, 1),
        None => (want, 6),
    };
    if hex.len() >= min_len && hex.len() <= 8 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
        u32::from_str_radix(hex, 16).ok()
    } else {
        None
    }
}

/// Size for an address with no symbol: the distance to the next recovered
/// entry point.
fn inferred_extent(exe: &Executable<'_>, addr: u32) -> Option<u32> {
    let starts = gow_decomp::report::discover_functions(exe, true);
    let i = starts.iter().position(|s| s.addr == addr)?;
    let text_end = exe.elf.text().map(|(b, t)| b + t.len() as u32)?;
    let next = starts.get(i + 1).map(|s| s.addr).unwrap_or(text_end);
    // Deliberately an `if`, not `then_some`: the subtraction must not be
    // evaluated when `next <= addr` (see the note in README on this pattern).
    if next > addr {
        Some(next - addr)
    } else {
        None
    }
}

/// The error for `--name` that matched nothing, with whatever help the binary
/// can actually offer.
fn no_such_name(exe: &Executable<'_>, map: &SymbolMap, want: &str) -> String {
    let mut names: Vec<String> = Vec::new();
    if let Some(m) = &exe.mdebug {
        names.extend(m.functions.iter().map(|f| f.name.clone()));
    }
    names.extend(
        exe.symtab
            .iter()
            .filter(|s| s.is_func() && !s.name.is_empty())
            .map(|s| s.name.clone()),
    );
    names.extend(map.iter().map(|(_, e)| e.name.clone()));
    names.sort();
    names.dedup();

    let mut msg = format!("no function named {want:?} in the symbol tables");
    if names.is_empty() {
        let scanned = gow_decomp::report::discover_functions(exe, true);
        msg.push_str("\nThis executable carries no function names at all (no .mdebug, no");
        msg.push_str("\n.symtab), so there is nothing for --name to match. ");
        if scanned.is_empty() {
            msg.push_str("Scanning .text found\nno entry points either.");
        } else {
            let first = scanned
                .iter()
                .find(|s| s.call_sites > 0)
                .unwrap_or(&scanned[0]);
            msg.push_str(&format!(
                "Scanning .text\nrecovered {} entry points; address them directly:\n\n  \
                 gowd funcs  <elf>\n  \
                 gowd disasm <elf> --addr {:#010x} --count 40\n  \
                 gowd disasm <elf> --name f_{:08x} --count 40\n  \
                 gowd disasm <elf> --entry --count 40\n\n\
                 Once you have named something, put it in a symbol map and pass\n\
                 --symbols map.syms.txt; --name then works for that name.",
                scanned.len(),
                first.addr,
                first.addr
            ));
        }
        return msg;
    }
    let lower = want.to_lowercase();
    let close: Vec<&String> = names
        .iter()
        .filter(|n| n.to_lowercase().contains(&lower))
        .take(8)
        .collect();
    if close.is_empty() {
        msg.push_str(&format!(
            "\n{} names are known; `gowd funcs <elf> --filter {want}` searches them.",
            names.len()
        ));
    } else {
        msg.push_str("\ndid you mean:");
        for n in close {
            msg.push_str(&format!("\n  {n}"));
        }
    }
    msg
}

fn parse_hex(s: &str) -> Result<u32, String> {
    let s = s.trim();
    let t = s.strip_prefix("0x").unwrap_or(s);
    u32::from_str_radix(t, 16).map_err(|_| format!("{s:?} is not a hex address"))
}

fn gen(argv: &[String]) -> Result<(), String> {
    let fl = flags(argv);
    let out_dir = fl
        .get("out")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("out/rust"));
    let layout = Layout { out_dir };
    let mut map = match fl.get("symbols") {
        Some(p) => SymbolMap::load(Path::new(p))?,
        None if layout.symbols_path().exists() => SymbolMap::load(&layout.symbols_path())?,
        None => SymbolMap::default(),
    };
    let opts = gow_decomp::report::GenOptions {
        filter: fl.get("filter").map(|s| s.to_string()),
        limit: fl.usize("limit")?.unwrap_or(0),
        include_anonymous: !fl.has("no-anon"),
        force: fl.has("force"),
        listing_limit: fl.usize("listing-limit")?.unwrap_or(400),
    };
    with_elf(argv, |_path, exe, _len| {
        let report = gow_decomp::report::generate(exe, &map, &layout, &opts)?;
        // A second merge gives `gowd gen` the side effect of refreshing
        // symbols.syms.txt with anything new the binary revealed.
        map.merge_auto(exe);
        println!(
            "wrote {} to {}/",
            report.functions_emitted_created + report.functions_emitted_refreshed,
            layout.out_dir.display()
        );
        println!(
            "  {} functions, {} named, {} instructions, {} undecoded",
            report.functions_total,
            report.functions_named,
            report.instructions,
            report.instructions_unknown
        );
        println!(
            "  created {} · refreshed {} · kept human-edited {} · skipped (done) {}",
            report.functions_emitted_created,
            report.functions_emitted_refreshed,
            report.functions_skipped_edited,
            report.functions_skipped_done
        );
        println!("  report: {}", layout.report_path().display());
        if !report.unknown_words.is_empty() {
            println!(
                "  {} unknown encodings — first few: {}",
                report.unknown_words.len(),
                report
                    .unknown_words
                    .iter()
                    .take(5)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        for w in report.warnings.iter().take(6) {
            println!("  warning: {w}");
        }
        Ok(())
    })
}

fn status_cmd(argv: &[String]) -> Result<(), String> {
    let fl = flags(argv);
    let layout = Layout {
        out_dir: fl
            .get("out")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("out/rust")),
    };
    let st = StatusFile::load(&layout.status_path())?;
    let (todo, wip, done) = st.counts();
    println!("status: {} todo, {} in-progress, {} done", todo, wip, done);
    let total = todo + wip + done;
    if total > 0 {
        println!(
            "        {:.1}% of {} tracked functions complete",
            100.0 * done as f64 / total as f64,
            total
        );
    }
    if layout.report_path().exists() {
        println!("        report: {}", layout.report_path().display());
    } else {
        println!("        (no report yet — run `gowd gen`)");
    }
    Ok(())
}

/// Write the synthetic executable so the CLI itself can be exercised (and so a
/// newcomer sees the workflow) without any copyrighted file.
fn write_fixture(argv: &[String]) -> Result<(), String> {
    let fl = flags(argv);
    let stripped = fl.has("stripped");
    // `--stripped PATH` swallows the path as the flag's value (the parser is
    // deliberately simple), so accept it from either side.
    let path = fl
        .positional
        .first()
        .cloned()
        .or_else(|| {
            fl.get("stripped")
                .filter(|v| *v != "1")
                .map(ToString::to_string)
        })
        .unwrap_or_else(|| "extracted/fixture.elf".to_string());
    let image = if stripped {
        ps2_elf::fixture::build_stripped()
    } else {
        ps2_elf::fixture::build()
    };
    if let Some(parent) = Path::new(&path).parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
        }
    }
    std::fs::write(&path, &image).map_err(|e| format!("{path}: {e}"))?;
    if stripped {
        println!(
            "wrote {path} ({} bytes): synthetic PS2 ELF with .text and .data only \
             (no .mdebug, no .symtab) — the stripped-retail shape",
            image.len()
        );
    } else {
        println!(
            "wrote {path} ({} bytes): synthetic PS2 ELF with .text, .data, .mdebug \
             (2 functions, STABS params, 1 global) and .symtab",
            image.len()
        );
    }
    println!("try:  gowd info {path} && gowd funcs {path} && gowd gen {path}");
    Ok(())
}

/// `gowd raw`: consume `ADDR HEX` (or bare `HEX`) lines and print
/// `HEX<TAB>mnemonic<TAB>operands`. Used by `tools/golden_check.py` to compare
/// against a reference disassembler's own test expectations.
fn raw_stdin() -> Result<(), String> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let opts = DecodeOptions {
        numeric_gprs: true,
        hex_imms: true,
        collapse_aliases: false,
    };
    for line in stdin.lock().lines() {
        let line = line.map_err(|e| e.to_string())?;
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut it = line.split_whitespace();
        let (a, b) = (it.next(), it.next());
        let (addr, word) = match b {
            Some(w) => (parse_hex(a.unwrap_or("0"))?, w),
            None => (0u32, a.unwrap_or("0")),
        };
        let raw = parse_hex(word)?;
        let ins = ee_isa::decode(addr, raw, &opts);
        writeln!(out, "{raw:08x}\t{}\t{}", ins.name, ins.operands(&opts))
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// selftest: prove the whole pipeline works with no external data
// ---------------------------------------------------------------------------

fn selftest(_fl: FlagSet) -> Result<(), String> {
    use ps2_elf::fixture;

    println!("gowd selftest — synthetic PS2 executable (see crates/ps2-elf/src/fixture.rs)");
    for (label, image) in [
        ("section-relative .mdebug offsets", fixture::build()),
        ("file-absolute .mdebug offsets", fixture::build_absolute()),
    ] {
        let exe = Executable::parse(&image).map_err(|e| format!("{label}: {e}"))?;
        check(
            &format!("{label}: entry"),
            exe.elf.entry() == fixture::FN_ONE,
        )?;
        check(
            &format!("{label}: .text size"),
            exe.text_size() == Some((fixture::text_words().len() * 4) as u32),
        )?;
        let m = exe
            .mdebug
            .as_ref()
            .ok_or_else(|| format!("{label}: .mdebug not found"))?;
        check(&format!("{label}: 2 procedures"), m.procedures.len() == 2)?;
        check(
            &format!("{label}: 2 functions named"),
            m.functions.len() == 2,
        )?;
        let one = m
            .function_by_name(fixture::FN_ONE_NAME)
            .ok_or_else(|| format!("{label}: fn_one not recovered"))?;
        check(
            &format!("{label}: fn_one address"),
            one.address == fixture::FN_ONE,
        )?;
        check(&format!("{label}: fn_one frame"), one.frame_size == 32)?;
        check(
            &format!("{label}: fn_one saved regs"),
            one.saved_register_mask == (1 << 31 | 1 << 30 | 1 << 23),
        )?;
        check(&format!("{label}: fn_one params"), one.params.len() == 2)?;
        check(
            &format!("{label}: fn_one source file"),
            one.source_file.as_deref() == Some("gow/fn_test.c"),
        )?;
        check(
            &format!("{label}: fn_two is static"),
            m.function_by_name(fixture::FN_TWO_NAME)
                .map(|f| f.is_static)
                .unwrap_or(false),
        )?;
        check(
            &format!("{label}: global recovered"),
            m.globals
                .iter()
                .any(|g| g.name == "g_TestGlobal" && g.address == fixture::G_TEST_GLOBAL),
        )?;
        check(
            &format!("{label}: name lookup"),
            exe.name_for_address(fixture::FN_TWO).as_deref() == Some(fixture::FN_TWO_NAME),
        )?;

        // Decoding + analysis + emission end to end.
        let a = gow_decomp::analyze::analyze(&exe, fixture::FN_ONE, Some(one))
            .map_err(|e| format!("{label}: analyze: {e}"))?;
        check(
            &format!("{label}: decoded 8 instructions"),
            a.instruction_count() == 8,
        )?;
        check(
            &format!("{label}: found the call"),
            a.calls.iter().any(|c| c.addr == fixture::FN_TWO),
        )?;
        check(
            &format!("{label}: no undecoded words"),
            a.unknown_count == 0,
        )?;
        let src = gow_decomp::emit::function_source(&a, &gow_decomp::emit::EmitOptions::default());
        check(
            &format!("{label}: emitted a stub"),
            src.contains("pub unsafe fn fn_one(") && src.contains("todo!"),
        )?;
        check(
            &format!("{label}: balanced braces"),
            src.matches('{').count() == src.matches('}').count(),
        )?;
    }

    // The stripped case: no symbols at all, which is what most retail PS2
    // discs actually shipped. Everything has to come from the scan.
    {
        let image = fixture::build_stripped();
        let exe = Executable::parse(&image).map_err(|e| format!("stripped: {e}"))?;
        check("stripped: no .mdebug", exe.mdebug.is_none())?;
        check(
            "stripped: no .symtab function symbols",
            !exe.symtab.iter().any(|s| s.is_func()),
        )?;
        let starts = gow_decomp::report::discover_functions(&exe, true);
        check(
            &format!("stripped: scan recovered {} entry points", starts.len()),
            starts.iter().any(|s| s.addr == fixture::FN_ONE)
                && starts.iter().any(|s| s.addr == fixture::FN_TWO),
        )?;
        check(
            "stripped: the called function is marked as a call target",
            starts
                .iter()
                .any(|s| s.addr == fixture::FN_TWO && s.call_sites == 1),
        )?;
        let dir = std::env::temp_dir().join(format!("gowd-selftest-nosyms-{}", std::process::id()));
        let layout = Layout {
            out_dir: dir.clone(),
        };
        let r = gow_decomp::report::generate(
            &exe,
            &SymbolMap::default(),
            &layout,
            &gow_decomp::report::GenOptions::default(),
        )?;
        check(
            &format!(
                "stripped: gen emitted {} stubs without a single symbol",
                r.functions_emitted_created
            ),
            r.functions_emitted_created >= 2 && r.functions_named == 0,
        )?;
        let _ = std::fs::remove_dir_all(&dir);
    }

    // And a full `gen` run into a scratch directory.
    let dir = std::env::temp_dir().join(format!("gowd-selftest-{}", std::process::id()));
    let image = fixture::build();
    let exe = Executable::parse(&image).map_err(|e| e.to_string())?;
    let layout = Layout {
        out_dir: dir.clone(),
    };
    let report = gow_decomp::report::generate(
        &exe,
        &SymbolMap::default(),
        &layout,
        &gow_decomp::report::GenOptions::default(),
    )?;
    check(
        &format!(
            "gen: emitted both functions (total {}, created {}, named {}, warnings {:?})",
            report.functions_total,
            report.functions_emitted_created,
            report.functions_named,
            report.warnings
        ),
        report.functions_emitted_created == 2 && report.functions_named == 2,
    )?;
    let stub = std::fs::read_to_string(dir.join("gen/fn_one.rs"))
        .map_err(|e| format!("fn_one.rs: {e}"))?;
    check("gen: stub has a listing", stub.contains("addu $v0,$a0,$a1"))?;
    let sketch =
        std::fs::read_to_string(dir.join("sketches/fn_one.rs.txt")).map_err(|e| e.to_string())?;
    check(
        "gen: sketch has delay-slot note",
        sketch.contains("delay slot"),
    )?;
    let modrs = std::fs::read_to_string(dir.join("gen/mod.rs")).map_err(|e| e.to_string())?;
    check(
        "gen: mod.rs declares both",
        modrs.contains("pub mod fn_one;") && modrs.contains("pub mod fn_two;"),
    )?;
    check("gen: status seeded", dir.join("status.txt").exists())?;
    check(
        "gen: symbols written",
        dir.join("symbols.syms.txt").exists(),
    )?;
    // Second run must preserve, not clobber.
    std::fs::write(dir.join("gen/fn_one.rs"), "// hand written by a human\n")
        .map_err(|e| e.to_string())?;
    let r2 = gow_decomp::report::generate(
        &exe,
        &SymbolMap::default(),
        &layout,
        &gow_decomp::report::GenOptions::default(),
    )?;
    check(
        "gen: human edits preserved",
        r2.functions_skipped_edited == 1,
    )?;
    let keep = std::fs::read_to_string(dir.join("gen/fn_one.rs")).map_err(|e| e.to_string())?;
    check("gen: file untouched", keep.contains("hand written"))?;
    let _ = std::fs::remove_dir_all(&dir);

    // Decoder spot checks against encodings we can state exactly.
    let o = DecodeOptions::raw();
    let cases: [(u32, &str); 10] = [
        (0x0000_0000, "sll"),
        (0x03e0_0008, "jr"),
        (0x701f_0489, "pand"),
        (0x701f_07fc, "psllw"),
        (0x4600_f834, "c.lt.s"),
        (0x461f_0018, "adda.s"),
        (0x4200_0038, "ei"),
        (0x4200_0039, "di"),
        (0x7800_0000, "lq"),
        (0x7c00_0000, "sq"),
    ];
    for (word, want) in cases {
        let got = ee_isa::decode(0x1000, word, &o).name;
        if got != want {
            return Err(format!(
                "decoder: {word:08x} decoded as {got:?}, expected {want:?}"
            ));
        }
    }
    println!("  {}", "all checks passed".green());
    Ok(())
}

trait Green {
    fn green(&self) -> String;
}
impl Green for str {
    fn green(&self) -> String {
        if std::env::var_os("NO_COLOR").is_some() {
            format!("  {self}")
        } else {
            format!("\x1b[32m{self}\x1b[0m")
        }
    }
}

fn check(what: &str, ok: bool) -> Result<(), String> {
    if ok {
        println!("  ok   {what}");
        Ok(())
    } else {
        Err(format!("FAILED: {what}"))
    }
}
