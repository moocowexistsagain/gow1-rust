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
const DEFAULT_ELF: &str = "extracted/SLUS_209.25";

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
  gowd funcs  [ELF] [--filter s]    list recovered functions
  gowd globals [ELF]                list recovered data symbols
  gowd disasm [ELF] [TARGET]        disassemble: --all | --addr 0x.. | --name sym | --range a:b
  gowd gen    [ELF] [--out DIR]     emit Rust stubs + sketches + report
  gowd status [ELF]                 coverage numbers
  gowd raw                          read 'ADDR HEX' lines on stdin, write listings (for tests)

  gowd fixture [PATH]               write the synthetic test executable (needs no ROM)

ELF defaults to {DEFAULT_ELF}. Put files you extracted from your own disc in
extracted/ — it is gitignored, and copyrighted data must never be committed
(see docs/LEGAL.md).

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
        format!(
            "cannot read {} ({e})\n\
             Put the executable you extracted from your own disc there, or pass\n\
             a path explicitly. `gowd selftest` checks the toolchain with no ROM.",
            path.display()
        )
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
        println!("    .symtab: {} entries", exe.symtab.len());
        for w in exe.warnings() {
            println!("  warning: {w}");
        }
        Ok(())
    })
}

fn sections(argv: &[String]) -> Result<(), String> {
    with_elf(argv, |_path, exe, _len| {
        println!(
            "{:<12} {:<8} {:>10} {:>10} {:>10} {:>6}",
            "name", "type", "addr", "off", "size", "flags"
        );
        for s in exe.elf.sections() {
            println!(
                "{:<12} {:<8} {:>10x} {:>10x} {:>10x} {:>6x}",
                s.name,
                match s.sh_type {
                    1 => "PROGBITS",
                    2 => "SYMTAB",
                    3 => "STRTAB",
                    8 => "NOBITS",
                    0x7000_002a => "REGINFO",
                    other => return Err(format!("section type {other:#x} unexpected")),
                },
                s.addr,
                s.offset,
                s.size,
                s.flags
            );
        }
        Ok(())
    })
}

fn funcs(argv: &[String]) -> Result<(), String> {
    let fl = flags(argv);
    let filter = fl.get("filter").map(|s| s.to_lowercase());
    let limit = fl.usize("limit")?.unwrap_or(200);
    with_elf(argv, |_path, exe, _len| {
        let starts = gow_decomp::report::function_starts(exe, false);
        let mut shown = 0usize;
        println!(
            "{:>12} {:>8} {:<6} {:<28} source file",
            "addr", "size", "kind", "name"
        );
        for (addr, sym) in &starts {
            let name = exe
                .name_for_address(*addr)
                .unwrap_or_else(|| format!("f_{addr:08x}"));
            if let Some(f) = &filter {
                if !name.to_lowercase().contains(f) {
                    continue;
                }
            }
            let (size, kind, src) =
                match sym.and_then(|i| exe.mdebug.as_ref().and_then(|m| m.functions.get(i))) {
                    Some(f) => (
                        f.size,
                        if f.is_static { "static" } else { "global" },
                        f.source_file.clone().unwrap_or_default(),
                    ),
                    None => (0, "symtab", String::new()),
                };
            println!("{addr:>12x} {size:>8x} {kind:<6} {name:<28} {src}");
            shown += 1;
            if shown >= limit {
                println!("... ({} more; --limit N)", starts.len() - shown);
                break;
            }
        }
        if shown == 0 {
            println!(
                "no functions found: {}",
                match &exe.mdebug {
                    Some(_) => "the .mdebug parsed but had no procedure descriptors".to_string(),
                    None => "no .mdebug and no .symtab function symbols".to_string(),
                }
            );
        }
        Ok(())
    })
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
        let off = (start - base) as usize;
        let end_off = ((start + count) - base) as usize;
        let insns = ee_isa::decode_all(start, &text[off..end_off], &opts);
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
                let n = exe.name_for_address(ins.addr);
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
    if let Some(v) = fl.get("addr") {
        let start = parse_hex(v)?;
        let count = fl.usize("count")?.unwrap_or(64) as u32;
        return Ok((start, count.min(size - (start - base))));
    }
    if let Some(v) = fl.get("name") {
        let f = exe
            .mdebug
            .as_ref()
            .and_then(|m| m.function_by_name(v))
            .ok_or_else(|| format!("no function named {v:?} in the symbol tables"))?;
        let start = f.address;
        let count = if f.size >= 4 { f.size } else { 64 };
        return Ok((start, count));
    }
    if let Some(v) = fl.get("range") {
        let (a, b) = v
            .split_once(':')
            .ok_or_else(|| "--range wants start:end".to_string())?;
        let (a, b) = (parse_hex(a)?, parse_hex(b)?);
        if b <= a {
            return Err("--range end must be after start".to_string());
        }
        return Ok((a, b - a));
    }
    if fl.has("all") {
        return Ok((base, size));
    }
    // Positional target: `disasm --name` style is preferred, but accept a bare
    // hex address as the second positional argument.
    if let Some(t) = fl.positional.get(1) {
        let start = parse_hex(t)?;
        let count = fl.usize("count")?.unwrap_or(64) as u32;
        return Ok((start, count.min(size.saturating_sub(start - base))));
    }
    Ok((base, fl.usize("count")?.unwrap_or(64) as u32))
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
    let path = flags(argv)
        .positional
        .first()
        .cloned()
        .unwrap_or_else(|| "extracted/fixture.elf".to_string());
    let image = ps2_elf::fixture::build();
    if let Some(parent) = Path::new(&path).parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
        }
    }
    std::fs::write(&path, &image).map_err(|e| format!("{path}: {e}"))?;
    println!(
        "wrote {path} ({} bytes): synthetic PS2 ELF with .text, .data, .mdebug \
         (2 functions, STABS params, 1 global) and .symtab",
        image.len()
    );
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
