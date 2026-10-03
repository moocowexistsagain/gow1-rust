//! Project orchestration + coverage reporting.
//!
//! `generate` is the one place that decides *which* functions get emitted, and
//! `report_markdown` is the artifact a decompilation team reads: named vs
//! unnamed coverage, per-section numbers, and the list of undecoded encodings
//! that still need table entries in `ee-isa`.

use std::fmt::Write as _;

use ps2_elf::Executable;

use crate::analyze::{self, FunctionAnalysis};
use crate::emit::{self, Action, EmitOptions};
use crate::naming::SymbolMap;
use crate::status::StatusFile;
use crate::Layout;

#[derive(Clone, Debug)]
pub struct GenOptions {
    /// Only functions whose name contains this substring (case-insensitive).
    pub filter: Option<String>,
    /// Stop after N functions (0 = no limit). Useful while iterating.
    pub limit: usize,
    /// Also emit stubs for prologue-scanned functions that have no symbol.
    pub include_anonymous: bool,
    /// Rewrite files even if a human edited them.
    pub force: bool,
    pub listing_limit: usize,
}

impl Default for GenOptions {
    fn default() -> Self {
        Self {
            filter: None,
            limit: 0,
            include_anonymous: true,
            force: false,
            listing_limit: 400,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct ProjectReport {
    pub functions_total: usize,
    pub functions_named: usize,
    /// How many of `functions_total` came from the instruction-stream scan
    /// rather than from a symbol table.
    pub functions_scanned: usize,
    pub functions_emitted_created: usize,
    pub functions_emitted_refreshed: usize,
    pub functions_skipped_edited: usize,
    pub functions_skipped_done: usize,
    pub instructions: usize,
    pub instructions_unknown: usize,
    pub text_bytes: usize,
    pub done: usize,
    pub in_progress: usize,
    pub todo: usize,
    pub warnings: Vec<String>,
    /// `0xADDR 0xWORD` for the first few unknown encodings, so the reader knows
    /// what to add to `ee-isa` next.
    pub unknown_words: Vec<String>,
    pub analyzed: Vec<String>,
}

/// Where a candidate function start came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// A `.mdebug` procedure descriptor (the index is into `mdebug.functions`).
    Mdebug(usize),
    /// An ELF `.symtab` `STT_FUNC` symbol.
    Symtab,
    /// Recovered from the instruction stream — see [`analyze::Evidence`].
    Scan(analyze::Evidence),
}

impl Source {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Source::Mdebug(_) => "mdebug",
            Source::Symtab => "symtab",
            Source::Scan(e) => e.label(),
        }
    }
    #[must_use]
    pub fn is_symbol(self) -> bool {
        !matches!(self, Source::Scan(_))
    }
    #[must_use]
    pub fn mdebug_index(self) -> Option<usize> {
        match self {
            Source::Mdebug(i) => Some(i),
            _ => None,
        }
    }
}

/// One candidate function start.
#[derive(Clone, Copy, Debug)]
pub struct Start {
    pub addr: u32,
    pub source: Source,
    /// `jal` sites targeting this address, when it came from the scan.
    pub call_sites: u32,
}

/// Candidate function starts: every symbol we know about, plus (optionally)
/// everything the instruction-stream scan recovers.
///
/// On a stripped executable the symbol half is empty and the scan is all there
/// is; `include_scanned` should then always be on, which is what the CLI does
/// by default.
#[must_use]
pub fn discover_functions(exe: &Executable<'_>, include_scanned: bool) -> Vec<Start> {
    let mut out: Vec<Start> = Vec::new();
    if let Some(m) = &exe.mdebug {
        for (i, f) in m.functions.iter().enumerate() {
            out.push(Start {
                addr: f.address,
                source: Source::Mdebug(i),
                call_sites: 0,
            });
        }
    }
    for s in &exe.symtab {
        if s.is_func() && s.value != 0 {
            out.push(Start {
                addr: s.value,
                source: Source::Symtab,
                call_sites: 0,
            });
        }
    }
    out.sort_by_key(|s| s.addr);
    out.dedup_by_key(|s| s.addr);

    if include_scanned {
        // Symbols win where both agree. A scanned address that lands *inside* a
        // symbol's known extent is a label, not a function, so it is dropped;
        // without sizes the next symbol's address is the only extent we have,
        // and a scanned address strictly between two symbols is kept only when
        // the evidence is strong (something calls it).
        let known: Vec<u32> = out.iter().map(|s| s.addr).collect();
        let sized: Vec<(u32, u32)> = exe
            .mdebug
            .as_ref()
            .map(|m| {
                m.functions
                    .iter()
                    .filter(|f| f.size >= 8)
                    .map(|f| (f.address, f.address + f.size))
                    .collect()
            })
            .unwrap_or_default();
        let text_end = exe.elf.text().map(|(b, s)| b + s.len() as u32).unwrap_or(0);
        for c in analyze::scan_function_starts(exe) {
            if c.addr >= text_end || known.binary_search(&c.addr).is_ok() {
                continue;
            }
            if sized.iter().any(|(a, b)| c.addr > *a && c.addr < *b) {
                continue;
            }
            // Inside a symbolised span whose extents we do not know: only a
            // call target is trustworthy enough to add.
            let inside_symbol_span = !known.is_empty()
                && c.addr > known[0]
                && c.addr < *known.last().unwrap()
                && sized.is_empty();
            if inside_symbol_span && c.evidence < analyze::Evidence::CallTarget {
                continue;
            }
            out.push(Start {
                addr: c.addr,
                source: Source::Scan(c.evidence),
                call_sites: c.call_sites,
            });
        }
        out.sort_by_key(|s| s.addr);
        out.dedup_by_key(|s| s.addr);
    }
    out
}

/// Back-compatible view: `(address, .mdebug index)` pairs.
#[must_use]
pub fn function_starts(exe: &Executable<'_>, include_anonymous: bool) -> Vec<(u32, Option<usize>)> {
    discover_functions(exe, include_anonymous)
        .into_iter()
        .map(|s| (s.addr, s.source.mdebug_index()))
        .collect()
}

pub fn generate(
    exe: &Executable<'_>,
    map: &SymbolMap,
    layout: &Layout,
    opts: &GenOptions,
) -> Result<ProjectReport, String> {
    let st = StatusFile::load(&layout.status_path())?;
    let starts = discover_functions(exe, opts.include_anonymous);
    let mut funcs: Vec<FunctionAnalysis> = Vec::new();
    let mut report = ProjectReport {
        functions_total: starts.len(),
        functions_scanned: starts.iter().filter(|s| !s.source.is_symbol()).count(),
        warnings: exe.warnings(),
        ..ProjectReport::default()
    };

    for (i, start) in starts.iter().enumerate() {
        let addr = start.addr;
        let hint = start
            .source
            .mdebug_index()
            .and_then(|i| exe.mdebug.as_ref().and_then(|m| m.functions.get(i)));
        let next = starts.get(i + 1).map(|s| s.addr);
        let mut a = match analyze::analyze_bounded(exe, addr, hint, next) {
            Ok(a) => a,
            Err(e) => {
                report.warnings.push(format!("skip {addr:#010x}: {e}"));
                continue;
            }
        };
        // The user's symbol map wins over everything, which is the whole point
        // of keeping names in a reviewed text file.
        if let Some(e) = map.get(addr) {
            a.name = e.name.clone();
            if a.confidence == crate::analyze::Confidence::Anonymous {
                a.confidence = crate::analyze::Confidence::Symbolised;
            }
        }
        if let Some(f) = &opts.filter {
            if !a.name.to_lowercase().contains(&f.to_lowercase()) {
                continue;
            }
        }
        if !a.name.starts_with("f_") {
            report.functions_named += 1;
        }
        report.instructions += a.instruction_count();
        for ins in &a.insns {
            if ins.is_unknown() {
                report.instructions_unknown += 1;
                if report.unknown_words.len() < 40 {
                    report
                        .unknown_words
                        .push(format!("{:#010x} {:08x}", ins.addr, ins.raw));
                }
            }
        }
        funcs.push(a);
        if opts.limit != 0 && funcs.len() >= opts.limit {
            report
                .warnings
                .push(format!("stopped after {} functions (--limit)", funcs.len()));
            break;
        }
    }

    let eo = EmitOptions {
        force: opts.force,
        listing: true,
        listing_limit: opts.listing_limit,
    };
    let emitted = emit::generate(&layout.out_dir, &funcs, &st, &eo)?;
    for e in &emitted {
        match e.action {
            Action::Created => report.functions_emitted_created += 1,
            Action::Refreshed => report.functions_emitted_refreshed += 1,
            Action::SkippedEdited => report.functions_skipped_edited += 1,
            Action::SkippedDone => report.functions_skipped_done += 1,
            Action::Skipped => {}
        }
    }
    report.text_bytes = exe.text_size().unwrap_or(0) as usize;
    report.analyzed = funcs.iter().map(crate::emit::summary).collect();

    std::fs::create_dir_all(&layout.out_dir)
        .map_err(|e| format!("{}: {e}", layout.out_dir.display()))?;
    let md = report_markdown(exe, map, &report);
    std::fs::write(layout.report_path(), md).map_err(|e| format!("report.md: {e}"))?;

    // Seed the status + symbol files so the team has something to review and
    // edit; existing entries are never replaced.
    // Seed first, then read the counts, so a fresh checkout reports the real
    // `todo` total instead of zeroes taken from a status file that did not exist
    // yet when this run started.
    let mut st = st;
    if st.seed(funcs.iter().map(|f| f.address)) > 0 {
        st.save(&layout.status_path())?;
    }
    let (todo, wip, done) = st.counts();
    report.todo = todo;
    report.in_progress = wip;
    report.done = done;
    let mut map = map.clone();
    map.merge_auto(exe);
    if !layout.symbols_path().exists() {
        map.save(&layout.symbols_path())?;
    }
    Ok(report)
}

#[must_use]
pub fn report_markdown(exe: &Executable<'_>, map: &SymbolMap, r: &ProjectReport) -> String {
    let mut s = String::new();
    s.push_str("# God of War (PS2) decompilation status\n\n");
    s.push_str("Generated by `gowd gen`. Do not hand-edit; re-run instead.\n\n");
    s.push_str("## Binary\n\n| item | value |\n|---|---|\n");
    let _ = writeln!(s, "| entry | {:#010x} |", exe.elf.entry());
    let _ = writeln!(
        s,
        "| `.text` size | {:#x} bytes ({:.1} KiB) |",
        r.text_bytes,
        r.text_bytes as f64 / 1024.0
    );
    let _ = writeln!(
        s,
        "| `.mdebug` | {} |",
        match &exe.mdebug {
            Some(m) => format!(
                "present, {} files / {} functions recovered",
                m.files.len(),
                m.functions.len()
            ),
            None => "absent".to_string(),
        }
    );
    let _ = writeln!(s, "| ELF `.symtab` | {} entries |", exe.symtab.len());
    let _ = writeln!(s, "| symbol map overrides | {} |", map.len());

    s.push_str("\n## Coverage\n\n| metric | value |\n|---|---|\n");
    let _ = writeln!(s, "| functions found | {} |", r.functions_total);
    let _ = writeln!(s, "| functions named | {} |", r.functions_named);
    let _ = writeln!(
        s,
        "| recovered by scanning (no symbol) | {} |",
        r.functions_scanned
    );
    let _ = writeln!(s, "| instructions analysed | {} |", r.instructions);
    let _ = writeln!(
        s,
        "| undecoded instructions | {} ({:.3}%) |",
        r.instructions_unknown,
        if r.instructions == 0 {
            0.0
        } else {
            100.0 * r.instructions_unknown as f64 / r.instructions as f64
        }
    );
    let _ = writeln!(s, "| `done` | {} |", r.done);
    let _ = writeln!(s, "| `in-progress` | {} |", r.in_progress);
    let _ = writeln!(s, "| `todo` | {} |", r.todo);
    let _ = writeln!(
        s,
        "| stubs created / refreshed | {} / {} |",
        r.functions_emitted_created, r.functions_emitted_refreshed
    );
    let _ = writeln!(
        s,
        "| preserved (human-edited / done) | {} / {} |",
        r.functions_skipped_edited, r.functions_skipped_done
    );

    if !r.unknown_words.is_empty() {
        s.push_str("\n## Encodings `ee-isa` cannot yet decode\n\n");
        s.push_str(
            "Add these to the tables in `crates/ee-isa/src/decode.rs` (verify each against a\n\
             reference disassembler), then re-run `gowd gen`.\n\n```text\n",
        );
        for w in &r.unknown_words {
            let _ = writeln!(s, "{w}");
        }
        s.push_str("```\n");
    }

    if !r.warnings.is_empty() {
        s.push_str("\n## Warnings\n\n");
        for w in &r.warnings {
            let _ = writeln!(s, "* {w}");
        }
    }

    if !r.analyzed.is_empty() {
        s.push_str("\n## Functions\n\nColumns: address, size, instructions, name.\n\n```text\n");
        for l in r.analyzed.iter().take(400) {
            s.push_str(l);
            s.push('\n');
        }
        if r.analyzed.len() > 400 {
            let _ = writeln!(s, "... {} more", r.analyzed.len() - 400);
        }
        s.push_str("```\n");
    }
    s
}
