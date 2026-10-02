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

/// Candidate function starts: every symbol we know about, plus (optionally) a
/// prologue scan for the unnamed remainder. The `Option<usize>` is an index
/// into `.mdebug`'s function table, so the analysis can reuse the frame info.
#[must_use]
pub fn function_starts(exe: &Executable<'_>, include_anonymous: bool) -> Vec<(u32, Option<usize>)> {
    let mut out: Vec<(u32, Option<usize>)> = Vec::new();
    if let Some(m) = &exe.mdebug {
        for (i, f) in m.functions.iter().enumerate() {
            out.push((f.address, Some(i)));
        }
    }
    for s in &exe.symtab {
        if s.is_func() && s.value != 0 {
            out.push((s.value, None));
        }
    }
    out.sort_by_key(|(a, _)| *a);
    out.dedup_by_key(|(a, _)| *a);
    if include_anonymous {
        // The prologue scan finds functions the symbols missed, but it also
        // fires on delay-slot/padding patterns *inside* a known function. Keep
        // only candidates that fall outside every known function's extent, which
        // is what "an unnamed function" means here.
        let known: Vec<u32> = out.iter().map(|(a, _)| *a).collect();
        let text_end = exe.elf.text().map(|(b, s)| b + s.len() as u32).unwrap_or(0);
        for a in analyze::find_function_starts(exe) {
            let inside_known = known.windows(2).any(|w| a >= w[0] && a < w[1]);
            let trailing = known.last().is_some_and(|k| a <= *k);
            let beyond = a >= text_end;
            if !inside_known && !trailing && !beyond {
                out.push((a, None));
            }
        }
        out.sort_by_key(|(a, _)| *a);
    }
    out
}

pub fn generate(
    exe: &Executable<'_>,
    map: &SymbolMap,
    layout: &Layout,
    opts: &GenOptions,
) -> Result<ProjectReport, String> {
    let st = StatusFile::load(&layout.status_path())?;
    let starts = function_starts(exe, opts.include_anonymous);
    let mut funcs: Vec<FunctionAnalysis> = Vec::new();
    let mut report = ProjectReport {
        functions_total: starts.len(),
        warnings: exe.warnings(),
        ..ProjectReport::default()
    };

    for (addr, sym_idx) in &starts {
        let hint = sym_idx.and_then(|i| exe.mdebug.as_ref().and_then(|m| m.functions.get(i)));
        let mut a = match analyze::analyze(exe, *addr, hint) {
            Ok(a) => a,
            Err(e) => {
                report.warnings.push(format!("skip {addr:#010x}: {e}"));
                continue;
            }
        };
        // The user's symbol map wins over everything, which is the whole point
        // of keeping names in a reviewed text file.
        if let Some(e) = map.get(*addr) {
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
