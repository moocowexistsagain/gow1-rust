//! `gow-decomp` — analysis and Rust code generation for the God of War PS2
//! executable.
//!
//! Pipeline shape (each stage is independently useful and independently
//! testable):
//!
//! ```text
//!   SCUS_973.99 --ps2-elf--> ELF + .mdebug symbols (when the build kept them)
//!               --ee-isa----> instruction stream
//!               --scan------>  entry points, when there are no symbols at all
//!               --analyze--->  FunctionAnalysis (frame, slots, calls, refs)
//!               --emit------>  compilable Rust stubs + transliteration sketches
//! ```
//!
//! The emitter deliberately produces *stubs with full analysis context* rather
//! than fake "decompiled" code: for behaviourally faithful Rust the translation
//! step is a judgement call about names, types and control flow, and a tool that
//! guesses there is worse than a tool that hands you the facts.

#![forbid(unsafe_code)]

pub mod analyze;
pub mod emit;
pub mod naming;
pub mod report;
pub mod status;
pub mod translit;

pub use analyze::{analyze, analyze_bounded, scan_function_starts, Evidence, FunctionAnalysis};
pub use ps2_elf::Executable;
pub use report::{discover_functions, generate, ProjectReport, Start};

/// Where a project's generated output lives.
#[derive(Clone, Debug)]
pub struct Layout {
    /// `out/rust` by default; safe to point at the repo's real `src/` later.
    pub out_dir: std::path::PathBuf,
}

impl Default for Layout {
    fn default() -> Self {
        Self {
            out_dir: std::path::PathBuf::from("out/rust"),
        }
    }
}

impl Layout {
    #[must_use]
    pub fn status_path(&self) -> std::path::PathBuf {
        self.out_dir.join("status.txt")
    }
    #[must_use]
    pub fn symbols_path(&self) -> std::path::PathBuf {
        self.out_dir.join("symbols.syms.txt")
    }
    #[must_use]
    pub fn report_path(&self) -> std::path::PathBuf {
        self.out_dir.join("report.md")
    }
}
