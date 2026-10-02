//! `ee-isa` — MIPS R5900 (PlayStation 2 "Emotion Engine") instruction decoder.
//!
//! This is the foundation of the decompilation pipeline: every later stage
//! (control-flow recovery, frame/stack-slot inference, the Rust emitter)
//! consumes the [`Insn`] stream produced here.
//!
//! Design rules
//! ------------
//! * **No invented mnemonics.** Where the decoder does not know an encoding it
//!   returns `unknown`/`mmi?`/`vu0ct` with `Flags::UNKNOWN` set and every field
//!   preserved, rather than guessing a name. A listing that is silently wrong
//!   costs far more to a decompilation than one with visible gaps.
//! * **Encodings were cross-checked against GNU binutils' own R5900
//!   conformance corpus** (`gas/testsuite/gas/mips/r5900-full.d`,
//!   `r5900@c0.d`, `r5900@c1.d`, `r5900@c2.d`), which pairs each 32-bit word
//!   with its authoritative disassembly, plus LLVM's MC encoder for FPU field
//!   positions. `tools/golden_check.py` re-runs that comparison; the tables are
//!   not committed (binutils is GPLv3+) because only architecture facts are
//!   transcribed here, exactly as they appear in the Emotion Engine User's
//!   Manual.
//! * **The EE is not MIPS32.** `op = 0x1c` (SPECIAL2) is MMI, not
//!   `clz/mul/madd`, and the FPU puts `$fd` in a different field than MIPS IV
//!   does. See `decode.rs` for both traps.
//! * No dependencies. Everything here is `core`/`alloc`, so `cargo test`
//!   works in a sealed network and the crate can be reused by a `no_std`
//!   tool later.

#![forbid(unsafe_code)]

use std::fmt;

pub mod decode;
pub mod regs;

pub use decode::{
    branch_target, decode, decode_all, f_func, f_mmi, f_rd, f_rs, f_rt, f_sa, f_target, primary,
};
pub use regs::{
    cop0_reg, cop2_reg, fpr, gpr, mmi_acc, GPR_ABI, GPR_AT, GPR_FP, GPR_GP, GPR_RA, GPR_SP,
    GPR_ZERO,
};

/// Instruction classification bits. A hand-rolled bitflags so the crate stays
/// dependency-free.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct Flags(pub u32);

impl Flags {
    pub const NONE: Flags = Flags(0);
    /// Conditional branch: a delay slot follows.
    pub const BRANCH: Flags = Flags(1 << 0);
    /// Unconditional jump (jr/j/jal/...): a delay slot follows.
    pub const JUMP: Flags = Flags(1 << 1);
    /// Writes a return address.
    pub const LINK: Flags = Flags(1 << 2);
    /// `LIKELY` suffix: the delay slot runs only when the branch is taken.
    pub const LIKELY: Flags = Flags(1 << 3);
    /// Predicated on a condition.
    pub const COND: Flags = Flags(1 << 4);
    pub const LOAD: Flags = Flags(1 << 5);
    pub const STORE: Flags = Flags(1 << 6);
    /// Touches memory at all.
    pub const MEMORY: Flags = Flags(1 << 7);
    /// Touches a coprocessor register file.
    pub const COP: Flags = Flags(1 << 8);
    pub const FLOAT: Flags = Flags(1 << 9);
    /// 128-bit multimedia (MMI) instruction.
    pub const MMI: Flags = Flags(1 << 10);
    /// Unconditional block terminator (jr/j/eret/syscall).
    pub const TERMINATOR: Flags = Flags(1 << 11);
    /// Writes `$hi`/`$lo` (or the EE's second accumulator pair).
    pub const HILO: Flags = Flags(1 << 12);
    pub const SYSCALL: Flags = Flags(1 << 13);
    /// Unrecognised encoding. Never auto-emit recovered Rust over these.
    pub const UNKNOWN: Flags = Flags(1 << 14);
    /// `$gp`-relative access: a candidate named global.
    pub const GP_REL: Flags = Flags(1 << 15);
    /// `$sp`-relative access: a candidate stack slot (local or spilled arg).
    pub const STACK: Flags = Flags(1 << 16);
    /// Prologue frame allocation.
    pub const FRAME: Flags = Flags(1 << 17);
    /// Call: target may resolve to a symbol.
    pub const CALL: Flags = Flags(1 << 18);
    /// Register move or materialised constant.
    pub const MOVE: Flags = Flags(1 << 19);
    /// `lui`-style upper immediate half.
    pub const UPPER_IMM: Flags = Flags(1 << 20);
    /// Comparison producing a GPR boolean.
    pub const CMP: Flags = Flags(1 << 21);
    /// Writes a VU0/FPU register.
    pub const FPU_WRITE: Flags = Flags(1 << 22);
    /// 128-bit MM register access (`lq`/`sq`).
    pub const WIDE: Flags = Flags(1 << 23);
    /// The mnemonic is known but some operand sub-fields are not modelled yet
    /// (the VU0 broadcast / destination-mask bits). Listings stay honest: the
    /// raw word is always printed alongside, and nothing should be auto-emitted
    /// from a PARTIAL decode without checking it.
    pub const PARTIAL: Flags = Flags(1 << 24);

    #[must_use]
    pub const fn bits(&self) -> u32 {
        self.0
    }
    #[must_use]
    pub const fn contains(&self, other: Flags) -> bool {
        (self.0 & other.0) == other.0
    }
    #[must_use]
    pub const fn intersects(&self, other: Flags) -> bool {
        (self.0 & other.0) != 0
    }
    #[must_use]
    pub const fn union(self, other: Flags) -> Flags {
        Flags(self.0 | other.0)
    }
    #[must_use]
    pub const fn without(self, other: Flags) -> Flags {
        Flags(self.0 & !other.0)
    }
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0 == 0
    }

    const NAMED: &'static [(Flags, &'static str)] = &[
        (Flags::BRANCH, "BRANCH"),
        (Flags::JUMP, "JUMP"),
        (Flags::LINK, "LINK"),
        (Flags::LIKELY, "LIKELY"),
        (Flags::COND, "COND"),
        (Flags::LOAD, "LOAD"),
        (Flags::STORE, "STORE"),
        (Flags::MEMORY, "MEMORY"),
        (Flags::COP, "COP"),
        (Flags::FLOAT, "FLOAT"),
        (Flags::MMI, "MMI"),
        (Flags::TERMINATOR, "TERMINATOR"),
        (Flags::HILO, "HILO"),
        (Flags::SYSCALL, "SYSCALL"),
        (Flags::UNKNOWN, "UNKNOWN"),
        (Flags::GP_REL, "GP_REL"),
        (Flags::STACK, "STACK"),
        (Flags::FRAME, "FRAME"),
        (Flags::CALL, "CALL"),
        (Flags::MOVE, "MOVE"),
        (Flags::UPPER_IMM, "UPPER_IMM"),
        (Flags::CMP, "CMP"),
        (Flags::FPU_WRITE, "FPU_WRITE"),
        (Flags::WIDE, "WIDE"),
        (Flags::PARTIAL, "PARTIAL"),
    ];
}

impl std::ops::BitOr for Flags {
    type Output = Flags;
    fn bitor(self, rhs: Flags) -> Flags {
        Flags(self.0 | rhs.0)
    }
}
impl std::ops::BitOrAssign for Flags {
    fn bitor_assign(&mut self, rhs: Flags) {
        self.0 |= rhs.0;
    }
}
impl fmt::Debug for Flags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for (bit, name) in Flags::NAMED {
            if self.contains(*bit) {
                if !first {
                    f.write_str("|")?;
                }
                first = false;
                f.write_str(name)?;
            }
        }
        if first {
            f.write_str("NONE")?;
        }
        Ok(())
    }
}

/// Operand layout: which fields are live operands and how to render them.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Form {
    /// No operands (`nop`, `sync`, `ei`).
    No,
    Rd,
    /// `$rt` — coprocessor moves that take no selector operand.
    Rt,
    Rs,
    RdRs,
    /// `$rd,$rt` — MMI forms like PABSW whose second operand is in the `rt` slot.
    RdRt,
    RsRt,
    RdRsRt,
    /// `$rd,$rt,$rs` — vector shifts (PSLLVW) take the count from `$rs`.
    RdRtRs,
    /// `$rd,$rt,0xSA` — MMI shifts.
    RdRtSa,
    /// `$rd,$rs,0xSA`
    RdRsSa,
    /// `$rt,$rs,imm`
    RtRsImm,
    /// `$rt,imm` (LUI, and the `$rs`-ignoring immediate traps)
    RtImm,
    /// `$rs,imm` (EE `MTSAB`/`MTSAH`)
    RsImm,
    /// `$rt,imm($rs)`
    Mem,
    /// `$fN,imm($rs)`
    MemF,
    /// `0x{rt},imm($rs)` (PREF, CACHE)
    HintMem,
    /// `0xTARGET`
    Target,
    /// `$rs,$rt,0xTARGET`
    BrRsRt,
    /// `$rs,0xTARGET`
    BrRs,
    /// `$rt,0xTARGET` (BGTZ/BLEZ use the `rt` slot for the compared register)
    BrRt,
    /// `$rt,$reg` (MFC0/MTC0/MFC2/CTC2/CFC1/...)
    RtCopReg,
    /// `$rt,0xSEL` — EE COP0 moves selected by the function field.
    RtSel,
    /// `$fd,$fs,$ft`
    Fpu3,
    /// `$fd,$fs`
    Fpu2,
    /// `$fd,$ft` — the accumulating `*a.s` forms.
    FpuFdFt,
    /// `$fs,$ft` — comparisons, no destination register.
    FpuCmp,
    /// `0x{nd,cc},0xTARGET` — FBCCL/FCMPBF.
    FpuBranch,
    /// `0x{co} raw` — VU0 float "CT" space, fields preserved but not yet split.
    VuCtl,
    /// VU0 integer-space operands, which address `$vi` registers.
    VuVi,
    /// `0x{code} raw` — unknown MMI code.
    MmiUnknown,
    /// `0xCODE` (syscall/break code field)
    Code,
    /// Unrecognised: prints the raw word.
    Unknown,
}

/// A decoded instruction plus every field a later pass can use.
#[derive(Clone, Copy)]
pub struct Insn {
    pub addr: u32,
    pub raw: u32,
    pub name: &'static str,
    pub form: Form,
    pub flags: Flags,

    // --- encoding fields --------------------------------------------------
    /// Primary opcode, bits 31..26.
    pub op: u32,
    /// `rs`, bits 25..21 — the coprocessor select field for `COP*`.
    pub rs: u32,
    /// `rt`, bits 20..16 — the FPU `ft` field for FPU ops.
    pub rt: u32,
    /// `rd`, bits 15..11 — the FPU `fs` field for FPU ops.
    pub rd: u32,
    /// `sa`, bits 10..6 — the FPU `$fd` field on the EE.
    pub sa: u32,
    /// Function code, bits 5..0 (or the 11-bit MMI code for `op == 0x1c`).
    pub func: u32,
    /// Sign-extended immediate, bits 15..0.
    pub imm: i32,
    /// Zero-extended immediate, bits 15..0.
    pub uimm: u32,
    /// Absolute branch/jump target; valid when BRANCH or JUMP is set.
    pub target: u32,
    /// Coprocessor register number, or selector for the EE `MOV` forms.
    pub sel: u32,
    /// Floating-point condition code fields for FPU branches.
    pub cc: u32,
    /// FPU format field (`co`) — 0x10 = `.s`, 0x14 = `.w`, 0x15 = `.l`.
    pub fmt: u32,
}

impl Insn {
    /// The VU0 destination-field bits (`bits[15:12]` of a CT instruction).
    #[must_use]
    pub(crate) fn fmt_bits(&self) -> u32 {
        (self.raw >> 12) & 0xf
    }

    /// True when the next word is a delay slot.
    #[must_use]
    pub fn has_delay_slot(&self) -> bool {
        self.flags.intersects(Flags::BRANCH | Flags::JUMP)
    }

    #[must_use]
    pub fn is_branch(&self) -> bool {
        self.flags.contains(Flags::BRANCH)
    }
    #[must_use]
    pub fn is_call(&self) -> bool {
        self.flags.contains(Flags::CALL)
    }
    #[must_use]
    pub fn is_return(&self) -> bool {
        (self.name == "jr" && self.rs == GPR_RA) || self.name == "eret"
    }
    #[must_use]
    pub fn is_unknown(&self) -> bool {
        self.flags.contains(Flags::UNKNOWN)
    }

    /// The GPR written by this instruction, if any. `$zero` writes are dropped.
    #[must_use]
    pub fn writes_gpr(&self) -> Option<u32> {
        let reg = match self.form {
            Form::RdRsRt
            | Form::RdRtRs
            | Form::RdRtSa
            | Form::RdRsSa
            | Form::RdRs
            | Form::RdRt
            | Form::Rd => self.rd,
            Form::RtRsImm | Form::RtImm | Form::Mem => {
                if self.flags.contains(Flags::STORE) {
                    return None;
                }
                self.rt
            }
            Form::Rt | Form::RtCopReg | Form::RtSel => {
                if self.flags.contains(Flags::LOAD) {
                    self.rt
                } else {
                    return None;
                }
            }
            _ => return None,
        };
        (reg != GPR_ZERO).then_some(reg)
    }

    /// GPRs read by this instruction. Deliberately conservative: enough for
    /// liveness and prologue analysis, not a substitute for real data flow.
    #[must_use]
    pub fn reads_gprs(&self) -> Vec<u32> {
        let mut out: Vec<u32> = Vec::with_capacity(3);
        let add = |r: u32, out: &mut Vec<u32>| {
            let r = r & 31;
            if r != GPR_ZERO && !out.contains(&r) {
                out.push(r);
            }
        };
        match self.form {
            Form::RdRsRt | Form::RdRtRs => {
                add(self.rs, &mut out);
                add(self.rt, &mut out);
            }
            Form::RdRs => add(self.rs, &mut out),
            Form::RdRt => add(self.rt, &mut out),
            Form::RsRt | Form::BrRsRt => {
                add(self.rs, &mut out);
                add(self.rt, &mut out);
            }
            Form::Rs | Form::BrRs => add(self.rs, &mut out),
            Form::RdRtSa => add(self.rt, &mut out),
            Form::RdRsSa => add(self.rs, &mut out),
            Form::RtRsImm => {
                add(self.rs, &mut out);
                if !self.flags.contains(Flags::STORE) {
                    // `addi $rt,$rs` reads $rs only.
                }
            }
            Form::Mem | Form::MemF | Form::HintMem => add(self.rs, &mut out),
            Form::RsImm => add(self.rs, &mut out),
            Form::RtCopReg | Form::RtSel => {
                if !self.flags.contains(Flags::LOAD) {
                    add(self.rt, &mut out);
                }
            }
            _ => {}
        }
        if matches!(self.form, Form::Mem | Form::MemF) && self.flags.contains(Flags::STORE) {
            add(self.rt, &mut out);
        }
        out
    }

    /// Writes a VU0/FPU/MMI register (which the recovered Rust will model as a
    /// distinct vector type, not as a GPR).
    #[must_use]
    pub fn writes_fpr(&self) -> Option<u32> {
        if self.flags.contains(Flags::STORE) {
            return None;
        }
        match self.form {
            Form::MemF => Some(self.rt),
            Form::Fpu2 | Form::Fpu3 => Some(self.sa),
            // The `*a.s` forms accumulate in the field MIPS names $fs.
            Form::FpuFdFt => Some(self.rd),
            _ => None,
        }
    }

    /// `(base register, displacement)` for memory operands.
    #[must_use]
    pub fn memory_operand(&self) -> Option<(u32, i32)> {
        match self.form {
            Form::Mem | Form::MemF | Form::HintMem => Some((self.rs, self.imm)),
            _ => None,
        }
    }

    /// Whether a branch/call target is meaningful for this instruction.
    #[must_use]
    pub fn has_target(&self) -> bool {
        self.flags.intersects(Flags::BRANCH | Flags::JUMP)
    }

    /// Render operands only.
    #[must_use]
    pub fn operands(&self, opts: &DecodeOptions) -> String {
        let g = |n: u32| gpr(n, opts.numeric_gprs);
        let i = |n: i32| match (opts.hex_imms, n < 0) {
            (true, true) => format!("-{:#x}", -(n as i64)),
            (true, false) => format!("{n:#x}"),
            (false, _) => format!("{n}"),
        };
        let cop_reg = |ins: &Insn| match ins.op {
            0x10 => cop0_reg(ins.sel),
            0x11 => fpr(ins.sel),
            0x12 => cop2_reg(ins.sel),
            _ => g(ins.sel),
        };
        match self.form {
            Form::No => String::new(),
            Form::Rd => g(self.rd),
            Form::Rt => g(self.rt),
            Form::Rs | Form::BrRs => g(self.rs),
            Form::RdRs => format!("{},{}", g(self.rd), g(self.rs)),
            Form::RdRt => format!("{},{}", g(self.rd), g(self.rt)),
            Form::RsRt => format!("{},{}", g(self.rs), g(self.rt)),
            Form::RdRsRt => format!("{},{},{}", g(self.rd), g(self.rs), g(self.rt)),
            Form::RdRtRs => format!("{},{},{}", g(self.rd), g(self.rt), g(self.rs)),
            Form::RdRtSa => format!("{},{},0x{:x}", g(self.rd), g(self.rt), self.sa),
            Form::RdRsSa => format!("{},{},0x{:x}", g(self.rd), g(self.rs), self.sa),
            Form::RtRsImm => {
                // ANDI/ORI/XORI take an *unsigned* 16-bit immediate; ADDI/SLTI
                // a signed one. Printing the logical ones as negative is a classic
                // mistranslation source (`andi $1,$1,0xffff` is not -1).
                let v = if matches!(self.op, 0x0c..=0x0e) {
                    format!("{:#x}", self.uimm)
                } else {
                    i(self.imm)
                };
                format!("{},{},{}", g(self.rt), g(self.rs), v)
            }
            // LUI shows the raw 16-bit field (binutils convention); the
            // "value" it produces is that field shifted left by 16, which the
            // emitter computes when it folds lui+ori pairs.
            Form::RtImm => format!("{},0x{:x}", g(self.rt), self.uimm),
            Form::RsImm => format!("{},{}", g(self.rs), i(self.imm)),
            Form::Mem => format!("{},{}({})", g(self.rt), i(self.imm), g(self.rs)),
            Form::MemF => {
                // `lq`/`sq` name one of the 32 128-bit MM registers, which are
                // numbered like GPRs (they overlap them in the register file);
                // `lwc1`/`swc1` name an FPU register.
                let reg = if self.flags.contains(Flags::WIDE) {
                    g(self.rt)
                } else {
                    fpr(self.rt)
                };
                format!("{},{}({})", reg, i(self.imm), g(self.rs))
            }
            Form::HintMem => format!("0x{:x},{}({})", self.rt, i(self.imm), g(self.rs)),
            Form::Target => format!("{:#010x}", self.target),
            Form::BrRsRt => format!("{},{},{:#010x}", g(self.rs), g(self.rt), self.target),
            Form::BrRt => format!("{},{:#010x}", g(self.rt), self.target),
            Form::RtCopReg => format!("{},{}", g(self.rt), cop_reg(self)),
            Form::RtSel => format!("{},0x{:x}", g(self.rt), self.sel),
            Form::Fpu3 => format!("{},{},{}", fpr(self.sa), fpr(self.rd), fpr(self.rt)),
            Form::Fpu2 => format!("{},{}", fpr(self.sa), fpr(self.rd)),
            Form::FpuFdFt => format!("{},{}", fpr(self.rd), fpr(self.rt)),
            Form::FpuCmp => format!("{},{}", fpr(self.rd), fpr(self.rt)),
            Form::FpuBranch => format!("0x{:x},{:#010x}", self.cc, self.target),
            Form::VuCtl => {
                // Fields, deliberately *not* resolved operands.
                //
                // The reference disassembler prints the third operand of
                // `vaddx.` as `$vf0x` and that of `vmax.` as `$vf0`, and the
                // difference cannot be read off the mnemonic: `...x.` is a
                // broadcast component in one case and the tail of the name
                // `max` in the other. Deciding it needs the per-op operand kinds
                // from the VU0 chapter of the manual, which is milestone M3;
                // inventing a suffix here would put a wrong-looking-but-plausible
                // operand in front of whoever is rewriting the function, which is
                // worse than showing the numbers and saying "unknown".
                format!(
                    "$vf{}[tfd],$vf{}[ts],bc={} tf={} (fields; see M3)",
                    self.rd,
                    self.rt,
                    self.rs & 0x1f,
                    self.fmt_bits(),
                )
            }
            // VU0 integer ops address the `$vi` file, numbered the same way.
            Form::VuVi => format!("$vi{},$vi{},$vi{}", self.rd, self.rt, self.rs),
            Form::MmiUnknown => format!("code=0x{:03x} raw=0x{:08x}", self.func, self.raw),
            Form::Code => format!("0x{:x}", self.uimm),
            Form::Unknown => format!("0x{:08x}", self.raw),
        }
    }

    /// `mnemonic operands`.
    #[must_use]
    pub fn text(&self, opts: &DecodeOptions) -> String {
        let ops = self.operands(opts);
        if ops.is_empty() {
            self.name.to_string()
        } else {
            format!("{} {}", self.name, ops)
        }
    }

    /// `0010a4c0: 27bdfff8  addiu $sp,$sp,-8` — the canonical listing line.
    #[must_use]
    pub fn listing(&self, opts: &DecodeOptions) -> String {
        format!("{:08x}: {:08x}  {}", self.addr, self.raw, self.text(opts))
    }
}

impl fmt::Display for Insn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text(&DecodeOptions::default()))
    }
}

impl fmt::Debug for Insn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:08x}:{:08x} {:<30} [{}]",
            self.addr,
            self.raw,
            self.text(&DecodeOptions::numeric()),
            if self.flags.is_empty() {
                "NONE".to_string()
            } else {
                format!("{:?}", self.flags)
            }
        )
    }
}

#[derive(Clone, Copy, Debug)]
pub struct DecodeOptions {
    /// Print `$2` instead of `$v0`.
    pub numeric_gprs: bool,
    /// Print immediates in hex.
    pub hex_imms: bool,
    /// Fold `sll $0,$0,0` into `nop`, `addiu $rt,$zero,x` into `li`, etc.
    /// Set this false when doing byte-matching, where the raw form is the truth.
    pub collapse_aliases: bool,
}

impl Default for DecodeOptions {
    fn default() -> Self {
        Self {
            numeric_gprs: false,
            hex_imms: false,
            collapse_aliases: true,
        }
    }
}

impl DecodeOptions {
    /// Numeric registers + hex immediates + no alias folding: what the
    /// `--raw`/golden-comparison paths use.
    #[must_use]
    pub fn raw() -> Self {
        Self {
            numeric_gprs: true,
            hex_imms: true,
            collapse_aliases: false,
        }
    }
    /// What generated listings use: ABI register names (so `$a0` reads as an
    /// argument), hex immediates (the PS2 convention), and no alias folding
    /// (a listing must show what is really encoded).
    #[must_use]
    pub fn listing() -> Self {
        Self {
            numeric_gprs: false,
            hex_imms: true,
            collapse_aliases: false,
        }
    }
    #[must_use]
    pub fn numeric() -> Self {
        Self {
            numeric_gprs: true,
            hex_imms: true,
            collapse_aliases: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(r: u32) -> Insn {
        decode(0x1000_0000, r, &DecodeOptions::raw())
    }
    fn text(r: u32) -> String {
        raw(r).text(&DecodeOptions::numeric())
    }

    /// These (word, disassembly) pairs are taken verbatim from binutils'
    /// `r5900-full.d` expectations, i.e. the reference disassembly of the same
    /// encoding. Note that a couple of FPU *print orders* differ (binutils
    /// prints `madd.s` with the sources swapped); the encodings and field roles
    /// are what is asserted here.
    #[test]
    fn base_integer_and_ee_extras() {
        assert_eq!(
            raw(0x0143_0820).text(&DecodeOptions::numeric()),
            "add $1,$10,$3"
        );
        assert_eq!(raw(0x03e0_0008).text(&DecodeOptions::numeric()), "jr $31");
        assert_eq!(
            raw(0x201f_0000).text(&DecodeOptions::numeric()),
            "addi $31,$0,0x0"
        );
        assert_eq!(
            raw(0x301f_0000).text(&DecodeOptions::numeric()),
            "andi $31,$0,0x0"
        );
        assert_eq!(raw(0x001f_000b).name, "movn");
        assert_eq!(raw(0x001f_000a).name, "movz");
        // R5900 flips the naive expectation here: 0x38 is `ei`, 0x39 is `di`.
        assert_eq!(raw(0x4200_0038).name, "ei");
        assert_eq!(raw(0x4200_0039).name, "di");
        assert_eq!(raw(0x0000_000f).name, "sync");
        assert_eq!(
            raw(0x0000_000e).name,
            "unknown",
            "0x0e is not a SPECIAL function"
        );
        assert_eq!(raw(0x0000_0028).name, "mfsa");
        assert_eq!(raw(0x03e0_0029).name, "mtsa");
        // MTSAB/MTSAH live in REGIMM with the `rt` field as the selector and the
        // 16-bit payload in the immediate.
        assert_eq!(
            raw(0x0418_ffff).text(&DecodeOptions::numeric()),
            "mtsab $0,-0x1"
        );
        assert_eq!(
            raw(0x0419_ffff).text(&DecodeOptions::numeric()),
            "mtsah $0,-0x1"
        );
        assert_eq!(raw(0x4000_c002).name, "mfiab");
        assert_eq!(raw(0x4080_c002).name, "mtiab");
        assert_eq!(raw(0x401f_c801).name, "mfpc");
        assert_eq!(raw(0x4000_c800).name, "mfps");
    }

    #[test]
    fn mmi() {
        assert_eq!(text(0x701f_0489), "pand $0,$0,$31");
        assert_eq!(text(0x73e0_fc89), "pand $31,$31,$0");
        assert_eq!(text(0x7000_f83c), "psllw $31,$0,0x0");
        assert_eq!(text(0x701f_07fc), "psllw $0,$31,0x1f");
        assert_eq!(text(0x701f_0089), "psllvw $0,$31,$0");
        assert_eq!(text(0x703f_001a), "div1 $0,$1,$31");
        assert_eq!(text(0x73e1_001a), "div1 $0,$31,$1");
        assert_eq!(text(0x7000_f968), "pabsh $31,$0");
        assert_eq!(text(0x73e0_0004), "plzcw $0,$31");
        assert_eq!(text(0x7000_0010), "mfhi1 $0");
        assert_eq!(raw(0x701f_0489).flags, Flags::MMI);
        // Shift forms carry the amount inside bits[10:6]; the lookup retries.
        assert_eq!(text(0x7000_f83f), "psraw $31,$0,0x0");
        let unk = raw(0x701f_0002);
        assert_eq!(unk.name, "mmi?");
        assert!(unk.flags.contains(Flags::UNKNOWN));
    }

    #[test]
    fn cop1_fpu_field_roles() {
        // trunc.w.s $f0,$f31 == 4600f824: destination lives at bits[10:6].
        let ins = raw(0x4600_f824);
        assert_eq!(ins.name, "trunc.w.s");
        assert_eq!(ins.form, Form::Fpu2);
        assert_eq!(ins.sa, 0, "$fd must be bits[10:6]");
        assert_eq!(ins.rd, 31, "$fs must be bits[15:11]");
        let cmp = raw(0x4600_f834);
        assert_eq!(cmp.name, "c.lt.s");
        assert_eq!(cmp.rd, 31);
        assert_eq!(cmp.rt, 0);
        // adda.s $f0,$f31 == 461f0018 uses ft (bits[20:16]) as its source.
        let adda = raw(0x461f_0018);
        assert_eq!(adda.name, "adda.s");
        assert_eq!(adda.rt, 31);
    }

    #[test]
    fn branches_and_jumps() {
        let beq = decode(0x1000, 0x1040_fffe, &DecodeOptions::raw());
        assert!(beq.flags.contains(Flags::BRANCH));
        assert_eq!(beq.target, 0x1000 + 4 - 8);
        let jal = decode(0x1000_0000, 0x0c00_0010, &DecodeOptions::raw());
        assert_eq!(jal.name, "jal");
        assert_eq!(
            jal.target, 0x1000_0040,
            "the top nibble comes from the pc, per MIPS J-format"
        );
        assert!(jal.flags.contains(Flags::CALL));
        // beq $0,$0,0 folds to `b` only with alias collapsing on.
        let folded = decode(0x1000, 0x1000_0000, &DecodeOptions::default());
        assert_eq!(folded.name, "b");
    }

    #[test]
    fn memory_and_frame_hints() {
        let prologue = decode(0x1000, 0x27bd_ffd0, &DecodeOptions::default());
        assert_eq!(prologue.name, "addiu");
        assert!(prologue.flags.contains(Flags::FRAME));
        let gp = decode(0x1000, 0x8f82_0120, &DecodeOptions::default());
        assert_eq!(gp.name, "lw");
        assert!(gp.flags.contains(Flags::GP_REL));
        assert_eq!(gp.memory_operand(), Some((28, 0x120)));
        assert_eq!(gp.writes_gpr(), Some(2));
        let store = decode(0x1000, 0xafa2_0008_u32, &DecodeOptions::default());
        assert!(store.flags.contains(Flags::STACK));
        assert_eq!(
            store.writes_gpr(),
            None,
            "a store writes memory, not a register"
        );
        let lq = decode(0x1000, 0x7821_7fff, &DecodeOptions::raw());
        assert_eq!(lq.name, "lq");
        assert!(lq.flags.contains(Flags::MMI));
    }

    #[test]
    fn delay_slot_and_return_detection() {
        let jr = raw(0x03e0_0008);
        assert!(jr.is_return());
        assert!(jr.has_delay_slot());
        let nop = decode(0x0, 0x0000_0000, &DecodeOptions::default());
        assert_eq!(nop.name, "nop");
    }

    #[test]
    fn decode_all_is_little_endian_word_stream() {
        let bytes = [0x20u8, 0x08, 0x43, 0x01, 0x08, 0x00, 0xe0, 0x03];
        let v = decode_all(0x100, &bytes, &DecodeOptions::numeric());
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].text(&DecodeOptions::numeric()), "add $1,$10,$3");
        assert_eq!(v[1].name, "jr");
        assert_eq!(v[1].addr, 0x104);
    }
}
