//! R5900 instruction decoder.
//!
//! Field positions
//! ---------------
//! Standard MIPS R/I/J formats throughout, with three Emotion Engine specifics
//! that bite anyone porting a generic MIPS decoder:
//!
//! 1. `op = 0x1c` (SPECIAL2 on MIPS32) belongs to **MMI** on the EE. There is
//!    no `clz`/`mul`/`madd`-accumulate; the function code is 11 bits wide
//!    (`bits[10:0]`) and the `sa` field doubles as part of the opcode, so a
//!    MIPS32 table silently mislabels MMI instructions.
//! 2. The **FPU destination field is swapped** relative to MIPS IV: `$fd` sits
//!    at `bits[10:6]` and `$fs` at `bits[15:11]` (`$ft` stays at `bits[20:16]`).
//!    `MFC1`/`MTC1` are unaffected (GPR at `bits[20:16]`, FPR at `bits[15:11]`).
//! 3. `COP0` register `$25` selects between `mfps`/`mfpc` with `func =
//!    (sel << 1) | is_pc`, so a table of "register 25 means mfps" is wrong for
//!    every non-zero selector.
//!
//! Two of the three above were found by machine-comparing this decoder against a
//! reference disassembler (`tools/golden_check.py`), not by reading a manual, and
//! each has a test. The `ei`/`di` encodings are likewise the *opposite* of what
//! a MIPS-I-era table suggests (0x38 is `ei`, 0x39 is `di`); swapping them is a
//! silent, catastrophic bug for anything touching interrupts, so the pair is
//! asserted below and in `selftest`.

use crate::{
    gpr,
    regs::{GPR_GP, GPR_RA, GPR_SP, GPR_ZERO},
    DecodeOptions, Flags, Form, Insn,
};

#[inline]
const fn bits(raw: u32, lo: u32, width: u32) -> u32 {
    (raw >> lo) & ((1u32 << width) - 1)
}

/// Primary opcode, bits 31..26.
#[inline]
pub const fn primary(raw: u32) -> u32 {
    raw >> 26
}
/// `rs` (bits 25..21) — the coprocessor-select field for `COP*` opcodes.
#[inline]
pub const fn f_rs(raw: u32) -> u32 {
    bits(raw, 21, 5)
}
/// `rt` (bits 20..16) — the FPU `$ft` field for FPU ops.
#[inline]
pub const fn f_rt(raw: u32) -> u32 {
    bits(raw, 16, 5)
}
/// `rd` (bits 15..11) — the FPU `$fs` field for FPU ops.
#[inline]
pub const fn f_rd(raw: u32) -> u32 {
    bits(raw, 11, 5)
}
/// `sa` (bits 10..6) — the FPU `$fd` field on the EE.
#[inline]
pub const fn f_sa(raw: u32) -> u32 {
    bits(raw, 6, 5)
}
/// Function code, bits 5..0.
#[inline]
pub const fn f_func(raw: u32) -> u32 {
    raw & 0x3f
}
/// The 11-bit MMI function code, bits 10..0.
#[inline]
pub const fn f_mmi(raw: u32) -> u32 {
    raw & 0x7ff
}
/// Sign-extended immediate, bits 15..0.
#[inline]
pub const fn f_imm(raw: u32) -> i32 {
    (raw as u16) as i16 as i32
}
/// J-format target: 26-bit index shifted left by two, with the upper four bits
/// of the current pc spliced in (the EE has no `j` with a full 32-bit index).
#[inline]
pub const fn f_target(raw: u32, addr: u32) -> u32 {
    (raw & 0x03ff_ffff) << 2 | (addr & 0xf000_0000)
}

/// Branch/call target: a 16-bit displacement relative to the *delay slot*,
/// which is what MIPS specifies. `wrapping_add` because a `-0x8000` displacement
/// near address 0 must not panic a debug build.
#[inline]
pub const fn branch_target(addr: u32, raw: u32) -> u32 {
    (addr + 4).wrapping_add((f_imm(raw) as u32) << 2)
}

/// Decode one 32-bit word at `addr`.
#[must_use]
pub fn decode(addr: u32, raw: u32, opts: &DecodeOptions) -> Insn {
    let mut ins = Insn {
        addr,
        raw,
        name: "unknown",
        form: Form::Unknown,
        flags: Flags::NONE,
        op: primary(raw),
        rs: f_rs(raw),
        rt: f_rt(raw),
        rd: f_rd(raw),
        sa: f_sa(raw),
        func: f_func(raw),
        imm: f_imm(raw),
        uimm: raw as u16 as u32,
        target: branch_target(addr, raw),
        sel: 0,
        cc: 0,
        fmt: 0,
    };
    decode_into(&mut ins);
    if opts.collapse_aliases {
        collapse(&mut ins);
    }
    ins
}

/// Decode a little-endian word stream, as `.text` is stored in a PS2 ELF.
/// Trailing partial words are dropped.
#[must_use]
pub fn decode_all(base: u32, bytes: &[u8], opts: &DecodeOptions) -> Vec<Insn> {
    let (words, _tail) = bytes.as_chunks::<4>();
    words
        .iter()
        .enumerate()
        .map(|(i, w)| decode(base + (i as u32) * 4, u32::from_le_bytes(*w), opts))
        .collect()
}

fn decode_into(ins: &mut Insn) {
    match ins.op {
        0x00 => special(ins),
        0x01 => regimm(ins),
        0x02 | 0x03 => {
            ins.name = if ins.op == 0x02 { "j" } else { "jal" };
            ins.form = Form::Target;
            ins.target = f_target(ins.raw, ins.addr);
            ins.flags |= Flags::JUMP | Flags::TERMINATOR;
            if ins.op == 0x03 {
                ins.flags |= Flags::CALL | Flags::LINK;
            }
        }
        0x04..=0x07 => branch(ins),
        0x08..=0x0f => arithi(ins),
        0x10 => cop0(ins),
        0x11 => cop1(ins),
        0x12 => cop2(ins),
        0x13 => cop3(ins),
        0x14 => likely_branch(ins),
        0x15 => regimm_likely(ins),
        0x16 | 0x17 => cop_branch(ins),
        0x1c => mmi(ins),
        0x1e | 0x1f => ee128bit_mem(ins),
        0x20..=0x3f => load_store(ins),
        _ => {
            // 0x18/0x19/0x1a/0x1b (COP2/COP3 branches and `b*` variants that do
            // not exist on the EE), 0x1d (SPECIAL3), 0x2c.. and the rest.
            ins.flags |= Flags::UNKNOWN;
        }
    }
}

/// Mark the base memory-ish flags shared by load/store handling below.
fn flag_mem(ins: &mut Insn, store: bool) {
    ins.flags |= if store { Flags::STORE } else { Flags::LOAD };
    ins.flags |= Flags::MEMORY;
    if ins.rs == GPR_SP {
        ins.flags |= Flags::STACK;
    }
    if ins.rs == GPR_GP {
        ins.flags |= Flags::GP_REL;
    }
}

// ---------------------------------------------------------------------------
// op 0x00: SPECIAL
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_lines)]
fn special(ins: &mut Insn) {
    let (name, form) = match ins.func {
        0x00 => ("sll", Form::RdRtSa),
        0x02 => ("srl", Form::RdRtSa),
        0x03 => ("sra", Form::RdRtSa),
        0x04 => ("sllv", Form::RdRtRs),
        0x06 => ("srlv", Form::RdRtRs),
        0x07 => ("srav", Form::RdRtRs),
        0x08 => ("jr", Form::Rs),
        0x09 => ("jalr", Form::RdRs),
        0x0a => ("movz", Form::RdRsRt),
        0x0b => ("movn", Form::RdRsRt),
        0x0c => ("syscall", Form::Code),
        0x0d => ("break", Form::Code),
        0x0f => ("sync", Form::No),
        0x10 => ("mfhi", Form::Rd),
        0x11 => ("mthi", Form::Rs),
        0x12 => ("mflo", Form::Rd),
        0x13 => ("mtlo", Form::Rs),
        0x18 => ("mult", Form::RsRt),
        0x19 => ("multu", Form::RsRt),
        0x1a => ("div", Form::RsRt),
        0x1b => ("divu", Form::RsRt),
        0x20 => ("add", Form::RdRsRt),
        0x21 => ("addu", Form::RdRsRt),
        0x22 => ("sub", Form::RdRsRt),
        0x23 => ("subu", Form::RdRsRt),
        0x24 => ("and", Form::RdRsRt),
        0x25 => ("or", Form::RdRsRt),
        0x26 => ("xor", Form::RdRsRt),
        0x27 => ("nor", Form::RdRsRt),
        // The EE puts MFS/MTS here, where MIPS32 has `dsrl`/`dsra`: the
        // serialise/async flags for MMI. `mfsa`/`mtsa` are how the compiler
        // reads and writes the MMI status word.
        0x28 => ("mfsa", Form::Rd),
        0x29 => ("mtsa", Form::Rs),
        0x2a => ("slt", Form::RdRsRt),
        0x2b => ("sltu", Form::RdRsRt),
        0x30 => ("tge", Form::RsRt),
        0x31 => ("tgeu", Form::RsRt),
        0x32 => ("tlt", Form::RsRt),
        0x33 => ("tltu", Form::RsRt),
        0x34 => ("teq", Form::RsRt),
        0x36 => ("tne", Form::RsRt),
        _ => {
            ins.flags |= Flags::UNKNOWN;
            return;
        }
    };
    ins.name = name;
    ins.form = form;
    match name {
        "jr" => ins.flags |= Flags::JUMP | Flags::TERMINATOR,
        "jalr" => ins.flags |= Flags::JUMP | Flags::TERMINATOR | Flags::LINK | Flags::CALL,
        "syscall" | "break" => ins.flags |= Flags::SYSCALL,
        "mult" | "multu" | "div" | "divu" | "mfhi" | "mflo" | "mthi" | "mtlo" => {
            ins.flags |= Flags::HILO
        }
        "movz" | "movn" => ins.flags |= Flags::COND | Flags::MOVE | Flags::CMP,
        "slt" | "sltu" => ins.flags |= Flags::CMP,
        "mfsa" | "mtsa" => ins.flags |= Flags::MMI | Flags::COP,
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// op 0x01 / 0x15: REGIMM and its LIKELY twin
// ---------------------------------------------------------------------------

fn regimm_entry(sel: u32) -> Option<(&'static str, Form)> {
    Some(match sel {
        0x00 => ("bltz", Form::BrRs),
        0x01 => ("bgez", Form::BrRs),
        0x02 => ("bltzl", Form::BrRs),
        0x03 => ("bgezl", Form::BrRs),
        0x08 => ("tgei", Form::RsImm),
        0x09 => ("tgeiu", Form::RsImm),
        0x0a => ("tlti", Form::RsImm),
        0x0b => ("tltiu", Form::RsImm),
        0x0c => ("teqi", Form::RsImm),
        0x0d => ("teqiu", Form::RsImm),
        0x0e => ("tnei", Form::RsImm),
        0x0f => ("tneiu", Form::RsImm),
        0x10 => ("bltzal", Form::BrRs),
        0x11 => ("bgezal", Form::BrRs),
        0x12 => ("bltzall", Form::BrRs),
        0x13 => ("bgezall", Form::BrRs),
        // The EE's synchronous-breakpoint address/mask triggers, which the
        // compiler does not normally emit but debug patches and IOP-side code do.
        0x18 => ("mtsab", Form::RsImm),
        0x19 => ("mtsah", Form::RsImm),
        _ => return None,
    })
}

fn regimm(ins: &mut Insn) {
    let Some((name, form)) = regimm_entry(ins.rt) else {
        ins.flags |= Flags::UNKNOWN;
        return;
    };
    finish_regimm(ins, name, form);
}

fn regimm_likely(ins: &mut Insn) {
    // op 0x15 holds the LIKELY forms of the REGIMM space.
    let Some((name, form)) = regimm_entry(ins.rt) else {
        ins.flags |= Flags::UNKNOWN;
        return;
    };
    let name = match name {
        "bltz" => "bltzl",
        "bgez" => "bgezl",
        _ => name,
    };
    finish_regimm(ins, name, form);
    ins.flags |= Flags::LIKELY;
}

fn finish_regimm(ins: &mut Insn, name: &'static str, form: Form) {
    ins.name = name;
    ins.form = form;
    if name.starts_with('t') {
        ins.flags |= Flags::SYSCALL;
        return;
    }
    ins.flags |= Flags::BRANCH | Flags::COND;
    if name.ends_with('l') {
        ins.flags |= Flags::LIKELY;
    }
    if name.contains("al") {
        ins.flags |= Flags::CALL | Flags::LINK;
    }
    if matches!(name, "mtsab" | "mtsah") {
        ins.flags = ins
            .flags
            .without(Flags::BRANCH | Flags::COND | Flags::LIKELY);
        ins.flags |= Flags::MMI | Flags::SYSCALL;
    }
}

// ---------------------------------------------------------------------------
// op 0x04..0x07 / 0x14: conditional branches
// ---------------------------------------------------------------------------

fn branch(ins: &mut Insn) {
    let (name, form) = match ins.op {
        0x04 => ("beq", Form::BrRsRt),
        0x05 => ("bne", Form::BrRsRt),
        0x06 => ("blez", Form::BrRs),
        0x07 => ("bgtz", Form::BrRt),
        _ => unreachable!(),
    };
    ins.name = name;
    ins.form = form;
    ins.flags |= Flags::BRANCH | Flags::COND;
}

fn likely_branch(ins: &mut Insn) {
    let (name, form) = match ins.rt {
        0x00 => ("beql", Form::BrRsRt),
        0x01 => ("bnel", Form::BrRsRt),
        0x02 => ("blezl", Form::BrRs),
        0x03 => ("bgtzl", Form::BrRt),
        _ => {
            ins.flags |= Flags::UNKNOWN;
            return;
        }
    };
    ins.name = name;
    ins.form = form;
    ins.flags |= Flags::BRANCH | Flags::COND | Flags::LIKELY;
}

// ---------------------------------------------------------------------------
// op 0x08..0x0f: immediate ALU
// ---------------------------------------------------------------------------

fn arithi(ins: &mut Insn) {
    let (name, form) = match ins.op {
        0x08 => ("addi", Form::RtRsImm),
        0x09 => ("addiu", Form::RtRsImm),
        0x0a => ("slti", Form::RtRsImm),
        0x0b => ("sltiu", Form::RtRsImm),
        0x0c => ("andi", Form::RtRsImm),
        0x0d => ("ori", Form::RtRsImm),
        0x0e => ("xori", Form::RtRsImm),
        0x0f => ("lui", Form::RtImm),
        _ => unreachable!(),
    };
    ins.name = name;
    ins.form = form;
    if matches!(name, "slti" | "sltiu") {
        ins.flags |= Flags::CMP;
    }
    if name == "lui" {
        ins.flags |= Flags::UPPER_IMM;
    }
    // `addiu $sp,$sp,-N` opening a function is the frame allocation, which the
    // analysis layer uses to size the stack frame.
    if name == "addiu" && ins.rs == GPR_SP && ins.rt == GPR_SP && ins.imm < 0 {
        ins.flags |= Flags::FRAME;
    }
    if matches!(name, "addiu" | "ori") && ins.rs == GPR_ZERO {
        ins.flags |= Flags::MOVE;
    }
    if ins.rs == GPR_GP {
        ins.flags |= Flags::GP_REL;
    }
}

// ---------------------------------------------------------------------------
// memory
// ---------------------------------------------------------------------------

/// (name, is_store) for every load/store the EE implements in O32 code.
fn ls_entry(op: u32) -> Option<(&'static str, bool, Form)> {
    Some(match op {
        0x20 => ("lb", false, Form::Mem),
        0x21 => ("lh", false, Form::Mem),
        0x22 => ("lwl", false, Form::Mem),
        0x23 => ("lw", false, Form::Mem),
        0x24 => ("lbu", false, Form::Mem),
        0x25 => ("lhu", false, Form::Mem),
        0x26 => ("lwr", false, Form::Mem),
        0x28 => ("sb", true, Form::Mem),
        0x29 => ("sh", true, Form::Mem),
        0x2a => ("swl", true, Form::Mem),
        0x2b => ("sw", true, Form::Mem),
        0x2c => ("ll", false, Form::Mem),
        0x2e => ("swr", true, Form::Mem),
        0x2f => ("cache", false, Form::HintMem),
        0x30 => ("lwc1", false, Form::MemF),
        0x31 => ("lwc2", false, Form::MemF),
        0x33 => ("pref", false, Form::HintMem),
        0x35 => ("ldc1", false, Form::MemF),
        0x38 => ("sc", true, Form::Mem),
        0x39 => ("swc1", true, Form::MemF),
        0x3a => ("swc2", true, Form::MemF),
        0x3d => ("sdc1", true, Form::MemF),
        _ => return None,
    })
}

fn load_store(ins: &mut Insn) {
    let Some((name, store, form)) = ls_entry(ins.op) else {
        ins.flags |= Flags::UNKNOWN;
        return;
    };
    ins.name = name;
    ins.form = form;
    flag_mem(ins, store);
    if matches!(name, "lwc1" | "swc1" | "ldc1" | "sdc1") {
        ins.flags |= Flags::FLOAT | Flags::COP;
    }
    if matches!(name, "lwc2" | "swc2") {
        ins.flags |= Flags::COP | Flags::MMI;
    }
}

/// `lq`/`sq`: 128-bit moves between memory and the MM register file. These are
/// how the SN Systems compiler passes 128-bit values and spills MMI state, so
/// recognising them is what makes vector code readable.
fn ee128bit_mem(ins: &mut Insn) {
    ins.name = if ins.op == 0x1e { "lq" } else { "sq" };
    ins.form = Form::MemF;
    ins.flags |= Flags::MEMORY | Flags::MMI | Flags::WIDE | Flags::COP;
    ins.flags |= if ins.op == 0x1e {
        Flags::LOAD
    } else {
        Flags::STORE
    };
    if ins.rs == GPR_SP {
        ins.flags |= Flags::STACK;
    }
    if ins.rs == GPR_GP {
        ins.flags |= Flags::GP_REL;
    }
}

// ---------------------------------------------------------------------------
// op 0x10: COP0
// ---------------------------------------------------------------------------

fn cop0(ins: &mut Insn) {
    let co = ins.rs;
    ins.sel = ins.rd;
    ins.flags |= Flags::COP;
    match co {
        0x00 | 0x04 => {
            // The EE's MOV forms borrow this slot; anything else (including a
            // plain register write to $24/$25) stays MFC0/MTC0 with the
            // selector left visible in `cc`.
            if ee_mov(ins) {
                return;
            }
            ins.name = if co == 0 { "mfc0" } else { "mtc0" };
            ins.form = Form::RtCopReg;
            ins.cc = ins.func;
            ins.sel = ins.rd;
            ins.flags |= if co == 0 { Flags::LOAD } else { Flags::STORE };
        }
        0x01 => {
            ins.name = "dmfc0";
            ins.form = Form::RtCopReg;
            ins.flags |= Flags::LOAD;
        }
        0x02 | 0x03 => {
            ins.name = if co == 2 { "cfc0" } else { "ctc0" };
            ins.form = Form::RtCopReg;
            ins.flags |= if co == 2 { Flags::LOAD } else { Flags::STORE };
        }
        // The `CO` group: TLB maintenance plus the EE's interrupt control.
        0x10 => {
            let (name, form) = match ins.func {
                0x01 => ("tlbr", Form::No),
                0x02 => ("tlbwi", Form::No),
                0x06 => ("tlbwr", Form::No),
                0x08 => ("tlbp", Form::No),
                0x18 => ("eret", Form::No),
                0x20 => ("wait", Form::No),
                0x38 => ("ei", Form::No),
                0x39 => ("di", Form::No),
                _ => {
                    ins.flags |= Flags::UNKNOWN;
                    return;
                }
            };
            ins.name = name;
            ins.form = form;
            if matches!(name, "eret" | "wait") {
                ins.flags |= Flags::TERMINATOR;
            }
        }
        _ => {
            ins.flags |= Flags::UNKNOWN;
        }
    }
}

/// Apply an EE COP0 "MOV" encoding to `ins`, returning whether one applied.
///
/// These borrow the MFC0/MTC0 slot and use `$24`/`$25` as an instruction
/// selector rather than a register number; a plain register write to `$24`/`$25`
/// still decodes as `mfc0`/`mtc0` with the selector left visible.
fn ee_mov(ins: &mut Insn) -> bool {
    let is_load = ins.rs == 0;
    if !matches!(ins.rd, 24 | 25) {
        return false;
    }
    let Some((name, sel)) = ee_mov_name(ins.rd, ins.func, is_load) else {
        return false;
    };
    ins.name = name;
    // `$24`'s moves have no selector operand at all (the function code *is* the
    // selection), while `$25`'s print one -- and the reference disassembler
    // hides a zero selector for the former.
    match sel {
        Some(sel) => {
            ins.form = Form::RtSel;
            ins.sel = sel;
        }
        None => ins.form = Form::Rt,
    }
    ins.flags |= if is_load { Flags::LOAD } else { Flags::STORE };
    true
}

/// EE COP0 moves: MFC0/MTC0 with `$24`/`$25` and a function selector.
///
/// `$24` is a flat selector (breakpoint control, and the instruction/data
/// address and value-match registers). `$25` is *not*: its function code is
/// `(sel << 1) | is_pc`, which is why `mfpc $0,1` is `0x4000c803` and not
/// `0x4000c801`. Both shapes are read straight out of the reference
/// disassembly; treating `$25` as a table of opcodes would have silently
/// mislabelled every non-zero selector.
fn ee_mov_name(reg: u32, func: u32, load: bool) -> Option<(&'static str, Option<u32>)> {
    if reg == 25 {
        if func & !0b11 != 0 {
            return None;
        }
        let sel = Some(func >> 1);
        let n = match (func & 1, load) {
            (0, true) => "mfps",
            (0, false) => "mtps",
            (1, true) => "mfpc",
            _ => "mtpc",
        };
        return Some((n, sel));
    }
    let n = match (reg, func) {
        (24, 0x00) => {
            if load {
                "mfbpc"
            } else {
                "mtbpc"
            }
        }
        (24, 0x02) => {
            if load {
                "mfiab"
            } else {
                "mtiab"
            }
        }
        (24, 0x03) => {
            if load {
                "mfiabm"
            } else {
                "mtiabm"
            }
        }
        (24, 0x04) => {
            if load {
                "mfdab"
            } else {
                "mtdab"
            }
        }
        (24, 0x05) => {
            if load {
                "mfdabm"
            } else {
                "mtdabm"
            }
        }
        (24, 0x06) => {
            if load {
                "mfdvb"
            } else {
                "mtdvb"
            }
        }
        (24, 0x07) => {
            if load {
                "mfdvbm"
            } else {
                "mtdvbm"
            }
        }
        _ => return None,
    };
    Some((n, None))
}

// ---------------------------------------------------------------------------
// op 0x11: COP1 (FPU)
// ---------------------------------------------------------------------------

fn cop1(ins: &mut Insn) {
    let co = ins.rs;
    ins.flags |= Flags::COP | Flags::FLOAT;
    match co {
        // GPR in `rt`, FPR in `rd`, for all four transfers (verified against
        // LLVM's MC encoder: `mtc1 $a3,$f9` -> rt=7, rd=9).
        0x00 | 0x04 => {
            ins.name = if co == 0 { "mfc1" } else { "mtc1" };
            ins.form = Form::RtCopReg;
            ins.sel = ins.rd;
            ins.flags |= if co == 0 { Flags::LOAD } else { Flags::STORE };
        }
        0x02 | 0x03 => {
            ins.name = if co == 2 { "cfc1" } else { "ctc1" };
            ins.form = Form::RtCopReg;
            ins.sel = ins.rd;
            ins.flags |= if co == 2 { Flags::LOAD } else { Flags::STORE };
        }
        // FBCCL / FCMPBF: the condition-code and negate-flag bits live inside
        // the function field; the raw selector is shown until M3 splits them.
        0x08..=0x0f => {
            ins.name = if co & 1 == 0 { "fbccl" } else { "fcmpbf" };
            ins.form = Form::FpuBranch;
            ins.cc = ins.sa;
            ins.target = branch_target(ins.addr, ins.raw);
            ins.flags |= Flags::BRANCH | Flags::COND | Flags::PARTIAL;
        }
        _ => {
            ins.fmt = co;
            let Some((name, form)) = cop1_entry(co, ins.func) else {
                ins.flags |= Flags::UNKNOWN;
                return;
            };
            ins.name = name;
            ins.form = form;
            if matches!(form, Form::Fpu2 | Form::Fpu3 | Form::FpuFdFt) {
                ins.flags |= Flags::FPU_WRITE;
            }
        }
    }
}

/// R5900 COP1 arithmetic. Keyed on `(co, func)`: the EE's FPU implements the
/// single `.s` format for arithmetic (with the fixed-point conversions as their
/// own function codes), so `co = 0x10` carries every instruction the compiler
/// emits. Derived from the reference corpus; encodings it does not name are
/// absent here too.
fn cop1_entry(co: u32, func: u32) -> Option<(&'static str, Form)> {
    if co != 0x10 {
        return None;
    }
    Some(match func {
        0x00 => ("add.s", Form::Fpu3),
        0x01 => ("sub.s", Form::Fpu3),
        0x02 => ("mul.s", Form::Fpu3),
        0x03 => ("div.s", Form::Fpu3),
        0x04 => ("sqrt.s", Form::Fpu2),
        0x05 => ("abs.s", Form::Fpu2),
        0x06 => ("mov.s", Form::Fpu2),
        0x07 => ("neg.s", Form::Fpu2),
        0x08 => ("round.l.s", Form::Fpu2),
        0x09 => ("trunc.l.s", Form::Fpu2),
        0x0a => ("ceil.l.s", Form::Fpu2),
        0x0b => ("floor.l.s", Form::Fpu2),
        0x16 => ("rsqrt.s", Form::Fpu3),
        0x18 => ("adda.s", Form::FpuFdFt),
        0x19 => ("suba.s", Form::FpuFdFt),
        0x1a => ("mula.s", Form::FpuFdFt),
        0x1c => ("madd.s", Form::Fpu3),
        0x1d => ("msub.s", Form::Fpu3),
        0x1e => ("madda.s", Form::FpuFdFt),
        0x1f => ("msuba.s", Form::FpuFdFt),
        // `trunc.w.s` deliberately shares the opcode of MIPS `cvt.w.s`, which is
        // why the name and the number look mismatched next to `trunc.l.s`.
        0x24 => ("trunc.w.s", Form::Fpu2),
        0x25 => ("cvt.l.s", Form::Fpu2),
        0x28 => ("max.s", Form::Fpu3),
        0x29 => ("min.s", Form::Fpu3),
        // R5900 comparisons: `c.lt.s` is MIPS I's `c.olt.s` (0x34) and
        // `c.le.s` is `c.ole.s` (0x36).
        0x30 => ("c.f.s", Form::FpuCmp),
        0x32 => ("c.eq.s", Form::FpuCmp),
        0x34 => ("c.lt.s", Form::FpuCmp),
        0x36 => ("c.le.s", Form::FpuCmp),
        _ => return None,
    })
}

// ---------------------------------------------------------------------------
// op 0x12 / 0x13: COP2 (MMI control + VU0) and COP3 (VU1 control)
// ---------------------------------------------------------------------------

fn cop2(ins: &mut Insn) {
    let co = ins.rs;
    ins.sel = ins.rd;
    ins.flags |= Flags::COP;
    match co {
        0x00 => {
            ins.name = "mfc2";
            ins.form = Form::RtCopReg;
            ins.flags |= Flags::LOAD;
        }
        0x02 => {
            ins.name = "cfc2";
            ins.form = Form::RtCopReg;
            ins.flags |= Flags::LOAD;
        }
        0x03 => {
            ins.name = "ctc2";
            ins.form = Form::RtCopReg;
            ins.flags |= Flags::STORE;
        }
        0x04 => {
            ins.name = "mtc2";
            ins.form = Form::RtCopReg;
            ins.flags |= Flags::STORE;
        }
        // VU0 "CT" and integer space. The *mnemonic* is a function of
        // (co, func) and fully table-driven below; the operand sub-fields
        // (destination mask `w:`, broadcast `.x`, `i:`/`r:` conditions) are
        // milestone M3 in docs/ROADMAP.md, so these carry PARTIAL: the name is
        // trustworthy, the operand split is not, and the raw word always sits
        // next to it in every listing.
        _ => {
            ins.sel = co;
            match vu0_entry(co, ins.func) {
                Some(name) => {
                    ins.name = name;
                    ins.form = if name.starts_with("vi") {
                        Form::VuVi
                    } else if name.starts_with("vcallms") {
                        Form::Code
                    } else {
                        Form::VuCtl
                    };
                    ins.target = (ins.raw & 0x03ff_ffff) << 2 | (ins.addr & 0xf000_0000);
                    ins.flags |= Flags::PARTIAL;
                }
                None => {
                    ins.name = "vu0ct";
                    ins.form = Form::VuCtl;
                    ins.flags |= Flags::UNKNOWN;
                }
            }
        }
    }
}

fn cop3(ins: &mut Insn) {
    let co = ins.rs;
    ins.sel = ins.rd;
    ins.flags |= Flags::COP;
    match co {
        0x00 => {
            ins.name = "mfc3";
            ins.form = Form::RtCopReg;
            ins.flags |= Flags::LOAD;
        }
        0x02 => {
            ins.name = "cfc3";
            ins.form = Form::RtCopReg;
            ins.flags |= Flags::LOAD;
        }
        0x03 => {
            ins.name = "ctc3";
            ins.form = Form::RtCopReg;
            ins.flags |= Flags::STORE;
        }
        0x04 => {
            ins.name = "mtc3";
            ins.form = Form::RtCopReg;
            ins.flags |= Flags::STORE;
        }
        _ => ins.flags |= Flags::UNKNOWN,
    }
}

/// op 0x16/0x17: `BC0`/`BC1` (`fbccl`-family) branches. Naming them needs the
/// `nd`/`cc` split, so the selector is printed verbatim; see `cop1` above for
/// the FPU-side form that the EE's assembler actually prefers.
fn cop_branch(ins: &mut Insn) {
    let co = ins.rs;
    ins.target = branch_target(ins.addr, ins.raw);
    if co != 0x08 && co != 0x09 {
        ins.flags |= Flags::UNKNOWN;
        return;
    }
    ins.name = if ins.op == 0x16 { "bc0" } else { "bc1" };
    ins.form = Form::FpuBranch;
    ins.cc = ins.sa;
    ins.flags |= Flags::BRANCH | Flags::COND | Flags::PARTIAL | Flags::COP;
}

// ---------------------------------------------------------------------------
// op 0x1c: SPECIAL2 == MMI on the EE (11-bit function code)
// ---------------------------------------------------------------------------

/// MMI shift forms: for these the `sa` field *is* an operand, so the code only
/// occupies `bits[5:0]`. Without the retry below, `psllw $0,$31,0x1f`
/// (code `0x7fc`) would decode as unknown even though `0x03c` is in the table.
const MMI_SHIFT_CODES: [u32; 6] = [0x34, 0x36, 0x37, 0x3c, 0x3e, 0x3f];

fn mmi(ins: &mut Insn) {
    ins.flags |= Flags::MMI;
    let code = f_mmi(ins.raw);
    let code = match mmi_entry(code) {
        Some(_) => code,
        None if MMI_SHIFT_CODES.contains(&(code & 0x3f)) => code & 0x3f,
        None => code,
    };
    match mmi_entry(code) {
        Some((name, form)) => {
            ins.name = name;
            ins.form = form;
            if matches!(
                name,
                "madd"
                    | "maddu"
                    | "madd1"
                    | "maddu1"
                    | "mult1"
                    | "multu1"
                    | "div1"
                    | "divu1"
                    | "mfhi1"
                    | "mflo1"
                    | "mthi1"
                    | "mtlo1"
            ) {
                ins.flags |= Flags::HILO;
            }
        }
        None => {
            // Keep the group visible: the 11-bit code plus the raw word is
            // enough to look the encoding up in the Emotion Engine manual.
            ins.name = "mmi?";
            ins.form = Form::MmiUnknown;
            ins.func = code;
            ins.flags |= Flags::UNKNOWN;
        }
    }
}

// ---------------------------------------------------------------------------
// Print aliases (what a human expects to read, not separate encodings)
// ---------------------------------------------------------------------------

fn collapse(ins: &mut Insn) {
    match ins.form {
        // `sll $0,$0,0` and the EE's other nop encodings.
        Form::RdRtSa
            if ins.raw == 0 || (ins.func == 0x00 && ins.rd == 0 && ins.rt == 0 && ins.sa == 0) =>
        {
            ins.name = "nop";
            ins.form = Form::No;
        }
        Form::RtRsImm if ins.rs == 0 && matches!(ins.name, "addi" | "addiu" | "ori") => {
            ins.name = "li";
            ins.form = Form::RtImm;
        }
        Form::RdRsRt if ins.func == 0x25 && ins.rs == ins.rt => {
            ins.name = "move";
            ins.form = Form::RdRs;
        }
        Form::RdRtSa if ins.func == 0x00 && ins.rt != 0 && ins.rd != ins.rt => {
            // `sll $rd,$rt,0` is a register move.
            ins.name = "move";
            ins.form = Form::RdRs;
        }
        Form::BrRsRt if ins.rs == 0 && ins.rt == 0 => {
            ins.name = "b";
            ins.form = Form::Target;
            ins.flags |= Flags::JUMP | Flags::TERMINATOR;
            ins.flags = ins.flags.without(Flags::BRANCH | Flags::COND);
        }
        Form::BrRsRt if ins.rt == 0 && ins.rs != 0 && ins.name == "beq" => {
            ins.name = "beqz";
            ins.form = Form::BrRs;
        }
        Form::BrRsRt if ins.rt == 0 && ins.rs != 0 && ins.name == "bne" => {
            ins.name = "bnez";
            ins.form = Form::BrRs;
        }
        _ => {}
    }
    if ins.name == "jr" && ins.rs == GPR_RA {
        ins.flags |= Flags::TERMINATOR;
    }
}

/// Convenience for the emitters: name a GPR the way the toolchain does.
#[must_use]
pub fn reg_name(n: u32, numeric: bool) -> String {
    gpr(n, numeric)
}

// ---------------------------------------------------------------------------
// Generated tables (tools/gen_isa_tables.py)
// ---------------------------------------------------------------------------

/// MMI function code (`bits[10:0]` of an `op == 0x1c` word) to mnemonic and
/// operand form. Every entry comes from a verified (encoding, disassembly)
/// pair in a reference disassembler's conformance corpus, including which field
/// holds each operand, so no operand position here is guessed. Codes the corpus
/// does not cover are absent; those decode as `mmi?` with the raw word kept.
/// Regenerate with: tools/gen_isa_tables.py --clone <binutils-dir>
#[allow(clippy::too_many_lines)]
pub(crate) fn mmi_entry(code: u32) -> Option<(&'static str, Form)> {
    match code {
        0x000 => Some(("madd", Form::RsRt)),
        0x001 => Some(("maddu", Form::RsRt)),
        0x004 => Some(("plzcw", Form::RdRs)),
        0x008 => Some(("paddw", Form::RdRsRt)),
        0x009 => Some(("pmaddw", Form::RdRsRt)),
        0x010 => Some(("mfhi1", Form::Rd)),
        0x011 => Some(("mthi1", Form::Rs)),
        0x012 => Some(("mflo1", Form::Rd)),
        0x013 => Some(("mtlo1", Form::Rs)),
        0x018 => Some(("mult1", Form::RsRt)),
        0x019 => Some(("multu1", Form::RsRt)),
        0x01a => Some(("div1", Form::RdRsRt)),
        0x01b => Some(("divu1", Form::RdRsRt)),
        0x020 => Some(("madd1", Form::RsRt)),
        0x021 => Some(("maddu1", Form::RsRt)),
        0x029 => Some(("pmadduw", Form::RdRsRt)),
        0x030 => Some(("pmfhl.lw", Form::Rd)),
        0x031 => Some(("pmthl.lw", Form::Rs)),
        0x034 => Some(("psllh", Form::RdRtSa)),
        0x036 => Some(("psrlh", Form::RdRtSa)),
        0x037 => Some(("psrah", Form::RdRtSa)),
        0x03c => Some(("psllw", Form::RdRtSa)),
        0x03e => Some(("psrlw", Form::RdRtSa)),
        0x03f => Some(("psraw", Form::RdRtSa)),
        0x048 => Some(("psubw", Form::RdRsRt)),
        0x068 => Some(("pabsw", Form::RdRt)),
        0x070 => Some(("pmfhl.uw", Form::Rd)),
        0x088 => Some(("pcgtw", Form::RdRsRt)),
        0x089 => Some(("psllvw", Form::RdRtRs)),
        0x0a8 => Some(("pceqw", Form::RdRsRt)),
        0x0b0 => Some(("pmfhl.slw", Form::Rd)),
        0x0c8 => Some(("pmaxw", Form::RdRsRt)),
        0x0c9 => Some(("psrlvw", Form::RdRtRs)),
        0x0e8 => Some(("pminw", Form::RdRsRt)),
        0x0e9 => Some(("psravw", Form::RdRtRs)),
        0x0f0 => Some(("pmfhl.lh", Form::Rd)),
        0x108 => Some(("paddh", Form::RdRsRt)),
        0x109 => Some(("pmsubw", Form::RdRsRt)),
        0x128 => Some(("padsbh", Form::RdRsRt)),
        0x130 => Some(("pmfhl.sh", Form::Rd)),
        0x148 => Some(("psubh", Form::RdRsRt)),
        0x168 => Some(("pabsh", Form::RdRt)),
        0x188 => Some(("pcgth", Form::RdRsRt)),
        0x1a8 => Some(("pceqh", Form::RdRsRt)),
        0x1c8 => Some(("pmaxh", Form::RdRsRt)),
        0x1e8 => Some(("pminh", Form::RdRsRt)),
        0x208 => Some(("paddb", Form::RdRsRt)),
        0x209 => Some(("pmfhi", Form::Rd)),
        0x229 => Some(("pmthi", Form::Rs)),
        0x248 => Some(("psubb", Form::RdRsRt)),
        0x249 => Some(("pmflo", Form::Rd)),
        0x269 => Some(("pmtlo", Form::Rs)),
        0x288 => Some(("pcgtb", Form::RdRsRt)),
        0x289 => Some(("pinth", Form::RdRsRt)),
        0x2a8 => Some(("pceqb", Form::RdRsRt)),
        0x2a9 => Some(("pinteh", Form::RdRsRt)),
        0x309 => Some(("pmultw", Form::RdRsRt)),
        0x329 => Some(("pmultuw", Form::RdRsRt)),
        0x349 => Some(("pdivw", Form::RsRt)),
        0x369 => Some(("pdivuw", Form::RsRt)),
        0x389 => Some(("pcpyld", Form::RdRsRt)),
        0x3a9 => Some(("pcpyud", Form::RdRsRt)),
        0x408 => Some(("paddsw", Form::RdRsRt)),
        0x409 => Some(("pmaddh", Form::RdRsRt)),
        0x428 => Some(("padduw", Form::RdRsRt)),
        0x448 => Some(("psubsw", Form::RdRsRt)),
        0x449 => Some(("phmadh", Form::RdRsRt)),
        0x468 => Some(("psubuw", Form::RdRsRt)),
        0x488 => Some(("pextlw", Form::RdRsRt)),
        0x489 => Some(("pand", Form::RdRsRt)),
        0x4a8 => Some(("pextuw", Form::RdRsRt)),
        0x4a9 => Some(("por", Form::RdRsRt)),
        0x4c8 => Some(("ppacw", Form::RdRsRt)),
        0x4c9 => Some(("pxor", Form::RdRsRt)),
        0x4e9 => Some(("pnor", Form::RdRsRt)),
        0x508 => Some(("paddsh", Form::RdRsRt)),
        0x509 => Some(("pmsubh", Form::RdRsRt)),
        0x528 => Some(("padduh", Form::RdRsRt)),
        0x548 => Some(("psubsh", Form::RdRsRt)),
        0x549 => Some(("phmsbh", Form::RdRsRt)),
        0x568 => Some(("psubuh", Form::RdRsRt)),
        0x588 => Some(("pextlh", Form::RdRsRt)),
        0x5a8 => Some(("pextuh", Form::RdRsRt)),
        0x5c8 => Some(("ppach", Form::RdRsRt)),
        0x608 => Some(("paddsb", Form::RdRsRt)),
        0x628 => Some(("paddub", Form::RdRsRt)),
        0x648 => Some(("psubsb", Form::RdRsRt)),
        0x668 => Some(("psubub", Form::RdRsRt)),
        0x688 => Some(("pextlb", Form::RdRsRt)),
        0x689 => Some(("pexeh", Form::RdRt)),
        0x6a8 => Some(("pextub", Form::RdRsRt)),
        0x6a9 => Some(("pexch", Form::RdRt)),
        0x6c8 => Some(("ppacb", Form::RdRsRt)),
        0x6c9 => Some(("prevh", Form::RdRt)),
        0x6e8 => Some(("qfsrv", Form::RdRsRt)),
        0x6e9 => Some(("pcpyh", Form::RdRt)),
        0x709 => Some(("pmulth", Form::RdRsRt)),
        0x749 => Some(("pdivbw", Form::RsRt)),
        0x788 => Some(("pext5", Form::RdRt)),
        0x789 => Some(("pexew", Form::RdRt)),
        0x7a9 => Some(("pexcw", Form::RdRt)),
        0x7c8 => Some(("ppac5", Form::RdRt)),
        0x7c9 => Some(("prot3w", Form::RdRt)),
        0x7f4 => Some(("psllh", Form::RdRtSa)),
        0x7f6 => Some(("psrlh", Form::RdRtSa)),
        0x7f7 => Some(("psrah", Form::RdRtSa)),
        0x7fc => Some(("psllw", Form::RdRtSa)),
        0x7fe => Some(("psrlw", Form::RdRtSa)),
        0x7ff => Some(("psraw", Form::RdRtSa)),
        _ => None,
    }
}

/// VU0 "CT" and integer-space mnemonics, indexed by (co, func).
///
/// Derived from the reference disassembler's `r5900@c2` expectations, which
/// enumerate the whole space; see `tools/gen_isa_tables.py`.
/// Every entry is a verified (encoding, disassembly) pair from binutils'
/// `r5900@c2` conformance corpus; sub-fields that change the *operands*
/// (destination masks, broadcast, `i:`/`r:` conditions) are not modelled,
/// so callers see `Flags::PARTIAL`.
pub(crate) fn vu0_entry(co: u32, func: u32) -> Option<&'static str> {
    match (co, func) {
        (0x10, 0x00) => Some("vaddx."),
        (0x10, 0x01) => Some("vaddy."),
        (0x10, 0x02) => Some("vaddz."),
        (0x10, 0x03) => Some("vaddw."),
        (0x10, 0x04) => Some("vsubx."),
        (0x10, 0x05) => Some("vsuby."),
        (0x10, 0x06) => Some("vsubz."),
        (0x10, 0x07) => Some("vsubw."),
        (0x10, 0x08) => Some("vmaddx."),
        (0x10, 0x09) => Some("vmaddy."),
        (0x10, 0x0a) => Some("vmaddz."),
        (0x10, 0x0b) => Some("vmaddw."),
        (0x10, 0x0c) => Some("vmsubx."),
        (0x10, 0x0d) => Some("vmsuby."),
        (0x10, 0x0e) => Some("vmsubz."),
        (0x10, 0x0f) => Some("vmsubw."),
        (0x10, 0x10) => Some("vmaxx."),
        (0x10, 0x11) => Some("vmaxy."),
        (0x10, 0x12) => Some("vmaxz."),
        (0x10, 0x13) => Some("vmaxw."),
        (0x10, 0x14) => Some("vminix."),
        (0x10, 0x15) => Some("vminiy."),
        (0x10, 0x16) => Some("vminiz."),
        (0x10, 0x17) => Some("vminiw."),
        (0x10, 0x18) => Some("vmulx."),
        (0x10, 0x19) => Some("vmuly."),
        (0x10, 0x1a) => Some("vmulz."),
        (0x10, 0x1b) => Some("vmulw."),
        (0x10, 0x1c) => Some("vmulq."),
        (0x10, 0x1d) => Some("vmaxi."),
        (0x10, 0x1e) => Some("vmuli."),
        (0x10, 0x1f) => Some("vminii."),
        (0x10, 0x20) => Some("vaddq."),
        (0x10, 0x21) => Some("vmaddq."),
        (0x10, 0x22) => Some("vaddi."),
        (0x10, 0x23) => Some("vmaddi."),
        (0x10, 0x24) => Some("vsubq."),
        (0x10, 0x25) => Some("vmsubq."),
        (0x10, 0x26) => Some("vsubi."),
        (0x10, 0x27) => Some("vmsubi."),
        (0x10, 0x28) => Some("vadd."),
        (0x10, 0x29) => Some("vmadd."),
        (0x10, 0x2a) => Some("vmul."),
        (0x10, 0x2b) => Some("vmax."),
        (0x10, 0x2c) => Some("vsub."),
        (0x10, 0x2d) => Some("vmsub."),
        (0x10, 0x2f) => Some("vmini."),
        (0x10, 0x30) => Some("viadd"),
        (0x10, 0x31) => Some("visub"),
        (0x10, 0x32) => Some("viaddi"),
        (0x10, 0x34) => Some("viand"),
        (0x10, 0x35) => Some("vior"),
        (0x10, 0x38) => Some("vcallms"),
        (0x10, 0x39) => Some("vcallmsr"),
        (0x10, 0x3c) => Some("vaddax."),
        (0x10, 0x3d) => Some("vadday."),
        (0x10, 0x3e) => Some("vaddaz."),
        (0x10, 0x3f) => Some("vaddaw."),
        (0x18, 0x00) => Some("vaddx.x"),
        (0x18, 0x01) => Some("vaddy.x"),
        (0x18, 0x02) => Some("vaddz.x"),
        (0x18, 0x03) => Some("vaddw.x"),
        (0x18, 0x04) => Some("vsubx.x"),
        (0x18, 0x05) => Some("vsuby.x"),
        (0x18, 0x06) => Some("vsubz.x"),
        (0x18, 0x07) => Some("vsubw.x"),
        (0x18, 0x08) => Some("vmaddx.x"),
        (0x18, 0x09) => Some("vmaddy.x"),
        (0x18, 0x0a) => Some("vmaddz.x"),
        (0x18, 0x0b) => Some("vmaddw.x"),
        (0x18, 0x0c) => Some("vmsubx.x"),
        (0x18, 0x0d) => Some("vmsuby.x"),
        (0x18, 0x0e) => Some("vmsubz.x"),
        (0x18, 0x0f) => Some("vmsubw.x"),
        (0x18, 0x10) => Some("vmaxx.x"),
        (0x18, 0x11) => Some("vmaxy.x"),
        (0x18, 0x12) => Some("vmaxz.x"),
        (0x18, 0x13) => Some("vmaxw.x"),
        (0x18, 0x14) => Some("vminix.x"),
        (0x18, 0x15) => Some("vminiy.x"),
        (0x18, 0x16) => Some("vminiz.x"),
        (0x18, 0x17) => Some("vminiw.x"),
        (0x18, 0x18) => Some("vmulx.x"),
        (0x18, 0x19) => Some("vmuly.x"),
        (0x18, 0x1a) => Some("vmulz.x"),
        (0x18, 0x1b) => Some("vmulw.x"),
        (0x18, 0x1c) => Some("vmulq.x"),
        (0x18, 0x1d) => Some("vmaxi.x"),
        (0x18, 0x1e) => Some("vmuli.x"),
        (0x18, 0x1f) => Some("vminii.x"),
        (0x18, 0x20) => Some("vaddq.x"),
        (0x18, 0x21) => Some("vmaddq.x"),
        (0x18, 0x22) => Some("vaddi.x"),
        (0x18, 0x23) => Some("vmaddi.x"),
        (0x18, 0x24) => Some("vsubq.x"),
        (0x18, 0x25) => Some("vmsubq.x"),
        (0x18, 0x26) => Some("vsubi.x"),
        (0x18, 0x27) => Some("vmsubi.x"),
        (0x18, 0x28) => Some("vadd.x"),
        (0x18, 0x29) => Some("vmadd.x"),
        (0x18, 0x2a) => Some("vmul.x"),
        (0x18, 0x2b) => Some("vmax.x"),
        (0x18, 0x2c) => Some("vsub.x"),
        (0x18, 0x2d) => Some("vmsub.x"),
        (0x18, 0x2f) => Some("vmini.x"),
        (0x18, 0x3c) => Some("vaddax.x"),
        (0x18, 0x3d) => Some("vadday.x"),
        (0x18, 0x3e) => Some("vaddaz.x"),
        (0x18, 0x3f) => Some("vaddaw.x"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ins(raw: u32) -> Insn {
        decode(0x1000_0000, raw, &DecodeOptions::raw())
    }

    #[test]
    fn imm_helpers_agree_with_the_field_accessors() {
        let raw = 0x2402_0008u32; // addiu $v0,$zero,8
        assert_eq!(f_imm(raw), 8);
        assert_eq!(f_rs(raw), 0);
        assert_eq!(f_rt(raw), 2);
        assert_eq!(bits(raw, 26, 6), 0x09);
        // A -1 immediate sign-extends but the zero-extended view stays 0xffff.
        assert_eq!(f_imm(0x2402_ffff), -1);
        assert_eq!(0x2402_ffffu32 as u16 as u32, 0xffff);
    }

    #[test]
    fn branch_target_wraps_instead_of_panicking() {
        // b -0x8000 from address 0: the target must wrap, not overflow-panic.
        let i = decode(0x0, 0x1000_fffe, &DecodeOptions::raw());
        assert_eq!(i.target, 4 + (-2i64 << 2) as u32);
    }

    #[test]
    fn shift_mmi_retry() {
        assert_eq!(ins(0x701f_07fc).name, "psllw");
        assert_eq!(ins(0x7000_f834).name, "psllh");
        // A code that is not a shift and not in the table stays unknown.
        assert_eq!(ins(0x701f_0002).name, "mmi?");
    }

    #[test]
    fn cop0_reg25_selectors() {
        assert_eq!(ins(0x4000_c800).name, "mfps");
        assert_eq!(ins(0x401f_c801).name, "mfpc");
        assert_eq!(ins(0x4000_c803).name, "mfpc");
        assert_eq!(ins(0x4000_c803).sel, 1);
        assert_eq!(ins(0x4080_c802).name, "mtps");
        assert_eq!(ins(0x4080_c802).sel, 1);
        // bits above the selector mean this is not a known MOV
        assert_eq!(ins(0x4000_c808).name, "mfc0");
    }

    #[test]
    fn ei_and_di_are_not_swapped() {
        assert_eq!(ins(0x4200_0038).name, "ei");
        assert_eq!(ins(0x4200_0039).name, "di");
    }

    #[test]
    fn vu0_names_are_partial_not_unknown() {
        let i = ins(0x4a00_0000);
        assert_eq!(i.name, "vaddx.");
        assert!(i.flags.contains(Flags::PARTIAL));
        assert!(!i.flags.contains(Flags::UNKNOWN));
    }
}
