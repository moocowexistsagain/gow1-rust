//! Register naming tables for the MIPS R5900 "Emotion Engine".
//!
//! The PS2's main CPU is a 128-bit MIPS IV variant: the 32-bit integer
//! registers are MIPS-standard, but the coprocessor spaces differ from a normal
//! R4x00 — COP0 carries EE-specific debug/performance registers and COP2 is the
//! VU0 control / MMI space.
//!
//! Two naming conventions are supported because decompilation projects need
//! both: `$0`-style numeric names (unambiguous, what IDA/Ghidra default to) and
//! the MIPS ABI names used by the SN Systems / GCC toolchains that the
//! SNR98 assembler expects when re-building for byte matching.

/// GPR names in the O32/ABI convention used by the PS2 SDKs.
pub const GPR_ABI: [&str; 32] = [
    "zero", "at", "v0", "v1", "a0", "a1", "a2", "a3", "t0", "t1", "t2", "t3", "t4", "t5", "t6",
    "t7", "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "t8", "t9", "k0", "k1", "gp", "sp", "fp",
    "ra",
];

/// Register numbers that carry structural meaning when recovering a function.
pub const GPR_ZERO: u32 = 0;
pub const GPR_AT: u32 = 1;
pub const GPR_SP: u32 = 29;
pub const GPR_FP: u32 = 30;
pub const GPR_RA: u32 = 31;
/// `$gp`, the global pointer. SN Systems builds position-independent data
/// access through it, so `lw $rt, offset($28)` maps to a global variable.
pub const GPR_GP: u32 = 28;

pub fn gpr(n: u32, numeric: bool) -> String {
    let n = n & 31;
    if numeric {
        format!("${n}")
    } else {
        format!("${}", GPR_ABI[n as usize])
    }
}

pub fn fpr(n: u32) -> String {
    format!("$f{}", n & 31)
}

/// COP0 register names for the Emotion Engine.
///
/// The EE reuses the MIPS COP0 slots for its own debug and performance
/// counters; entries we have not confirmed against a disassembly are given by
/// number so the output never claims a wrong name.
pub fn cop0_reg(n: u32) -> String {
    let name = match n & 31 {
        0 => Some("BPC"),
        1 => Some("BDA"),
        2 => Some("BDAM"),
        3 => Some("BPCS"),
        4 => Some("BDDBC"),
        5 => Some("BDIB"),
        6 => Some("BDIM"),
        7 => Some("SPE3"),
        8 => Some("SPE4"),
        12 => Some("SR"),
        13 => Some("CAUSE"),
        14 => Some("EPC"),
        15 => Some("PRID"),
        16 => Some("TAGLO"),
        17 => Some("DMAS3"),
        18 => Some("CACHE3"),
        19 => Some("FCPU3"),
        20 => Some("CFCU0"),
        23 => Some("CFCU3"),
        24 => Some("BADV2"),
        25 => Some("JMP_DEBUG"),
        26 => Some("COUNT"),
        27 => Some("COMPARE"),
        _ => None,
    };
    match name {
        Some(s) => format!("${s}"),
        None => format!("$c{n}"),
    }
}

/// COP2 (VU0 control / MMI) register names.
///
/// Only the slots that are stable across every PS2 toolchain are named; the
/// rest print as `$cN` because a mislabeled VU0 control register is worse for a
/// decompilation than an explicit number.
pub fn cop2_reg(n: u32) -> String {
    let name = match n & 31 {
        0 => Some("VI"),
        1 => Some("VF0"),
        2 => Some("VFACC"),
        3 => Some("VFI"),
        4 => Some("VFK"),
        5 => Some("VFP"),
        6 => Some("VFG"),
        8 => Some("VCF0"),
        16 => Some("VC0"),
        17 => Some("VC1"),
        20 => Some("VCE0"),
        21 => Some("VCE1"),
        28 => Some("VCF1"),
        _ => None,
    };
    match name {
        Some(s) => format!("${s}"),
        None => format!("$c{n}"),
    }
}

/// MMI accumulator (`$ac0`/`$ac1`) selectors used by MADD/MADDU/MULT/DIV.
pub fn mmi_acc(sel: u32) -> &'static str {
    match sel & 3 {
        2 => "$ac0",
        3 => "$ac1",
        _ => "$hi/$lo",
    }
}
