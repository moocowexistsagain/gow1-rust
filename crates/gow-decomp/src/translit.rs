//! Instruction-by-instruction transliteration into Rust statements.
//!
//! This is *not* a decompiler: there is no SSA, no type inference and no
//! control-flow structuring. It is a faithful, mechanically generated "what
//! this machine code does" sketch that a human (or an agent) uses as the source
//! material for the real Rust function. Two properties matter:
//!
//! * **Never invent semantics.** Anything not modelled becomes a `// 0xADDR: raw`
//!   comment line, so nothing can be silently mistranslated.
//! * **Delay slots stay visible.** MIPS executes the instruction after a branch
//!   unconditionally, which is the single most common source of mistranslation in
//!   naive PS2 decompilations, so every branch is emitted together with its slot.

use ee_isa::{Flags, Insn};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Style {
    /// `$v0`, `$a0`, ... (ABI names) — reads well, matches the SDK.
    Abi,
    /// `$2`, `$29` — unambiguous, what the listings use.
    Numeric,
}

/// Register variable name inside generated Rust (`v0`, `a3`, `sp`).
#[must_use]
pub fn local(n: u32, style: Style) -> String {
    match style {
        Style::Abi => ee_isa::GPR_ABI[n as usize & 31].to_string(),
        Style::Numeric => format!("r{n}"),
    }
}

/// FPU register variable name.
#[must_use]
pub fn flocal(n: u32) -> String {
    format!("f{}", n & 31)
}

#[must_use]
pub fn decls(style: Style) -> String {
    let mut out = String::new();
    out.push_str("    // Machine state, one Rust local per register. These are\n");
    out.push_str("    // scaffolding for the rewrite, not part of the recovered API.\n");
    out.push_str("    let mut zero: u32 = 0;\n");
    for i in 1..32u32 {
        out.push_str(&format!("    let mut {} : u32 = 0;\n", local(i, style)));
    }
    for i in 0..32u32 {
        out.push_str(&format!("    let mut {} : f32 = 0.0;\n", flocal(i)));
    }
    out.push_str("    let mut hi: u32 = 0;\n    let mut lo: u32 = 0;\n");
    out.push_str("    let mut acc1_hi: u32 = 0;\n    let mut acc1_lo: u32 = 0;\n");
    out
}

/// Transliterate one instruction into Rust statements. `None` means "leave it
/// as a raw comment" — never invent a translation.
///
/// The generated statements address memory through integer register values, so
/// they are a faithful model of what the machine does (and a useful checklist),
/// not safe Rust. That is why they live in a `.rs.txt` sketch rather than in the
/// compilable stub.
pub fn transliterate(ins: &Insn, style: Style) -> Option<Vec<String>> {
    let g = |n: u32| local(n, style);
    let f = |n: u32| flocal(n);
    let imm = ins.imm;
    let u = ins.uimm;
    // A signed immediate as a Rust literal: `-32` stays `-32` rather than
    // becoming a 64-bit two's-complement blob.
    let lit = |v: i64| format!("{v}");
    let ulit = |v: u32| format!("{v:#x}");
    let assign = |dst: u32, expr: String| -> Vec<String> {
        if dst == 0 {
            vec![format!("// {expr}  (result discarded: writes $zero)")]
        } else {
            vec![format!("let {} = {expr};", g(dst))]
        }
    };
    // Same as `assign`, but with a register-file prefix (`mm` for the 128-bit
    // MM registers, which share numbering with the GPRs).
    let assign_dummy = |dst: u32, expr: String, prefix: &str| -> Vec<String> {
        if dst == 0 {
            vec![format!("// {expr}  (result discarded: writes {prefix}0)")]
        } else {
            vec![format!("let {prefix}{dst} = {expr};")]
        }
    };
    let addr = |base: u32, off: i32| -> String {
        let b = g(base);
        match off {
            0 => b,
            off if off > 0 => format!("{b} + {off}"),
            off => format!("{b} - {}", -off),
        }
    };

    // ---- control flow: branches carry their delay slot in the sketch ----
    if ins.flags.contains(Flags::BRANCH) {
        let target = format!("goto L_{:08x}", ins.target);
        let cond = match (ins.name, ins.rs, ins.rt) {
            ("beq", a, b) | ("beql", a, b) => Some(format!("{} == {}", g(a), g(b))),
            ("bne", a, b) | ("bnel", a, b) => Some(format!("{} != {}", g(a), g(b))),
            ("blez", a, _) | ("blezl", a, _) => Some(format!("({} as i32) <= 0", g(a))),
            ("bgtz", _, b) | ("bgtzl", _, b) => Some(format!("({} as i32) > 0", g(b))),
            ("bltz", a, _) | ("bltzal", a, _) => Some(format!("({} as i32) < 0", g(a))),
            ("bgez", a, _) | ("bgezal", a, _) => Some(format!("({} as i32) >= 0", g(a))),
            _ => None,
        };
        return Some(match cond {
            Some(c) => vec![format!("if {c} {{ {target}; }}")],
            None => vec![format!(
                "// {target}   // condition `{}` not modelled",
                ins.name
            )],
        });
    }
    if ins.name == "j" || ins.name == "b" {
        return Some(vec![format!("goto L_{:08x};", ins.target)]);
    }
    if ins.name == "jal" {
        let callee = crate::naming::rust_fn_name(&format!("f_{:08x}", ins.target));
        return Some(vec![
            format!("// call {:#010x}", ins.target),
            format!("let v0 = {callee}(a0, a1, a2, a3);"),
        ]);
    }
    if ins.name == "jr" {
        if ins.rs == 31 {
            return Some(vec!["return v0;".to_string()]);
        }
        return Some(vec![format!(
            "// indirect jump through {} (switch or vtable)",
            g(ins.rs)
        )]);
    }
    if ins.name == "jalr" {
        let dst = if ins.rd == 0 {
            "_".to_string()
        } else {
            g(ins.rd)
        };
        return Some(vec![format!("let {dst} = {}(a0, a1, a2, a3);", g(ins.rs))]);
    }

    // ---- memory ----
    if let Some((_base, off)) = ins.memory_operand() {
        let a = addr(ins.rs, off);
        let (load_ty, store_ty, wide) = match ins.name {
            "lb" => ("i8", "u8", false),
            "lbu" => ("u8", "u8", false),
            "lh" => ("i16", "u16", false),
            "lhu" => ("u16", "u16", false),
            "lq" => ("u128", "u128", true),
            "sq" => ("u128", "u128", true),
            "lwc1" | "swc1" => ("f32", "f32", false),
            "ldc1" | "sdc1" => ("f64", "f64", false),
            _ => ("u32", "u32", false),
        };
        if ins.flags.contains(Flags::STORE) {
            let src = if ins.name.ends_with("c1") {
                f(ins.rt)
            } else if wide {
                format!("mm{}", ins.rt)
            } else {
                g(ins.rt)
            };
            return Some(vec![format!("*(({a}) as *mut {store_ty}) = {src};")]);
        }
        let expr = format!("*(({a}) as *const {load_ty})");
        if ins.name.ends_with('1') && ins.name.starts_with('l') {
            return Some(vec![format!("{} = {expr};", f(ins.rt))]);
        }
        if wide {
            return Some(assign_dummy(ins.rt, expr, "mm"));
        }
        return Some(assign(ins.rt, expr));
    }

    // ---- integer ALU ----
    let add_s = |a: String, b: String| format!("{a}.wrapping_add({b})");
    let sub_s = |a: String, b: String| format!("{a}.wrapping_sub({b})");
    match ins.name {
        "nop" => return Some(vec!["/* nop (delay slot or padding) */".to_string()]),
        "li" => return Some(assign(ins.rt, ulit(u))),
        "move" => return Some(assign(ins.rd, g(ins.rs))),
        "addu" | "add" => return Some(assign(ins.rd, add_s(g(ins.rs), g(ins.rt)))),
        "subu" | "sub" => return Some(assign(ins.rd, sub_s(g(ins.rs), g(ins.rt)))),
        "and" => return Some(assign(ins.rd, format!("{} & {}", g(ins.rs), g(ins.rt)))),
        "or" => return Some(assign(ins.rd, format!("{} | {}", g(ins.rs), g(ins.rt)))),
        "xor" => return Some(assign(ins.rd, format!("{} ^ {}", g(ins.rs), g(ins.rt)))),
        "nor" => return Some(assign(ins.rd, format!("!({} | {})", g(ins.rs), g(ins.rt)))),
        "sll" => return Some(assign(ins.rd, format!("{} << {:#x}", g(ins.rt), ins.sa))),
        "srl" => return Some(assign(ins.rd, format!("{} >> {:#x}", g(ins.rt), ins.sa))),
        "sra" => {
            return Some(assign(
                ins.rd,
                format!("(({} as i32) >> {:#x}) as u32", g(ins.rt), ins.sa),
            ))
        }
        "sllv" => {
            return Some(assign(
                ins.rd,
                format!("{} << ({} & 31)", g(ins.rt), g(ins.rs)),
            ))
        }
        "srlv" => {
            return Some(assign(
                ins.rd,
                format!("{} >> ({} & 31)", g(ins.rt), g(ins.rs)),
            ))
        }
        "srav" => {
            return Some(assign(
                ins.rd,
                format!("(({} as i32) >> ({} & 31)) as u32", g(ins.rt), g(ins.rs)),
            ))
        }
        "addiu" | "addi" => return Some(assign(ins.rt, add_s(g(ins.rs), lit(imm as i64)))),
        "ori" => return Some(assign(ins.rt, format!("{} | {}", g(ins.rs), ulit(u)))),
        "andi" => return Some(assign(ins.rt, format!("{} & {}", g(ins.rs), ulit(u)))),
        "xori" => return Some(assign(ins.rt, format!("{} ^ {}", g(ins.rs), ulit(u)))),
        "lui" => return Some(assign(ins.rt, format!("{} << 16", ulit(u)))),
        "slti" => {
            return Some(assign(
                ins.rt,
                format!("(({} as i32) < {imm}) as u32", g(ins.rs)),
            ))
        }
        "sltiu" => return Some(assign(ins.rt, format!("({} < {:#x}) as u32", g(ins.rs), u))),
        "slt" => {
            return Some(assign(
                ins.rd,
                format!("(({} as i32) < ({} as i32)) as u32", g(ins.rs), g(ins.rt)),
            ))
        }
        "sltu" => {
            return Some(assign(
                ins.rd,
                format!("({} < {}) as u32", g(ins.rs), g(ins.rt)),
            ))
        }
        "movn" | "movz" => {
            let test = if ins.name == "movn" { "!= 0" } else { "== 0" };
            return Some(vec![format!(
                "if {} {test} {{ {} = {}; }}",
                g(ins.rt),
                g(ins.rd),
                g(ins.rs)
            )]);
        }
        "mfhi" => return Some(assign(ins.rd, "hi".to_string())),
        "mflo" => return Some(assign(ins.rd, "lo".to_string())),
        "mthi" => return Some(vec![format!("hi = {};", g(ins.rs))]),
        "mtlo" => return Some(vec![format!("lo = {};", g(ins.rs))]),
        "mult" | "multu" => {
            return Some(vec![
                format!(
                    "let prod: u64 = ({} as u64).wrapping_mul({} as u64);",
                    g(ins.rs),
                    g(ins.rt)
                ),
                "lo = prod as u32; hi = (prod >> 32) as u32;".to_string(),
            ])
        }
        "div" | "divu" => {
            let cast = if ins.name == "div" { " as i32" } else { "" };
            return Some(vec![
                format!("if {} != 0 {{", g(ins.rt)),
                format!(
                    "    lo = ({}{cast} / {}{cast}) as u32;",
                    g(ins.rs),
                    g(ins.rt)
                ),
                format!(
                    "    hi = ({}{cast} % {}{cast}) as u32;",
                    g(ins.rs),
                    g(ins.rt)
                ),
                "}".to_string(),
            ]);
        }
        "syscall" | "break" => return Some(vec![format!("// {} 0x{u:x}", ins.name)]),
        _ => {}
    }
    if ins.flags.contains(Flags::FLOAT) || ins.flags.contains(Flags::MMI) {
        // Scalar FPU and packed MMI ops need a vector/float model that the
        // recovered Rust defines by hand; show them, do not fake them.
        return Some(vec![format!(
            "// {}",
            ins.text(&ee_isa::DecodeOptions::listing())
        )]);
    }
    None
}

/// Sketch of the whole function body, as Rust-flavoured pseudo-code. Returned
/// as lines so callers can prefix addresses.
pub fn sketch(insns: &[Insn], style: Style) -> Vec<(u32, Vec<String>)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < insns.len() {
        let ins = &insns[i];
        let mut lines = match transliterate(ins, style) {
            Some(l) => l,
            None => vec![format!("// untranslated: {:08x}", ins.raw)],
        };
        // Fold the delay slot into the branch so its unconditional execution is
        // impossible to miss while reading.
        if ins.has_delay_slot() {
            if let Some(d) = insns.get(i + 1) {
                let dl = transliterate(d, style)
                    .unwrap_or_else(|| vec![format!("// untranslated: {:08x}", d.raw)]);
                lines.push(format!("// [delay slot] {}", dl.join(" ")));
                i += 1;
            }
        }
        out.push((ins.addr, lines));
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ee_isa::{decode, DecodeOptions};

    /// Build an R-type word.
    const fn r(op: u32, rs: u32, rt: u32, rd: u32, sa: u32, func: u32) -> u32 {
        (op << 26) | (rs << 21) | (rt << 16) | (rd << 11) | (sa << 6) | func
    }
    /// Build an I-type word.
    const fn i(op: u32, rs: u32, rt: u32, imm: u16) -> u32 {
        (op << 26) | (rs << 21) | (rt << 16) | imm as u32
    }

    fn t(raw: u32) -> Vec<String> {
        let ins = decode(0x1000, raw, &DecodeOptions::raw());
        transliterate(&ins, Style::Abi).unwrap_or_default()
    }
    fn one(raw: u32) -> String {
        t(raw).join(" | ")
    }

    #[test]
    fn arithmetic_uses_wrapping_methods_not_infix() {
        assert_eq!(
            one(r(0x00, 4, 5, 2, 0, 0x21)),
            "let v0 = a0.wrapping_add(a1);"
        );
        assert_eq!(
            one(r(0x00, 4, 5, 2, 0, 0x23)),
            "let v0 = a0.wrapping_sub(a1);"
        );
        assert_eq!(
            one(i(0x09, 29, 29, (-32i16) as u16)),
            "let sp = sp.wrapping_add(-32);"
        );
        assert_eq!(one(i(0x0f, 0, 2, 0x1234)), "let v0 = 0x1234 << 16;");
        assert_eq!(one(r(0x00, 4, 5, 2, 0, 0x24)), "let v0 = a0 & a1;");
        // shifts read `rt`, not `rs` -- the classic MIPS asymmetry.
        assert_eq!(one(r(0x00, 2, 3, 4, 7, 0x00)), "let a0 = v1 << 0x7;");
    }

    #[test]
    fn loads_and_stores_keep_the_displacement_visible() {
        assert_eq!(
            one(i(0x23, 29, 2, 8)),
            "let v0 = *((sp + 8) as *const u32);"
        );
        assert_eq!(
            one(i(0x2b, 29, 2, (-8i16) as u16)),
            "*((sp - 8) as *mut u32) = v0;"
        );
        assert_eq!(one(i(0x20, 4, 3, 1)), "let v1 = *((a0 + 1) as *const i8);");
        // `lq`/`sq` name the MM register file, which is numbered like the GPRs.
        assert_eq!(
            one(i(0x1e, 29, 2, 32)),
            "let mm2 = *((sp + 32) as *const u128);"
        );
    }

    #[test]
    fn writes_to_zero_become_comments() {
        assert_eq!(
            one(r(0x00, 0, 0, 0, 0, 0x00)),
            "// zero << 0x0  (result discarded: writes $zero)"
        );
    }

    #[test]
    fn branches_carry_their_target() {
        let line = one(i(0x04, 5, 3, (-2i16) as u16));
        assert_eq!(line, "if a1 == v1 { goto L_00000ffc; }", "{line}");
    }

    #[test]
    fn mmi_and_fpu_are_shown_not_faked() {
        // pand $v0,$a0,$a1 / add.s $f2,$f0,$f1
        assert!(
            one(0x701f_0489).starts_with("// pand"),
            "{}",
            one(0x701f_0489)
        );
        let adds = one(0x4603_1040);
        assert!(adds.starts_with("// add.s"), "{adds}");
    }

    #[test]
    fn division_guards_the_zero_divider() {
        let lines = t(r(0x00, 4, 5, 0, 0, 0x1a));
        assert_eq!(lines.len(), 4, "{lines:?}");
        assert!(lines[0].contains("if a1 != 0"), "{lines:?}");
        assert!(
            lines[1].contains("lo = (a0 as i32 / a1 as i32) as u32;"),
            "{lines:?}"
        );
    }

    #[test]
    fn untranslated_instructions_stay_as_addresses() {
        // A word with no modelled translation must not vanish from the sketch.
        let lines = t(0x701f_07fc); // psllw, MMI shift: modelled as a comment
        assert_eq!(lines.len(), 1);
        assert!(lines[0].starts_with("// psllw"), "{lines:?}");
    }
}
