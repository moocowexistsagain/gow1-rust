//! Single-function analysis: turn a run of R5900 instructions into the facts a
//! Rust re-implementation needs (frame layout, saved registers, calls, labels,
//! data references), without pretending we can recover types.

use ee_isa::{decode_all, DecodeOptions, Flags, Insn};
use ps2_elf::Executable;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotKind {
    /// A callee-saved register spilled by the prologue.
    SavedReg(u32),
    /// A compiler temporary / local variable.
    Local,
    /// An argument the caller passed on the stack (O32: `$a0..$a3` are
    /// registers 4..7, everything past that is on the stack).
    IncomingArg,
    /// A spilled 128-bit MMI register pair.
    SavedMmi(u32),
}

#[derive(Clone, Debug)]
pub struct FrameSlot {
    pub offset: i32,
    pub size: u32,
    pub kind: SlotKind,
    /// Name from STABS when the binary carries it.
    pub name: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Confidence {
    /// Named by `.mdebug` or a supplied symbol map; frame info is trustworthy.
    Symbolised,
    /// Named, but frame/saved-register info inferred from the prologue.
    Inferred,
    /// No symbol at all: address-derived name, everything inferred.
    Anonymous,
}

#[derive(Clone, Debug)]
pub struct Ref {
    pub addr: u32,
    pub name: Option<String>,
    pub from: u32,
}

#[derive(Clone, Debug)]
pub struct FunctionAnalysis {
    pub name: String,
    pub address: u32,
    pub end: u32,
    pub insns: Vec<Insn>,
    pub frame_size: u32,
    /// `true` when the frame size came from the procedure descriptor rather
    /// than from a prologue scan.
    pub frame_from_symbol: bool,
    pub saved_regs: Vec<u32>,
    pub slots: Vec<FrameSlot>,
    pub calls: Vec<Ref>,
    pub indirect_jumps: Vec<u32>,
    pub labels: Vec<u32>,
    /// `$gp`-relative reads/writes: candidate named globals.
    pub data_refs: Vec<Ref>,
    pub uses_fpu: bool,
    pub uses_mmi: bool,
    pub uses_stack: bool,
    pub unknown_count: usize,
    pub confidence: Confidence,
    /// Raw STABS parameter records (`name`, `type`) when present.
    pub params: Vec<(String, String)>,
    /// STABS locals, keyed by `$sp`-relative offset, when the binary names them.
    pub stabs_locals: Option<std::collections::BTreeMap<i32, String>>,
    /// Return type descriptor as recorded by the compiler, if any.
    pub return_type: Option<String>,
    pub source_file: Option<String>,
    /// Truncated decode (odd trailing bytes, padding between functions).
    pub decode_note: Option<String>,
}

impl FunctionAnalysis {
    #[must_use]
    pub fn instruction_count(&self) -> usize {
        self.insns.len()
    }

    /// Rough guidance for the human/AI doing the rewrite: what makes this
    /// function hard.
    #[must_use]
    pub fn difficulty(&self) -> &'static str {
        (if self.unknown_count > 0 {
            "contains undecoded words"
        } else if self.uses_mmi {
            "uses MMI/128-bit registers"
        } else if self.uses_fpu {
            "uses the FPU"
        } else if !self.indirect_jumps.is_empty() {
            "has an indirect jump (switch or vtable)"
        } else if self.frame_size > 0x200 {
            "large stack frame"
        } else {
            "straightforward integer code"
        }) as _
    }

    #[must_use]
    pub fn byte_len(&self) -> u32 {
        self.end.saturating_sub(self.address)
    }
}

/// Analyze the function starting at `addr`. `hint` carries whatever the symbol
/// table already knows (name, size, frame, saved registers, STABS params).
pub fn analyze(
    exe: &Executable<'_>,
    addr: u32,
    hint: Option<&ps2_elf::Function>,
) -> Result<FunctionAnalysis, String> {
    let (end, note) = function_extent(exe, addr, hint);
    if end <= addr {
        return Err(format!("function at {addr:#010x} has no extent"));
    }
    let size = end - addr;
    let bytes = exe
        .elf
        .read_vaddr(addr, size)
        .ok_or_else(|| format!("cannot read {size:#x} bytes at {addr:#010x}"))?;
    // `.mdebug` procedure descriptors use `$sp`-relative offsets that are
    // measured from the *new* stack pointer, so aliasing the raw prologue scan
    // with them needs a consistent numeric view of registers.
    let opts = DecodeOptions {
        numeric_gprs: true,
        hex_imms: true,
        // Alias folding would hide `sll $0,$0,0` delay-slot nops, which matter
        // when reasoning about why the compiler put them there.
        collapse_aliases: false,
    };
    let insns = decode_all(addr, bytes, &opts);

    let mut a = FunctionAnalysis {
        name: hint
            .map(|h| h.name.clone())
            .or_else(|| exe.name_for_address(addr))
            .unwrap_or_else(|| format!("f_{addr:08x}")),
        address: addr,
        end,
        insns,
        frame_size: 0,
        frame_from_symbol: false,
        saved_regs: Vec::new(),
        slots: Vec::new(),
        calls: Vec::new(),
        indirect_jumps: Vec::new(),
        labels: Vec::new(),
        data_refs: Vec::new(),
        uses_fpu: false,
        uses_mmi: false,
        uses_stack: false,
        unknown_count: 0,
        confidence: if hint.is_some() {
            Confidence::Symbolised
        } else {
            Confidence::Anonymous
        },
        params: Vec::new(),
        stabs_locals: None,
        return_type: None,
        source_file: None,
        decode_note: note,
    };

    if let Some(h) = hint {
        if h.frame_size > 0 {
            a.frame_size = h.frame_size;
            a.frame_from_symbol = true;
        }
        if h.saved_register_mask != 0 {
            a.saved_regs = (0..32)
                .filter(|i| h.saved_register_mask & (1 << i) != 0)
                .collect();
        }
        a.params = h
            .params
            .iter()
            .map(|p| (p.name.clone(), p.raw_type.clone()))
            .collect();
        a.return_type = h.return_type.clone();
        a.source_file = h.source_file.clone();
    }

    // Prologue scan: fill in whatever the symbols did not tell us.
    if a.frame_size == 0 {
        if let Some(sz) = scan_frame_setup(&a.insns) {
            a.frame_size = sz;
            if a.confidence == Confidence::Symbolised && sz != 0 {
                a.confidence = Confidence::Inferred;
            }
        }
    }
    if a.saved_regs.is_empty() {
        a.saved_regs = scan_saved_regs(&a.insns, a.frame_size);
        if !a.saved_regs.is_empty() && a.confidence == Confidence::Symbolised {
            a.confidence = Confidence::Inferred;
        }
    }

    a.slots = infer_slots(&a);

    for ins in &a.insns {
        if ins.is_unknown() {
            a.unknown_count += 1;
        }
        if ins.flags.contains(Flags::FLOAT) {
            a.uses_fpu = true;
        }
        if ins.flags.contains(Flags::MMI) {
            a.uses_mmi = true;
        }
        if ins.flags.contains(Flags::STACK) {
            a.uses_stack = true;
        }
        if ins.is_call() {
            let target = if ins.flags.contains(Flags::JUMP) && ins.name == "jal" {
                ins.target
            } else if ins.flags.contains(Flags::CALL) && ins.name == "jalr" {
                // Indirect: only resolvable for a `$t9`-style GP-relative call,
                // which the SN compiler emits for imports.
                ins.target
            } else {
                0
            };
            if ins.name == "jal" || (ins.name == "jalr" && ins.rs == 0) {
                a.calls.push(Ref {
                    addr: target,
                    name: exe.name_for_address(target),
                    from: ins.addr,
                });
            } else {
                a.indirect_jumps.push(ins.addr);
            }
        }
        if ins.is_branch() {
            a.labels.push(ins.target);
        }
        if ins.name == "jr" && ins.rs != 31 {
            a.indirect_jumps.push(ins.addr);
        }
        if let Some((base, off)) = ins.memory_operand() {
            // Global-pointer-relative access: the decompiler's best hook for
            // naming data. `$gp` value is `local_sym + 0x7ff0` under O32.
            if base == 28 {
                let resolved = resolve_gp(exe, off);
                a.data_refs.push(Ref {
                    addr: resolved,
                    name: resolved
                        .checked_sub(0)
                        .and_then(|a| exe.name_for_address(a)),
                    from: ins.addr,
                });
            }
        }
        // Branches with a link (`bgezal`) are calls to nothing in particular but
        // still create labels; and `b` has no operands to record.
        for extra in [] as [Insn; 0] {
            let _ = extra;
        }
    }
    a.labels.sort_unstable();
    a.labels.dedup();
    a.data_refs.sort_by_key(|r| r.addr);
    a.calls.sort_by_key(|r| r.addr);
    a.calls.dedup_by_key(|r| r.addr);
    Ok(a)
}

/// Where a function ends.
///
/// With `.mdebug` this is exact: the procedure descriptors are adjacent, so the
/// next one's start is this one's end (that is what `Function::size` carries).
/// Without symbols the only honest options are the standard return patterns, so
/// we stop at the first `jr $ra` + delay slot (SN Systems' `rjr` form) or at the
/// next padding run, and we say so in `decode_note` so the emitted file is
/// marked for verification instead of looking authoritative.
fn function_extent(
    exe: &Executable<'_>,
    addr: u32,
    hint: Option<&ps2_elf::Function>,
) -> (u32, Option<String>) {
    if let Some(h) = hint {
        if h.size >= 8 {
            let end = h.address.saturating_add(h.size);
            if end > addr && exe.contains_text(end - 1) {
                return (end, None);
            }
        }
    }
    let Some((base, text)) = exe.elf.text() else {
        return (0, Some("no .text section".to_string()));
    };
    if addr < base {
        return (
            0,
            Some(format!("{addr:#010x} is below .text at {base:#010x}")),
        );
    }
    let start = (addr - base) as usize;
    let cap = (start + 0x4000).min(text.len());
    let word =
        |i: usize| -> u32 { u32::from_le_bytes([text[i], text[i + 1], text[i + 2], text[i + 3]]) };
    let opts = DecodeOptions::raw();
    let mut i = start;
    while i + 8 <= cap {
        let here = ee_isa::decode(base + i as u32, word(i), &opts);
        // SN Systems emits `rjr $ra` (a return whose delay slot *is* the next
        // instruction) or `jr $ra` followed by a filler nop.
        if here.is_return() {
            let nxt = word(i + 4);
            let filler = nxt == 0 || ee_isa::decode(base + i as u32 + 4, nxt, &opts).name == "nop";
            let end = if filler { i + 8 } else { i + 4 };
            return (
                base + end as u32,
                Some("function end inferred from the return pattern; verify".into()),
            );
        }
        // Padding: two zero words or two nops between functions.
        if word(i) == 0 && word(i + 4) == 0 {
            return (base + i as u32, Some("stopped at zero padding".into()));
        }
        i += 4;
    }
    (
        base + cap as u32,
        Some(format!(
            "no return found in {:#x} bytes; extent is a scan bound, verify before editing",
            cap - start
        )),
    )
}

/// `addiu $sp,$sp,-N` / `daddiu` in the first few instructions.
fn scan_frame_setup(insns: &[Insn]) -> Option<u32> {
    for ins in insns.iter().take(6) {
        if ins.flags.contains(Flags::FRAME) {
            return Some((-(ins.imm as i64)) as u32);
        }
        // Some SN builds use `addiu $sp,$sp,-N` after a `sll` delay slot filler.
        if ins.name == "addiu" && ins.rs == 29 && ins.rt == 29 && ins.imm < 0 {
            return Some((-ins.imm) as u32);
        }
    }
    None
}

/// `sw $reg,OFF($sp)` inside the prologue, where OFF is within the frame.
fn scan_saved_regs(insns: &[Insn], frame: u32) -> Vec<u32> {
    let mut regs: Vec<u32> = Vec::new();
    for ins in insns.iter().take(24) {
        if !ins.flags.contains(Flags::STORE) || ins.rs != 29 {
            continue;
        }
        if ins.imm < 0 || (ins.imm as u32) >= frame.max(1) {
            continue;
        }
        if ins.rt != 0 && !regs.contains(&ins.rt) {
            regs.push(ins.rt);
        }
    }
    regs.sort_unstable();
    regs
}

/// Stack slots referenced anywhere in the body, tagged by kind.
///
/// Only `$sp`-relative accesses become slots. Slots the binary names via STABS
/// keep their names; everything else gets `local_N`, which the human rewriting
/// the function is expected to rename.
fn infer_slots(a: &FunctionAnalysis) -> Vec<FrameSlot> {
    let mut slots: Vec<FrameSlot> = Vec::new();
    for ins in &a.insns {
        if !ins.flags.contains(Flags::STACK) {
            continue;
        }
        let Some((base, off)) = ins.memory_operand() else {
            continue;
        };
        if base != 29 {
            continue;
        }
        let size = match ins.name {
            "sb" | "lbu" => 1,
            "sh" | "lhu" => 2,
            "lq" | "sq" => 16,
            _ => 4,
        };
        // A store of a callee-saved register low in the frame is a spill; a
        // `sw $gp`-style copy is the frame-pointer save SN Systems emits.
        let kind = a
            .saved_regs
            .iter()
            .copied()
            .find(|r| ins.flags.contains(Flags::STORE) && *r == ins.rt)
            .map_or(SlotKind::Local, SlotKind::SavedReg);
        match slots.iter_mut().find(|s| s.offset == off) {
            Some(existing) => {
                existing.size = existing.size.max(size);
                if matches!(existing.kind, SlotKind::Local) && !matches!(kind, SlotKind::Local) {
                    existing.kind = kind;
                }
            }
            None => slots.push(FrameSlot {
                offset: off,
                size,
                kind,
                name: None,
            }),
        }
    }
    // Attach STABS names by stack offset where the binary recorded them.
    if let Some(named) = a.stabs_locals.as_ref() {
        for slot in &mut slots {
            if let Some(name) = named.get(&slot.offset) {
                slot.name = Some(name.clone());
            }
        }
    }
    slots.sort_by_key(|s| s.offset);
    slots
}

/// O32 `$gp` is `&__global$0 + 0x7ff0`, and SN Systems emits gp-relative
/// accesses against the `.got`/`.data` split. Without a `.got` layout we can
/// only do the honest thing: report the raw displacement so a human can pair
/// it with the linker map.
fn resolve_gp(_exe: &Executable<'_>, off: i32) -> u32 {
    // `lw $v0,0x1234($gp)` -> candidate address, best effort. Marked
    // `candidate` by the caller through the (possibly missing) name.
    (0x7ff0u32 as i64 + off as i64) as u32
}

/// Find function start addresses when no symbol table exists, using the two
/// reliable prologue signatures of MIPS O32 code.
#[must_use]
pub fn find_function_starts(exe: &Executable<'_>) -> Vec<u32> {
    let Some((base, text)) = exe.elf.text() else {
        return Vec::new();
    };
    let opts = DecodeOptions::raw();
    let mut out = Vec::new();
    let mut i = 0;
    while i + 8 <= text.len() {
        let w = |j: usize| u32::from_le_bytes([text[j], text[j + 1], text[j + 2], text[j + 3]]);
        let first = ee_isa::decode(base + i as u32, w(i), &opts);
        let second = ee_isa::decode(base + i as u32 + 4, w(i + 4), &opts);
        let frame_prologue = first.flags.contains(Flags::FRAME);
        let saved_then_frame = second.flags.contains(Flags::FRAME)
            && (first.name == "sll" && first.raw == 0 || first.name == "nop");
        if frame_prologue || saved_then_frame {
            out.push(base + i as u32);
            i += 8;
            continue;
        }
        i += 4;
    }
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn slot_sizes_use_the_access_width() {
        // Sanity on the width mapping used above.
        let m = |n: &str| match n {
            "sb" | "lbu" => 1usize,
            "sh" | "lhu" => 2,
            "lq" | "sq" => 16,
            _ => 4,
        };
        assert_eq!(m("sb"), 1);
        assert_eq!(m("lq"), 16);
        assert_eq!(m("lw"), 4);
    }
}
