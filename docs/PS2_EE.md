# Emotion Engine notes

What the PS2's CPU does that a generic MIPS decoder gets wrong. These are the
facts that shaped `crates/ee-isa`; each one has a test, because each one is a way
to be *silently* wrong.

## The core

The EE's main processor is the R5900: a MIPS IV-family core with a 128-bit
internal data path, running O32 32-bit code in retail games. Registers are the
MIPS 32 GPRs (32-bit as seen by the ABI), a 32-register FPU, and the 128-bit MMI
register file, which is *numbered like the GPR file* and overlaps it. Kernel-mode
64-bit behaviour does not matter for a game executable and is not modelled.

Three coprocessors are in play:

| cop | what | in a retail game |
|---|---|---|
| COP0 | system control | TLB, status, plus EE debug/performance registers |
| COP1 | FPU | single precision `.s`, fixed `.w`/`.l` conversions |
| COP2 | VU0 control + MMI-adjacent state | VU0 control registers, and the VU0 instruction space as "CT" ops |
| `op = 0x1c` | **MMI** | packed 8/16/32/64-bit SIMD, the EE's only integer vector unit in the main core |

## Trap 1: `op = 0x1c` is MMI, not SPECIAL2

On MIPS32, `0x1c` is SPECIAL2 (`mul`, `clz`, `clo`, `madd`, `msub`). On the EE the
same opcode belongs to MMI, and the function code is **11 bits** (`bits[10:0]`),
not 6: the `sa` field is part of the opcode for most instructions.

Consequences, all observed in real R5900 encodings:

- `0x701f0002` is *not* `mul`; the EE has no such instruction there.
- `PADDB` is code `0x208`, `PSUBB` is `0x248`, `PAND` is `0x489`: bit 5 of the
  low 6 and the `sa` bits together select the operation.
- The shift family is the exception: `PSLLW`/`PSRLW`/`PSRAW`/`PSLLH`/`PSRLH`/
  `PSRAH` put the *shift amount* in `bits[10:6]`, so the opcode is only
  `bits[5:0]`. `psllw $0,$31,0x1f` has code `0x7fc`, not `0x03c`, and a decoder
  that keys only on the full 11 bits calls it unknown. `MMI_SHIFT_CODES` in
  `decode.rs` is what fixes that up.

## Trap 2: the FPU's destination is in a different field

For the EE's FPU arithmetic, `$fd` is `bits[10:6]` (the position MIPS calls `sa`)
and `$fs` is `bits[15:11]` (the position MIPS calls `rd`); `$ft` stays at
`bits[20:16]`. `trunc.w.s $f0,$f31` is `4600f824`, where the destination `0`
lives in `bits[10:6]`.

`MFC1`/`MTC1` are *not* affected: the GPR is at `bits[20:16]` and the FPR at
`bits[15:11]` (so `mtc1 $a3,$f9` is `44874800`).

This is the kind of thing that reads as a typo in a listing and then turns into
a swapped-operand bug in recovered code, so the field roles are asserted directly
in `cop1_fpu_field_roles`.

Print *order* is a separate matter: the reference disassembler prints
`madd.s $f0,$f31,$f0` for an encoding whose operands are `$fd=0,$fs=31,$ft=0`,
i.e. it prints the accumulating forms with the sources in a different order than
the field names suggest. `ee-isa` renders the semantic order (`$fd,$fs,$ft`) and
records which field each value came from in `Insn`, so nothing is lost either way.

## Trap 3: `COP0` `$24`/`$25` are overloaded

The EE's debug/performance moves reuse the MFC0/MTC0 slots:

| encoding | mnemonic | |
|---|---|---|
| `4000c000` | `mfbpc $0` | COP0 reg field `24`, func `0` |
| `4000c002` | `mfiab $0` | reg `24`, func `2` |
| `4000c004` | `mfdab $0` | reg `24`, func `4` |
| `4000c800` | `mfps $0,0` | reg `25`, func `0` |
| `401fc801` | `mfpc $31,0` | reg `25`, func `1` |
| `4000c803` | `mfpc $0,1` | reg `25`, func `3` |

The `$24` group is a flat function selector; the `$25` group is
`func = (sel << 1) | is_pc`, so `mfpc` with selector 3 is func 3, not func 1+3.
A table that maps `(reg 25, func 1) -> mfpc` and stops there mislabels every
non-zero selector, which is why `ee_mov_name` computes it.

## Trap 4: `ei` and `di` are the other way round

`0x42000038` is **`ei`** and `0x42000039` is **`di`** on the R5900. Both the
`r5900-full.d` and `r5900@c0.d` expectations agree, and it is the opposite of the
pairing an older MIPS table suggests. Swapping them is invisible in a listing and
fatal in anything that touches interrupts, so the pair is asserted twice
(`ee-isa` unit test and `gowd selftest`).

## The rest of the EE-specific space

- `LQ` (`op = 0x1e`) and `SQ` (`op = 0x1f`) move 128 bits between memory and an
  MM register, numbered like GPRs. They are how the SN Systems compiler passes and
  spills 128-bit values; `Flags::WIDE` marks them so the analysis does not treat
  the register as a GPR.
- `PREF` is `op = 0x33` (the MIPS `LWC3` slot, repurposed) with the hint in `rt`.
- `PLZCW` (`MMI` code `0x004`) counts leading zeros across two registers; the
  compiler emits it for 64-bit comparisons, so it shows up in ordinary scalar code.
- `MTSAB`/`MTSAH` live in `REGIMM` with the selector in the `rt` field (`24`/`25`)
  and the payload as a 16-bit immediate.
- `MADD1`/`DIV1`/`MULT1`/`MFHI1`… use the EE's second accumulator pair ("pipeline
  1"), which `Flags::HILO` covers; the recovered Rust models these as a distinct
  accumulator, not as the same `$hi`/`$lo`.
- VU0 "CT" instructions (`op = 0x12`, `co = 0x10`/`0x18`): the **mnemonic** is a
  function of `(co, func)` and is fully table-driven, so a listing reads `vaddx.`
  or `vmsubw.y` rather than a hex word. The operand sub-fields — destination
  mask (`w:`), broadcast (`.x`), `i:`/`r:` conditions — are *not* modelled yet, so
  these carry `Flags::PARTIAL`: trust the name, check the raw word (which every
  listing prints beside it) before rewriting the code.

## Mapping to Rust

The behavioural target, not a line-by-line transliteration:

- GPRs are scaffolding, not API: the sketch keeps one `u32` local per register so
  the data flow is checkable, and the human-authored function drops them entirely.
- `MM` registers and MMI ops become an explicit 128-bit vector type in the
  recovered crate rather than `u128` arithmetic spelled out inline; until that
  type exists the emitter prints those instructions as comments.
- `$gp`-relative accesses are reported as candidate globals (`.mdebug` usually
  names them), `$sp`-relative ones as named stack slots when STABS knows them.
- Calls are resolved through the symbol map, so a recovered function reads as
  `ScrMatch(...)` and not `f_001129b0()`.
