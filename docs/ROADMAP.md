# Roadmap

Ordered by what unblocks what. Each milestone names the thing that makes it
verifiable, because a decompilation toolchain that cannot be checked against
something external just produces confident nonsense.

## M0 — pipeline foundation (done)

- `ee-isa`: R5900 decoder for the base integer ISA, `LQ`/`SQ`/`PREF`, COP0
  (including the EE `$24`/`$25` moves), COP1 FPU, the full MMI space, and VU0
  mnemonics. 1250 reference encodings agree with it name-for-name, and the MMI +
  VU0 tables are machine-derived from that corpus
  (`tools/gen_isa_tables.py --check`).
- `ps2-elf`: ELF32 reader plus ECOFF `.mdebug` recovery — function names, sizes,
  frame sizes, saved-register masks, STABS parameters and locals, globals, source
  file names. Handles both file-absolute and rebased sub-table offsets.
- `gow-decomp`: per-function analysis (frame, stack slots, calls, `$gp`
  references, undecoded words), a Rust stub emitter that never clobbers curated
  files, a mechanical transliteration sketch, symbol/status files, and a coverage
  report.
- `gowd`: `selftest`, `info`, `sections`, `funcs`, `globals`, `disasm`, `gen`,
  `status`, `raw`, `fixture`.
- No dependencies anywhere, so the whole thing builds and tests offline.

## M1 — the real binary (next, needs your extraction)

Run the pipeline on `SLUS_209.25` and record what it says. Specifically:

1. Does it carry `.mdebug`? (`gowd info`) If yes: how many functions, how many
   names, what fraction of `.text` is covered. That number decides whether the
   project is "name everything for free" or "name them by hand".
2. How many words does `ee-isa` fail to decode? `gowd gen` prints the list into
   `report.md`. Extend the tables with whatever real code needs, in order of
   frequency, each with an encoding verified against the reference disassembler.
3. Where does function-boundary detection disagree with `.mdebug`? That drives
   the heuristics used for any function the symbols missed.

Deliverable: `out/rust/report.md` committed as a baseline, plus the first ~10
curated functions in `crates/gow1/src/`, as the pattern everyone else copies.

## M2 — types, not just names

`.mdebug` holds complete ECOFF type information; the reader currently keeps the
raw STABS type strings without resolving them.

- Walk the dense table to resolve `x`-prefixed type references, structs, unions,
  enums, arrays, function prototypes and typedefs.
- Emit `struct`/`enum` definitions into `out/rust/types/`, deriving field offsets
  from the ECOFF field records and checking them against the code's actual
  `$fp`/`$gp`-relative accesses (a type that disagrees with the load offsets in
  the disassembly is wrong — that is the test).
- Use resolved prototypes for signatures instead of the current
  "`u32` per used argument register" guess, and drop the guess once a prototype
  exists.

## M3 — VU0 microcode operands

The names are already table-driven; the operand fields are not. Needed: the
destination mask (`w:`/`xyz:`), broadcast (`.x`/`.y`/`.z`/`.w`/`.i`/`.r`), the
`[i]`/`[r]` condition tests, `I`, `Q`, `P`, `R`, ACC and `VI`/`VC` register
access, and the split/integer-op (`viadd`, `vcallms` with its 26-bit target).

Verification: `gas/testsuite/gas/mips/r5900*vu0*.d` covers VU0 encodings, so the
same `golden_check.py` approach extends to operand text once the fields are
modelled. Until then VU0 instructions keep `Flags::PARTIAL` and the emitter says
so in each affected file, rather than producing a plausible-looking mistranslation.

## M4 — control-flow structuring

The emitter currently emits a *listing* plus a linear transliteration, and leaves
structuring to the human. The next tooling step is a real structuring pass:

- build the CFG from `Insn` targets, including the delay-slot rules, and split
  basic blocks at terminators;
- recover `if`/`else`, `while`/`do`/`while(true)`, and `switch` (jump tables via
  `plzcw`/`lw $t9,…` patterns, which the decoder already flags), emitting
  structured Rust with the original addresses kept as comments;
- liveness, so a `$t` temporary can be renamed to something meaningful, and so
  unused spills disappear from the recovered source;
- constant folding for `lui`+`ori`/`lui`+`addiu` pairs, and `$gp`-relative
  resolution so data reads as `g_GameState.field` rather than an offset.

This is where a decompilation stops being annotated disassembly, and it is the
reason `Insn` carries every raw field and `Insn::flags` records `FRAME`, `STACK`,
`GP_REL`, `LIKELY`, `HILO` and friends instead of formatting text and discarding
the structure.

## M5 — assets

`.TOC` → `.PAK` → `.WAD` containers: the tag/handler-table reader, texture/mesh/
level/streaming layout, and the `PART*.PAK` repack path so a change can be tested
on hardware or an emulator. A WAD is a stream of tagged chunks rather than a
fixed header, so this is a format-reverse-engineering task, not a parsing task —
hence its own milestone, and hence no half-invented parser in the repo today.

Goal for the recovered Rust: data structures the game itself uses (entity lists,
level records, VIF packets) get real types, so functions recovered under M2/M4
can reference them instead of `*mut u8`.

## M6 — build integration

A `crates/gow1` crate that owns the recovered code, with:

- a `no_std`-style target layout matching the original sections and a linker
  script placing each function at its original address;
- `gowd check` comparing the built ELF's `.text` against the original to report
  which functions match byte-for-byte;
- CI on a synthetic executable only — the game binary never enters the
  repository, so the matching loop runs locally (see [LEGAL.md](LEGAL.md)).

Fidelity target for this project is *behavioural*: idiomatic, readable Rust that
does the same thing. Byte-matching is a useful test, not the goal, so M6 is
optional and everything before it stands on its own.

## Known rough edges

- `SymbolMap` overrides are consulted for functions and globals, not yet for
  struct field names (no types until M2).
- `gowd disasm` on `--all` materialises the whole listing in memory; fine for a
  few megabytes of `.text`, but it should stream if that changes.
- The last function in an image gets a size estimated by scanning (its extent
  has no neighbour to stop at), and the generated file says so in
  `decode_note`.
- VU0 CT operand *text* is not rendered the way the reference disassembler
  does: a mnemonic cannot distinguish `vaddx.` (third operand broadcast over
  `x`) from `vmax.` (no broadcast), because `...x.` is a component in one case
  and the tail of the word `max` in the other. `ee-isa` therefore prints the raw
  fields and says so, which accounts for most of the operand-text differences
  `golden_check.py` reports; all 1250 *names* match.
