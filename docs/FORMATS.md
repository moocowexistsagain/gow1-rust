# File formats

Everything the tooling reads or writes, with the offsets it assumes. The
executable-side facts here were transcribed from the ECOFF/`.mdebug` layout the
PS2 toolchains emit and cross-checked against `crates/ps2-elf/tests/mdebug_roundtrip.rs`,
which reads the same fields directly out of a byte array.

## The executable

A PS2 game executable is a plain **ELF32, little-endian, `EM_MIPS`** file: no
encryption, no compression. `SYSTEM.CNF` on the disc names it (for `SLUS-20925`
that is `SLUS_209.25`). Section names are conventional (`.text`, `.data`, `.bss`,
`.sdata`, `.sbss`, `.rodata`, `.ctors`, `.dtors`), and the useful content is:

| section | why it matters |
|---|---|
| `.text` | the code being recovered; analysis reads it through vaddr translation |
| `.mdebug` | **the whole reason this project is feasible** — see below |
| `.symtab` / `.strtab` | usually stripped in retail builds, so `.mdebug` is the fallback in the other direction: symbol map → `.mdebug` → `.symtab` → `f_<addr>` |

`Elf::vaddr_to_offset` prefers program headers and falls back to the section
table, because hand-patched and repacked images disagree between the two.

## `.mdebug` (ECOFF symbolic header + sub-tables)

All values 32-bit little-endian. The section starts with a **0x60-byte symbolic
header**; the sub-table offsets that follow it are *usually* file-absolute, but a
linker that moved the section leaves them pointing at the old position. `Mdebug`
detects this (the first sub-table must start at `section + 0x60`) and rebases,
reporting the delta as a warning rather than silently misreading.

### Symbolic header

| off | field | off | field |
|---|---|---|---|
| `0x00` | `magic` (must be `0x7009`) | `0x30` | `caux` (auxiliary entry count) |
| `0x02` | `version_stamp` | `0x34` | `cbAuxOffset` |
| `0x04` | `cbLine` (line record count) | `0x38` | `cbSs` (local string table size) |
| `0x08` | `iall`/size of the line-number table | `0x3c` | `cbSsOffset` (local strings) |
| `0x0c` | `cbLine` offset (line numbers) | `0x40` | external string table size |
| `0x10` | `cdense` (dense table count) | `0x44` | external string table offset |
| `0x14` | `cbDensityOffset` | `0x48` | `cfd` (file descriptor count) |
| `0x18` | `ipd` (procedure descriptor count) | `0x4c` | `cbFdOffset` |
| `0x1c` | `cbPdOffset` | `0x50` | `crfd` (relative file descriptor count) |
| `0x20` | `isym` (local symbol count) | `0x54` | `cbRfdOffset` |
| `0x24` | `cbSymOffset` | `0x58` | `iext` (external symbol count) |
| `0x28` | `copt` (optimization record count) | `0x5c` | `cbExtOffset` |
| `0x2c` | `cbOptOffset` | | |

A field name that differs between ECOFF documents (`iall`, `iept`) is not
reproduced here: this table lists what the reader actually uses, and
`mdebug_roundtrip.rs` asserts each position against raw bytes.

### Entry sizes

| table | size | notes |
|---|---|---|
| `SymbolHeader` (local symbol) | 12 | `iss`, `value`, bitfields |
| `ExternalSymbolHeader` | 16 | `flags:u16`, `ifd:i16`, then a `SymbolHeader` |
| `FileDescriptor` | `0x48` | one per source file |
| `ProcedureDescriptor` | `0x34` | one per function |
| dense (`MIPSDENSE`) | 8 | `index:i32`, `value:i32` — MIPS uses 8-byte entries, not the 12-byte a.out form |
| auxiliary | 4 | |

`SymbolHeader` bitfields: `symtype = bits[5:0]`, `symclass = bits[10:6]`,
one reserved bit, `index = bits[31:12]`.

The two enums that matter:

- **`symtype`** — `Nil 0, Global 1, Static 2, Param 3, Local 4, Label 5, Proc 6,
  Block 7, End 8, Member 9, Typedef 10, File 11, StaticProc 14, Constant 15`.
  `Proc`/`StaticProc` are functions; `StaticProc` is what makes a name local to
  its object file, which the emitter preserves (`is_static`).
- **`symclass`** — decides whether `value` is an address. `Text 1, Data 2,
  Bss 3, Register 4, Sdata 13, Sbss 14, Rdata 15, Xdata 24, Pdata 25` are.
  Note that the class field is 5 bits, so class `27` (`NONGP`) and above exist;
  unrecognised values are kept as `Other(u32)` rather than coerced.

### Procedure descriptor — why frame recovery is cheap

| off | field |
|---|---|
| `0x00` | `address` (function start) |
| `0x04` | `symbol_index` — **relative to the file descriptor's `isym_base`** |
| `0x08` | `iline` (first line number entry) |
| `0x0c` | `regmask` — callee-saved GPR bitmask, `bit n == $n` |
| `0x10` | `regopt` (offset of saved registers in the frame) |
| `0x18` | `regmask_fpc` (saved FPRs) |
| `0x20` | `frame` — frame size in bytes |
| `0x24` | `ifpmode:16` — frame pointer register, `-1` if none |
| `0x26` | `ipcmode:16` — return-address register, `-1` if none |
| `0x28`–`0x30` | line number range and offset |

`regmask` is a *bitmask in a signed word*: `$ra` is bit 31, so it reads as a
negative number. Clamping it with `max(0)` — the obvious-looking defensive thing
to do — silently deletes the return address from every function's saved-register
set. `mdebug.rs` casts instead, and `mdebug_roundtrip.rs` asserts that `$ra`
survives.

### Stabs records

Local symbols carry debug records in the `index` field: a symbol is a stab when
`(index & 0xfff00) == 0x8f300`, and the stab code is `index - 0x8f300`. The codes
this project reads:

| code | name | used for |
|---|---|---|
| `0x20` | `N_GSYM` | global (external) variable |
| `0x22` | `N_FNAME` | function name |
| `0x24` | `N_FUN` | function, and an *empty* name means the function's end |
| `0x26` | `N_STSYM` | static variable |
| `0x28` | `N_LCSYM` | local (BSS) static |
| `0x40` | `N_RSYM` | register-allocated local (`value` = register number) |
| `0x44` | `N_SLINE` | source line ↔ address |
| `0x64` | `N_SO` | source file name |
| `0x80` | `N_LSYM` | local variable (`value` = fp-relative offset) |
| `0x84` | `N_SOL` | included file |
| `0xa0` | `N_PSYM` | parameter (`value` = fp-relative offset) |
| `0xc0` / `0xe0` | `N_LBRAC` / `N_RBRAC` | lexical block extents |
| `0xc4` | `N_SCOPE` | end of local scope |

Each stab's string is `name:type`, where `type` is a raw ECOFF type expression
(`x1` for `int`, `*...` for pointers, `(subrange)` for arrays and so on). The
tooling keeps the raw string: full ECOFF type-graph resolution (following `x`
references through the dense table) is milestone M2 in
[ROADMAP.md](ROADMAP.md), and until then `ps2_elf::mdebug::stabs_type_hint`
renders a readable hint without pretending to have resolved anything.

## Files the tool writes

These are deliberately plain text so they can be reviewed in a pull request and
merged without conflicts.

### `out/rust/status.txt`

```
# <address> <todo|in-progress|done> [# note]
0x001129b0 done          # verified against the original by hand
0x00112a40 in-progress
```

`gowd gen` skips functions marked `done`. Unknown states are reported, not
dropped silently, and re-seeding never rewrites an existing line.

### `symbols.syms.txt` (the name map)

```
# <address> <function|data> <name> [# note]
0x001129b0 function _ScrMatch_0_1129b0
0x00216a40 data g_GameState # main game state block
```

Addresses may be `0x…`, bare hex, or decimal; a `#` comment becomes the note.
Entries here override `.mdebug` names, which is the point: the map is curated,
regenerated names never clobber it (`SymbolMap::merge_auto` only adds keys that
are absent).

### `out/rust/gen/<name>.rs` and `out/rust/sketches/<name>.rs.txt`

The first is a compilable stub: a doc comment of everything recovered (address
range, size, frame, saved registers, callees, data references, original source
path, difficulty), the raw listing, and a `todo!()`. Deleting its `@gowd-stub`
line makes the generator treat the file as human-owned. The second is the
per-instruction transliteration — not Rust, never compiled, reference material
for the rewrite.

`out/rust/gen/mod.rs` declares every generated module, so `cargo build` checks
the whole recovered tree at once.

## Container formats (not implemented yet)

The disc's assets are `GODOFWAR.TOC` plus `PART1.PAK`/`PART2.PAK`, which contain
`.WAD` files; a WAD is a sequence of tagged chunks
(`id`, `tag`, `flags`, `size`, then a name and a node id) rather than a
fixed-layout header, so reading them needs a per-tag handler table. That is
deliberately out of the first milestone — see [ROADMAP.md](ROADMAP.md) — and no
parser is shipped for it, because a guessed container format is worse than none.
