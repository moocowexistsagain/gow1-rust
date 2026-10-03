# Legal and provenance

One rule, stated first: **no copyrighted material goes in this repository.**
Not the game executable, not `SYSTEM.CNF`, not a `.TOC`/`.PAK`/`.WAD`, not a
disc image, not a screenshot, not a ripped texture — and not anything *derived*
from them either (a table of names copied out of the binary, a dump of its data).

Everything the tooling produces stays in `out/` and `extracted/`, both
gitignored, and `.gitignore` also refuses the file names a PS2 disc uses
(`SLUS_*`, `SLES_*`, `SCUS_*`, `SLPM_*`, `*.TOC`, `*.PAK`, `*.WAD`, `*.iso`) so a
careless `git add -A` cannot do the damage for you.

## Why that restriction is workable here

The recoverable information in a game executable is *facts about code*, and the
facts are what we restate: an address, a mnemonic, a frame size, a name that a
symbol table states. Writing "the function at `0x001129b0` is called
`_ScrMatch_0_1129b0` and saves `$s0`–`$s6`" is a statement about a file you own,
not a copy of a protected work. Reproducing the game's assets, or shipping
anything cut out of its binary, is a different matter and is not what this
project is for.

A decompilation of this kind also cannot be *built* from the repository alone:
`cargo test`, `cargo clippy` and `gowd selftest` pass with no game data present,
because the executable used for testing is a synthetic one this project writes
itself (`crates/ps2-elf/src/fixture.rs`). If you find yourself wanting to commit
`extracted/SLUS_209.25` to make CI pass, that is the signal to fix the fixture
instead.

## What the ISA tables are, and how they were made

The opcode tables in `crates/ee-isa` map an encoding to a mnemonic and to the
field each operand occupies. That information is documented by Sony in the
*Emotion Engine User's Manual* and is the same in any disassembler: an
architecture fact, not an expression of a particular author's style.

The tables were nonetheless **checked mechanically**, because hand-transcribed
opcode tables are wrong in ways that look right:

- `tools/golden_check.py` compares every mnemonic `ee-isa` produces against the
  expectations in GNU binutils' R5900 testsuite (1250 encodings covering the base
  ISA, MMI, and the COP0/COP1/COP2 spaces). The comparison currently reports
  zero name mismatches.
- `tools/gen_isa_tables.py` *derives* the MMI and VU0 tables from the same
  corpus — including which field holds each operand — and `--check` verifies
  that the committed tables still follow from it.

binutils is GPLv3+. Its sources and test data are **not** vendored, committed,
or copied into this repository; the corpus is downloaded into a throwaway
directory (`/tmp`, or `.cache/`, both ignored) at check time. What remains here
is a mapping of numbers to mnemonics, which is what any hand-written table would
have contained and what the manual itself lists.

## Reference projects, and what was taken from each

Where an existing tool was read, its license decided what could be taken:

| project | license | what was used |
|---|---|---|
| `chaoticgd/ccc` (Chaos Compiler Collection) | MIT | the ECOFF `.mdebug` structure layouts and enum values, restated with attribution in `crates/ps2-elf/src/mdebug.rs`. No source was copied. |
| GNU binutils | GPLv3+ | its R5900 testsuite as a **verification oracle** only; no files vendored, no code copied. |
| `mogaika/god_of_war_browser` | no license file → all rights reserved | **nothing**: no code, no data. Only the public observation that the game's assets are `.TOC` → `.PAK` → `.WAD` with tagged chunks, which is why the container reader is a milestone with real research in it rather than a guess committed today. |

Because that third row is all-rights-reserved, any future work on the container
formats starts from the disc you own and from documentation, not from that
codebase.

## If you are contributing

- Do not commit anything from a disc. If a bug needs a real binary to
  reproduce, attach the *tool's output* (`gowd info`, a listing excerpt,
  `report.md`) and describe the address; do not attach the input file.
- Do not paste code from GPL or unlicensed projects into these crates. Stating a
  numeric fact you verified independently is fine; a translation of someone
  else's expression is not.
- Keep the decoder honest: a new table entry needs its encoding verified
  against a reference disassembler, and the commit message should say what it was
  verified against.
- No ROM, no emulator BIOS, no `ps2sdk` binaries.

This project is a fan-made research effort. It is not affiliated with, endorsed
by, or sponsored by Sony Interactive Entertainment or Santa Monica Studio.
