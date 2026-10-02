# God of War (PS2) → Rust

Tooling for decompiling **God of War 1** (PS2 / `SLUS-20925`) into readable,
behaviourally faithful Rust. This repository contains the *toolchain*, not the
game: nothing here is derived from a copyrighted binary, and the loaders take a
path to files you extract from a disc you own.

The approach is a rebuild-in-Rust decompilation: recover the executable's
symbols and instruction stream mechanically, lay each function out as a
documented stub plus a mechanical transliteration, and rewrite the behaviour in
idiomatic Rust one function at a time, tracking coverage as you go.

## Status

| piece | state |
|---|---|
| `ee-isa` — R5900 decoder (base ISA, MMI, COP0/COP1, VU0 names) | done, verified name-for-name against a 1250-vector reference corpus |
| `ps2-elf` — ELF32 + ECOFF `.mdebug` symbol recovery | done, round-trip tested against a synthetic executable |
| `gow-decomp` — frame/slot/call analysis, Rust stub + sketch emission | done for the analysis, emitter is the working surface |
| `gowd` — CLI driver | done (`selftest`, `info`, `funcs`, `globals`, `disasm`, `gen`, `status`) |
| VU0 micro-op operands, `.TOC`/`.PAK`/`.WAD` asset containers | not started (see [docs/ROADMAP.md](docs/ROADMAP.md)) |

## Quick check that it works, with no game files

```sh
cargo run -p gowd -- selftest
```

That builds a synthetic PS2 executable in memory (`crates/ps2-elf/src/fixture.rs`)
and drives the whole pipeline through it: ELF parse → `.mdebug` symbol recovery →
decode → analysis → Rust emission, asserting ~40 facts on the way. It also needs
no network and no third-party crates — everything here is `std` only.

## Trying it on a real executable

1. Make an `extracted/` directory at the repo root. It is gitignored, and
   [docs/LEGAL.md](docs/LEGAL.md) explains why nothing in it may ever be committed.
2. Put the disc's main executable there, e.g. `extracted/SLUS_209.25` (the
   `SYSTEM.CNF` `ELF` line names it; on the NTSC-U disc it is `SLUS_209.25`).
3. Look at what the binary gives you:

   ```sh
   cargo run -p gowd -- info extracted/SLUS_209.25
   cargo run -p gowd -- funcs extracted/SLUS_209.25 --limit 40
   cargo run -p gowd -- disasm extracted/SLUS_209.25 --name <some_name> --count 40
   ```

   If the executable has a `.mdebug` section — many early-SDK PS2 retail builds
   do, and it is the single biggest factor in how fast this project moves — you
   get function names, source file names, frame sizes, saved-register masks and
   parameter lists for free. `gowd info` says whether it is there.
4. Generate the working tree:

   ```sh
   cargo run -p gowd -- gen extracted/SLUS_209.25 --out out/rust
   ```

   This writes, per function, a compilable documented stub into `out/rust/gen/`
   and a mechanical transliteration into `out/rust/sketches/`, plus
   `out/rust/report.md` (coverage), `out/rust/status.txt` (per-function progress)
   and `out/rust/symbols.syms.txt` (the name map).
5. Pick a function, read its stub (address range, frame, callees, data
   references, difficulty note) and its sketch, write real Rust over the body,
   delete the `@gowd-stub` marker line so the generator stops touching the file,
   and mark it `done` in `status.txt`. Re-run `gowd gen` any time: it never
   overwrites a file you have edited.

No ROM handy? `cargo run -p gowd -- fixture /tmp/f.elf` writes a synthetic
executable that behaves like a symbolised PS2 binary, and every subcommand works
on it.

## Layout

```
crates/ee-isa      R5900 decoder: encodings, fields, flags (no dependencies)
crates/ps2-elf     ELF32 reader + ECOFF .mdebug symbol recovery
crates/gow-decomp  function analysis, symbol naming, status tracking, Rust emitter
crates/gowd        the CLI (`gowd help`)
tools/             verification + table-generation scripts (Python, not built)
docs/              architecture, formats, roadmap, legal
```

## Reading

- [docs/PS2_EE.md](docs/PS2_EE.md) — what the Emotion Engine does that a generic
  MIPS decoder gets wrong, including three bugs this project's oracle caught.
- [docs/FORMATS.md](docs/FORMATS.md) — the `.mdebug` layout, symbol map and
  status file formats.
- [docs/ROADMAP.md](docs/ROADMAP.md) — what is next and why, in dependency order.
- [docs/LEGAL.md](docs/LEGAL.md) — the one rule that is not negotiable.

## Verifying the decoder

`tools/golden_check.py` compares every mnemonic `ee-isa` produces against the
disassembly expectations from GNU binutils' own R5900 conformance corpus (1250
encodings covering the base ISA, MMI, and the COP0/COP1/COP2 spaces):

```sh
tools/golden_check.py --clone /tmp/binutils        # clones, builds, compares
tools/gen_isa_tables.py --clone /tmp/binutils --check   # tables match derivation
```

The corpus is fetched into a throwaway directory and never committed, because
binutils is GPLv3+; what lands in this repository is only the architecture
mapping (opcode → mnemonic → operand field), which is the same information the
Emotion Engine User's Manual states.

## Contributing

- `cargo test --workspace --all-features`, `cargo clippy --workspace
  --all-targets --all-features -- -D warnings` and `cargo fmt --check` are all
  clean and are the bar for any change. CI pins Rust `1.94.1` because clippy's
  lint set moves between releases; use that version locally if you want the same
  verdict, and any recent stable otherwise.
- Prefer explicit code over lint-driven cleverness where the clever form changes
  evaluation: `ps2-elf`'s `stabs_code` keeps an `if` rather than
  `then_some(...)`, because the latter computes `index - 0x8f300` even when the
  symbol is not a stab, which underflows.
- New instruction tables must come with a verified encoding, not a guess; say
  where it was confirmed in the commit message.
- Recovered code lives in `out/` until it is reviewed; only curated modules get
  moved under version control, and the generator preserves them from then on.

## License

MIT for the tooling in this repository (see `LICENSE`). This project is not
affiliated with and produces no redistribution of any Sony or Santa Monica
Studio material.
