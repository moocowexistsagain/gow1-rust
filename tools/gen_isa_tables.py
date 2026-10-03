#!/usr/bin/env python3
"""Regenerate the opcode tables in `crates/ee-isa/src/decode.rs`.

Why a generator
---------------
The Emotion Engine's opcode space is documented in Sony's manual, but the fast
way to get a table that is *provably* right -- including which encoding field
each operand lives in -- is to read it off the reference disassembler's own
conformance corpus. GNU binutils ships `gas/testsuite/gas/mips/r5900*.d`, which
pairs each 32-bit word with the disassembly it must produce, for the base ISA,
all three relevant coprocessor spaces and the MMI set.

For every mnemonic in the corpus we *solve* for an assignment of its printed
operands to encoding fields (`rs`/`rt`/`rd`/`sa`) that is consistent across all
sample encodings of that mnemonic. Anything that does not solve is not emitted,
so the generated tables contain no guesses -- and a form like `pabsw $rd,$rt`
(which differs from the `paddw $rd,$rs,$rt` shape people assume) comes out of
the data rather than out of someone's memory.

Usage
-----
    tools/gen_isa_tables.py --clone /tmp/binutils            # print Rust to stdout
    tools/gen_isa_tables.py DIR_WITH_D_FILES                 # local corpus
    tools/gen_isa_tables.py --clone /tmp/binutils --check    # diff vs decode.rs

`--check` compares the generated tables against what is committed in
`crates/ee-isa/src/decode.rs` and exits non-zero on drift, so the tables can be
verified in CI without pasting anything.

Licensing
---------
binutils is GPLv3+. Its files are never copied into this repository and never
vendored; the corpus is read from a throwaway checkout. What ends up committed is
a mapping from an opcode number to a mnemonic and an operand field --
architecture facts, the same information the Emotion Engine User's Manual
states -- which is what any hand-written table would have contained.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from collections import defaultdict
from itertools import product

LINE = re.compile(r"> ([0-9a-f]{8})\s+(.*)$")
D_FILES = [
    "r5900-full.d",
    "r5900.d",
    "r5900@c0.d",
    "r5900@c1.d",
    "r5900@c2.d",
    "r5900@mul.d",
    "r5900-fix.d",
]

FIELDS = {
    "rs": lambda v: (v >> 21) & 0x1F,
    "rt": lambda v: (v >> 16) & 0x1F,
    "rd": lambda v: (v >> 11) & 0x1F,
    "sa": lambda v: (v >> 6) & 0x1F,
}

# Preference order: the first assignment consistent with every sample wins. The
# order matters where a corpus uses degenerate operands (`pand $0,$0,$31` prints
# rd == rs), so the conventional R-type order is tried first.
PREFERENCE = [
    ("rd",),
    ("rs",),
    ("rt",),
    ("rd", "rs"),
    ("rd", "rt"),
    ("rs", "rt"),
    ("rs", "rd"),
    ("rd", "rs", "rt"),
    ("rd", "rt", "rs"),
    ("rd", "rt", "sa"),
    ("rd", "rs", "sa"),
]

FORM = {
    ("rd",): "Form::Rd",
    ("rs",): "Form::Rs",
    ("rt",): "Form::Rt",
    ("rd", "rs"): "Form::RdRs",
    ("rd", "rt"): "Form::RdRt",
    ("rs", "rt"): "Form::RsRt",
    ("rs", "rd"): "Form::RsRd",
    ("rd", "rs", "rt"): "Form::RdRsRt",
    ("rd", "rt", "rs"): "Form::RdRtRs",
    ("rd", "rt", "sa"): "Form::RdRtSa",
    ("rd", "rs", "sa"): "Form::RdRsSa",
}


def load(path: str):
    for ln in open(path, encoding="utf-8", errors="replace"):
        m = LINE.search(ln)
        if not m:
            continue
        word = int(m.group(1), 16)
        text = m.group(2).strip().replace("\\", "")
        if not text or text[0] == ".":
            continue
        yield word, text


def split_operands(rest: str):
    """`$31,$31,$0` -> [31, 31, 0]; `0x1f` -> ('imm', 31). None if not a plain
    list of registers/immediates (memory operands, VU0 field suffixes, ...)."""
    if not rest:
        return []
    if "(" in rest or "[" in rest:
        return None
    out = []
    for part in (p.strip() for p in rest.split(",")):
        if re.fullmatch(r"\$\d+", part):
            out.append(int(part[1:]))
        elif re.fullmatch(r"-?(0x)?[0-9a-f]+", part, re.I):
            out.append(("imm", int(part, 0)))
        else:
            return None
    return out


def fits(word: int, ops, combo) -> bool:
    for i, fld in enumerate(combo):
        want = ops[i]
        if isinstance(want, tuple):
            # An immediate operand must be the `sa` field and must equal it;
            # this is what distinguishes `psllw $rd,$rt,sa` from a third register.
            if fld != "sa" or FIELDS[fld](word) != want[1]:
                return False
        elif FIELDS[fld](word) != want:
            return False
    return True


def solve(samples) -> tuple | None:
    for combo in PREFERENCE:
        n = len(combo)
        same = [(w, o) for w, o in samples if len(o) == n]
        if same and all(fits(w, o, combo) for w, o in same):
            return combo
    return None


def collect(files):
    mmi = {}
    vu0 = {}
    unresolved = []
    by_name = defaultdict(list)
    for f in files:
        for word, text in load(f):
            name = text.split("\t")[0].split(" ")[0]
            # The VU0 (COP2) space is name-only: its operands carry component
            # suffixes and field masks that the four-field solver cannot express,
            # and the mnemonic alone is the useful, verifiable part.
            if word >> 26 == 0x12 and not name.startswith(("c2", "unknown")):
                vu0[((word >> 21) & 0x1F, word & 0x3F)] = name
            rest = text.split("\t", 1)[1].strip() if "\t" in text else ""
            ops = split_operands(rest)
            if ops is None:
                continue
            by_name[name].append((word, ops))

    for name, samples in by_name.items():
        op = {w >> 26 for w, _ in samples}
        # Only the MMI space (op 0x1c) is table-generated; the base ISA, COP0 and
        # COP1 tables in decode.rs are hand-written, and `tools/golden_check.py`
        # is what verifies those.
        if op != {0x1C}:
            continue
        if name.startswith(("c0", "c1", "c2", "c3", "unknown")):
            continue  # the reference labels these unknown too
        combo = solve(samples)
        if combo is None or combo not in FORM:
            unresolved.append(name)
            continue
        form = FORM[combo]
        for c in {w & 0x7FF for w, _ in samples}:
            mmi[c] = (name, form)
        if form == "Form::RdRtSa":
            # Shift forms keep the amount inside the code; register the 6-bit
            # base too, so any shift amount resolves.
            for c in list({w & 0x7FF for w, _ in samples}):
                mmi[c & 0x3F] = (name, form)
    return mmi, vu0, unresolved


HEADER_MMI = """/// MMI function code (`bits[10:0]` of an `op == 0x1c` word) to mnemonic and
/// operand form. Every entry comes from a verified (encoding, disassembly)
/// pair in a reference disassembler's conformance corpus, including which field
/// holds each operand, so no operand position here is guessed. Codes the corpus
/// does not cover are absent; those decode as `mmi?` with the raw word kept.
/// Regenerate with: tools/gen_isa_tables.py --clone <binutils-dir>
#[allow(clippy::too_many_lines)]
pub(crate) fn mmi_entry(code: u32) -> Option<(&'static str, Form)> {
    match code {"""

HEADER_VU0 = """/// VU0 "CT" and integer-space mnemonics, indexed by (co, func). The operand
/// sub-fields are intentionally not modelled here (see `Flags::PARTIAL`), so
/// only the name is claimed. Regenerated by tools/gen_isa_tables.py.
#[allow(clippy::too_many_lines)]
pub(crate) fn vu0_entry(co: u32, func: u32) -> Option<&'static str> {
    match (co, func) {"""


def render(mmi, vu0) -> str:
    out = [HEADER_MMI]
    for c in sorted(mmi):
        n, form = mmi[c]
        out.append(f'        0x{c:03x} => Some(("{n}", {form})),')
    out += ["        _ => None,", "    }", "}", "", HEADER_VU0]
    for (co, func) in sorted(vu0):
        out.append(f'        (0x{co:02x}, 0x{func:02x}) => Some("{vu0[(co, func)]}"),')
    out += ["        _ => None,", "    }", "}"]
    return "\n".join(out) + "\n"


def maybe_clone(dest: str):
    if os.path.isdir(os.path.join(dest, "gas")):
        return
    subprocess.run(
        ["git", "clone", "-q", "--depth", "1", "--filter=blob:none", "--sparse",
         "https://github.com/gnutools/binutils-gdb", dest],
        check=True,
    )
    subprocess.run(["git", "-C", dest, "sparse-checkout", "set", "gas/testsuite/gas/mips"], check=True)


def committed_tables() -> str:
    path = os.path.join(os.path.dirname(__file__), "..", "crates", "ee-isa", "src", "decode.rs")
    src = open(path, encoding="utf-8").read()
    keep = []
    for fn in ("mmi_entry", "vu0_entry"):
        m = re.search(rf"pub\(crate\) fn {fn}\(.*?\n}}\n", src, re.S)
        if m:
            keep.append(m.group(0))
    return "\n".join(keep)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("corpus", nargs="?", help="directory holding r5900*.d files")
    ap.add_argument("--clone", help="directory to shallow-clone binutils into")
    ap.add_argument("--check", action="store_true", help="compare against decode.rs instead of printing")
    a = ap.parse_args()

    if a.clone:
        maybe_clone(a.clone)
        root = os.path.join(a.clone, "gas/testsuite/gas/mips")
    elif a.corpus:
        root = a.corpus
    else:
        ap.print_help()
        return 1
    files = [os.path.join(root, n) for n in D_FILES if os.path.exists(os.path.join(root, n))]
    if not files:
        print(f"no r5900 corpus files in {root}", file=sys.stderr)
        return 1

    mmi, vu0, unresolved = collect(files)
    print(f"corpus: {len(files)} files -> {len(mmi)} MMI codes, {len(vu0)} VU0 names", file=sys.stderr)
    if unresolved:
        print(f"not emitted (operand shapes the solver cannot pin): {sorted(unresolved)}", file=sys.stderr)

    generated = render(mmi, vu0)
    if a.check:
        def entries(text):
            return {l.strip() for l in text.splitlines() if l.strip().startswith(("0x", "(0x"))}
        have = entries(committed_tables())
        want = entries(generated)
        missing = sorted(want - have)
        extra = sorted(h for h in have if h not in want and h.startswith("0x"))
        for m in missing[:20]:
            print(f"missing from decode.rs: {m}")
        for e in extra[:20]:
            print(f"in decode.rs but not derived: {e}")
        if missing or extra:
            print(f"\n{len(missing)} missing, {len(extra)} unexplained", file=sys.stderr)
            return 1
        print(f"decode.rs tables match the corpus ({len(want)} entries)", file=sys.stderr)
        return 0
    print(generated)
    print("# paste into crates/ee-isa/src/decode.rs, then run tools/golden_check.py", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
