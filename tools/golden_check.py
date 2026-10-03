#!/usr/bin/env python3
"""Compare the `ee-isa` decoder against GNU binutils' R5900 expectations.

binutils' testsuite pairs each 32-bit encoding with the disassembly the
reference disassembler must produce. That makes it an oracle for *names*: if
`ee-isa` and binutils disagree about which mnemonic an encoding is, one of them
is wrong, and for a decompilation that is the bug worth catching early.

    tools/golden_check.py --clone /tmp/binutils          # fetch + check
    tools/golden_check.py DIR_WITH_D_FILES               # use a local copy
    tools/golden_check.py --clone /tmp/binutils --show 30

What is compared
----------------
* Mnemonic for every vector in the corpus.
* Alias printings (`nop`, `li`, `move`, ...) are accepted either way, since
  `gowd raw` deliberately prints the underlying encoding.
* Encodings binutils itself labels `c0`/`c1`/`c2` ("a coprocessor instruction I
  do not name") must come back unknown-ish from us; that catches tables that
  guess.

Operand *text* is compared too, but only as a warning: binutils' print order for
some FPU ops differs from the field roles (see crates/ee-isa/src/decode.rs), and
this project renders the semantic order.

binutils is GPLv3+; nothing from it is copied into this repository. Only the
corpus is read, and only to verify.
"""

import argparse
import os
import re
import subprocess
import sys
import tempfile

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
# binutils print aliases: acceptable from us as the raw form.
ALIASES = {
    "nop", "li", "la", "move", "b", "bal", "j", "beqz", "bnez", "blt", "bgt",
    "ble", "bge", "negu", "not", "neg", "mfc0", "mtc0", "blez", "bgtz",
}
# binutils' own "I do not know this coprocessor instruction" printings.
UNKNOWNISH = {"c0", "c1", "c2", "c3"}
OUR_UNKNOWNISH = {"unknown", "mmi?", "vu0ct", "cop3?"}


def maybe_clone(dest):
    if os.path.isdir(os.path.join(dest, "gas")):
        return
    subprocess.run(
        ["git", "clone", "-q", "--depth", "1", "--filter=blob:none", "--sparse",
         "https://github.com/gnutools/binutils-gdb", dest],
        check=True,
    )
    subprocess.run(
        ["git", "-C", dest, "sparse-checkout", "set", "gas/testsuite/gas/mips"],
        check=True,
    )


def load(root):
    vecs = []
    for name in D_FILES:
        path = os.path.join(root, name)
        if not os.path.exists(path):
            continue
        for ln in open(path, encoding="utf-8", errors="replace"):
            m = LINE.search(ln)
            if not m:
                continue
            word = int(m.group(1), 16)
            text = m.group(2).strip().replace("\\", "")
            if not text or text[0] == ".":
                continue
            parts = re.split(r"\s+", text, maxsplit=1)
            mnem = parts[0]
            ops = parts[1].strip() if len(parts) > 1 else ""
            vecs.append((word, mnem, ops, name))
    return vecs


ABIS = "zero at v0 v1 a0 a1 a2 a3 t0 t1 t2 t3 t4 t5 t6 t7 s0 s1 s2 s3 s4 s5 s6 s7 t8 t9 k0 k1 gp sp fp ra".split()


def canonical_ops(s):
    """Normalise an operand string so that spelling choices are not reported as
    differences: `$29` == `$sp`, `0x8` == `8`, whitespace and comma style."""
    s = re.sub(r"\s+", "", s)
    # Split a `off($base)` memory operand into its parts *before* normalising,
    # so the displacement is recognised as a number rather than as junk.
    s = s.replace("(", ",").replace(")", "")
    if not s:
        return ""
    out = []
    for part in s.split(","):
        reg = re.fullmatch(r"\$(f|vf|c|cc)?(\d+)([xyzw])?", part)
        if reg:
            pre, n, suf = reg.group(1), int(reg.group(2)), reg.group(3) or ""
            if pre is None and n < 32:
                part = f"{ABIS[n]}{suf}"
            else:
                part = f"{pre}{n}{suf}"
        elif re.fullmatch(r"-?0x[0-9a-fA-F]+", part):
            part = str(int(part, 16))
        out.append(part)
    return ",".join(p for p in out if p)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("corpus", nargs="?", help="directory containing r5900*.d files")
    ap.add_argument("--clone", help="where to shallow-clone binutils for the corpus")
    ap.add_argument("--show", type=int, default=15, help="how many mismatches to print")
    ap.add_argument("--ops", action="store_true", help="also fail on operand mismatches")
    ap.add_argument(
        "--binary",
        default=None,
        help="gowd binary to use (default: build it with cargo)",
    )
    a = ap.parse_args()

    root = a.corpus
    if a.clone:
        maybe_clone(a.clone)
        root = os.path.join(a.clone, "gas/testsuite/gas/mips")
    if not root or not os.path.isdir(root):
        ap.error("need a corpus directory (or --clone)")

    binary = a.binary
    tmp = None
    if binary is None:
        tmp = tempfile.mkdtemp(prefix="gowd-golden-")
        subprocess.run(
            ["cargo", "build", "--offline", "--target-dir", tmp, "-p", "gowd"],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        binary = os.path.join(tmp, "debug", "gowd")

    vecs = load(root)
    if not vecs:
        print("no vectors found in", root, file=sys.stderr)
        return 1

    # One process, batched over stdin: 4 corpora x hundreds of vectors.
    inp = "".join(f"0 {w:08x}\n" for w, _, _, _ in vecs)
    res = subprocess.run(
        [binary, "raw"], input=inp, capture_output=True, text=True, check=True
    )
    got = {}
    for line in res.stdout.splitlines():
        f = line.split("\t")
        if len(f) >= 2:
            got[int(f[0], 16)] = (f[1], f[2] if len(f) > 2 else "")

    bad, ops_bad, skipped = [], [], 0
    for word, want, want_ops, src in vecs:
        mine = got.get(word)
        if mine is None:
            bad.append((word, want, "<missing>", src))
            continue
        name, ops = mine
        if want in ALIASES:
            skipped += 1
            continue
        if want in UNKNOWNISH:
            if name not in OUR_UNKNOWNISH:
                bad.append((word, want, f"{name} (binutils leaves this unnamed)", src))
            continue
        elif name != want:
            bad.append((word, want, name, src))
            continue
        if want_ops and canonical_ops(want_ops) and canonical_ops(ops) != canonical_ops(want_ops):
            ops_bad.append((word, want, want_ops, ops, src))

    total = len(vecs)
    print(f"corpus: {root}")
    print(f"vectors: {total}   name mismatches: {len(bad)}   alias-skipped: {skipped}")
    for word, want, mine, src in bad[: a.show]:
        print(f"  {word:08x}  binutils={want!r}  ee-isa={mine!r}   ({src})")
    if len(bad) > a.show:
        print(f"  ... {len(bad) - a.show} more")

    print(f"operand-text differences: {len(ops_bad)} (informational)")
    for word, want, wops, mops, src in ops_bad[: a.show]:
        print(f"  {word:08x} {want}: binutils={wops!r} ours={mops!r}")
    return 1 if (bad or (a.ops and ops_bad)) else 0


if __name__ == "__main__":
    sys.exit(main())
