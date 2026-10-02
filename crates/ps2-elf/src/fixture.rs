//! A synthetic PS2 executable, laid out the way a real one is.
//!
//! This exists so the *whole* pipeline — ELF parse → `.mdebug` symbol recovery →
//! decode → analysis → Rust emission — can be exercised by `cargo test`, by CI,
//! and by `gowd selftest`, without anyone attaching a disc image. It also pins
//! the struct layouts `mdebug.rs` assumes: if a field offset drifts, the
//! round-trip tests fail.
//!
//! Everything here is invented (fake names, fake code, fake source paths); it
//! describes no shipping executable.
//!
//! The `.mdebug` sub-table offsets are written *section-relative*, which is the
//! "section was moved after linking" case that the reference tooling handles by
//! rebasing; `Mdebug::detect_fudge` is expected to recover it.
//! `build_with_absolute_offsets()` emits the normal file-absolute variant so
//! both paths are tested.

/// `.text` virtual address.
pub const TEXT_VADDR: u32 = 0x1000;
/// `.data` virtual address.
pub const DATA_VADDR: u32 = 0x2000;
/// Address of the first synthetic function.
pub const FN_ONE: u32 = TEXT_VADDR;
/// Address of the second synthetic function.
pub const FN_TWO: u32 = TEXT_VADDR + 0x20;
/// A global with a symbol on it.
pub const G_TEST_GLOBAL: u32 = DATA_VADDR;
/// Its contents.
pub const G_TEST_GLOBAL_VALUE: u32 = 0xdead_beef;
/// Name the fixture gives the first function.
pub const FN_ONE_NAME: &str = "fn_one";
/// Name the fixture gives the second function.
pub const FN_TWO_NAME: &str = "fn_two";

/// R-type builder.
const fn r(op: u32, rs: u32, rt: u32, rd: u32, sa: u32, func: u32) -> u32 {
    (op << 26) | (rs << 21) | (rt << 16) | (rd << 11) | (sa << 6) | func
}
/// I-type builder.
const fn i(op: u32, rs: u32, rt: u32, imm: u16) -> u32 {
    (op << 26) | (rs << 21) | (rt << 16) | imm as u32
}

/// Two hand-encoded functions. `fn_one` allocates a frame, saves `$ra`/`$s7`,
/// calls `fn_two`, adds two argument registers, and returns through a delay-slot
/// `nop`; `fn_two` does one load and one store.
/// Two hand-encoded functions of eight instructions each, so that
/// `FN_TWO - FN_ONE` (the size `.mdebug` claims for `fn_one`) exactly matches
/// the emitted code. `fn_one` allocates a frame, spills `$ra` and a pointer
/// copy, calls `fn_two`, and returns through a delay-slot `or` (the classic
/// "compute the result in the delay slot" idiom). `fn_two` loads, stores, and
/// executes one MMI instruction, so the analysis exercises both paths.
#[must_use]
pub fn text_words() -> Vec<u32> {
    vec![
        // ---- fn_one @ 0x1000, 8 words ----
        i(0x09, 29, 29, (-32i16) as u16), // addiu $sp,$sp,-32
        i(0x2b, 29, 31, 28),              // sw    $ra,28($sp)
        i(0x2b, 29, 23, 24),              // sw    $s7,24($sp)
        (0x03 << 26) | (FN_TWO >> 2),     // jal   fn_two
        r(0x00, 4, 5, 2, 0, 0x21),        // addu  $v0,$a0,$a1  (delay slot)
        r(0x00, 31, 0, 0, 0, 0x08),       // jr    $ra
        r(0x00, 0, 2, 2, 0, 0x25),        // or    $v0,$v0,$zero (delay slot)
        r(0x00, 0, 0, 0, 0, 0x00),        // nop   (padding to the next symbol)
        // ---- fn_two @ 0x1020, 8 words ----
        i(0x09, 29, 29, (-16i16) as u16), // addiu $sp,$sp,-16
        i(0x23, 4, 2, 8),                 // lw    $v0,8($a0)
        i(0x2b, 4, 2, 8),                 // sw    $v0,8($a0)
        r(0x1c, 4, 5, 2, 0, 0x208 & 0x3f) | (0x8 << 6), // paddb $v0,$a0,$a1
        i(0x0c, 0, 0, 0x1234),            // ori   -> lui-free constant load
        r(0x00, 31, 0, 0, 0, 0x08),       // jr    $ra
        r(0x00, 0, 0, 0, 0, 0x00),        // nop
        r(0x00, 0, 0, 0, 0, 0x00),        // nop
    ]
}

/// Build a `.mdebug` section body with section-relative sub-table offsets.
/// When `absolute`, the caller-supplied section file offset is added instead.
fn u32le(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}
fn i32le(out: &mut Vec<u8>, v: i32) {
    out.extend_from_slice(&v.to_le_bytes());
}
fn cstr(out: &mut Vec<u8>, s: &str) -> u32 {
    let off = out.len() as u32;
    out.extend_from_slice(s.as_bytes());
    out.push(0);
    off
}

fn mdebug_body(section_file_off: u32, absolute: bool) -> Vec<u8> {
    let base = if absolute { section_file_off } else { 0 };
    let mut strtab: Vec<u8> = Vec::new();
    let p_path = cstr(&mut strtab, "gow/fn_test.c");
    let p_fn_one = cstr(&mut strtab, FN_ONE_NAME);
    let p_argc = cstr(&mut strtab, "argc:x1");
    let p_argv = cstr(&mut strtab, "argv:x2");
    let p_sum = cstr(&mut strtab, "sum:x1");
    let p_fn_two = cstr(&mut strtab, FN_TWO_NAME);
    let p_global = cstr(&mut strtab, "g_TestGlobal");
    let local_strings_size = strtab.len() as u32;

    let mut ext_strtab: Vec<u8> = Vec::new();
    let e_global = cstr(&mut ext_strtab, "g_TestGlobal");
    let e_start = cstr(&mut ext_strtab, "_start");
    let ext_strings_size = ext_strtab.len() as u32;

    // Layout: procedures | locals | strings | fd | externals | ext strings.
    // Every offset below is measured from the *start of the section*, i.e. it
    // includes the 0x60-byte symbolic header, which is what ECOFF specifies.
    const HDR: u32 = 0x60;
    let mut out: Vec<u8> = Vec::new();

    // Procedure descriptors (0x34 each).
    let pd_off = HDR + out.len() as u32;
    // `sym_index` is relative to the file's `isym_base`, i.e. the *second*
    // symbol in the array (the first is the mandatory Nil filler) is index 0.
    for (addr, sym_index, mask, frame) in [
        (FN_ONE, 0u32, (1u32 << 31) | (1 << 23) | (1 << 30), 32i32),
        (FN_TWO, 5, 1 << 31, 16),
    ] {
        debug_assert_eq!(addr - FN_ONE % 4, addr);
        u32le(&mut out, addr);
        u32le(&mut out, sym_index);
        i32le(&mut out, -1); // line number entry index
        i32le(&mut out, mask as i32);
        i32le(&mut out, 0); // saved register offset
        i32le(&mut out, -1); // optimization index
        i32le(&mut out, 0); // saved float mask
        i32le(&mut out, 0);
        i32le(&mut out, frame);
        out.extend_from_slice(&30i16.to_le_bytes()); // fp register
        out.extend_from_slice(&31i16.to_le_bytes()); // ra register
        i32le(&mut out, 0);
        i32le(&mut out, 0);
        u32le(&mut out, 0);
    }
    let pd_count = 2u32;

    // Local symbols (12 each). `iss` values are relative to the *file's* string
    // table, which for this single file is the whole local string table.
    let sym_off = HDR + out.len() as u32;
    // The file's symbol range starts at index 1 (0 is the filler `Nil` symbol
    // every ECOFF object starts with), so `isym_base` below is 1.
    let sym = |iss: u32, value: u32, ty: u32, class: u32, index: u32, out: &mut Vec<u8>| {
        u32le(out, iss);
        u32le(out, value);
        u32le(out, ty | (class << 6) | (index << 12));
    };
    sym(0, 0, 0, 0, 0, &mut out);
    sym(p_fn_one, FN_ONE, 6, 1, 0, &mut out); // PROC / TEXT
    sym(p_argc, 0x30, 3, 7, 0x8f300 + 0xa0, &mut out); // PARAM, N_PSYM
    sym(p_argv, 0x34, 3, 7, 0x8f300 + 0xa0, &mut out); // PARAM, N_PSYM
    sym(p_sum, (-16i32) as u32, 4, 7, 0x8f300 + 0x80, &mut out); // LOCAL, N_LSYM
    sym(p_global, G_TEST_GLOBAL, 1, 2, 0, &mut out); // GLOBAL / DATA
    sym(p_fn_two, FN_TWO, 14, 1, 0, &mut out); // STATICPROC / TEXT
    let sym_count = 7u32;

    let strings_off = HDR + out.len() as u32;
    out.extend_from_slice(&strtab);

    // File descriptor (0x48).
    let fd_off = HDR + out.len() as u32;
    u32le(&mut out, FN_ONE); // address
    i32le(&mut out, p_path as i32); // file path string offset
    i32le(&mut out, 0); // this file's string offset within the local strings
    u32le(&mut out, local_strings_size); // cb_ss
    u32le(&mut out, 1); // isym_base (skip the Nil filler)
    u32le(&mut out, sym_count - 1); // symbol count for this file
    u32le(&mut out, 0); // iline_base
    u32le(&mut out, 0); // cline
    u32le(&mut out, 0); // iopt
    u32le(&mut out, 0); // copt
    out.extend_from_slice(&0u16.to_le_bytes()); // ipd_first
    out.extend_from_slice(&2u16.to_le_bytes()); // procedure count
    u32le(&mut out, 0); // iaux_base
    u32le(&mut out, 0); // caux
    u32le(&mut out, 0); // rfd_base
    u32le(&mut out, 0); // crfd
    u32le(&mut out, 0x10); // lang = C (bit 4)
    u32le(&mut out, 0); // iline
    u32le(&mut out, 0); // cb_line

    // External symbols (0x10 each): flags, ifd, then SymbolHeader.
    let ext_off = HDR + out.len() as u32;
    for (iss, value, ty, class) in [
        (e_global, G_TEST_GLOBAL, 1u32, 2u32),
        (e_start, 0x8000_0000, 1, 6), // undefined import
    ] {
        out.extend_from_slice(&0x01u16.to_le_bytes());
        out.extend_from_slice(&0i16.to_le_bytes());
        u32le(&mut out, iss);
        u32le(&mut out, value);
        u32le(&mut out, ty | (class << 6));
    }
    let ext_count = 2u32;

    let ext_strings_off = HDR + out.len() as u32;
    out.extend_from_slice(&ext_strtab);

    // Symbolic header, patched now that every sub-table position is known.
    let mut h: Vec<u8> = Vec::new();
    h.extend_from_slice(&0x7009u16.to_le_bytes());
    h.extend_from_slice(&0x00e5u16.to_le_bytes()); // version stamp
    fn field(v: i32, h: &mut Vec<u8>) {
        h.extend_from_slice(&v.to_le_bytes());
    }
    field(0, &mut h); // cbLine
    field(0, &mut h); // cbLineOffset (size)
    field(0, &mut h); // cbLineOffset
    field(0, &mut h); // cdense
    field(0, &mut h); // cbDensityOffset
    field(pd_count as i32, &mut h);
    field((pd_off + base) as i32, &mut h);
    field(sym_count as i32, &mut h);
    field((sym_off + base) as i32, &mut h);
    field(0, &mut h); // cOpt
    field(0, &mut h); // cbOptOffset
    field(0, &mut h); // iaext / caux count
    field(0, &mut h); // cbAuxOffset
    field(local_strings_size as i32, &mut h);
    field((strings_off + base) as i32, &mut h);
    field(ext_strings_size as i32, &mut h);
    field((ext_strings_off + base) as i32, &mut h);
    field(1, &mut h); // cfd
    field((fd_off + base) as i32, &mut h);
    field(0, &mut h); // crfd
    field(0, &mut h); // cbRfdOffset
    field(ext_count as i32, &mut h);
    field((ext_off + base) as i32, &mut h);
    debug_assert_eq!(h.len(), HDR as usize, "symbolic header must be 0x60 bytes");

    let mut section = h;
    section.extend_from_slice(&out);
    section
}

/// A complete, parseable synthetic executable (section-relative `.mdebug`).
#[must_use]
pub fn build() -> Vec<u8> {
    build_inner(false)
}

/// Same, but with file-absolute `.mdebug` offsets (the usual real-world case).
#[must_use]
pub fn build_absolute() -> Vec<u8> {
    build_inner(true)
}

fn build_inner(absolute: bool) -> Vec<u8> {
    let text: Vec<u8> = text_words().iter().flat_map(|w| w.to_le_bytes()).collect();
    let data: Vec<u8> = [G_TEST_GLOBAL_VALUE, 1, 2, 0]
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .collect();

    // Names/offsets that depend on where things land are computed in one pass:
    // header, then each payload 16-byte aligned, then the section table.
    let ehsize = 52u32;
    let mut off = ehsize;
    let align = |v: &mut u32| *v = (*v + 15) & !15;
    let text_off = off;
    off += text.len() as u32;
    align(&mut off);
    let data_off = off;
    off += data.len() as u32;
    align(&mut off);

    // `.mdebug` sits at `off`, which is already final, so one pass suffices.
    let md = mdebug_body(off, absolute);
    let md_off = off;
    off += md.len() as u32;
    align(&mut off);

    // .symtab / .strtab
    let mut strtab: Vec<u8> = vec![0];
    let s_fn1 = cstr(&mut strtab, FN_ONE_NAME);
    let mut symtab: Vec<u8> = vec![0; 16]; // index 0: null symbol
    symtab.extend_from_slice(&s_fn1.to_le_bytes());
    symtab.extend_from_slice(&FN_ONE.to_le_bytes());
    symtab.extend_from_slice(&0x28u32.to_le_bytes()); // size
    symtab.extend_from_slice(&[0x12, 0]); // STT_FUNC | STB_GLOBAL<<4, other
    symtab.extend_from_slice(&1u16.to_le_bytes()); // shndx = .text
    let symtab_off = off;
    off += symtab.len() as u32;
    align(&mut off);
    let strtab_off = off;
    off += strtab.len() as u32;
    align(&mut off);

    // .shstrtab
    let mut shstr: Vec<u8> = vec![0];
    let mut names: Vec<u32> = Vec::new();
    for n in [
        ".text",
        ".data",
        ".mdebug",
        ".symtab",
        ".strtab",
        ".shstrtab",
    ] {
        names.push(cstr(&mut shstr, n));
    }
    let shstr_off = off;
    off += shstr.len() as u32;
    align(&mut off);
    let shoff = off;

    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(&[0x7f, b'E', b'L', b'F', 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    let push16 = |out: &mut Vec<u8>, v: u16| out.extend_from_slice(&v.to_le_bytes());
    let push32 = |out: &mut Vec<u8>, v: u32| out.extend_from_slice(&v.to_le_bytes());
    push16(&mut out, 2); // ET_EXEC
    push16(&mut out, 8); // EM_MIPS
    push32(&mut out, 1); // EV_CURRENT
    push32(&mut out, FN_ONE); // e_entry
    push32(&mut out, 0); // e_phoff (no program headers: section table only)
    push32(&mut out, shoff);
    push32(&mut out, 0x7000_0005); // EF_MIPS_32BIT | MIPS2 | ... (cosmetic)
    push16(&mut out, ehsize as u16);
    push16(&mut out, 0); // e_phentsize
    push16(&mut out, 0); // e_phnum
    push16(&mut out, 40); // e_shentsize
    push16(&mut out, 7); // e_shnum (null + 6)
    push16(&mut out, 6); // e_shstrndx

    let write_at = |out: &mut Vec<u8>, blob: &[u8], at: u32| {
        out.resize(at as usize, 0);
        out.extend_from_slice(blob);
    };
    write_at(&mut out, &text, text_off);
    write_at(&mut out, &data, data_off);
    write_at(&mut out, &md, md_off);
    write_at(&mut out, &symtab, symtab_off);
    write_at(&mut out, &strtab, strtab_off);
    write_at(&mut out, &shstr, shstr_off);

    out.resize(shoff as usize, 0);
    let sh = |out: &mut Vec<u8>,
              name: u32,
              ty: u32,
              flags: u32,
              addr: u32,
              offset: u32,
              size: u32,
              link: u32,
              info: u32,
              align: u32,
              entsize: u32| {
        for v in [
            name, ty, flags, addr, offset, size, link, info, align, entsize,
        ] {
            push32(out, v);
        }
    };
    sh(&mut out, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    sh(
        &mut out,
        names[0],
        1,
        6,
        TEXT_VADDR,
        text_off,
        text.len() as u32,
        0,
        0,
        16,
        0,
    );
    sh(
        &mut out,
        names[1],
        1,
        3,
        DATA_VADDR,
        data_off,
        data.len() as u32,
        0,
        0,
        16,
        0,
    );
    sh(
        &mut out,
        names[2],
        1,
        0,
        0,
        md_off,
        md.len() as u32,
        0,
        0,
        4,
        0,
    );
    sh(
        &mut out,
        names[3],
        2,
        0,
        0,
        symtab_off,
        symtab.len() as u32,
        5, // link -> .strtab (section index 5)
        1,
        4,
        16,
    );
    sh(
        &mut out,
        names[4],
        3,
        0,
        0,
        strtab_off,
        strtab.len() as u32,
        0,
        0,
        1,
        0,
    );
    sh(
        &mut out,
        names[5],
        3,
        0,
        0,
        shstr_off,
        shstr.len() as u32,
        0,
        0,
        1,
        0,
    );
    out
}
