//! `.mdebug` layout round-trip.
//!
//! The point of this test is to pin the *byte offsets* the reader assumes to the
//! documented ECOFF layout, independently of the fixture writer: each assertion
//! reads a field at a hand-written offset in the raw image and compares it with
//! what the parser reports. If someone "fixes" an offset in `mdebug.rs` to match
//! a different (non-PS2) ECOFF variant, this test says so instead of the parser
//! silently reading a string table as a frame size.

use ps2_elf::fixture;
use ps2_elf::mdebug::{
    AUX_SIZE, DENSE_SIZE, EXTERNAL_SYMBOL_SIZE, FILE_DESCRIPTOR_SIZE, PROCEDURE_DESCRIPTOR_SIZE,
    SYMBOLIC_HEADER_SIZE, SYMBOL_SIZE,
};

fn u32_at(img: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([img[off], img[off + 1], img[off + 2], img[off + 3]])
}

#[test]
fn entry_sizes_match_the_documented_layout() {
    assert_eq!(SYMBOLIC_HEADER_SIZE, 0x60);
    assert_eq!(FILE_DESCRIPTOR_SIZE, 0x48);
    assert_eq!(SYMBOL_SIZE, 12);
    assert_eq!(EXTERNAL_SYMBOL_SIZE, 16);
    assert_eq!(PROCEDURE_DESCRIPTOR_SIZE, 0x34);
    assert_eq!(
        DENSE_SIZE, 8,
        "MIPSDENSE, not the 12-byte a.out dense table"
    );
    assert_eq!(AUX_SIZE, 4);
}

#[test]
fn mdebug_header_fields_are_where_the_reader_thinks() {
    let img = fixture::build();
    let elf = ps2_elf::Elf::parse(&img).expect("fixture parses");
    let (_, off) = elf.mdebug_section().expect("fixture has .mdebug");
    let base = off as usize;

    // Magic first, then the count/offset pairs at their documented positions.
    assert_eq!(
        u16::from_le_bytes([img[base], img[base + 1]]),
        0x7009,
        ".mdebug magic"
    );
    assert_eq!(u32_at(&img, base + 0x18), 2, "procedure descriptor count");
    // This fixture uses section-relative sub-table offsets (the "the linker
    // moved .mdebug" case), so the *bytes* say 0x60 while the file position is
    // `base + 0x60`. Both must hold: the raw layout, and the reader's rebase.
    let m_rel = ps2_elf::Mdebug::parse(&img, off).unwrap();
    assert_eq!(
        u32_at(&img, base + 0x1c) as usize,
        SYMBOLIC_HEADER_SIZE as usize,
        "procedure descriptors follow the header (section-relative)"
    );
    assert_eq!(
        (m_rel.header().procedure_offset as i64 + m_rel.fudge()) as usize,
        base + SYMBOLIC_HEADER_SIZE as usize,
        "and the reader resolves them to the file"
    );
    assert_eq!(u32_at(&img, base + 0x20), 7, "local symbol count");
    assert_eq!(
        u32_at(&img, base + 0x24) as usize,
        SYMBOLIC_HEADER_SIZE as usize + 2 * PROCEDURE_DESCRIPTOR_SIZE as usize,
        "local symbols follow the procedure descriptors"
    );
    assert_eq!(u32_at(&img, base + 0x48), 1, "file descriptor count");
    assert_eq!(u32_at(&img, base + 0x58), 2, "external symbol count");

    // A symbol, field by field: `iss`, `value`, `bitfields` at 0, 4, 8 of a
    // 12-byte entry, with type in bits[5:0], class in bits[10:6], and the
    // stab index / auxiliary pointer in bits[31:12].
    let sym0 = base + 0x60 + 2 * PROCEDURE_DESCRIPTOR_SIZE as usize;
    let bits_of = |i: usize| u32_at(&img, sym0 + SYMBOL_SIZE as usize * i + 8);
    assert_eq!(bits_of(0) & 0x3f, 0, "the filler symbol has type Nil");
    assert_eq!((bits_of(0) >> 6) & 0x1f, 0, "and class Nil");
    assert_eq!(bits_of(0) >> 12, 0, "and no stab index");
    // The symbol at array index 1 is `fn_one`: PROC (6) / TEXT (1).
    assert_eq!(bits_of(1) & 0x3f, 6, "symtype PROC");
    assert_eq!((bits_of(1) >> 6) & 0x1f, 1, "symclass TEXT");
    // Index 2 is a parameter stab: the code sits in `index` as 0x8f300 + N_PSYM.
    assert_eq!(
        bits_of(2) >> 12,
        0x8f300 + 0xa0,
        "N_PSYM packed into the index"
    );
    // `iss` is an offset into the file's own string table: "gow/fn_test.c\0" (14)
    // then "fn_one\0" (7) puts "argc:x1" at 21.
    assert_eq!(
        u32_at(&img, sym0 + SYMBOL_SIZE as usize * 2),
        21,
        "its iss is an offset into the file's string table"
    );
    assert!(
        u32_at(&img, sym0 + SYMBOL_SIZE as usize * 3) > 21,
        "the string table is append-ordered, so the next name sits further along"
    );
    // For a parameter the `value` field is the offset from the frame pointer, so
    // the second argument lands four bytes above the first.
    let argc_value = u32_at(&img, sym0 + SYMBOL_SIZE as usize * 2 + 4);
    let argv_value = u32_at(&img, sym0 + SYMBOL_SIZE as usize * 3 + 4);
    assert_eq!(
        argv_value.wrapping_sub(argc_value),
        4,
        "incoming arguments ascend by 4 bytes"
    );

    // And the parser agrees with the bytes.
    let m = ps2_elf::Mdebug::parse(&img, off).expect("mdebug parses");
    assert_eq!(m.header().procedure_count, 2);
    assert_eq!(m.header().local_symbol_count, 7);
    assert_eq!(m.header().file_count, 1);
    assert_eq!(m.header().external_symbol_count, 2);
    assert_eq!(m.procedures.len(), 2);
    assert_eq!(m.files.len(), 1);

    // One procedure descriptor, field by field.
    let pd0 = base + 0x60;
    assert_eq!(u32_at(&img, pd0), fixture::FN_ONE, "pd.address");
    assert_eq!(u32_at(&img, pd0 + 4), 0, "pd.symbol_index");
    assert_eq!(
        u32_at(&img, pd0 + 0xc),
        (1 << 31 | 1 << 30 | 1 << 23),
        "pd.saved_register_mask"
    );
    assert_eq!(u32_at(&img, pd0 + 0x20), 32, "pd.frame_size");
    assert_eq!(
        i16::from_le_bytes([img[pd0 + 0x24], img[pd0 + 0x25]]),
        30,
        "pd.frame_pointer_register"
    );
    assert_eq!(
        i16::from_le_bytes([img[pd0 + 0x26], img[pd0 + 0x27]]),
        31,
        "pd.return_pc_register"
    );
    let p = &m.procedures[0];
    assert_eq!(p.address, fixture::FN_ONE);
    assert_eq!(p.frame_size, 32);
    assert_eq!(p.saved_register_mask as u32, 1 << 31 | 1 << 30 | 1 << 23);
    assert_eq!(
        p.frame_pointer_register, 30,
        "pd fields keep their signedness"
    );
    assert_eq!(
        p.saved_gprs(),
        vec![23, 30, 31],
        "the mask must expand ascending, including $ra from the sign bit"
    );
}

#[test]
fn functions_carry_names_frames_and_params() {
    for (label, img) in [
        ("section-relative", fixture::build()),
        ("file-absolute", fixture::build_absolute()),
    ] {
        let exe = ps2_elf::Executable::parse(&img).expect("parses");
        let m = exe
            .mdebug
            .as_ref()
            .unwrap_or_else(|| panic!("{label}: .mdebug missing"));
        let f = m
            .function_by_name(fixture::FN_ONE_NAME)
            .unwrap_or_else(|| panic!("{label}: fn_one missing"));
        assert_eq!(f.address, fixture::FN_ONE, "{label}");
        assert_eq!(f.frame_size, 32, "{label}");
        assert_eq!(f.params.len(), 2, "{label}: STABS parameters");
        assert_eq!(f.params[0].name, "argc", "{label}");
        assert_eq!(f.params[0].raw_type, "x1", "{label}");
        assert_eq!(f.params[0].code, 0xa0, "{label}: N_PSYM");
        assert_eq!(f.locals.len(), 1, "{label}: N_LSYM local");
        assert_eq!(f.locals[0].name, "sum", "{label}");
        assert_eq!(f.locals[0].stack_offset, Some(-16), "{label}");
        assert_eq!(f.source_file.as_deref(), Some("gow/fn_test.c"), "{label}");
        let two = m
            .function_by_name(fixture::FN_TWO_NAME)
            .expect("fn_two present");
        assert!(two.is_static, "{label}: STATICPROC means static");
        // Sizes come from the adjacency of procedure descriptors.
        assert_eq!(f.size, 0x20, "{label}: fn_one spans to fn_two");
        assert_eq!(
            m.function_at(fixture::FN_ONE).map(|x| x.name.as_str()),
            Some("fn_one"),
            "{label}: exact-address lookup"
        );
        assert_eq!(
            m.function_at(fixture::FN_ONE + 4).map(|x| x.name.as_str()),
            None,
            "{label}: function_at is exact, so a mid-function address resolves to nothing"
        );
        assert_eq!(
            m.containing_function(fixture::FN_ONE + 4)
                .map(|x| x.name.as_str()),
            Some("fn_one"),
            "{label}: the enclosing-function lookup is what listings annotate with"
        );
    }
}

#[test]
fn a_moved_section_is_rebased_and_reported() {
    // The fixture with section-relative offsets is exactly the "linker moved
    // .mdebug" case; the reader must notice and say so rather than misparse.
    let img = fixture::build();
    let elf = ps2_elf::Elf::parse(&img).unwrap();
    let (_, off) = elf.mdebug_section().unwrap();
    let m = ps2_elf::Mdebug::parse(&img, off).unwrap();
    assert_eq!(m.fudge(), off as i64, "rebase by the section offset");

    let abs = fixture::build_absolute();
    let elf2 = ps2_elf::Elf::parse(&abs).unwrap();
    let (_, off2) = elf2.mdebug_section().unwrap();
    let m2 = ps2_elf::Mdebug::parse(&abs, off2).unwrap();
    assert_eq!(m2.fudge(), 0, "normal images need no rebase");
    assert_eq!(m.functions.len(), m2.functions.len());
}

#[test]
fn garbage_offsets_error_instead_of_panicking() {
    // Truncated / hostile input must produce Err, never a panic: the analysis
    // loop feeds this parser garbage from stripped and hand-patched binaries.
    let mut img = fixture::build();
    let elf = ps2_elf::Elf::parse(&img).unwrap();
    let (_, off) = elf.mdebug_section().unwrap();
    // Point the procedure offset somewhere absurd.
    let end = std::cmp::min(img.len(), off as usize + 0x60);
    if end > off as usize + 0x1c + 4 {
        let at = off as usize + 0x1c;
        img[at..at + 4].copy_from_slice(&0xffff_fff0u32.to_le_bytes());
    }
    let _ = ps2_elf::Mdebug::parse(&img, off); // must not panic
                                               // A short image must also be an error rather than an out-of-bounds read.
    let short = vec![0u8; 8];
    assert!(ps2_elf::Mdebug::parse(&short, 0).is_err());
}
