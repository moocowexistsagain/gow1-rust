//! ECOFF `.mdebug` reader: the section that makes a PS2 decompilation feasible.
//!
//! Many early PS2 retail executables were shipped *without* stripping the
//! compiler's debug information. It lives in a `.mdebug` section in ECOFF
//! format, and it is far richer than an ELF `.symtab`: per-procedure frame size
//! and saved-register mask, complete STABS type strings for globals, parameters
//! and locals, and the original source file names. Where it survives, it is the
//! difference between naming 4000 functions and guessing from prologue
//! patterns. The retail `God of War` executable (NTSC-U `SCUS-97399`) is *not*
//! one of those builds — it carries neither `.mdebug` nor a populated
//! `.symtab`, so there the entry points come from
//! `gow_decomp::analyze::scan_function_starts` and the names come from a
//! hand-curated symbol map.
//!
//! Layout (all offsets in this section are 32-bit, little endian, and relative
//! either to the section start or to the file start — auto-detected below):
//!
//! ```text
//! 0x00 Symbolic header (0x60 bytes)   magic 0x7009 at 0x00
//! 0x60 sub-tables: line numbers, dense table, procedure descriptors,
//!      local symbols (+aux), string tables, file descriptors, externals
//! ```
//!
//! Struct field offsets match what the Chaos Compiler Collection (MIT, used by
//! the GTA3/GTA-VC decompilations) uses for PS2 executables; the field sizes
//! are cross-checked by `tests/mdebug_roundtrip.rs`, which builds a synthetic
//! `.mdebug` and reads it back.

use crate::elf::{cstr_at, ParseError, Reader, Result};

pub const SYMBOLIC_HEADER_SIZE: u32 = 0x60;
pub const FILE_DESCRIPTOR_SIZE: u32 = 0x48;
pub const SYMBOL_SIZE: u32 = 0xc;
pub const EXTERNAL_SYMBOL_SIZE: u32 = 0x10;
pub const PROCEDURE_DESCRIPTOR_SIZE: u32 = 0x34;
/// `MIPSDENSE` — the ECOFF variant the MIPS/EE toolchains use.
pub const DENSE_SIZE: u32 = 8;
pub const AUX_SIZE: u32 = 4;

/// ECOFF symbol types (`asym.symtype`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SymType {
    Nil,
    Global,
    Static,
    Param,
    Local,
    Label,
    Proc,
    Block,
    End,
    Member,
    Typedef,
    File,
    StaticProc,
    Constant,
    Other(u32),
}

impl SymType {
    pub const fn from_raw(v: u32) -> Self {
        match v {
            0 => SymType::Nil,
            1 => SymType::Global,
            2 => SymType::Static,
            3 => SymType::Param,
            4 => SymType::Local,
            5 => SymType::Label,
            6 => SymType::Proc,
            7 => SymType::Block,
            8 => SymType::End,
            9 => SymType::Member,
            10 => SymType::Typedef,
            11 => SymType::File,
            14 => SymType::StaticProc,
            15 => SymType::Constant,
            other => SymType::Other(other),
        }
    }
    #[must_use]
    pub const fn is_function(self) -> bool {
        matches!(self, SymType::Proc | SymType::StaticProc)
    }
}

/// Storage class (`asym.symclass`); the ones that decide whether `value` is an
/// address or something else.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SymClass {
    Nil,
    Text,
    Data,
    Bss,
    Register,
    Abs,
    Undefined,
    Local,
    Bits,
    Dbx,
    RegImage,
    Info,
    UserStruct,
    Sdata,
    Sbss,
    Rdata,
    Var,
    Common,
    Scommon,
    VarRegister,
    Variant,
    Sundefined,
    Init,
    BasedVar,
    Xdata,
    Pdata,
    Fini,
    Nongp,
    Other(u32),
}

impl SymClass {
    pub const fn from_raw(v: u32) -> Self {
        match v {
            0 => SymClass::Nil,
            1 => SymClass::Text,
            2 => SymClass::Data,
            3 => SymClass::Bss,
            4 => SymClass::Register,
            5 => SymClass::Abs,
            6 => SymClass::Undefined,
            7 => SymClass::Local,
            8 => SymClass::Bits,
            9 => SymClass::Dbx,
            10 => SymClass::RegImage,
            11 => SymClass::Info,
            12 => SymClass::UserStruct,
            13 => SymClass::Sdata,
            14 => SymClass::Sbss,
            15 => SymClass::Rdata,
            16 => SymClass::Var,
            17 => SymClass::Common,
            18 => SymClass::Scommon,
            19 => SymClass::VarRegister,
            20 => SymClass::Variant,
            21 => SymClass::Sundefined,
            22 => SymClass::Init,
            23 => SymClass::BasedVar,
            24 => SymClass::Xdata,
            25 => SymClass::Pdata,
            26 => SymClass::Fini,
            27 => SymClass::Nongp,
            other => SymClass::Other(other),
        }
    }
    /// True when `value` is a virtual address into `.text`/`.data`/`.bss`.
    #[must_use]
    pub const fn is_address(self) -> bool {
        matches!(
            self,
            SymClass::Text
                | SymClass::Data
                | SymClass::Bss
                | SymClass::Sdata
                | SymClass::Sbss
                | SymClass::Rdata
                | SymClass::Xdata
                | SymClass::Pdata
        )
    }
}

/// The 0x60-byte symbolic header.
#[derive(Clone, Copy, Debug, Default)]
pub struct SymbolicHeader {
    pub magic: u16,
    pub version_stamp: u16,
    pub line_number_count: i32,
    pub line_numbers_size: i32,
    pub line_numbers_offset: i32,
    pub dense_count: i32,
    pub dense_offset: i32,
    pub procedure_count: i32,
    pub procedure_offset: i32,
    pub local_symbol_count: i32,
    pub local_symbol_offset: i32,
    pub optimization_count: i32,
    pub optimization_offset: i32,
    pub aux_count: i32,
    pub aux_offset: i32,
    pub local_strings_size: i32,
    pub local_strings_offset: i32,
    pub external_strings_size: i32,
    pub external_strings_offset: i32,
    pub file_count: i32,
    pub file_offset: i32,
    pub relative_file_count: i32,
    pub relative_file_offset: i32,
    pub external_symbol_count: i32,
    pub external_symbol_offset: i32,
}

impl SymbolicHeader {
    fn read(r: &Reader<'_>, at: u32) -> Result<Self> {
        Ok(Self {
            magic: r.u16(at)?,
            version_stamp: r.u16(at + 2)?,
            line_number_count: r.i32(at + 4)?,
            line_numbers_size: r.i32(at + 8)?,
            line_numbers_offset: r.i32(at + 0xc)?,
            dense_count: r.i32(at + 0x10)?,
            dense_offset: r.i32(at + 0x14)?,
            procedure_count: r.i32(at + 0x18)?,
            procedure_offset: r.i32(at + 0x1c)?,
            local_symbol_count: r.i32(at + 0x20)?,
            local_symbol_offset: r.i32(at + 0x24)?,
            optimization_count: r.i32(at + 0x28)?,
            optimization_offset: r.i32(at + 0x2c)?,
            aux_count: r.i32(at + 0x30)?,
            aux_offset: r.i32(at + 0x34)?,
            local_strings_size: r.i32(at + 0x38)?,
            local_strings_offset: r.i32(at + 0x3c)?,
            external_strings_size: r.i32(at + 0x40)?,
            external_strings_offset: r.i32(at + 0x44)?,
            file_count: r.i32(at + 0x48)?,
            file_offset: r.i32(at + 0x4c)?,
            relative_file_count: r.i32(at + 0x50)?,
            relative_file_offset: r.i32(at + 0x54)?,
            external_symbol_count: r.i32(at + 0x58)?,
            external_symbol_offset: r.i32(at + 0x5c)?,
        })
    }

    /// Candidate sub-table starts, used to auto-detect whether the offsets in
    /// this header are file-absolute or section-relative.
    fn sub_table_offsets(&self) -> Vec<u32> {
        [
            self.line_numbers_offset,
            self.dense_offset,
            self.procedure_offset,
            self.local_symbol_offset,
            self.aux_offset,
            self.local_strings_offset,
            self.file_offset,
            self.external_symbol_offset,
        ]
        .into_iter()
        .filter(|&v| v > 0)
        .map(|v| v as u32)
        .collect()
    }
}

#[derive(Clone, Debug)]
pub struct RawSymbol {
    pub iss: u32,
    pub value: u32,
    pub sym_type: SymType,
    pub sym_class: SymClass,
    pub index: u32,
    /// Absolute index into the file's local symbol array (for debugging).
    pub array_index: u32,
}

impl RawSymbol {
    fn read(r: &Reader<'_>, at: u32, array_index: u32) -> Result<Self> {
        let iss = r.u32(at)?;
        let value = r.u32(at + 4)?;
        let bits = r.u32(at + 8)?;
        Ok(Self {
            iss,
            value,
            sym_type: SymType::from_raw(bits & 0x3f),
            sym_class: SymClass::from_raw((bits >> 6) & 0x1f),
            index: bits >> 12,
            array_index,
        })
    }
    /// ECOFF packs STABS codes into `index`: `(index & 0xfff00) == 0x8f300`.
    #[must_use]
    pub fn is_stabs(&self) -> bool {
        (self.index & 0xfff00) == 0x8f300
    }
    /// The packed stab code, or `None`.
    ///
    /// Written as an `if`, not `is_stabs().then_some(index - 0x8f300)`:
    /// `then_some` evaluates its argument eagerly, and most symbols are not
    /// stabs, so that form subtracts `0x8f300` from `index == 0` and panics on
    /// overflow in a debug build. Clippy's `unnecessary_lazy_evaluations` fires
    /// on the `then(|| …)` spelling here; it is wrong for this particular
    /// expression, and the test below is what keeps it that way.
    #[must_use]
    pub fn stabs_code(&self) -> Option<u32> {
        if self.is_stabs() {
            Some(self.index - 0x8f300)
        } else {
            None
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ProcedureDescriptor {
    pub address: u32,
    pub symbol_index: u32,
    pub line_number_entry_index: i32,
    /// Bitmask of GPRs saved to the frame (bit n == `$n`).
    pub saved_register_mask: i32,
    pub saved_register_offset: i32,
    pub optimization_index: i32,
    pub saved_float_register_mask: i32,
    pub saved_float_register_offset: i32,
    pub frame_size: i32,
    pub frame_pointer_register: i16,
    pub return_pc_register: i16,
    pub line_number_low: i32,
    pub line_number_high: i32,
    pub line_number_offset: u32,
}

impl ProcedureDescriptor {
    fn read(r: &Reader<'_>, at: u32) -> Result<Self> {
        Ok(Self {
            address: r.u32(at)?,
            symbol_index: r.u32(at + 4)?,
            line_number_entry_index: r.i32(at + 8)?,
            saved_register_mask: r.i32(at + 0xc)?,
            saved_register_offset: r.i32(at + 0x10)?,
            optimization_index: r.i32(at + 0x14)?,
            saved_float_register_mask: r.i32(at + 0x18)?,
            saved_float_register_offset: r.i32(at + 0x1c)?,
            frame_size: r.i32(at + 0x20)?,
            frame_pointer_register: r.u16(at + 0x24)? as i16,
            return_pc_register: r.u16(at + 0x26)? as i16,
            line_number_low: r.i32(at + 0x28)?,
            line_number_high: r.i32(at + 0x2c)?,
            line_number_offset: r.u32(at + 0x30)?,
        })
    }

    /// The saved-register mask expanded to GPR numbers, in the order the ABI
    /// pushes them (ascending).
    #[must_use]
    pub fn saved_gprs(&self) -> Vec<u32> {
        let mut out = Vec::new();
        for i in 0..32 {
            if self.saved_register_mask & (1 << i) != 0 {
                out.push(i);
            }
        }
        out
    }
}

/// A recovered function: name, address, size, and the prologue facts the
/// decompiler needs to lay out a Rust stack frame equivalent.
#[derive(Clone, Debug)]
pub struct Function {
    pub name: String,
    pub address: u32,
    /// Best-effort; `0` when unknown.
    pub size: u32,
    pub is_static: bool,
    pub frame_size: u32,
    pub saved_register_mask: u32,
    pub saved_float_register_mask: u32,
    pub frame_pointer_register: Option<u32>,
    pub return_pc_register: Option<u32>,
    pub source_file: Option<String>,
    /// Parameters as recorded by STABS, in declaration order.
    pub params: Vec<StabsVar>,
    pub locals: Vec<StabsVar>,
    /// Raw STABS type descriptor for the return type, when available.
    pub return_type: Option<String>,
}

/// One `name:type` STABS record (parameter, local, or global).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StabsVar {
    pub name: String,
    /// Raw STABS type expression, e.g. `xt10,2,-2147483648..2147483647`.
    pub raw_type: String,
    /// `Some(offset)` for stack-allocated variables: bytes from `$fp` (or the
    /// frame pointer the procedure descriptor names).
    pub stack_offset: Option<i32>,
    /// `Some(reg)` for register-allocated variables.
    pub register: Option<u32>,
    pub code: u32,
}

#[derive(Clone, Debug)]
pub struct Global {
    pub name: String,
    pub address: u32,
    pub size: u32,
    pub raw_type: Option<String>,
    pub section: SectionKind,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SectionKind {
    Text,
    Data,
    Bss,
    Sdata,
    Sbss,
    Rdata,
    Other,
}

#[derive(Clone, Debug, Default)]
pub struct SourceFile {
    pub address: u32,
    pub path: String,
    pub symbol_count: u32,
}

/// Parsed `.mdebug` contents.
pub struct Mdebug<'a> {
    data: &'a [u8],
    r: Reader<'a>,
    section_offset: u32,
    fudge: i64,
    header: SymbolicHeader,
    pub files: Vec<SourceFile>,
    pub procedures: Vec<ProcedureDescriptor>,
    pub functions: Vec<Function>,
    pub globals: Vec<Global>,
    /// External (linker-visible) symbols, including the undefined ones.
    pub externals: Vec<(String, u32, SymType, SymClass)>,
    /// True when the header's magic was not the expected 0x7009.
    pub header_magic_suspect: bool,
    /// (isym_base, symbol_count) per file descriptor.
    file_symbol_bases: Vec<(i32, u32)>,
    /// Absolute start of each file's own string table.
    file_string_bases: Vec<i64>,
}

impl<'a> Mdebug<'a> {
    /// `section_offset` is where `.mdebug` starts inside the file image.
    pub fn parse(data: &'a [u8], section_offset: u32) -> Result<Self> {
        let r = Reader::new(data);
        let header = SymbolicHeader::read(&r, section_offset)?;
        let suspect = !matches!(header.magic, 0x7001..=0x7009);
        let fudge = Self::detect_fudge(section_offset, &header);
        let mut me = Self {
            data,
            r,
            section_offset,
            fudge,
            header,
            files: Vec::new(),
            procedures: Vec::new(),
            functions: Vec::new(),
            globals: Vec::new(),
            externals: Vec::new(),
            header_magic_suspect: suspect,
            file_symbol_bases: Vec::new(),
            file_string_bases: Vec::new(),
        };
        me.read_files()?;
        me.read_procedures()?;
        me.read_externals()?;
        me.build_functions()?;
        Ok(me)
    }

    /// Sub-table offsets in `.mdebug` are normally file-absolute, but if the
    /// section was moved by the linker without fixing them up they are all
    /// wrong by one constant. Compute that constant the same way the reference
    /// tooling does: the first sub-table must start immediately after the
    /// 0x60-byte header.
    fn detect_fudge(section_offset: u32, h: &SymbolicHeader) -> i64 {
        let expected = section_offset as i64 + SYMBOLIC_HEADER_SIZE as i64;
        match h.sub_table_offsets().into_iter().min() {
            None => 0,
            Some(first) => {
                let delta = expected - first as i64;
                if delta == 0 {
                    0
                } else {
                    // Section-relative offsets (first == header size) produce
                    // delta == section_offset; accept both rather than fail.
                    delta
                }
            }
        }
    }

    fn abs(&self, off: i32) -> Result<u32> {
        let v = off as i64 + self.fudge;
        if v < 0 || v as usize >= self.data.len() {
            return Err(ParseError::new(format!(
                ".mdebug sub-table offset {off:#x} (+fudge {:#x}) lands outside the file",
                self.fudge as u32
            )));
        }
        Ok(v as u32)
    }

    #[must_use]
    pub fn header(&self) -> &SymbolicHeader {
        &self.header
    }
    #[must_use]
    pub fn section_offset(&self) -> u32 {
        self.section_offset
    }
    #[must_use]
    pub fn fudge(&self) -> i64 {
        self.fudge
    }

    fn string_at(&self, off: u32) -> String {
        cstr_at(self.data, off)
    }

    fn read_files(&mut self) -> Result<()> {
        let count = self.header.file_count.max(0) as u32;
        if count == 0 {
            return Ok(());
        }
        let base = self.abs(self.header.file_offset)?;
        for i in 0..count {
            let at = base + i * FILE_DESCRIPTOR_SIZE;
            let address = self.r.u32(at)?;
            let path_off = self.r.i32(at + 4)?;
            let strings_off = self.r.i32(at + 8)?;
            let isym_base = self.r.i32(at + 0x10)?;
            let symbol_count = self.r.i32(at + 0x14)?.max(0) as u32;
            let strings_base = self.abs(self.header.local_strings_offset)?;
            let path = self.string_at((strings_base as i64 + path_off as i64) as u32);
            self.files.push(SourceFile {
                address,
                path,
                symbol_count,
            });
            // Stash the per-file symbol range for later passes: it is encoded
            // in the order files were read, so keep parallel vecs.
            self.file_symbol_bases.push((isym_base, symbol_count));
            self.file_string_bases
                .push(strings_base as i64 + strings_off as i64);
        }
        Ok(())
    }

    fn local_symbol(&self, file: usize, idx: u32) -> Result<(RawSymbol, String)> {
        let (isym_base, count) = *self
            .file_symbol_bases
            .get(file)
            .ok_or_else(|| ParseError::new(format!("no file descriptor {file}")))?;
        if idx >= count {
            return Err(ParseError::new(format!(
                "local symbol index {idx} out of range (file has {count})"
            )));
        }
        let sym_base = self.abs(self.header.local_symbol_offset)?;
        let at = sym_base + ((isym_base + idx as i32) as u32) * SYMBOL_SIZE;
        let s = RawSymbol::read(&self.r, at, idx)?;
        let strings_base = self.file_string_bases[file];
        let name = self.string_at((strings_base + s.iss as i64) as u32);
        Ok((s, name))
    }

    fn read_procedures(&mut self) -> Result<()> {
        let count = self.header.procedure_count.max(0) as u32;
        if count == 0 {
            return Ok(());
        }
        let base = self.abs(self.header.procedure_offset)?;
        for i in 0..count {
            self.procedures.push(ProcedureDescriptor::read(
                &self.r,
                base + i * PROCEDURE_DESCRIPTOR_SIZE,
            )?);
        }
        Ok(())
    }

    fn read_externals(&mut self) -> Result<()> {
        let count = self.header.external_symbol_count.max(0) as u32;
        if count == 0 {
            return Ok(());
        }
        let base = self.abs(self.header.external_symbol_offset)?;
        let strings = self.abs(self.header.external_strings_offset).unwrap_or(0);
        for i in 0..count {
            let at = base + i * EXTERNAL_SYMBOL_SIZE;
            let iss = self.r.u32(at + 4)?;
            let value = self.r.u32(at + 8)?;
            let bits = self.r.u32(at + 0xc)?;
            let name = self.string_at(strings + iss);
            self.externals.push((
                name,
                value,
                SymType::from_raw(bits & 0x3f),
                SymClass::from_raw((bits >> 6) & 0x1f),
            ));
        }
        Ok(())
    }

    /// Turn procedure descriptors + STABS records into [`Function`]s.
    fn build_functions(&mut self) -> Result<()> {
        // Index procedures by their name-symbol's file, then walk local symbols
        // once per file to pick up params/locals that fall inside each range.
        struct Pending {
            name: String,
            address: u32,
            is_static: bool,
            pd: Option<usize>,
            file: usize,
            sym_idx: u32,
        }
        let mut pending: Vec<Pending> = Vec::new();

        // Prefer procedure descriptors: they carry the frame information.
        for (i, pd) in self.procedures.iter().enumerate() {
            let file = self.file_for_address(pd.address);
            let (name, is_static) = match file {
                Some(f) => match self.local_symbol(f, pd.symbol_index) {
                    Ok((sym, name)) => (name, sym.sym_type == SymType::StaticProc),
                    Err(_) => (String::new(), false),
                },
                None => (String::new(), false),
            };
            pending.push(Pending {
                name,
                address: pd.address,
                is_static,
                pd: Some(i),
                file: file.unwrap_or(0),
                sym_idx: pd.symbol_index,
            });
        }

        // Add symbols named PROC/STATICPROC that no descriptor covered (some
        // toolchains emit pds only for functions with frames).
        let mut covered: std::collections::HashSet<(usize, u32)> = std::collections::HashSet::new();
        for p in &pending {
            covered.insert((p.file, p.sym_idx));
        }
        for (file, (isym_base, count)) in self.file_symbol_bases.iter().enumerate() {
            let _ = isym_base;
            for idx in 0..*count {
                let Ok((s, name)) = self.local_symbol(file, idx) else {
                    continue;
                };
                if !s.sym_type.is_function() || name.is_empty() || covered.contains(&(file, idx)) {
                    continue;
                }
                if s.sym_class == SymClass::Text || s.value != 0 {
                    pending.push(Pending {
                        name,
                        address: s.value,
                        is_static: s.sym_type == SymType::StaticProc,
                        pd: None,
                        file,
                        sym_idx: idx,
                    });
                }
            }
        }

        pending.sort_by_key(|p| p.address);
        for (i, p) in pending.iter().enumerate() {
            let end = pending.get(i + 1).map(|n| n.address).unwrap_or(0);
            let size = end.saturating_sub(p.address);
            let pd = p.pd.and_then(|i| self.procedures.get(i));
            let mut f = Function {
                name: if p.name.is_empty() {
                    format!("f_{:08x}", p.address)
                } else {
                    p.name.clone()
                },
                address: p.address,
                size,
                is_static: p.is_static,
                frame_size: pd.map(|p| p.frame_size.max(0) as u32).unwrap_or(0),
                // Masks are bitfields stored in signed words: `$ra` is bit 31,
                // so `max(0)` here would silently drop the return address from
                // every saved-register set. Cast, never clamp.
                saved_register_mask: pd.map(|p| p.saved_register_mask as u32).unwrap_or(0),
                saved_float_register_mask: pd
                    .map(|p| p.saved_float_register_mask as u32)
                    .unwrap_or(0),
                frame_pointer_register: pd.and_then(|p| {
                    (p.frame_pointer_register >= 0).then_some(p.frame_pointer_register as u32)
                }),
                return_pc_register: pd.and_then(|p| {
                    (p.return_pc_register >= 0).then_some(p.return_pc_register as u32)
                }),
                source_file: self.files.get(p.file).and_then(|f| {
                    if f.path.is_empty() {
                        None
                    } else {
                        Some(f.path.clone())
                    }
                }),
                params: Vec::new(),
                locals: Vec::new(),
                return_type: None,
            };
            // Local symbols between this function's PROC entry and the next one
            // are its parameters/locals/typedefs.
            let (lo, hi) = (p.sym_idx, self.next_function_sym(p.file, p.sym_idx));
            for idx in lo.saturating_add(1)..hi {
                let Ok((s, name)) = self.local_symbol(p.file, idx) else {
                    continue;
                };
                let Some(code) = s.stabs_code() else { continue };
                let var = parse_stabs_var(&name, code, s.value, s.sym_class);
                match code {
                    // N_PSYM
                    0xa0 => f.params.push(var),
                    // N_LSYM (locals) and N_RSYM (register locals)
                    0x80 | 0x40 => {
                        if s.sym_type == SymType::Local || s.sym_type == SymType::Param {
                            f.locals.push(var)
                        }
                    }
                    // N_FUN with an empty name marks the end; N_FUN with a name
                    // is a range start we already have.
                    _ => {}
                }
            }
            self.functions.push(f);
        }
        Ok(())
    }

    fn next_function_sym(&self, file: usize, from: u32) -> u32 {
        let count = self
            .file_symbol_bases
            .get(file)
            .map(|(_, c)| *c)
            .unwrap_or(0);
        for idx in from + 1..count {
            if let Ok((s, _)) = self.local_symbol(file, idx) {
                if s.sym_type.is_function() {
                    return idx;
                }
            }
        }
        count
    }

    fn file_for_address(&self, addr: u32) -> Option<usize> {
        let mut best: Option<(u32, usize)> = None;
        for (i, f) in self.files.iter().enumerate() {
            if f.address <= addr {
                match best {
                    Some((a, _)) if a >= f.address => {}
                    _ => best = Some((f.address, i)),
                }
            }
        }
        best.map(|(_, i)| i)
    }

    /// Globals: ELF `.symtab` is usually stripped, so they come from the
    /// `.mdebug` external table plus `N_GSYM`/`N_STSYM`/`N_LCSYM` records.
    pub fn collect_globals(&mut self) -> Result<()> {
        self.globals.clear();
        for (name, value, ty, class) in &self.externals {
            if name.is_empty() {
                continue;
            }
            if matches!(ty, SymType::Proc | SymType::StaticProc) {
                continue;
            }
            self.globals.push(Global {
                name: name.clone(),
                address: *value,
                size: 0,
                raw_type: None,
                section: match class {
                    SymClass::Text => SectionKind::Text,
                    SymClass::Data => SectionKind::Data,
                    SymClass::Bss => SectionKind::Bss,
                    SymClass::Sdata => SectionKind::Sdata,
                    SymClass::Sbss => SectionKind::Sbss,
                    SymClass::Rdata => SectionKind::Rdata,
                    _ => SectionKind::Other,
                },
            });
        }
        for file in 0..self.files.len() {
            let count = self.file_symbol_bases[file].1;
            for idx in 0..count {
                let Ok((s, name)) = self.local_symbol(file, idx) else {
                    continue;
                };
                let Some(code) = s.stabs_code() else { continue };
                // N_GSYM 0x20, N_STSYM 0x26, N_LCSYM 0x28, N_RSYM 0x40
                if !matches!(code, 0x20 | 0x26 | 0x28) || name.is_empty() {
                    continue;
                }
                let var = parse_stabs_var(&name, code, s.value, s.sym_class);
                self.globals.push(Global {
                    name: var.name,
                    address: s.value,
                    size: 0,
                    raw_type: Some(var.raw_type),
                    section: match code {
                        0x26 => SectionKind::Data,
                        0x28 => SectionKind::Bss,
                        _ => SectionKind::Other,
                    },
                });
            }
        }
        self.globals.sort_by_key(|g| g.address);
        self.globals.dedup_by_key(|g| g.address);
        Ok(())
    }

    #[must_use]
    pub fn function_at(&self, addr: u32) -> Option<&Function> {
        // Binary search over the sorted function table.
        let idx = self
            .functions
            .binary_search_by(|f| f.address.cmp(&addr))
            .ok()?;
        self.functions.get(idx)
    }

    /// The function whose address range contains `addr`.
    ///
    /// Kept separate from [`Mdebug::function_at`] on purpose: an exact hit is
    /// what a call target needs, while a listing annotation wants the enclosing
    /// function. Conflating them mislabels every instruction after the first.
    #[must_use]
    pub fn containing_function(&self, addr: u32) -> Option<&Function> {
        if self.functions.is_empty() {
            return None;
        }
        // Last function with address <= addr.
        let i = match self.functions.binary_search_by(|f| f.address.cmp(&addr)) {
            Ok(i) => i,
            Err(0) => return None,
            Err(i) => i - 1,
        };
        let f = self.functions.get(i)?;
        let end = if f.size > 0 {
            f.address.saturating_add(f.size)
        } else {
            self.functions
                .get(i + 1)
                .map(|n| n.address)
                .unwrap_or(u32::MAX)
        };
        (addr < end).then_some(f)
    }

    #[must_use]
    pub fn function_by_name(&self, name: &str) -> Option<&Function> {
        self.functions.iter().find(|f| f.name == name)
    }

    /// Range of a function: explicit size when known, else up to the next one.
    #[must_use]
    pub fn function_range(&self, idx: usize) -> Option<(u32, u32)> {
        let f = self.functions.get(idx)?;
        let end = self
            .functions
            .get(idx + 1)
            .map(|n| n.address)
            .unwrap_or_else(|| f.address.saturating_add(f.size.max(4)));
        Some((f.address, end.max(f.address + 4)))
    }
}

/// Split `name:type` STABS text. Full ECOFF type-graph resolution (following
/// `xtype` indices through the dense table) is a later milestone; the raw
/// descriptor is preserved so nothing is lost in the meantime.
pub fn parse_stabs_var(text: &str, code: u32, value: u32, class: SymClass) -> StabsVar {
    let (name, ty) = match text.find(':') {
        Some(i) => (&text[..i], &text[i + 1..]),
        None => (text, ""),
    };
    let mut stack_offset = None;
    let mut register = None;
    // N_PSYM: `value` is the offset from the frame pointer (negative for
    // locals, positive for incoming args past the saved registers).
    // N_RSYM / N_LSYM with class REGISTER: `value` is the register number.
    match code {
        0xa0 => stack_offset = Some(value as i32),
        0x40 => register = Some(value & 31),
        _ => {
            if class == SymClass::Register {
                register = Some(value & 31);
            } else if class == SymClass::Local {
                stack_offset = Some(value as i32);
            }
        }
    }
    StabsVar {
        name: name.to_string(),
        raw_type: ty.to_string(),
        stack_offset,
        register,
        code,
    }
}

/// Human-readable rendering of a raw STABS type string, good enough to put in a
/// Rust comment. Understands the common SN Systems subset: `int`, `unsigned`,
/// `float`, pointers (`*`), arrays `(t1,t2;-1)`, `x` type references.
pub fn stabs_type_hint(raw: &str) -> String {
    let raw = raw.trim();
    if raw.is_empty() {
        return "?".to_string();
    }
    // Strip the leading 'x' cross-reference marker the MIPS ECOFF emits.
    let body = raw.strip_prefix('x').unwrap_or(raw);
    let base = body.split([':', ';', '(']).next().unwrap_or(body);
    let named = match base {
        "1" | "t1" => "i32",
        "2" | "t2" => "u32",
        "4" | "t4" => "f32",
        "8" | "t8" => "u8",
        "9" | "t9" => "i8",
        "10" => "char",
        "23" => "void",
        "24" | "32" | "33" | "34" => "volatile u32",
        other => return format!("raw({other})"),
    };
    if body.starts_with('*') {
        return format!("*mut {named}");
    }
    named.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sym_bits(index: u32, ty: u32, class: u32) -> RawSymbol {
        RawSymbol {
            iss: 0,
            value: 0,
            sym_type: SymType::from_raw(ty),
            sym_class: SymClass::from_raw(class),
            index,
            array_index: 0,
        }
    }

    #[test]
    fn stabs_code_is_lazy_about_the_subtraction() {
        // `index == 0` is the common case (an ordinary symbol). Eagerly
        // computing `index - 0x8f300` here underflows and panics in debug.
        let plain = sym_bits(0, 6, 1);
        assert!(!plain.is_stabs());
        assert_eq!(plain.stabs_code(), None);
        let undefined = sym_bits(0x8f300, 1, 6);
        assert_eq!(undefined.stabs_code(), Some(0));
        assert_eq!(sym_bits(0x8f300 + 0xa0, 3, 7).stabs_code(), Some(0xa0));
    }

    #[test]
    fn symtype_and_class_tables_cover_what_ps2_builds_emit() {
        assert!(SymType::from_raw(6).is_function());
        assert!(SymType::from_raw(14).is_function());
        assert!(!SymType::from_raw(1).is_function());
        assert!(SymClass::from_raw(1).is_address());
        assert!(
            !SymClass::from_raw(4).is_address(),
            "Register is not an address"
        );
        assert_eq!(SymType::from_raw(99), SymType::Other(99));
        assert_eq!(SymClass::from_raw(31), SymClass::Other(31));
    }

    #[test]
    fn saved_register_mask_expands_including_ra() {
        let pd = ProcedureDescriptor {
            saved_register_mask: 1 << 31 | 1 << 30 | 1 << 23,
            ..Default::default()
        };
        assert_eq!(pd.saved_gprs(), vec![23, 30, 31]);
        let none = ProcedureDescriptor::default();
        assert!(none.saved_gprs().is_empty());
    }
}
