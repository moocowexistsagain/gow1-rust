//! Minimal ELF32 reader for PlayStation 2 executables.
//!
//! PS2 game executables (`SCUS_973.99` and friends) are ordinary 32-bit
//! little-endian MIPS ELF files — no encryption, no compression — which is what
//! makes a decompilation pipeline like this one possible at all. Two details
//! differ from a Linux ELF:
//!
//! * The real symbol information usually lives in a `.mdebug` section holding
//!   an ECOFF *symbolic header* (see [`crate::mdebug`]), not in `.symtab`,
//!   which retail builds are normally stripped down to nothing.
//! * Section addresses/offsets are laid out for the EE's 32-bit physical address
//!   map (kernel `.text` at `0x8000_0000`-ish aliases, game code around
//!   `0x0010_0000`), so vaddr→file-offset translation must go through the
//!   program headers, with the section table as a fallback.

use std::fmt;

/// Everything that can go wrong while parsing. Kept as a string-carrying enum
/// because the messages need to include offsets, and this crate has no
/// dependencies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseError(pub String);

impl ParseError {
    pub fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for ParseError {}

pub type Result<T> = std::result::Result<T, ParseError>;

// ELF constants we actually need.
pub const ELFMAG: [u8; 4] = [0x7f, b'E', b'L', b'F'];
pub const ELFCLASS32: u8 = 1;
pub const ELFDATA2LSB: u8 = 1;
pub const EM_MIPS: u16 = 8;
pub const ET_EXEC: u16 = 2;
pub const ET_REL: u16 = 1;

pub const SHT_PROGBITS: u32 = 1;
pub const SHT_SYMTAB: u32 = 2;
pub const SHT_STRTAB: u32 = 3;
pub const SHT_NOBITS: u32 = 8;
/// MIPS-specific: register usage info, present in nearly every PS2 executable.
pub const SHT_MIPS_REGINFO: u32 = 0x7000_002a;
pub const PT_LOAD: u32 = 1;

/// ELF flags for MIPS. The low bits carry the ABI; PS2 retail binaries built
/// with the SN Systems toolchain typically report `EF_MIPS_ABI_O32`.
pub const EF_MIPS_ABI_O32: u32 = 0x0000_1000;
pub const EF_MIPS_NOREORDER: u32 = 0x0000_0001;
pub const EF_MIPS_CPIC: u32 = 0x0000_0009;

#[derive(Clone, Copy, Debug, Default)]
pub struct Header {
    pub kind: u16,
    pub machine: u16,
    pub version: u32,
    pub entry: u32,
    pub phoff: u32,
    pub shoff: u32,
    pub flags: u32,
    pub ehsize: u16,
    pub phentsize: u16,
    pub phnum: u16,
    pub shentsize: u16,
    pub shnum: u16,
    pub shstrndx: u16,
}

#[derive(Clone, Debug)]
pub struct Section {
    /// Index of the name in `.shstrtab`.
    pub name_offset: u32,
    pub name: String,
    pub sh_type: u32,
    pub flags: u32,
    pub addr: u32,
    pub offset: u32,
    pub size: u32,
    pub link: u32,
    pub info: u32,
    pub align: u32,
    pub entsize: u32,
}

impl Section {
    #[must_use]
    pub fn contains_vaddr(&self, v: u32) -> bool {
        self.sh_type != SHT_NOBITS && v >= self.addr && v < self.addr.saturating_add(self.size)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ProgramHeader {
    pub p_type: u32,
    pub offset: u32,
    pub vaddr: u32,
    pub paddr: u32,
    pub filesz: u32,
    pub memsz: u32,
    pub flags: u32,
    pub align: u32,
}

/// An `Elf32_Sym` entry.
#[derive(Clone, Debug)]
pub struct Sym {
    pub name: String,
    pub value: u32,
    pub size: u32,
    pub info: u8,
    pub other: u8,
    pub shndx: u16,
}

impl Sym {
    #[must_use]
    pub fn is_func(&self) -> bool {
        self.info & 0xf == 2
    }
    #[must_use]
    pub fn is_object(&self) -> bool {
        self.info & 0xf == 1
    }
    #[must_use]
    pub fn is_section(&self) -> bool {
        self.info & 0xf == 3
    }
    /// STB_GLOBAL == 1, STB_WEAK == 2.
    #[must_use]
    pub fn bind(&self) -> u8 {
        self.info >> 4
    }
}

/// Bounds-checked little-endian cursor over the file image.
#[derive(Clone, Copy)]
pub(crate) struct Reader<'a> {
    pub data: &'a [u8],
}

impl<'a> Reader<'a> {
    #[must_use]
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    pub fn slice(&self, off: u32, len: u32) -> Result<&'a [u8]> {
        let start = off as usize;
        let end = start
            .checked_add(len as usize)
            .ok_or_else(|| ParseError::new(format!("range overflow at {off:#x} + {len:#x}")))?;
        self.data.get(start..end).ok_or_else(|| {
            ParseError::new(format!(
                "offset {off:#x}+{len:#x} past EOF ({:#x})",
                self.data.len()
            ))
        })
    }

    pub fn u8(&self, off: u32) -> Result<u8> {
        Ok(*self
            .data
            .get(off as usize)
            .ok_or_else(|| ParseError::new(format!("u8 at {off:#x} out of bounds")))?)
    }
    pub fn u16(&self, off: u32) -> Result<u16> {
        let s = self.slice(off, 2)?;
        Ok(u16::from_le_bytes([s[0], s[1]]))
    }
    pub fn u32(&self, off: u32) -> Result<u32> {
        let s = self.slice(off, 4)?;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }
    pub fn i32(&self, off: u32) -> Result<i32> {
        Ok(self.u32(off)? as i32)
    }
}

/// A parsed PS2 executable. Borrows the image, so callers own the bytes.
pub struct Elf<'a> {
    r: Reader<'a>,
    header: Header,
    sections: Vec<Section>,
    segments: Vec<ProgramHeader>,
    shstrtab: &'a [u8],
}

impl<'a> Elf<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        let r = Reader::new(data);
        if data.len() < 52 {
            return Err(ParseError::new("file shorter than an ELF32 header"));
        }
        if data[0..4] != ELFMAG {
            return Err(ParseError::new(
                "not an ELF file (missing \\x7fELF magic) — is this the disc's executable and not an ISO?",
            ));
        }
        if data[4] != ELFCLASS32 {
            return Err(ParseError::new(format!(
                "ELF class {} (want 32-bit: PS2 executables are ELFCLASS32)",
                data[4]
            )));
        }
        if data[5] != ELFDATA2LSB {
            return Err(ParseError::new(
                "ELF is big-endian; PS2 EE executables are little-endian",
            ));
        }
        let header = Header {
            kind: r.u16(16)?,
            machine: r.u16(18)?,
            version: r.u32(20)?,
            entry: r.u32(24)?,
            phoff: r.u32(28)?,
            shoff: r.u32(32)?,
            flags: r.u32(36)?,
            ehsize: r.u16(40)?,
            phentsize: r.u16(42)?,
            phnum: r.u16(44)?,
            shentsize: r.u16(46)?,
            shnum: r.u16(48)?,
            shstrndx: r.u16(50)?,
        };
        if header.machine != EM_MIPS {
            return Err(ParseError::new(format!(
                "e_machine = {} (want {EM_MIPS} = EM_MIPS)",
                header.machine
            )));
        }
        if header.kind != ET_EXEC && header.kind != ET_REL {
            return Err(ParseError::new(format!(
                "unexpected e_type {} (expected ET_EXEC for a game executable)",
                header.kind
            )));
        }

        let mut sections = Vec::new();
        if header.shoff != 0 && header.shnum != 0 {
            let entsize = if header.shentsize == 0 {
                40
            } else {
                header.shentsize
            };
            for i in 0..header.shnum as u32 {
                let base = header.shoff + i * entsize as u32;
                // Elf32_Shdr: name 0, type 4, flags 8, addr 12, offset 16,
                // size 20, link 24, info 28, addralign 32, entsize 36.
                sections.push(Section {
                    name_offset: r.u32(base)?,
                    name: String::new(),
                    sh_type: r.u32(base + 4)?,
                    flags: r.u32(base + 8)?,
                    addr: r.u32(base + 12)?,
                    offset: r.u32(base + 16)?,
                    size: r.u32(base + 20)?,
                    link: r.u32(base + 24)?,
                    info: r.u32(base + 28)?,
                    align: r.u32(base + 32)?,
                    entsize: r.u32(base + 36)?,
                });
            }
        }
        let shstrtab = match sections.get(header.shstrndx as usize) {
            Some(s) => r.slice(s.offset, s.size)?,
            None => &[],
        };
        for s in &mut sections {
            s.name = cstr_at(shstrtab, s.name_offset);
        }

        let mut segments = Vec::new();
        if header.phoff != 0 && header.phnum != 0 {
            let entsize = if header.phentsize == 0 {
                32
            } else {
                header.phentsize
            };
            for i in 0..header.phnum as u32 {
                let base = header.phoff + i * entsize as u32;
                segments.push(ProgramHeader {
                    p_type: r.u32(base)?,
                    offset: r.u32(base + 4)?,
                    vaddr: r.u32(base + 8)?,
                    paddr: r.u32(base + 12)?,
                    filesz: r.u32(base + 16)?,
                    memsz: r.u32(base + 20)?,
                    flags: r.u32(base + 24)?,
                    align: r.u32(base + 28)?,
                });
            }
        }

        Ok(Self {
            r,
            header,
            sections,
            segments,
            shstrtab,
        })
    }

    #[must_use]
    pub fn header(&self) -> &Header {
        &self.header
    }
    #[must_use]
    pub fn data(&self) -> &'a [u8] {
        self.r.data
    }
    #[must_use]
    pub fn entry(&self) -> u32 {
        self.header.entry
    }
    #[must_use]
    pub fn sections(&self) -> &[Section] {
        &self.sections
    }
    #[must_use]
    pub fn segments(&self) -> &[ProgramHeader] {
        &self.segments
    }
    #[must_use]
    pub fn section(&self, name: &str) -> Option<&Section> {
        self.sections.iter().find(|s| s.name == name)
    }
    pub fn section_data(&self, s: &Section) -> Result<&'a [u8]> {
        if s.sh_type == SHT_NOBITS {
            return Ok(&[]);
        }
        self.r.slice(s.offset, s.size)
    }
    pub fn section_by_name(&self, name: &str) -> Result<&'a [u8]> {
        let s = self
            .section(name)
            .ok_or_else(|| ParseError::new(format!("no section named {name:?}")))?;
        self.section_data(s)
    }

    /// The `.mdebug` section, if the executable was not fully stripped.
    #[must_use]
    pub fn mdebug_section(&self) -> Option<(&Section, u32)> {
        // Some toolchains name it `.debug`; both appear in PS2 binaries.
        for n in [".mdebug", ".debug"] {
            if let Some(s) = self.section(n) {
                return Some((s, s.offset));
            }
        }
        None
    }

    /// Translate a virtual address to a file offset. Program headers first
    /// (authoritative for loaded images), then section headers.
    #[must_use]
    pub fn vaddr_to_offset(&self, vaddr: u32) -> Option<u32> {
        for p in &self.segments {
            if p.p_type == PT_LOAD && vaddr >= p.vaddr && vaddr < p.vaddr.saturating_add(p.filesz) {
                return Some(p.offset + (vaddr - p.vaddr));
            }
        }
        for s in &self.sections {
            if s.contains_vaddr(vaddr) {
                return Some(s.offset + (vaddr - s.addr));
            }
        }
        None
    }

    #[must_use]
    pub fn read_vaddr(&self, vaddr: u32, len: u32) -> Option<&'a [u8]> {
        let off = self.vaddr_to_offset(vaddr)?;
        self.r.slice(off, len).ok()
    }

    /// `.text` contents plus its virtual base — the primary analysis input.
    #[must_use]
    pub fn text(&self) -> Option<(u32, &'a [u8])> {
        let s = self.section(".text")?;
        (s.addr, self.section_data(s).ok()?).into()
    }

    /// ELF symbol table, if one survived.
    pub fn symtab(&self) -> Result<Vec<Sym>> {
        let s = self
            .section(".symtab")
            .ok_or_else(|| ParseError::new("no .symtab section"))?;
        let data = self.section_data(s)?;
        let strtab_sec = self
            .sections
            .get(s.link as usize)
            .ok_or_else(|| ParseError::new(".symtab has a bad sh_link"))?;
        let strtab = self.section_data(strtab_sec)?;
        let entsize = if s.entsize == 0 { 16 } else { s.entsize };
        let mut out = Vec::new();
        let mut off = 0u32;
        while off + entsize <= data.len() as u32 {
            let nameoff = self.r.u32(s.offset + off)?;
            out.push(Sym {
                name: cstr_at(strtab, nameoff),
                value: self.r.u32(s.offset + off + 4)?,
                size: self.r.u32(s.offset + off + 8)?,
                info: self.r.u8(s.offset + off + 12)?,
                other: self.r.u8(s.offset + off + 13)?,
                shndx: self.r.u16(s.offset + off + 14)?,
            });
            off += entsize;
        }
        Ok(out)
    }

    #[must_use]
    pub fn section_name_table(&self) -> &'a [u8] {
        self.shstrtab
    }
}

pub(crate) fn cstr_at(data: &[u8], off: u32) -> String {
    let start = off as usize;
    if start >= data.len() {
        return String::new();
    }
    let end = data[start..]
        .iter()
        .position(|&b| b == 0)
        .map(|p| start + p)
        .unwrap_or(data.len());
    String::from_utf8_lossy(&data[start..end]).into_owned()
}
