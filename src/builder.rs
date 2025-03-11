//! Contains everything required for building ELF files.
//!
//! The main type is [`ElfBuilder`], which can be used to construct the ELF file and build it into
//! bytes.
//!
//! # Examples
//!
//! See [tests/builder.rs](https://github.com/renshyle/eelf/blob/main/tests/builder.rs).

use std::{borrow::Cow, io::Write, num::TryFromIntError};

use num_traits::ToPrimitive;

use crate::{
    consts::{
        SectionKind, SymbolKind, ELF64_HEADER_SIZE, ELF64_PROGRAM_HEADER_SIZE,
        ELF64_SECTION_HEADER_SIZE, ELF_MAGIC,
    },
    flagset::FlagSet,
    Endianness, MachineKind, SegmentKind,
};

use super::{
    consts::{ELF32_HEADER_SIZE, ELF32_PROGRAM_HEADER_SIZE, ELF32_SECTION_HEADER_SIZE},
    ElfKind, SectionFlag, SegmentFlag,
};

mod elf32;
mod elf64;

// The built ELF file's section headers look as follows:
// ----------------
// |   section 1  |
// |     ...      |
// |   section n  |
// | symbol table |
// | relocation 1 |
// |     ...      |
// | relocation n |
// | string table |
// ----------------
//
// Sections 1..=n are the ones added with ElfBuilder::add_section. A symbol table is included if
// ElfBuilder::should_build_symbol_table() == true, which happens if the symbol table's ID has been
// requested using ElfBuilder::symbol_table or if a symbol has been added to the symbol table.

/// A builder for ELF object files.
#[derive(Debug, Clone)]
pub struct ElfBuilder<'data> {
    sections: Vec<Section<'data>>,
    strings: Vec<String>,
    symbols: Vec<Symbol>,
    relocations: Vec<RelocationTable>,
    segments: Vec<Segment>,
    entrypoint: u64,
    kind: ElfKind,
    machine: MachineKind,
    endianness: Endianness,
    is_64bit: bool,
    /// Whether a symbol table, even an empty one, is required
    symbol_table_needed: bool,
}

impl<'data> ElfBuilder<'data> {
    /// Creates a new `ElfBuilder` object.
    pub fn new(
        kind: ElfKind,
        machine: MachineKind,
        is_64bit: bool,
        endianness: Endianness,
    ) -> Self {
        Self {
            sections: vec![Section {
                data: Cow::Borrowed(&[]),
                name: StringId::empty(),
                kind: SectionKind::Null,
                flags: Default::default(),
                info: 0,
                vaddr: 0,
                entsize: 0,
                alignment: 0,
            }],
            strings: vec![String::new()],
            symbols: vec![Symbol {
                name: StringId::empty(),
                value: 0,
                size: 0,
                global: false,
                kind: SymbolKind::NoType,
                section: SectionId {
                    inner: SectionIdInner::Id(0),
                },
            }],
            relocations: Vec::new(),
            segments: Vec::new(),
            entrypoint: 0,
            kind,
            machine,
            endianness,
            is_64bit,
            symbol_table_needed: false,
        }
    }

    /// Builds the ELF file, consuming the builder.
    pub fn build<W: Write>(self, mut target: W) -> std::io::Result<()> {
        let mut builder = self;
        let endianness = builder.endianness;

        let mut symbol_table = Vec::new();

        if builder.is_64bit {
            for symbol in &builder.symbols {
                symbol_table
                    .extend_from_slice(&endianness.u32_to_bytes(symbol.name.try_into().unwrap()));
                let info = symbol.kind.to_u8().unwrap() | if symbol.global { 16 } else { 0 };
                symbol_table.push(info);
                symbol_table.push(0); // other, always 0
                let section = match symbol.section {
                    SectionId {
                        inner: SectionIdInner::Id(id),
                    } => id,
                    _ => todo!(),
                };
                symbol_table.extend_from_slice(&endianness.u16_to_bytes(section));

                symbol_table.extend_from_slice(&endianness.u64_to_bytes(symbol.value));
                symbol_table.extend_from_slice(&endianness.u64_to_bytes(symbol.size));
            }
        } else {
            for symbol in &builder.symbols {
                symbol_table
                    .extend_from_slice(&endianness.u32_to_bytes(symbol.name.try_into().unwrap()));
                symbol_table
                    .extend_from_slice(&endianness.u32_to_bytes(symbol.value.try_into().unwrap()));
                symbol_table
                    .extend_from_slice(&endianness.u32_to_bytes(symbol.size.try_into().unwrap()));

                let info = symbol.kind.to_u8().unwrap() | if symbol.global { 16 } else { 0 };
                symbol_table.push(info);
                symbol_table.push(0); // other, always 0

                let section = match symbol.section {
                    SectionId {
                        inner: SectionIdInner::Id(id),
                    } => id,
                    _ => todo!(),
                };
                symbol_table.extend_from_slice(&endianness.u16_to_bytes(section));
            }
        }

        if builder.should_build_symbol_table() {
            let name = builder.add_string(".symtab");
            builder.add_section(Section {
                name,
                data: Cow::Borrowed(&symbol_table),
                kind: SectionKind::SymbolTable,
                flags: Default::default(),
                vaddr: 0,
                entsize: if builder.is_64bit { 24 } else { 16 },
                alignment: 0,
                info: builder.symbols.len().try_into().unwrap(),
            });
        }

        let mut relocation_sections = Vec::new();

        for table in &builder.relocations {
            match table {
                RelocationTable::Rela(table) => {
                    let relocation_table = table.to_bytes(endianness, builder.is_64bit);

                    relocation_sections.push((
                        table.target_section,
                        table.name,
                        SectionKind::Rela,
                        if builder.is_64bit { 24 } else { 12 },
                        Cow::Owned(relocation_table),
                    ));
                }
                RelocationTable::Rel(table) => {
                    let relocation_table = table.to_bytes(endianness, builder.is_64bit);

                    relocation_sections.push((
                        table.target_section,
                        table.name,
                        SectionKind::Rel,
                        if builder.is_64bit { 16 } else { 8 },
                        Cow::Owned(relocation_table),
                    ));
                }
            }
        }

        relocation_sections
            .into_iter()
            .for_each(|(section, name, kind, entsize, data)| {
                builder.add_section(Section {
                    name,
                    data,
                    kind,
                    flags: Default::default(),
                    vaddr: 0,
                    entsize,
                    alignment: 0,
                    info: match section {
                        SectionId {
                            inner: SectionIdInner::Id(id),
                        } => id.into(),
                        _ => todo!(),
                    },
                });
            });

        // need to add the string before building the string table bytes
        let strtab_string = builder.add_string(".strtab");

        let mut string_table = Vec::new();

        for string in &builder.strings {
            string_table.extend_from_slice(string.as_bytes());
            string_table.push(0);
        }

        builder.add_section(Section {
            name: strtab_string,
            data: Cow::Borrowed(&string_table),
            kind: SectionKind::StringTable,
            flags: Default::default(),
            vaddr: 0,
            info: 0,
            entsize: 0,
            alignment: 0,
        });

        if builder.is_64bit {
            elf64::write_header(&builder, &mut target)?;
            elf64::write_phdrs(&builder, &mut target)?;
            builder.write_sections(&mut target)?;
            elf64::write_section_headers(&builder, &mut target)?;
        } else {
            elf32::write_header(&builder, &mut target)?;
            elf32::write_phdrs(&builder, &mut target)?;
            builder.write_sections(&mut target)?;
            elf32::write_section_headers(&builder, &mut target)?;
        }

        Ok(())
    }

    fn write_sections<W: Write>(&mut self, mut target: W) -> std::io::Result<()> {
        for section in &self.sections {
            target.write_all(&section.data)?;
        }

        Ok(())
    }

    fn should_build_symbol_table(&self) -> bool {
        self.symbol_table_needed || self.symbols.len() > 1
    }

    /// Returns the index of the symbol table in the section headers. May only be used after all
    /// sections, including the symbol table, relocations, and the string table have been built.
    fn symbol_table_index(&self) -> u16 {
        // -1 for the string table, another -1 for the symbol table
        (self.sections.len() - self.relocations.len() - 2)
            .try_into()
            .unwrap()
    }

    /// Returns the index of the string table in the section headers. May only be used after all
    /// sections, including the symbol table, relocations, and the string table have been built.
    fn string_table_index(&self) -> u16 {
        (self.sections.len() - 1).try_into().unwrap()
    }

    /// Returns the index of a section in the section headers. May only be used after all sections,
    /// including the symbol table, relocations, and the string table have been built.
    fn section_index(&self, section_id: SectionId) -> u16 {
        let SectionId { inner: section_id } = section_id;

        match section_id {
            SectionIdInner::SymbolTable => self.symbol_table_index(),
            SectionIdInner::StringTable => self.string_table_index(),
            SectionIdInner::Id(id) => id,
        }
    }

    /// Adds a section to the section table and the data to the ELF file. Returns the index at which
    /// the section was added.
    ///
    /// # Panics
    ///
    /// Panics if the virtual address, entry size, or alignment is greater than [`u32::MAX`] and the
    /// ELF file is 32-bit
    pub fn add_section(&mut self, section: Section<'data>) -> SectionId {
        if !self.is_64bit {
            assert!(section.vaddr <= u32::MAX.into());
            assert!(section.entsize <= u32::MAX.into());
            assert!(section.alignment <= u32::MAX.into());
        }

        self.sections.push(section);
        SectionId {
            inner: SectionIdInner::Id((self.sections.len() - 1).try_into().unwrap()),
        }
    }

    /// Adds a segment entry into the program header. The segment type must not be
    /// [`SegmentKind::Phdr`].
    ///
    /// # Panics
    ///
    /// Panics if
    /// * the segment type is [`SegmentKind::Phdr`], or
    /// * memsz is less than filesz.
    pub fn add_segment(&mut self, segment: Segment) {
        assert!(segment.memsz >= segment.filesz);
        assert!(segment.kind != SegmentKind::Phdr);

        self.segments.push(segment);
    }

    /// Adds a string to the string table if it doesn't exist already and returns its index.
    pub fn add_string(&mut self, string: impl Into<String> + AsRef<str>) -> StringId {
        let mut found = false;
        let mut offset = 0;
        for s in &self.strings {
            if s == string.as_ref() {
                found = true;
                break;
            }

            offset += s.len() + 1; // 1 for the null byte
        }

        if !found {
            self.strings.push(string.into());
        }

        StringId {
            offset: offset.try_into().unwrap(),
        }
    }

    /// Adds a symbol to the symbol table. The name is added to the string table. Returns the index
    /// of the symbol in the symbol table.
    ///
    /// # Panics
    ///
    /// Panics if the value or size is greater than [`u32::MAX`] and the ELF file is 32-bit.
    pub fn add_symbol(
        &mut self,
        name: impl Into<String> + AsRef<str>,
        value: u64,
        size: u64,
        global: bool,
        kind: SymbolKind,
        section: SectionId,
    ) -> SymbolId {
        let name_index = self.add_string(name);

        if !self.is_64bit {
            assert!(value <= u32::MAX.into());
            assert!(size <= u32::MAX.into());
        }

        self.symbols.push(Symbol {
            name: name_index,
            value,
            size,
            global,
            kind,
            section,
        });

        SymbolId {
            index: (self.symbols.len() - 1).try_into().unwrap(),
        }
    }

    /// Finds the index of a section in the section table by name. If it doesn't exist, [`None`] is
    /// returned.
    pub fn find_section(&self, name: &str) -> Option<SectionId> {
        let name_index = self.find_string(name)?;

        self.sections
            .iter()
            .position(|section| section.name == name_index)
            .map(|pos| SectionId {
                inner: SectionIdInner::Id(pos.try_into().unwrap()),
            })
    }

    /// Creates a new Rel-type relocation table. The table is not added; it must be added with
    /// [`ElfBuilder::add_relocation_table`]
    pub fn create_rel_table(
        &mut self,
        name: impl Into<String> + AsRef<str>,
        section: SectionId,
    ) -> RelTable {
        let name = self.add_string(name);

        RelTable {
            name,
            target_section: section,
            relocations: Vec::new(),
        }
    }

    /// Creates a new Rela-type relocation table. The table is not added; it must be added with
    /// [`ElfBuilder::add_relocation_table`]
    pub fn create_rela_table(
        &mut self,
        name: impl Into<String> + AsRef<str>,
        section: SectionId,
    ) -> RelaTable {
        let name = self.add_string(name);

        RelaTable {
            name,
            target_section: section,
            relocations: Vec::new(),
        }
    }

    /// Adds a relocation table to a section.
    pub fn add_relocation_table(&mut self, table: RelocationTable) {
        self.relocations.push(table);
    }

    /// Finds the index of a string in the string table. If it doesn't exist, [`None`] is returned.
    pub fn find_string(&self, string: &str) -> Option<StringId> {
        let mut offset = 0;
        for s in &self.strings {
            if s == string {
                return Some(StringId {
                    offset: offset.try_into().unwrap(),
                });
            }

            offset += s.len() + 1; // 1 for the null byte
        }

        None
    }

    /// Finds the index of a symbol in the symbol table. If it doesn't exist, [`None`] is returned.
    pub fn find_symbol(&self, name: &str) -> Option<SymbolId> {
        let name_index = self.find_string(name)?;

        self.symbols
            .iter()
            .position(|symbol| symbol.name == name_index)
            .map(|pos| SymbolId {
                index: pos.try_into().unwrap(),
            })
    }

    /// Sets the address the ELF file, if executable, will start executing at.
    ///
    /// # Panics
    ///
    /// Panics if the entrypoint is greater than [`u32::MAX`] for 32-bit files.
    pub fn set_entrypoint(&mut self, entrypoint: u64) {
        if !self.is_64bit {
            assert!(entrypoint <= u32::MAX.into());
        }

        self.entrypoint = entrypoint;
    }

    /// Returns the section ID of the first section, the null section.
    pub fn null_section(&self) -> SectionId {
        SectionId {
            inner: SectionIdInner::Id(0),
        }
    }

    /// Returns the section ID of the symbol table.
    pub fn symbol_table(&mut self) -> SectionId {
        self.symbol_table_needed = true;

        SectionId {
            inner: SectionIdInner::SymbolTable,
        }
    }

    /// Returns the section ID of the string table.
    pub fn string_table(&self) -> SectionId {
        SectionId {
            inner: SectionIdInner::StringTable,
        }
    }
}

/// A section in an ELF file
#[derive(Debug, Clone)]
pub struct Section<'a> {
    /// The data the section contains.
    pub data: Cow<'a, [u8]>,
    /// The name of the section
    pub name: StringId,
    /// The type of the section
    pub kind: SectionKind,
    /// Section flags
    pub flags: FlagSet<SectionFlag>,
    /// The virtual address the section is loaded at
    pub vaddr: u64,
    /// Extra information
    pub info: u32,
    /// If the section contains an array of entries, the size of a single entry in bytes
    pub entsize: u64,
    /// The required alignment of the virtual address
    pub alignment: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SectionIdInner {
    SymbolTable,
    StringTable,
    Id(u16),
}

/// Represents the ID of a section in an ELF file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SectionId {
    inner: SectionIdInner,
}

/// Represents the ID of a string in the string table of an ELF file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StringId {
    offset: u64,
}

impl StringId {
    /// The string ID of an empty string in all ELF files.
    pub fn empty() -> StringId {
        StringId { offset: 0 }
    }
}

impl From<StringId> for u64 {
    fn from(val: StringId) -> Self {
        val.offset
    }
}

impl TryFrom<StringId> for u32 {
    type Error = TryFromIntError;

    fn try_from(val: StringId) -> Result<u32, TryFromIntError> {
        val.offset.try_into()
    }
}

/// Represents the ID of a symbol in the symbol table of an ELF file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SymbolId {
    index: u64,
}

impl From<SymbolId> for u64 {
    fn from(value: SymbolId) -> Self {
        value.index
    }
}

/// A segment in the program header of an ELF file
#[derive(Debug, Clone)]
pub struct Segment {
    /// The index of the section the segment refers to
    pub section: SectionId,
    /// The type of the segment
    pub kind: SegmentKind,
    /// The virtual address of the segment
    pub vaddr: u64,
    /// The physical address of the segment
    pub paddr: u64,
    /// The size of the segment's data stored in the ELF file
    pub filesz: u64,
    /// The size of the segment's data in memory
    pub memsz: u64,
    /// Segment flags
    pub flags: FlagSet<SegmentFlag>,
    /// The required alignment of the virtual address
    pub align: u64,
}

/// A table containing relocations of a specific type of a section
#[derive(Debug, Clone)]
pub enum RelocationTable {
    /// Rel-type relocation table
    Rel(RelTable),
    /// Rela-type relocation table
    Rela(RelaTable),
}

/// A table containing the Rela-type relocations for a section
#[derive(Debug, Clone)]
pub struct RelaTable {
    name: StringId,
    target_section: SectionId,
    relocations: Vec<RelaEntry>,
}

impl RelaTable {
    /// Adds a relocation to the relocation table.
    pub fn add(&mut self, relocation: RelaEntry) {
        self.relocations.push(relocation);
    }

    /// Converts the relocation table to ELF section bytes.
    ///
    /// # Panics
    ///
    /// Panics if is_64bit is false and one of the relocation entries does not fit in 32 bits.
    fn to_bytes(&self, endianness: Endianness, is_64bit: bool) -> Vec<u8> {
        let mut relocation_table = Vec::new();

        if is_64bit {
            for relocation in &self.relocations {
                relocation_table.extend_from_slice(&endianness.u64_to_bytes(relocation.offset));
                relocation_table.extend_from_slice(&endianness.u64_to_bytes(relocation.info));
                relocation_table.extend_from_slice(&endianness.u64_to_bytes(relocation.addend));
            }
        } else {
            for relocation in &self.relocations {
                relocation_table.extend_from_slice(
                    &endianness.u32_to_bytes(relocation.offset.try_into().unwrap()),
                );
                relocation_table.extend_from_slice(
                    &endianness.u32_to_bytes(relocation.info.try_into().unwrap()),
                );
                relocation_table.extend_from_slice(
                    &endianness.u32_to_bytes(relocation.addend.try_into().unwrap()),
                );
            }
        }

        relocation_table
    }
}

/// A table containing the Rel-type relocations for a section
#[derive(Debug, Clone)]
pub struct RelTable {
    name: StringId,
    target_section: SectionId,
    relocations: Vec<RelEntry>,
}

impl RelTable {
    /// Adds a relocation to the relocation table.
    pub fn add(&mut self, relocation: RelEntry) {
        self.relocations.push(relocation);
    }

    /// Converts the relocation table to ELF section bytes.
    ///
    /// # Panics
    ///
    /// Panics if is_64bit is false and one of the relocation entries does not fit in 32 bits.
    fn to_bytes(&self, endianness: Endianness, is_64bit: bool) -> Vec<u8> {
        let mut relocation_table = Vec::new();

        if is_64bit {
            for relocation in &self.relocations {
                relocation_table.extend_from_slice(&endianness.u64_to_bytes(relocation.offset));
                relocation_table.extend_from_slice(&endianness.u64_to_bytes(relocation.info));
            }
        } else {
            for relocation in &self.relocations {
                relocation_table.extend_from_slice(
                    &endianness.u32_to_bytes(relocation.offset.try_into().unwrap()),
                );
                relocation_table.extend_from_slice(
                    &endianness.u32_to_bytes(relocation.info.try_into().unwrap()),
                );
            }
        }

        relocation_table
    }
}

#[derive(Debug, Clone)]
struct Symbol {
    name: StringId,
    value: u64,
    size: u64,
    global: bool,
    kind: SymbolKind,
    section: SectionId,
}

/// An `Elf_Rela`-type relocation entry
#[derive(Debug, Clone)]
pub struct RelaEntry {
    /// The offset which the relocation should be applied at
    pub offset: u64,
    /// Symbol table index and type of relocation
    pub info: u64,
    /// Constant addend to be used in the calculation
    pub addend: u64,
}

/// An `Elf_Rel`-type relocation entry
#[derive(Debug, Clone)]
pub struct RelEntry {
    /// The offset which the relocation should be applied at
    pub offset: u64,
    /// Symbol table index and type of relocation
    pub info: u64,
}
