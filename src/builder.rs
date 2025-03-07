//! Contains everything required for building ELF files.
//!
//! The main type is [`ElfBuilder`], which can be used to construct the ELF file and build it into
//! bytes.

use std::{borrow::Cow, io::Write};

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

impl From<SectionFlag> for Option<SegmentFlag> {
    fn from(val: SectionFlag) -> Self {
        match val {
            SectionFlag::Write => Some(SegmentFlag::Write),
            SectionFlag::Alloc => None,
            SectionFlag::ExecInstr => Some(SegmentFlag::Execute),
            _ => todo!(),
        }
    }
}

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
                name: 0,
                kind: SectionKind::Null,
                flags: Default::default(),
                info: 0,
                vaddr: 0,
                entsize: 0,
                alignment: 0,
            }],
            strings: vec![String::new()],
            symbols: vec![Symbol {
                name: 0,
                value: 0,
                size: 0,
                global: false,
                kind: SymbolKind::NoType,
                section: 0,
            }],
            relocations: Vec::new(),
            segments: Vec::new(),
            entrypoint: 0,
            kind,
            machine,
            endianness,
            is_64bit,
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
                symbol_table.extend_from_slice(&endianness.u16_to_bytes(symbol.section));

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

                symbol_table.extend_from_slice(&endianness.u16_to_bytes(symbol.section));
            }
        }

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

        let mut relocation_sections = Vec::new();

        for table in &builder.relocations {
            match table {
                RelocationTable::Rela(table) => {
                    let relocation_table = table.to_bytes(endianness, builder.is_64bit);

                    relocation_sections.push((
                        table.target_section,
                        table.name,
                        Cow::Owned(relocation_table),
                    ));
                }
                RelocationTable::Rel(table) => {
                    let relocation_table = table.to_bytes(endianness, builder.is_64bit);

                    relocation_sections.push((
                        table.target_section,
                        table.name,
                        Cow::Owned(relocation_table),
                    ));
                }
            }
        }

        relocation_sections
            .into_iter()
            .for_each(|(index, name, data)| {
                builder.add_section(Section {
                    name,
                    data,
                    kind: SectionKind::Rela,
                    flags: Default::default(),
                    vaddr: 0,
                    entsize: if builder.is_64bit { 24 } else { 12 },
                    alignment: 0,
                    info: index.try_into().unwrap(),
                });
            });

        // need to add the string before building the string table bytes
        builder.add_string(".strtab");

        let mut string_table = Vec::new();

        for string in &builder.strings {
            string_table.extend_from_slice(string.as_bytes());
            string_table.push(0);
        }

        builder.add_section(Section {
            name: builder.find_string(".strtab").unwrap(),
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

    /// Adds a section to the section table and the data to the ELF file. Returns the index at which
    /// the section was added.
    ///
    /// # Panics
    ///
    /// Panics, if
    /// * the virtual address, entry size, or alignment is greater than [`u32::MAX`] and the ELF
    ///   file is 32-bit, or
    /// * the name field in the section is invalid.
    pub fn add_section(&mut self, section: Section<'data>) -> usize {
        if !self.is_64bit {
            assert!(section.vaddr <= u32::MAX.into());
            assert!(section.entsize <= u32::MAX.into());
            assert!(section.alignment <= u32::MAX.into());
        }

        assert!(section.name < self.strings.iter().map(|s| s.len() + 1).sum());

        self.sections.push(section);
        self.sections.len() - 1
    }

    /// Adds a segment entry into the program header. The segment type must not be
    /// [`SegmentKind::Phdr`].
    ///
    /// # Panics
    ///
    /// Panics, if
    /// * the segment type is [`SegmentKind::Phdr`], or
    /// * memsz is less than filesz.
    pub fn add_segment(&mut self, segment: Segment) {
        assert!(segment.memsz >= segment.filesz);
        assert!(segment.kind != SegmentKind::Phdr);

        self.segments.push(segment);
    }

    /// Adds a string to the string table if it doesn't exist already and returns its index.
    pub fn add_string(&mut self, string: impl Into<String> + AsRef<str>) -> usize {
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

        offset
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
        section: u16,
    ) -> usize {
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

        self.symbols.len() - 1
    }

    /// Finds the index of a section in the section table by name. If it doesn't exist, [`None`] is
    /// returned.
    pub fn find_section(&self, name: &str) -> Option<usize> {
        let name_index = self.find_string(name)?;

        self.sections
            .iter()
            .position(|section| section.name == name_index)
    }

    /// Creates a new Rel-type relocation table. The table is not added; it must be added with
    /// [`ElfBuilder::add_relocation_table`]
    pub fn create_rel_table(
        &mut self,
        name: impl Into<String> + AsRef<str>,
        section: usize,
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
        section: usize,
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
    pub fn find_string(&self, string: &str) -> Option<usize> {
        let mut offset = 0;
        for s in &self.strings {
            if s == string {
                return Some(offset);
            }

            offset += s.len() + 1; // 1 for the null byte
        }

        None
    }

    /// Finds the index of a symbol in the symbol table. If it doesn't exist, [`None`] is returned.
    pub fn find_symbol(&self, name: &str) -> Option<usize> {
        let name_index = self.find_string(name)?;

        self.symbols
            .iter()
            .position(|symbol| symbol.name == name_index)
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
}

/// A section in an ELF file
#[derive(Debug, Clone)]
pub struct Section<'a> {
    /// The data the section contains.
    pub data: Cow<'a, [u8]>,
    /// The name of the section, an index into the string table
    pub name: usize,
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

/// A segment in the program header of an ELF file
#[derive(Debug, Clone)]
pub struct Segment {
    /// The index of the section the segment refers to
    pub section: usize,
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
    name: usize,
    target_section: usize,
    relocations: Vec<RelaEntry>,
}

impl RelaTable {
    /// Adds a relocation to the relocation table.
    pub fn add(&mut self, relocation: RelaEntry) {
        self.relocations.push(relocation);
    }

    /// # Panics
    ///
    /// Panics, if `is_64bit` == false and one of the relocation entries does not fit in 32 bits.
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
    name: usize,
    target_section: usize,
    relocations: Vec<RelEntry>,
}

impl RelTable {
    /// Adds a relocation to the relocation table.
    pub fn add(&mut self, relocation: RelEntry) {
        self.relocations.push(relocation);
    }

    /// # Panics
    ///
    /// Panics, if is_64bit == false and one of the relocation entries does not fit in 32 bits.
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
    /// An index into the string table
    name: usize,
    value: u64,
    size: u64,
    global: bool,
    kind: SymbolKind,
    section: u16,
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
