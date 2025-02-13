//! Very much WIP.

use std::{borrow::Cow, io::Write};

use flagset::FlagSet;
use num_traits::ToPrimitive;

use crate::{
    consts::{
        SectionKind, SymbolKind, ELF64_HEADER_SIZE, ELF64_PROGRAM_HEADER_SIZE,
        ELF64_SECTION_HEADER_SIZE, ELF_MAGIC,
    },
    Endianness, MachineKind,
};

use super::{
    consts::{ELF32_HEADER_SIZE, ELF32_PROGRAM_HEADER_SIZE, ELF32_SECTION_HEADER_SIZE},
    ElfKind, SectionFlag, SegmentFlag,
};

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
    relocations: Vec<RelaTable>,
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
                global: false,
                kind: SymbolKind::NoType,
                section: 0,
            }],
            relocations: Vec::new(),
            entrypoint: 0,
            kind,
            machine,
            endianness,
            is_64bit,
        }
    }

    /// Builds the ELF file and consumes the builder.
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
                symbol_table.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]); // TODO: no size
            }
        } else {
            for symbol in &builder.symbols {
                symbol_table
                    .extend_from_slice(&endianness.u32_to_bytes(symbol.name.try_into().unwrap()));
                symbol_table
                    .extend_from_slice(&endianness.u32_to_bytes(symbol.value.try_into().unwrap()));
                symbol_table.extend_from_slice(&[0, 0, 0, 0]); // no size

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

        if !builder.is_64bit {
            let mut relocation_sections = Vec::new();

            for table in &builder.relocations {
                let mut relocation_table = Vec::new();

                for relocation in &table.relocations {
                    relocation_table
                        .extend_from_slice(&endianness.u32_to_bytes(relocation.offset as u32));
                    relocation_table
                        .extend_from_slice(&endianness.u32_to_bytes(relocation.info as u32));
                    relocation_table
                        .extend_from_slice(&endianness.u32_to_bytes(relocation.addend as u32));
                }

                relocation_sections.push((
                    table.target_section,
                    table.name,
                    Cow::Owned(relocation_table),
                ));
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
        }

        builder.add_string(".strtab"); // need to add the string before building the string table bytes

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
            builder.build_elf64_header(&mut target)?;
            builder.build_elf64_phdrs(&mut target)?;
            builder.write_sections(&mut target)?;
            builder.build_elf64_section_headers(&mut target)?;
        } else {
            builder.build_elf32_header(&mut target)?;
            builder.build_elf32_phdrs(&mut target)?;
            builder.write_sections(&mut target)?;
            builder.build_elf32_section_headers(&mut target)?;
        }

        Ok(())
    }

    fn build_elf32_header<W: Write>(&mut self, mut target: W) -> std::io::Result<()> {
        let endianness = self.endianness;
        let string_table_index = self.sections.len() - 1;

        target.write_all(ELF_MAGIC)?;
        target.write_all(&[1])?; // 32-bit
        target.write_all(match self.endianness {
            Endianness::Little => &[1],
            Endianness::Big => &[2],
        })?;
        target.write_all(&[1])?; // elf version 1
        target.write_all(&[0, 0, 0, 0, 0, 0, 0, 0, 0])?; // padding

        target.write_all(&endianness.u16_to_bytes(self.kind.to_u16().unwrap()))?;
        target.write_all(&endianness.u16_to_bytes(self.machine.to_u16().unwrap()))?;
        target.write_all(&endianness.u32_to_bytes(1))?; // elf version 1
        target.write_all(&endianness.u32_to_bytes(self.entrypoint as u32))?;
        target.write_all(&if self.segments().next().is_none() {
            [0, 0, 0, 0]
        } else {
            endianness.u32_to_bytes(ELF32_HEADER_SIZE.into())
        })?; // program headers right after the header if there are segments, 0 otherwise
        target.write_all(
            &endianness.u32_to_bytes(
                u32::try_from(
                    self.sections
                        .iter()
                        .map(|section| section.data.len())
                        .sum::<usize>()
                        + usize::from(ELF32_HEADER_SIZE)
                        + usize::from(ELF32_PROGRAM_HEADER_SIZE) * self.segments().count(),
                )
                .unwrap(),
            ),
        )?; // section header table offset
        target.write_all(&[0, 0, 0, 0])?; // empty flags
        target.write_all(&endianness.u16_to_bytes(ELF32_HEADER_SIZE))?;
        target.write_all(&endianness.u16_to_bytes(ELF32_PROGRAM_HEADER_SIZE))?; // program header entry size
        target.write_all(&endianness.u16_to_bytes(self.segments().count().try_into().unwrap()))?; // program header entry count
        target.write_all(&endianness.u16_to_bytes(ELF32_SECTION_HEADER_SIZE))?;
        target.write_all(&endianness.u16_to_bytes(self.sections.len().try_into().unwrap()))?; // section header count
        target.write_all(&endianness.u16_to_bytes(u16::try_from(string_table_index).unwrap()))?; // string table index

        Ok(())
    }

    fn build_elf64_header<W: Write>(&mut self, mut target: W) -> std::io::Result<()> {
        let endianness = self.endianness;
        let string_table_index = self.sections.len() - 1;

        target.write_all(ELF_MAGIC)?;
        target.write_all(&[2])?; // 64-bit
        target.write_all(match self.endianness {
            Endianness::Little => &[1],
            Endianness::Big => &[2],
        })?;
        target.write_all(&[1])?; // elf version 1
        target.write_all(&[0, 0, 0, 0, 0, 0, 0, 0, 0])?; // padding

        target.write_all(&endianness.u16_to_bytes(self.kind.to_u16().unwrap()))?;
        target.write_all(&endianness.u16_to_bytes(self.machine.to_u16().unwrap()))?;
        target.write_all(&endianness.u32_to_bytes(1))?; // elf version 1
        target.write_all(&endianness.u64_to_bytes(self.entrypoint))?;
        target.write_all(&if self.segments().next().is_none() {
            [0, 0, 0, 0, 0, 0, 0, 0]
        } else {
            endianness.u64_to_bytes(ELF64_HEADER_SIZE.into())
        })?; // program headers right after the header if there are segments, 0 otherwise
        target.write_all(
            &endianness.u64_to_bytes(
                u64::try_from(
                    self.sections
                        .iter()
                        .map(|section| section.data.len())
                        .sum::<usize>()
                        + usize::from(ELF64_HEADER_SIZE)
                        + usize::from(ELF64_PROGRAM_HEADER_SIZE) * self.segments().count(),
                )
                .unwrap(),
            ),
        )?; // section header table offset
        target.write_all(&[0, 0, 0, 0])?; // empty flags
        target.write_all(&endianness.u16_to_bytes(ELF64_HEADER_SIZE))?;
        target.write_all(&endianness.u16_to_bytes(ELF64_PROGRAM_HEADER_SIZE))?; // program header entry size
        target.write_all(&endianness.u16_to_bytes(self.segments().count().try_into().unwrap()))?; // program header entry count
        target.write_all(&endianness.u16_to_bytes(ELF64_SECTION_HEADER_SIZE))?;
        target.write_all(&endianness.u16_to_bytes(self.sections.len().try_into().unwrap()))?; // section header count
        target.write_all(&endianness.u16_to_bytes(u16::try_from(string_table_index).unwrap()))?; // string table index

        Ok(())
    }

    fn build_elf32_phdrs<W: Write>(&mut self, mut target: W) -> std::io::Result<()> {
        if self.kind == ElfKind::Executable {
            let endianness = self.endianness;

            let init_offset = u32::from(ELF32_HEADER_SIZE)
                + u32::from(ELF32_PROGRAM_HEADER_SIZE)
                    * u32::try_from(self.segments().count()).unwrap();
            let mut sections = self
                .sections
                .iter()
                .scan(init_offset, |state, section| {
                    let offset = *state;
                    *state += u32::try_from(section.data.len()).unwrap();
                    Some((offset, section))
                })
                .collect::<Vec<_>>(); // create a Vec of (offset, section)
            sections.sort_by(|a, b| a.1.vaddr.cmp(&b.1.vaddr)); // sort by address
            let segments = sections
                .iter()
                .filter(|(_, section)| section.flags.contains(SectionFlag::Alloc));

            for (offset, section) in segments {
                target.write_all(&endianness.u32_to_bytes(1))?; // type LOAD
                target.write_all(&endianness.u32_to_bytes(*offset))?;
                target.write_all(&endianness.u32_to_bytes(section.vaddr.try_into().unwrap()))?;
                target.write_all(&[0, 0, 0, 0])?; // physical address 0, unused
                target.write_all(
                    &endianness.u32_to_bytes(u32::try_from(section.data.len()).unwrap()),
                )?; // filesz
                target.write_all(
                    &endianness.u32_to_bytes(u32::try_from(section.data.len()).unwrap()),
                )?; // memsz
                let segment_flags = SegmentFlag::Read
                    | section
                        .flags
                        .into_iter()
                        .filter_map(Option::<SegmentFlag>::from)
                        .fold(FlagSet::from(None), |a: FlagSet<SegmentFlag>, b| a | b);
                target.write_all(&endianness.u32_to_bytes(segment_flags.bits()))?;
                target.write_all(&[0, 0, 0, 0])?; // align 0, unused because a specific address is specified
            }
        }

        Ok(())
    }

    fn build_elf64_phdrs<W: Write>(&mut self, mut target: W) -> std::io::Result<()> {
        if self.kind == ElfKind::Executable {
            let endianness = self.endianness;

            let init_offset = u64::from(ELF64_HEADER_SIZE)
                + u64::from(ELF64_PROGRAM_HEADER_SIZE)
                    * u64::try_from(self.segments().count()).unwrap();
            let mut sections = self
                .sections
                .iter()
                .scan(init_offset, |state, section| {
                    let offset = *state;
                    *state += u64::try_from(section.data.len()).unwrap();
                    Some((offset, section))
                })
                .collect::<Vec<_>>(); // create a Vec of (offset, section)
            sections.sort_by(|a, b| a.1.vaddr.cmp(&b.1.vaddr)); // sort by address
            let segments = sections
                .iter()
                .filter(|(_, section)| section.flags.contains(SectionFlag::Alloc));

            for (offset, section) in segments {
                target.write_all(&endianness.u32_to_bytes(1))?; // type LOAD
                let segment_flags = SegmentFlag::Read
                    | section
                        .flags
                        .into_iter()
                        .filter_map(Option::<SegmentFlag>::from)
                        .fold(FlagSet::from(None), |a: FlagSet<SegmentFlag>, b| a | b);
                target.write_all(&endianness.u32_to_bytes(segment_flags.bits()))?;

                target.write_all(&endianness.u64_to_bytes(*offset))?;
                target.write_all(&endianness.u64_to_bytes(section.vaddr))?;
                target.write_all(&[0, 0, 0, 0, 0, 0, 0, 0])?; // TODO: physical address 0
                target.write_all(
                    &endianness.u64_to_bytes(u64::try_from(section.data.len()).unwrap()),
                )?; // filesz
                target.write_all(
                    &endianness.u64_to_bytes(u64::try_from(section.data.len()).unwrap()),
                )?; // memsz
                target.write_all(&[0, 0, 0, 0, 0, 0, 0, 0])?; // TODO: align 0
            }
        }

        Ok(())
    }

    fn write_sections<W: Write>(&mut self, mut target: W) -> std::io::Result<()> {
        for section in &self.sections {
            target.write_all(&section.data)?;
        }

        Ok(())
    }

    fn build_elf32_section_headers<W: Write>(&mut self, mut target: W) -> std::io::Result<()> {
        let endianness = self.endianness;
        let mut offset = u32::from(ELF32_HEADER_SIZE)
            + u32::from(ELF32_PROGRAM_HEADER_SIZE)
                * u32::try_from(self.segments().count()).unwrap();
        for section in &self.sections {
            target.write_all(&endianness.u32_to_bytes(section.name.try_into().unwrap()))?;
            target.write_all(&endianness.u32_to_bytes(section.kind.to_u32().unwrap()))?;
            target.write_all(&endianness.u32_to_bytes(section.flags.bits()))?;
            target.write_all(&endianness.u32_to_bytes(section.vaddr.try_into().unwrap()))?;
            target.write_all(
                &endianness.u32_to_bytes(if section.kind == SectionKind::Null {
                    0
                } else {
                    offset
                }),
            )?;
            target.write_all(&endianness.u32_to_bytes(section.data.len().try_into().unwrap()))?;

            let link = match section.kind {
                SectionKind::SymbolTable => {
                    u32::try_from(self.find_section(".strtab").unwrap()).unwrap()
                }
                SectionKind::Rela => u32::try_from(self.find_section(".symtab").unwrap()).unwrap(),
                _ => 0,
            };

            target.write_all(&endianness.u32_to_bytes(link))?;
            target.write_all(&endianness.u32_to_bytes(section.info))?;
            target.write_all(&endianness.u32_to_bytes(section.alignment.try_into().unwrap()))?;
            target.write_all(&endianness.u32_to_bytes(section.entsize.try_into().unwrap()))?;

            offset += u32::try_from(section.data.len()).unwrap();
        }

        Ok(())
    }

    fn build_elf64_section_headers<W: Write>(&mut self, mut target: W) -> std::io::Result<()> {
        let endianness = self.endianness;
        let mut offset = u64::from(ELF64_HEADER_SIZE)
            + u64::from(ELF64_PROGRAM_HEADER_SIZE)
                * u64::try_from(self.segments().count()).unwrap();
        for section in &self.sections {
            target.write_all(&endianness.u32_to_bytes(section.name.try_into().unwrap()))?;
            target.write_all(&endianness.u32_to_bytes(section.kind.to_u32().unwrap()))?;
            target.write_all(&endianness.u64_to_bytes(section.flags.bits().into()))?;
            target.write_all(&endianness.u64_to_bytes(section.vaddr))?;
            target.write_all(
                &endianness.u64_to_bytes(if section.kind == SectionKind::Null {
                    0
                } else {
                    offset
                }),
            )?;
            target.write_all(&endianness.u64_to_bytes(section.data.len().try_into().unwrap()))?;

            let link = match section.kind {
                SectionKind::SymbolTable => {
                    u32::try_from(self.find_section(".strtab").unwrap()).unwrap()
                }
                SectionKind::Rela => u32::try_from(self.find_section(".symtab").unwrap()).unwrap(),
                _ => 0,
            };

            target.write_all(&endianness.u32_to_bytes(link))?;
            target.write_all(&endianness.u32_to_bytes(section.info))?;
            target.write_all(&endianness.u64_to_bytes(section.alignment))?;
            target.write_all(&endianness.u64_to_bytes(section.entsize))?;

            offset += u64::try_from(section.data.len()).unwrap();
        }

        Ok(())
    }

    /// Adds a section to the section table and the data to the ELF file. The name is added to the string table. Returns
    /// the index at which the section was added.
    ///
    /// # Panics
    ///
    /// Panics, if
    /// * the virtual address, entry size, or alignment is > [`u32::MAX`] and the ELF file is 32-bit, or
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

    /// Adds a symbol to the symbol table. The name is added to the string table. Returns the index of the symbol in the
    /// symbol table.
    ///
    /// # Panics
    ///
    /// Panics if the value is > [`u32::MAX`] and the ELF file is 32-bit.
    pub fn add_symbol(
        &mut self,
        name: impl Into<String> + AsRef<str>,
        value: u64,
        global: bool,
        kind: SymbolKind,
        section: u16,
    ) -> usize {
        let name_index = self.add_string(name);

        if !self.is_64bit {
            assert!(value <= u32::MAX.into());
        }

        self.symbols.push(Symbol {
            name: name_index,
            value,
            global,
            kind,
            section,
        });

        self.symbols.len() - 1
    }

    /// Finds the index of a section in the section table by index. If it doesn't exist, [`None`] is returned.
    pub fn find_section(&self, name: &str) -> Option<usize> {
        let name_index = self.find_string(name)?;

        self.sections
            .iter()
            .position(|section| section.name == name_index)
    }

    /// Adds a Rela relocation entry to a section's relocation table. The section is referred to by its index in the
    /// section table.
    ///
    /// # Panics
    ///
    /// Panics if the section does not already have a relocation table.
    pub fn add_relocation(&mut self, section: usize, relocation: RelaEntry) {
        let relocations = self
            .relocations
            .iter_mut()
            .find(|table| table.target_section == section)
            .unwrap();
        relocations.relocations.push(relocation);
    }

    /// Adds a Rela-type relocation table to a section.
    pub fn add_relocation_table(&mut self, name: impl Into<String> + AsRef<str>, section: usize) {
        let name = self.add_string(name);

        self.relocations.push(RelaTable {
            name,
            target_section: section,
            relocations: Vec::new(),
        })
    }

    /// Finds the indxe of a string in the string table. If it dosen't exist, [`None`] is returned.
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
    /// Panics if the entrypoint > [`u32::MAX`] for 32-bit files.
    pub fn set_entrypoint(&mut self, entrypoint: u64) {
        if !self.is_64bit {
            assert!(entrypoint <= u32::MAX.into());
        }

        self.entrypoint = entrypoint;
    }

    fn segments(&self) -> impl Iterator<Item = &Section> {
        self.sections.iter().filter(|section| {
            self.kind == ElfKind::Executable && section.flags.contains(SectionFlag::Alloc)
        })
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

/// A table containing the relocations for a section
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
}

#[derive(Debug, Clone)]
struct Symbol {
    /// An index into the string table
    name: usize,
    value: u64,
    global: bool,
    kind: SymbolKind,
    section: u16,
}

/// An `Elf32_Rela`-type relocation entry
#[derive(Debug, Clone)]
pub struct RelaEntry {
    /// The offset which the relocation should be applied at.
    pub offset: u64,
    /// Symbol table index and type of relocation.
    pub info: u64,
    /// Constant addend to be used in the calculation.
    pub addend: u64,
}
