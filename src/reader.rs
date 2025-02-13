//! Contains all relevant structures for parsing an ELF file.
//!
//! The root of the parsing is [`ElfReader`], through which it is possible to access all of the
//! fields in an ELF file. See `eelf-cli` for a `readelf`-like program.
//!
//! # Examples
//!
//! ```no_run
//! let bytes = std::fs::read("/usr/bin/bash").unwrap();
//! let reader = eelf::ElfReader::new(&bytes)?;
//! let header = reader.header()?;
//! println!("File target architecture: {:?}", header.machine());
//! # Ok::<(), eelf::ParseError>(())
//! ```

use core::str;
use std::{ffi::CStr, str::Utf8Error};

use flagset::FlagSet;
use num_traits::{FromPrimitive, ToPrimitive};
use thiserror::Error;

use crate::{
    consts::{
        OsAbi, SectionKind, SegmentKind, EI_ABIVERSION, EI_CLASS, EI_DATA, EI_NIDENT, EI_OSABI,
        EI_VERSION, ELF32_SECTION_HEADER_SIZE, ELF64_HEADER_SIZE, ELF64_PROGRAM_HEADER_SIZE,
        ELF64_SECTION_HEADER_SIZE,
    },
    Endianness, SectionFlag,
};

use super::{
    consts::{MachineKind, ELF32_HEADER_SIZE, ELF32_PROGRAM_HEADER_SIZE, ELF_MAGIC},
    ElfKind, SegmentFlag,
};

/// Reads data specified in the ELF specification from an ELF file.
///
/// Most data is read lazily; the objects themselves do not store the data but only act as readers. The reader can
/// dynamically read both 32-bit and 64-bit, and big endian and little endian ELF files, and thus the return values in
/// several functions are wider than required for 32-bit files.
#[derive(Debug, Clone)]
pub struct ElfReader<'data> {
    bytes: &'data [u8],
    endianness: Endianness,
    is_64bit: bool,
}

impl<'reader, 'data> ElfReader<'data> {
    /// Creates a new [`ElfReader`] object from a slice of bytes, or an error if the bytes colud not be recognized as a
    /// valid ELF file. Does not do a full validation of the file, and the function may return [`Result::Ok`] with an
    /// invalid ELF file.
    pub fn new(bytes: &'data [u8]) -> Result<Self, ParseError> {
        if !bytes.starts_with(ELF_MAGIC) {
            return Err(ParseError::InvalidHeader);
        }

        let is_64bit = match bytes.get(EI_CLASS) {
            Some(1) => false,
            Some(2) => true,
            Some(_) => return Err(ParseError::InvalidValue("ei_class")),
            None => return Err(ParseError::UnexpectedEof),
        };

        let endianness = match bytes.get(EI_DATA) {
            Some(1) => Endianness::Little,
            Some(2) => Endianness::Big,
            Some(_) => return Err(ParseError::InvalidValue("ei_data")),
            None => return Err(ParseError::UnexpectedEof),
        };

        match bytes.get(EI_VERSION) {
            Some(1) => {}
            Some(_) => return Err(ParseError::InvalidValue("ei_version")),
            None => return Err(ParseError::UnexpectedEof),
        }

        Ok(Self {
            bytes,
            endianness,
            is_64bit,
        })
    }

    /// Returns the endianness of the ELF file as specified in the header.
    pub fn endianness(&self) -> Endianness {
        self.endianness
    }

    /// Returns whether the ELF class is 32-bit or 64-bit.
    pub fn is_64bit(&self) -> bool {
        self.is_64bit
    }

    /// Returns a reference to the data.
    pub fn bytes(&self) -> &'data [u8] {
        self.bytes
    }

    /// Reads a [`u64`] at position `index` in the ELF file.
    pub fn read_u8(&self, index: usize) -> Option<u8> {
        self.bytes.get(index).copied()
    }

    /// Reads a [`u16`] at position `index` in the ELF file using the endianness specified in the header.
    pub fn read_u16(&self, index: usize) -> Option<u16> {
        self.bytes
            .get(index..index + 2)
            .map(|bytes| self.endianness.u16_from_bytes(bytes.try_into().unwrap()))
    }

    /// Reads a [`u32`] at position `index` in the ELF file using the endianness specified in the header.
    pub fn read_u32(&self, index: usize) -> Option<u32> {
        self.bytes
            .get(index..index + 4)
            .map(|bytes| self.endianness.u32_from_bytes(bytes.try_into().unwrap()))
    }

    /// Reads a [`u64`] at position `index` in the ELF file using the endianness specified in the header.
    pub fn read_u64(&self, index: usize) -> Option<u64> {
        self.bytes
            .get(index..index + 8)
            .map(|bytes| self.endianness.u64_from_bytes(bytes.try_into().unwrap()))
    }

    /// Returns a [`Header`] object, or an error if the header could not be read, such as if the data is shorter than an
    /// ELF header's length.
    pub fn header(&'reader self) -> Result<Header<'reader, 'data>, ParseError> {
        Header::new(self)
    }

    /// Returns a [`Segments`] object that can be used to access the segments in the ELF file, or an error if the data
    /// could not be read.
    pub fn segments(&'reader self) -> Result<Segments<'reader, 'data>, ParseError> {
        Segments::new(self)
    }

    /// Returns a [`Sections`] object that can be use do access the sections in the ELF file, or an error if the data
    /// could not be read.
    pub fn sections(&'reader self) -> Result<Sections<'reader, 'data>, ParseError> {
        Sections::new(self)
    }

    /// Returns a [`Strings`] object based on the header's `e_shstrndx` value, or an error if the section could not be
    /// read.
    pub fn strings(&self) -> Result<Strings<'data>, ParseError> {
        Strings::new(self)
    }
}

/// The ELF header.
#[derive(Debug, Clone)]
pub struct Header<'reader, 'data> {
    elf: &'reader ElfReader<'data>,
}

impl<'reader, 'data> Header<'reader, 'data> {
    fn new(elf: &'reader ElfReader<'data>) -> Result<Self, ParseError> {
        let header_size = match elf.is_64bit() {
            true => ELF64_HEADER_SIZE,
            false => ELF32_HEADER_SIZE,
        };

        if elf.bytes().len() < header_size.into() {
            return Err(ParseError::UnexpectedEof);
        }

        Ok(Header { elf })
    }

    /// The identification bytes of the ELF file. `e_ident` in the specification.
    pub fn ident(&self) -> &'data [u8; EI_NIDENT] {
        self.elf.bytes()[..EI_NIDENT].try_into().unwrap()
    }

    /// The version of the ELF file as specified in the identification bytes. `ei_version` in the specification.
    pub fn ei_version(&self) -> u8 {
        self.ident()[EI_VERSION]
    }

    /// The operating system or ABI of the ELF file. `ei_osabi` in the specification.
    pub fn osabi(&self) -> ElfValue<OsAbi, u8> {
        let value = self.ident()[EI_OSABI];

        OsAbi::from_u8(value).map_or(ElfValue::Unknown(value), ElfValue::Known)
    }

    /// The ABI version. `ei_abiversion` in the specification.
    pub fn abiversion(&self) -> u8 {
        self.elf.bytes()[EI_ABIVERSION]
    }

    /// The type of the ELF file. `e_type` in the specification.
    pub fn kind(&self) -> ElfValue<ElfKind, u16> {
        let value = self.elf.read_u16(16).unwrap();

        ElfKind::from_u16(value).map_or(ElfValue::Unknown(value), ElfValue::Known)
    }

    /// The required architecture of the ELF file. `e_mechine` in the specification.
    pub fn machine(&self) -> ElfValue<MachineKind, u16> {
        let value = self.elf.read_u16(18).unwrap();

        MachineKind::from_u16(value).map_or(ElfValue::Unknown(value), ElfValue::Known)
    }

    /// The version of the ELF file. `e_version` in the specification.
    pub fn version(&self) -> u32 {
        self.elf.read_u32(20).unwrap()
    }

    /// The entrypoint address of the program, or 0 if unspecified. `e_entry` in the specification.
    ///
    /// 32 bits for 32-bit ELF files.
    pub fn entry(&self) -> u64 {
        if self.elf.is_64bit() {
            self.elf.read_u64(24).unwrap()
        } else {
            self.elf.read_u32(24).unwrap().into()
        }
    }

    /// The offset at which the program headers are located in the ELF file. `e_phoff` in the specification.
    ///
    /// 32 bits for 32-bit ELF files.
    pub fn phoff(&self) -> u64 {
        if self.elf.is_64bit() {
            self.elf.read_u64(32).unwrap()
        } else {
            self.elf.read_u32(28).unwrap().into()
        }
    }

    /// The offset at which the section headers are located in the ELF file. `e_shoff` in the specification.
    ///
    /// 32 bits for 32-bit ELF files.
    pub fn shoff(&self) -> u64 {
        if self.elf.is_64bit() {
            self.elf.read_u64(40).unwrap()
        } else {
            self.elf.read_u32(32).unwrap().into()
        }
    }

    /// Processor-specific flags. `e_flags` in the specification.
    pub fn flags(&self) -> u32 {
        if self.elf.is_64bit() {
            self.elf.read_u32(48).unwrap()
        } else {
            self.elf.read_u32(36).unwrap()
        }
    }

    /// The size of the ELF header. `e_ehsize` in the specification.
    pub fn ehsize(&self) -> u16 {
        if self.elf.is_64bit() {
            self.elf.read_u16(52).unwrap()
        } else {
            self.elf.read_u16(40).unwrap()
        }
    }

    /// The size of a program header. `e_phentsize` in the specification.
    pub fn phentsize(&self) -> u16 {
        if self.elf.is_64bit() {
            self.elf.read_u16(54).unwrap()
        } else {
            self.elf.read_u16(42).unwrap()
        }
    }

    /// The number of program headers in the ELF file. `e_phnum` in the specification.
    pub fn phnum(&self) -> u16 {
        if self.elf.is_64bit() {
            self.elf.read_u16(56).unwrap()
        } else {
            self.elf.read_u16(44).unwrap()
        }
    }

    /// The size of a sectin header. `e_shentsize` in the specification.
    pub fn shentsize(&self) -> u16 {
        if self.elf.is_64bit() {
            self.elf.read_u16(58).unwrap()
        } else {
            self.elf.read_u16(46).unwrap()
        }
    }

    /// The number of section headers in the ELF file. `e_shnum` in the specification.
    pub fn shnum(&self) -> u16 {
        if self.elf.is_64bit() {
            self.elf.read_u16(60).unwrap()
        } else {
            self.elf.read_u16(48).unwrap()
        }
    }

    /// The index of the section containing the string table. `e_shstrndx` in the specification.
    pub fn shstrndx(&self) -> u16 {
        if self.elf.is_64bit() {
            self.elf.read_u16(62).unwrap()
        } else {
            self.elf.read_u16(50).unwrap()
        }
    }
}

/// A reader for the string table section.
#[derive(Debug, Clone)]
pub struct Strings<'data> {
    data: &'data [u8],
}

impl<'data> Strings<'data> {
    fn new(elf: &ElfReader<'data>) -> Result<Self, ParseError> {
        let shstrndx = elf.header()?.shstrndx();
        let strtab_section = elf.sections()?;
        let strtab_section = strtab_section
            .get(shstrndx.into())
            .ok_or(ParseError::InvalidValue("e_shstrndx"))?
            .data()?;

        Ok(Self {
            data: strtab_section,
        })
    }

    /// Reads a UTF-8 string from the string table using the index specified. If a zero-terminated string of bytes at
    /// the specified address could not be found, `None` is returned. If one was found but could not be parsed as UTF-8,
    /// `Some(Err())` is returned.
    pub fn get_str(&self, index: u32) -> Option<Result<&'data str, Utf8Error>> {
        self.get_cstr(index).map(CStr::to_str)
    }

    /// Reads a [`CStr`] from the string table using the index specified. If a zero-terminated string of bytes at the
    /// specified address could not be found, `None` is returned. The string must not be valid UTF-8.
    pub fn get_cstr(&self, index: u32) -> Option<&'data CStr> {
        let bytes = self.data.get(usize::try_from(index).unwrap()..)?;

        CStr::from_bytes_until_nul(bytes).ok()
    }
}

/// An object that can be used to read the section header table in an ELF file.
#[derive(Debug, Clone)]
pub struct Sections<'reader, 'data> {
    elf: &'reader ElfReader<'data>,
    header_size: usize,
    shoff: usize,
    shnum: usize,
}

impl<'reader, 'data> Sections<'reader, 'data> {
    fn new(elf: &'reader ElfReader<'data>) -> Result<Sections<'reader, 'data>, ParseError> {
        let header_size = match elf.is_64bit() {
            true => ELF64_SECTION_HEADER_SIZE,
            false => ELF32_SECTION_HEADER_SIZE,
        };
        let header = elf.header()?;
        let shoff = usize::try_from(header.shoff()).unwrap();
        let shnum = usize::from(header.shnum());

        if header.shentsize() != header_size {
            return Err(ParseError::InvalidValue("e_shentsize"));
        } else if shoff + shnum * usize::from(header_size) > elf.bytes().len() {
            return Err(ParseError::UnexpectedEof);
        }

        Ok(Self {
            elf,
            header_size: header_size.into(),
            shoff,
            shnum,
        })
    }

    /// Returns a [`Section`] of a section at the specified index in the section header table.
    pub fn get(&self, index: usize) -> Option<Section<'reader, 'data>> {
        if index >= self.shnum {
            return None;
        }

        let start = self.shoff + self.header_size * index;

        Some(Section {
            elf: self.elf,
            offset: start,
        })
    }
}

impl<'reader, 'data> IntoIterator for Sections<'reader, 'data> {
    type Item = Section<'reader, 'data>;
    type IntoIter = SectionsIter<'reader, 'data>;

    fn into_iter(self) -> Self::IntoIter {
        SectionsIter {
            sections: self,
            index: 0,
        }
    }
}

/// An iterator over all sections in the section header table.
#[derive(Debug, Clone)]
pub struct SectionsIter<'reader, 'data> {
    sections: Sections<'reader, 'data>,
    index: usize,
}

impl<'reader, 'data> Iterator for SectionsIter<'reader, 'data> {
    type Item = Section<'reader, 'data>;

    fn next(&mut self) -> Option<Self::Item> {
        let section = self.sections.get(self.index);
        self.index += 1;

        section
    }
}

/// A section in an ELF file.
#[derive(Debug, Clone)]
pub struct Section<'reader, 'data> {
    elf: &'reader ElfReader<'data>,
    offset: usize,
}

impl<'data> Section<'_, 'data> {
    fn read_u32(&self, offset: usize) -> u32 {
        self.elf.read_u32(self.offset + offset).unwrap()
    }

    fn read_u64(&self, offset: usize) -> u64 {
        self.elf.read_u64(self.offset + offset).unwrap()
    }

    /// The string table index of the section's name. `sh_name` in the specification.
    pub fn name(&self) -> u32 {
        self.read_u32(0)
    }

    /// The type of the section. `sh_type` in the specification.
    pub fn kind(&self) -> ElfValue<SectionKind, u32> {
        let value = self.read_u32(4);

        SectionKind::from_u32(value).map_or(ElfValue::Unknown(value), ElfValue::Known)
    }

    /// Section flags. `sh_flags` in the specification.
    pub fn flags(&self) -> ElfValue<FlagSet<SectionFlag>, u64> {
        let value = if self.elf.is_64bit() {
            self.read_u64(8)
        } else {
            self.read_u32(8).into()
        };

        u32::try_from(value)
            .ok()
            .map(FlagSet::new)
            .and_then(Result::ok)
            .map_or(ElfValue::Unknown(value), ElfValue::Known)
    }

    /// The address the section will be located at during execution, or 0 if the data isn't loaded. `sh_addr` in the
    /// specification.
    pub fn addr(&self) -> u64 {
        if self.elf.is_64bit() {
            self.read_u64(16)
        } else {
            self.read_u32(12).into()
        }
    }

    /// The offset at which the section's data is located in the ELF file. `sh_offset` in the specification.
    pub fn offset(&self) -> u64 {
        if self.elf.is_64bit() {
            self.read_u64(24)
        } else {
            self.read_u32(16).into()
        }
    }

    /// The size of the section. `sh_size` in the specification.
    pub fn size(&self) -> u64 {
        if self.elf.is_64bit() {
            self.read_u64(32)
        } else {
            self.read_u32(20).into()
        }
    }

    /// Index to another section in the section header table. `sh_link` in the specification.
    pub fn link(&self) -> u32 {
        if self.elf.is_64bit() {
            self.read_u32(40)
        } else {
            self.read_u32(24)
        }
    }

    /// Section type-dependent data. `sh_infa` in the specification.
    pub fn info(&self) -> u32 {
        if self.elf.is_64bit() {
            self.read_u32(44)
        } else {
            self.read_u32(28)
        }
    }

    /// The required alignment of the section's address; a power of two or 0 for no alignment requirement. `sh_addralign` in the
    /// specification.
    pub fn addralign(&self) -> u64 {
        if self.elf.is_64bit() {
            self.read_u64(48)
        } else {
            self.read_u32(32).into()
        }
    }

    /// The size of an entry in the section. `sh_entsize` in the specification.
    pub fn entsize(&self) -> u64 {
        if self.elf.is_64bit() {
            self.read_u64(56)
        } else {
            self.read_u32(36).into()
        }
    }

    /// Returns a reference to the data of the section, or an error if it could not be read.
    pub fn data(&self) -> Result<&'data [u8], ParseError> {
        if self.size() == 0 {
            return Ok(&[]);
        }

        self.elf
            .bytes()
            .get(
                usize::try_from(self.offset()).unwrap()
                    ..usize::try_from(self.offset()).unwrap()
                        + usize::try_from(self.size()).unwrap(),
            )
            .ok_or(ParseError::UnexpectedEof)
    }
}

/// Parses the program header tabel of an ELF file.
#[derive(Debug, Clone)]
pub struct Segments<'reader, 'data> {
    elf: &'reader ElfReader<'data>,
    header_size: usize,
    phoff: usize,
    phnum: usize,
}

impl<'reader, 'data> Segments<'reader, 'data> {
    fn new(elf: &'reader ElfReader<'data>) -> Result<Self, ParseError> {
        let header_size = match elf.is_64bit() {
            true => ELF64_PROGRAM_HEADER_SIZE,
            false => ELF32_PROGRAM_HEADER_SIZE,
        };
        let header = elf.header()?;
        let phoff = usize::try_from(header.phoff()).unwrap();
        let phnum = usize::from(header.phnum());

        if header.phentsize() != header_size {
            return Err(ParseError::InvalidValue("e_phentsize"));
        } else if phoff + phnum * usize::from(header_size) > elf.bytes().len() {
            return Err(ParseError::UnexpectedEof);
        }

        Ok(Self {
            elf,
            header_size: header_size.into(),
            phoff,
            phnum,
        })
    }

    /// Returns a [`Segment`] corresponding to the given index, or None if the index is out of bounds.
    pub fn get(&self, index: usize) -> Option<Segment<'reader, 'data>> {
        if index >= self.phnum {
            return None;
        }

        let start = self.phoff + self.header_size * index;

        Some(Segment {
            elf: self.elf,
            offset: start,
        })
    }
}

impl<'reader, 'data> IntoIterator for Segments<'reader, 'data> {
    type Item = Segment<'reader, 'data>;
    type IntoIter = SegmentsIter<'reader, 'data>;

    fn into_iter(self) -> Self::IntoIter {
        SegmentsIter {
            segments: self,
            index: 0,
        }
    }
}

/// An iterator object over the segments in a program header table.
#[derive(Debug, Clone)]
pub struct SegmentsIter<'reader, 'data> {
    segments: Segments<'reader, 'data>,
    index: usize,
}

impl<'reader, 'data> Iterator for SegmentsIter<'reader, 'data> {
    type Item = Segment<'reader, 'data>;

    fn next(&mut self) -> Option<Self::Item> {
        let segment = self.segments.get(self.index);
        self.index += 1;

        segment
    }
}

/// An ELF segment
#[derive(Debug, Clone)]
pub struct Segment<'reader, 'data> {
    elf: &'reader ElfReader<'data>,
    offset: usize,
}

impl<'data> Segment<'_, 'data> {
    fn read_u32(&self, offset: usize) -> u32 {
        self.elf.read_u32(self.offset + offset).unwrap()
    }

    fn read_u64(&self, offset: usize) -> u64 {
        self.elf.read_u64(self.offset + offset).unwrap()
    }

    /// Type of segment. `p_type` in the specification.
    pub fn kind(&self) -> ElfValue<SegmentKind, u32> {
        let value = self.read_u32(0);

        SegmentKind::from_u32(value).map_or(ElfValue::Unknown(value), ElfValue::Known)
    }

    /// The offset at which the segment's data is located in the ELF file. This, in conjuction with [`Segment::filesz`],
    /// can be used to get a `&[u8]` to the data, but the data can be accessed easiest using [`Segment::data`].
    /// `p_offset` in the specification.
    pub fn offset(&self) -> u64 {
        if self.elf.is_64bit() {
            self.read_u64(8)
        } else {
            self.read_u32(4).into()
        }
    }

    /// The virtual address which the segment should be loaded at during execution. `p_vaddr` in the specification.
    pub fn vaddr(&self) -> u64 {
        if self.elf.is_64bit() {
            self.read_u64(16)
        } else {
            self.read_u32(8).into()
        }
    }

    /// The physical address which the segment should be loaded at during execution. `p_paddr` in the specification.
    pub fn paddr(&self) -> u64 {
        if self.elf.is_64bit() {
            self.read_u64(24)
        } else {
            self.read_u32(12).into()
        }
    }

    /// The number of bytes stored in the ELF file starting at [`Segment::offset`]. `p_filesz` in the specification.
    pub fn filesz(&self) -> u64 {
        if self.elf.is_64bit() {
            self.read_u64(32)
        } else {
            self.read_u32(16).into()
        }
    }

    /// The number of bytes the segment occupies in memory during execution. `p_memsz` in the specification.
    pub fn memsz(&self) -> u64 {
        if self.elf.is_64bit() {
            self.read_u64(40)
        } else {
            self.read_u32(20).into()
        }
    }

    /// Segment permissions during execution. `p_flags` in the specification.
    pub fn flags(&self) -> ElfValue<FlagSet<SegmentFlag>, u32> {
        let value = if self.elf.is_64bit() {
            self.read_u32(4)
        } else {
            self.read_u32(24)
        };

        FlagSet::new(value).map_or(ElfValue::Unknown(value), ElfValue::Known)
    }

    /// The required aligment of the virtual and physical address the segment is loaded at during execution. `p_align`
    /// in the specification.
    pub fn align(&self) -> u64 {
        if self.elf.is_64bit() {
            self.read_u64(48)
        } else {
            self.read_u32(28).into()
        }
    }

    /// Returns a reference to the segment's bytes stored in the ELF file, as dictated by [`Segment::offset`] and
    /// [`Segment::filesz`].
    pub fn data(&self) -> Result<&'data [u8], ParseError> {
        if self.filesz() == 0 {
            return Ok(&[]);
        }

        self.elf
            .bytes()
            .get(
                usize::try_from(self.offset()).unwrap()
                    ..usize::try_from(self.offset()).unwrap()
                        + usize::try_from(self.filesz()).unwrap(),
            )
            .ok_or(ParseError::UnexpectedEof)
    }
}

/// Represents the value of a field defined in the ELF specification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ElfValue<K, U> {
    /// If the field value was parsed successfully, `Known` contains the parsed representation of the data.
    Known(K),
    /// If the field was parsed unsuccessfully, `Unknown` contains the value of the field.
    Unknown(U),
}

impl<K, U> ElfValue<K, U> {
    /// Returns true the variant is [`ElfValue::Known`].
    pub fn is_known(&self) -> bool {
        match self {
            ElfValue::Known(_) => true,
            ElfValue::Unknown(_) => false,
        }
    }

    /// Returns true the variant is [`ElfValue::Unknown`].
    pub fn is_unknown(&self) -> bool {
        match self {
            ElfValue::Known(_) => false,
            ElfValue::Unknown(_) => true,
        }
    }
}

impl<K: ToPrimitive> ElfValue<K, u8> {
    /// Returns the numeric value regardless of if the meaning of the value is known.
    pub fn to_u8(&self) -> u8 {
        match self {
            ElfValue::Known(v) => v.to_u8().unwrap(),
            ElfValue::Unknown(v) => *v,
        }
    }
}

impl<K: ToPrimitive> ElfValue<K, u16> {
    /// Returns the numeric value regardless of if the meaning of the value is known.
    pub fn to_u16(&self) -> u16 {
        match self {
            ElfValue::Known(v) => v.to_u16().unwrap(),
            ElfValue::Unknown(v) => *v,
        }
    }
}

impl<K: ToPrimitive> ElfValue<K, u32> {
    /// Returns the numeric value regardless of if the meaning of the value is known.
    pub fn to_u32(&self) -> u32 {
        match self {
            ElfValue::Known(v) => v.to_u32().unwrap(),
            ElfValue::Unknown(v) => *v,
        }
    }
}

/// Represents an error that can occur in the parsing of an ELF file.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParseError {
    /// The ELF header was invalid
    #[error("invalid header")]
    InvalidHeader,
    /// A field in the ELF file had an invalid value
    #[error("invalid value in field {0}")]
    InvalidValue(&'static str),
    /// Data was shorter than expected
    #[error("unexpected end of file")]
    UnexpectedEof,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reader_new() {
        assert!(ElfReader::new(&[]).is_err());
        assert!(ElfReader::new(&[0x7f, b'E', b'L', b'F']).is_err());
        assert!(
            ElfReader::new(&[0x7f, b'E', b'L', b'F', 3, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]).is_err()
        );
        assert!(
            ElfReader::new(&[0x7f, b'E', b'L', b'F', 2, 3, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]).is_err()
        );
        assert!(
            ElfReader::new(&[0x7f, b'E', b'L', b'F', 2, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0]).is_err()
        );

        assert!(
            ElfReader::new(&[0x7f, b'E', b'L', b'F', 2, 2, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]).is_ok()
        );
    }

    #[test]
    fn header_parse() {
        let bytes = &[
            0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x03, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00, 0x60, 0x00, 0x31, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x98,
            0xe2, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x38, 0x00,
            0x0e, 0x00, 0x40, 0x00, 0x20, 0x00, 0x1f, 0x00,
        ];
        let reader = ElfReader::new(bytes).unwrap();
        let header = reader.header().unwrap();

        assert!(reader.is_64bit());
        assert_eq!(reader.endianness(), Endianness::Little);

        assert_eq!(header.osabi(), ElfValue::Known(OsAbi::None));
        assert_eq!(header.abiversion(), 0);
        assert_eq!(header.kind(), ElfValue::Known(ElfKind::Dynamic));
        assert_eq!(header.machine(), ElfValue::Known(MachineKind::X86_64));
    }
}
