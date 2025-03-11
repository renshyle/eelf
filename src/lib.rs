//! eelf is a library for parsing and writing ELF files.
//!
//! The ELF parser can read almost any kind of valid ELF file, but the writer is very limited.
//! It can write 32-bit and 64-bit ELF files, but has only been tested with RISC-V.
//!
//! # Limitations
//!
//! The builder only supports one symbol table through its easy interface.
//!
//! # Examples
//!
//! See [`reader`] and [`builder`].

#![warn(missing_docs)]

pub mod builder;
mod consts;
pub mod reader;

pub use flagset;

#[doc(inline)]
pub use builder::ElfBuilder;
pub use consts::{
    ElfKind, Endianness, MachineKind, OsAbi, SectionFlag, SectionKind, SegmentFlag, SegmentKind,
    SymbolKind,
};
#[doc(inline)]
pub use reader::{ElfReader, ParseError};
