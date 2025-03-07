use std::io::Write;

use num_traits::ToPrimitive;

use crate::{Endianness, SectionKind};

use super::{
    ElfBuilder, ELF32_HEADER_SIZE, ELF32_PROGRAM_HEADER_SIZE, ELF32_SECTION_HEADER_SIZE, ELF_MAGIC,
};

pub(super) fn write_header<W: Write>(builder: &ElfBuilder, mut target: W) -> std::io::Result<()> {
    let endianness = builder.endianness;
    let string_table_index = builder.sections.len() - 1;

    target.write_all(ELF_MAGIC)?;
    target.write_all(&[1])?; // 32-bit
    target.write_all(match builder.endianness {
        Endianness::Little => &[1],
        Endianness::Big => &[2],
    })?;
    target.write_all(&[1])?; // elf version 1
    target.write_all(&[0, 0, 0, 0, 0, 0, 0, 0, 0])?; // padding

    target.write_all(&endianness.u16_to_bytes(builder.kind.to_u16().unwrap()))?;
    target.write_all(&endianness.u16_to_bytes(builder.machine.to_u16().unwrap()))?;
    target.write_all(&endianness.u32_to_bytes(1))?; // elf version 1
    target.write_all(&endianness.u32_to_bytes(builder.entrypoint as u32))?;
    target.write_all(&if builder.segments.is_empty() {
        [0, 0, 0, 0]
    } else {
        endianness.u32_to_bytes(ELF32_HEADER_SIZE.into())
    })?; // program headers right after the header if there are segments, 0 otherwise
    target.write_all(
        &endianness.u32_to_bytes(
            u32::try_from(
                builder
                    .sections
                    .iter()
                    .map(|section| section.data.len())
                    .sum::<usize>()
                    + usize::from(ELF32_HEADER_SIZE)
                    + usize::from(ELF32_PROGRAM_HEADER_SIZE) * builder.segments.len(),
            )
            .unwrap(),
        ),
    )?; // section header table offset
    target.write_all(&[0, 0, 0, 0])?; // empty flags
    target.write_all(&endianness.u16_to_bytes(ELF32_HEADER_SIZE))?;
    target.write_all(&endianness.u16_to_bytes(ELF32_PROGRAM_HEADER_SIZE))?;
    target.write_all(&endianness.u16_to_bytes(builder.segments.len().try_into().unwrap()))?;
    target.write_all(&endianness.u16_to_bytes(ELF32_SECTION_HEADER_SIZE))?;
    target.write_all(&endianness.u16_to_bytes(builder.sections.len().try_into().unwrap()))?;
    target.write_all(&endianness.u16_to_bytes(u16::try_from(string_table_index).unwrap()))?;

    Ok(())
}

pub(super) fn write_phdrs<W: Write>(builder: &ElfBuilder, mut target: W) -> std::io::Result<()> {
    let endianness = builder.endianness;

    let init_offset = u32::from(ELF32_HEADER_SIZE)
        + u32::from(ELF32_PROGRAM_HEADER_SIZE) * u32::try_from(builder.segments.len()).unwrap();
    let sections = builder
        .sections
        .iter()
        .scan(init_offset, |state, section| {
            let offset = *state;
            *state += u32::try_from(section.data.len()).unwrap();
            Some((offset, section))
        })
        .collect::<Vec<_>>(); // create a Vec of (offset, section)
    let mut segments = builder.segments.iter().collect::<Vec<_>>();
    segments.sort_by(|a, b| a.vaddr.cmp(&b.vaddr));

    for segment in &segments {
        target.write_all(&endianness.u32_to_bytes(segment.kind.to_u32().unwrap()))?;
        target.write_all(&endianness.u32_to_bytes(sections[segment.section].0))?;
        target.write_all(&endianness.u32_to_bytes(segment.vaddr.try_into().unwrap()))?;
        target.write_all(&endianness.u32_to_bytes(segment.paddr.try_into().unwrap()))?;
        target.write_all(&endianness.u32_to_bytes(segment.filesz.try_into().unwrap()))?;
        target.write_all(&endianness.u32_to_bytes(segment.memsz.try_into().unwrap()))?;
        target.write_all(&endianness.u32_to_bytes(segment.flags.bits()))?;
        target.write_all(&endianness.u32_to_bytes(segment.align.try_into().unwrap()))?;
    }

    Ok(())
}

pub(super) fn write_section_headers<W: Write>(
    builder: &ElfBuilder,
    mut target: W,
) -> std::io::Result<()> {
    let endianness = builder.endianness;
    let mut offset = u32::from(ELF32_HEADER_SIZE)
        + u32::from(ELF32_PROGRAM_HEADER_SIZE) * u32::try_from(builder.segments.len()).unwrap();
    for section in &builder.sections {
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
                u32::try_from(builder.find_section(".strtab").unwrap()).unwrap()
            }
            SectionKind::Rela => u32::try_from(builder.find_section(".symtab").unwrap()).unwrap(),
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
