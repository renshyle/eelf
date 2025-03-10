use std::borrow::Cow;

use eelf::{
    builder::{RelEntry, RelaEntry, RelocationTable, Section, Segment},
    flagset::FlagSet,
    ElfBuilder, ElfKind, Endianness, MachineKind, SectionFlag, SectionKind, SegmentFlag,
    SegmentKind, SymbolKind,
};

#[test]
fn nonsense_build() {
    let mut builder = ElfBuilder::new(
        ElfKind::Executable,
        MachineKind::Ppc64,
        true,
        Endianness::Big,
    );

    builder.set_entrypoint(0xc001c0d3);

    let section_name = builder.add_string(".verylongsectionnamejusttotestthestringtable");
    builder.add_section(Section {
        // randomly generated, chosen by fair dice roll
        data: Cow::Borrowed(&[0x71, 0xb5, 0x88, 0xba, 0x44, 0x2a, 0x05, 0x2c]),
        name: section_name,
        kind: SectionKind::Progbits,
        flags: SectionFlag::Alloc | SectionFlag::OsNonconforming,
        vaddr: 0x1122334455667788,
        info: 0,
        entsize: 0xceadeeda,
        alignment: 0x11f000,
    });

    let section_name = builder.add_string(".section");
    let section = builder.add_section(Section {
        data: Cow::Owned(vec![1, 2, 3, 4, 5, 6, 7, 8]),
        name: section_name,
        kind: SectionKind::Progbits,
        flags: FlagSet::new(0).unwrap(),
        vaddr: 0x7fffffff98760000,
        info: 0,
        entsize: 4,
        alignment: 0x1000,
    });

    builder.add_segment(Segment {
        section,
        kind: SegmentKind::Tls,
        vaddr: 0x7fffffff98760000,
        paddr: 0x6eeeeeee87650000,
        filesz: 8,
        memsz: 24,
        flags: SegmentFlag::Read | SegmentFlag::Write,
        align: 0x4000,
    });

    let symbol_table = builder.symbol_table();
    builder.add_segment(Segment {
        section: symbol_table,
        kind: SegmentKind::Load,
        vaddr: 0x1122334433443322,
        paddr: 0x4232fab213a9923a,
        filesz: 16,
        memsz: 17,
        flags: SegmentFlag::Execute | SegmentFlag::Write,
        align: 0x12,
    });

    builder.add_symbol("local_symbol", 9, 32, false, SymbolKind::Object, section);
    builder.add_symbol("_____staaaaaaart", 4, 16, true, SymbolKind::Func, section);

    let mut rel_table = builder.create_rel_table(".rel.section", section);
    rel_table.add(RelEntry {
        offset: 4,
        info: (2 << 32) | 27,
    });
    builder.add_relocation_table(RelocationTable::Rel(rel_table));

    let mut rela_table = builder.create_rela_table(".rela.section", section);
    rela_table.add(RelaEntry {
        offset: 0,
        info: (1 << 32) | 1,
        addend: 0x9988776655443322,
    });
    builder.add_relocation_table(RelocationTable::Rela(rela_table));

    let mut bytes = Vec::new();
    builder.build(&mut bytes).unwrap();

    assert_eq!(bytes, include_bytes!("nonsense.bin"));
}
