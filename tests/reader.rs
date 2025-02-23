use eelf::{
    flagset::FlagSet, reader::ElfValue, ElfKind, ElfReader, Endianness, MachineKind, OsAbi,
    SectionFlag, SectionKind, SegmentFlag, SegmentKind,
};

#[test]
fn hello_world() {
    let bytes = include_bytes!("hello-world.bin");
    let reader = ElfReader::new(bytes).unwrap();
    let header = reader.header().unwrap();

    assert_eq!(
        header.ident(),
        &[
            0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00
        ]
    );
    assert!(reader.is_64bit());
    assert_eq!(reader.endianness(), Endianness::Little);
    assert_eq!(header.ei_version(), 1);
    assert_eq!(header.osabi(), ElfValue::Known(OsAbi::None));
    assert_eq!(header.abiversion(), 0);
    assert_eq!(header.kind(), ElfValue::Known(ElfKind::None));
    assert_eq!(header.machine(), ElfValue::Known(MachineKind::X86_64));
    assert_eq!(header.version(), 1);
    assert_eq!(header.entry(), 0x12345678);
    assert_eq!(header.phoff(), 64);
    assert_eq!(header.shoff(), 7504);
    assert_eq!(header.flags(), 0);
    assert_eq!(header.ehsize(), 64);
    assert_eq!(header.phentsize(), 56);
    assert_eq!(header.phnum(), 7);
    assert_eq!(header.shentsize(), 64);
    assert_eq!(header.shnum(), 10);
    assert_eq!(header.shstrndx(), 9);

    let expected_sections = [
        (
            0,
            ElfValue::Known(SectionKind::Null),
            0,
            0,
            0,
            0,
            ElfValue::Known(FlagSet::new(0).unwrap()),
            0,
            0,
            0,
        ),
        (
            1,
            ElfValue::Known(SectionKind::Progbits),
            0x2001c8,
            0x1c8,
            0x694,
            0,
            ElfValue::Known(SectionFlag::Alloc | SectionFlag::Merge | SectionFlag::Strings),
            0,
            0,
            8,
        ),
        (
            9,
            ElfValue::Known(SectionKind::Progbits),
            0x20085c,
            0x85c,
            0xac,
            0,
            ElfValue::Known(FlagSet::from(SectionFlag::Alloc)),
            0,
            0,
            4,
        ),
        (
            23,
            ElfValue::Known(SectionKind::Progbits),
            0x200908,
            0x908,
            0x39c,
            0,
            ElfValue::Known(FlagSet::from(SectionFlag::Alloc)),
            0,
            0,
            8,
        ),
        (
            33,
            ElfValue::Known(SectionKind::Progbits),
            0x201ca4,
            0xca4,
            0xe7b,
            0,
            ElfValue::Known(SectionFlag::Alloc | SectionFlag::ExecInstr),
            0,
            0,
            4,
        ),
        (
            39,
            ElfValue::Known(SectionKind::Nobits),
            0x202b20,
            0x1b20,
            0x0d,
            0,
            ElfValue::Known(SectionFlag::Write | SectionFlag::Alloc | SectionFlag::Tls),
            0,
            0,
            8,
        ),
        (
            45,
            ElfValue::Known(SectionKind::Progbits),
            0x203b20,
            0x1b20,
            0x1d2,
            0,
            ElfValue::Known(SectionFlag::Write | SectionFlag::Alloc),
            0,
            0,
            8,
        ),
        (
            51,
            ElfValue::Known(SectionKind::Nobits),
            0x204000,
            0x1cf2,
            0x31ac,
            0,
            ElfValue::Known(SectionFlag::Write | SectionFlag::Alloc),
            0,
            0,
            0x1000,
        ),
        (
            56,
            ElfValue::Known(SectionKind::Progbits),
            0,
            0x1cf2,
            0x13,
            1,
            ElfValue::Known(SectionFlag::Merge | SectionFlag::Strings),
            0,
            0,
            1,
        ),
        (
            65,
            ElfValue::Known(SectionKind::StringTable),
            0,
            0x1d05,
            0x4b,
            0,
            ElfValue::Known(FlagSet::new(0).unwrap()),
            0,
            0,
            1,
        ),
    ];

    for (i, section) in reader.sections().unwrap().into_iter().take(100).enumerate() {
        assert_eq!(section.name(), expected_sections[i].0);
        assert_eq!(section.kind(), expected_sections[i].1);
        assert_eq!(section.addr(), expected_sections[i].2);
        assert_eq!(section.offset(), expected_sections[i].3);
        assert_eq!(section.size(), expected_sections[i].4);
        assert_eq!(section.entsize(), expected_sections[i].5);
        assert_eq!(section.flags(), expected_sections[i].6);
        assert_eq!(section.link(), expected_sections[i].7);
        assert_eq!(section.info(), expected_sections[i].8);
        assert_eq!(section.addralign(), expected_sections[i].9);
    }

    let expected_strings = [
        "",
        ".rodata",
        ".eh_frame_hdr",
        ".eh_frame",
        ".text",
        ".tbss",
        ".data",
        ".bss",
        ".comment",
        ".shstrtab",
    ];

    let strings = reader.strings().unwrap();
    let mut offset = 0;
    for string in expected_strings {
        let s = strings.get_str(offset).unwrap().unwrap();

        assert_eq!(s, string);

        offset += u64::try_from(s.len()).unwrap() + 1;
    }
    assert_eq!(strings.get_str(offset), None);

    let expected_segments = [
        (
            ElfValue::Known(SegmentKind::Phdr),
            0x40,
            0x200040,
            0x200040,
            0x188,
            0x188,
            ElfValue::Known(FlagSet::from(SegmentFlag::Read)),
            8,
        ),
        (
            ElfValue::Known(SegmentKind::Load),
            0,
            0x200000,
            0x200000,
            0xca4,
            0xca4,
            ElfValue::Known(FlagSet::from(SegmentFlag::Read)),
            0x1000,
        ),
        (
            ElfValue::Known(SegmentKind::Load),
            0xca4,
            0x201ca4,
            0x201ca4,
            0xe7b,
            0xe7b,
            ElfValue::Known(SegmentFlag::Read | SegmentFlag::Execute),
            0x1000,
        ),
        (
            ElfValue::Known(SegmentKind::Load),
            0x1b20,
            0x203b20,
            0x203b20,
            0x1d2,
            0x368c,
            ElfValue::Known(SegmentFlag::Read | SegmentFlag::Write),
            0x1000,
        ),
        (
            ElfValue::Known(SegmentKind::Tls),
            0x1b20,
            0x202b20,
            0x202b20,
            0,
            0x0d,
            ElfValue::Known(FlagSet::from(SegmentFlag::Read)),
            8,
        ),
        (
            ElfValue::Unknown(0x6474e550),
            0x85c,
            0x20085c,
            0x20085c,
            0xac,
            0xac,
            ElfValue::Known(FlagSet::from(SegmentFlag::Read)),
            4,
        ),
        (
            ElfValue::Unknown(0x6474e551),
            0,
            0,
            0,
            0,
            0x1000000,
            ElfValue::Known(SegmentFlag::Read | SegmentFlag::Write),
            0,
        ),
    ];
    let segments = reader.segments().unwrap();

    for (i, segment) in segments.into_iter().enumerate() {
        assert_eq!(segment.kind(), expected_segments[i].0);
        assert_eq!(segment.offset(), expected_segments[i].1);
        assert_eq!(segment.vaddr(), expected_segments[i].2);
        assert_eq!(segment.paddr(), expected_segments[i].3);
        assert_eq!(segment.filesz(), expected_segments[i].4);
        assert_eq!(segment.memsz(), expected_segments[i].5);
        assert_eq!(segment.flags(), expected_segments[i].6);
        assert_eq!(segment.align(), expected_segments[i].7);
    }
}
