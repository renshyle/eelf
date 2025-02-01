use comfy_table::{modifiers::UTF8_ROUND_CORNERS, presets::UTF8_FULL, ContentArrangement, Table};
use eelf::{reader::ElfValue, ElfReader, Endianness, SegmentFlag, MACHINE_NAMES};
use listing::ListingFormatter;
use num_traits::ToPrimitive;

mod listing;

fn main() {
    let filename = std::env::args().nth(1).unwrap();
    let f = std::fs::read(&filename).unwrap();
    let reader = ElfReader::new(&f).unwrap();

    print_elf_header(&reader);
    println!();
    print_program_headers(&reader);
    println!();
    print_sections(&reader);
}

fn print_elf_header(reader: &ElfReader<'_>) {
    let header = reader.header().unwrap();

    let mut header_listing = ListingFormatter::new(2);
    header_listing.add("Class", if reader.is_64bit() { "ELF64" } else { "ELF32" });
    header_listing.add(
        "Data",
        match reader.endianness() {
            Endianness::Big => "big endian",
            Endianness::Little => "little endian",
        },
    );
    header_listing.add("Version", header.ei_version());
    header_listing.add(
        "OS/ABI",
        match header.osabi() {
            ElfValue::Known(osabi) => format!("{osabi:?}"),
            ElfValue::Unknown(value) => {
                format!("unknown OS/ABI {value}")
            }
        },
    );
    header_listing.add("ABI Version", header.abiversion());

    header_listing.add(
        "Type",
        match header.kind() {
            ElfValue::Known(kind) => format!("{kind:?}"),
            ElfValue::Unknown(value) => {
                format!("unknown type {value}")
            }
        },
    );

    header_listing.add(
        "Machine",
        match header.machine() {
            ElfValue::Known(machine) => MACHINE_NAMES
                .get(&machine.to_u16().unwrap())
                .unwrap()
                .to_string(),
            ElfValue::Unknown(value) => {
                format!("unknown machine {value}")
            }
        },
    );

    header_listing.add("Version", format!("0x{:x}", header.version()));
    header_listing.add("Entry point address", format!("0x{:x}", header.entry()));
    header_listing.add(
        "Start of program headers",
        format!("{} bytes", header.phoff()),
    );
    header_listing.add(
        "Start of section headers",
        format!("{} bytes", header.shoff()),
    );
    header_listing.add("Flags", format!("0x{:x}", header.flags()));
    header_listing.add("Size of this header", format!("{} bytes", header.ehsize()));
    header_listing.add(
        "Size of program headers",
        format!("{} bytes", header.phentsize()),
    );
    header_listing.add("Number of program headers", header.phnum());
    header_listing.add(
        "Size of section headers",
        format!("{} bytes", header.shentsize()),
    );
    header_listing.add("Number of section headers", header.shnum());
    header_listing.add("Section header string table index", header.shstrndx());

    println!("ELF Header:");
    print!("  Magic:  ");
    for byte in header.ident() {
        print!(" {byte:02x}");
    }
    println!();

    print!("{}", header_listing);
}

fn print_program_headers(reader: &ElfReader<'_>) {
    let program_headers = reader.segments().unwrap();

    if program_headers.get(0).is_none() {
        println!("There are no program headers in this file.");
        return;
    }

    println!("Program headers:");

    println!(
        "  {: <18} {: <18} {: <18} {: <18}",
        "Type", "Offset", "VirtAddr", "PhysAddr"
    );
    println!(
        "  {: <18} {: <18} {: <18}  {: <5}  Align",
        "", "FileSiz", "MemSiz", "Flags"
    );
    for program_header in program_headers {
        match program_header.kind() {
            ElfValue::Known(kind) => print!("  {: <18}", format!("{:?}", kind)),
            ElfValue::Unknown(value) => print!("  0x{: <16x}", value),
        }

        print!(" 0x{:016x}", program_header.offset());
        print!(" 0x{:016x}", program_header.vaddr());
        print!(" 0x{:016x}", program_header.paddr());
        println!();

        print!("  {: <18}", "");
        print!(" 0x{:016x}", program_header.filesz());
        print!(" 0x{:016x}  ", program_header.memsz());

        match program_header.flags() {
            ElfValue::Known(flags) => {
                if flags.contains(SegmentFlag::Read) {
                    print!("R");
                } else {
                    print!(" ");
                }

                if flags.contains(SegmentFlag::Write) {
                    print!("W");
                } else {
                    print!(" ");
                }

                if flags.contains(SegmentFlag::Execute) {
                    print!("E");
                } else {
                    print!(" ");
                }
            }
            ElfValue::Unknown(_) => todo!(),
        }

        print!("    ");

        let align = program_header.align();
        if align >= 0x100000000 {
            print!("big");
        } else {
            print!("0x{:x}", align);
        }

        println!();
    }
}

fn print_sections(reader: &ElfReader<'_>) {
    println!("Sections:");

    let sections = reader.sections().unwrap();
    let strings = reader.strings().unwrap();
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header([
            "Index", "Name", "Type", "Address", "Offset", "Size", "EntSize", "Flags", "Link",
            "Info", "Align",
        ]);
    for (i, section) in sections.into_iter().enumerate() {
        let mut row = Vec::new();
        row.push(i.to_string());
        row.push(
            strings
                .get_str(section.name())
                .unwrap()
                .unwrap()
                .to_string(),
        );
        row.push(match section.kind() {
            ElfValue::Known(kind) => format!("{kind:?}"),
            ElfValue::Unknown(value) => format!("0x{value:x}"),
        });
        row.push(format!("0x{:x}", section.addr()));
        row.push(format!("0x{:x}", section.offset()));
        row.push(format!("0x{:x}", section.size()));
        row.push(format!("0x{:x}", section.entsize()));

        match section.flags() {
            ElfValue::Known(flags) => row.push(
                flags
                    .into_iter()
                    .map(|flag| format!("{:?}", flag))
                    .collect::<Vec<_>>()
                    .as_slice()
                    .join(", "),
            ),
            ElfValue::Unknown(value) => row.push(format!("0x{:x}", value)),
        }

        row.push(format!("{}", section.link()));
        row.push(format!("{}", section.info()));
        row.push(format!("0x{:x}", section.addralign()));

        table.add_row(row);
    }

    println!("{table}");
}
