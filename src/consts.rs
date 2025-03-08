use flagset::flags;
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::ToPrimitive;
use phf::phf_map;

pub(crate) const ELF_MAGIC: &[u8] = &[0x7f, b'E', b'L', b'F'];
pub(crate) const EI_CLASS: usize = 4;
pub(crate) const EI_DATA: usize = 5;
pub(crate) const EI_VERSION: usize = 6;
pub(crate) const EI_OSABI: usize = 7;
pub(crate) const EI_ABIVERSION: usize = 8;
pub(crate) const EI_NIDENT: usize = 16;

pub(crate) const ELF32_HEADER_SIZE: u16 = 52;
pub(crate) const ELF64_HEADER_SIZE: u16 = 64;
pub(crate) const ELF32_SECTION_HEADER_SIZE: u16 = 40;
pub(crate) const ELF64_SECTION_HEADER_SIZE: u16 = 64;
pub(crate) const ELF32_PROGRAM_HEADER_SIZE: u16 = 32;
pub(crate) const ELF64_PROGRAM_HEADER_SIZE: u16 = 56;

flags! {
    /// ELF section flag. Directly corresponds to the sh_flags field.
    pub enum SectionFlag: u32 {
        /// The data is writable by the program.
        Write = 0x01,
        /// The data is loaded into memory when the program is started.
        Alloc = 0x02,
        /// The executed as instructions by the processor.
        ExecInstr = 0x04,
        /// The data may be merged to avoid duplication. The `sh_entsize` field states the size of
        /// each entry, unless the section is a string table.
        Merge = 0x10,
        /// The data is a string table, an array of null-terminated strings.
        Strings = 0x20,
        /// The `sh_info` field contains a section header table index.
        InfoLink = 0x40,
        /// There are special rules to ordering the linking of this section.
        LinkOrder = 0x80,
        /// OS-specific details are required to link correctly.
        OsNonconforming = 0x100,
        /// The section is a member of a section group.
        Group = 0x200,
        /// Thread-local storage
        Tls = 0x400,
        /// The section contains compressed data. This flag may not be used with `Alloc`.
        Compressed = 0x800,
    }

    /// Permission a segment is loaded with
    pub enum SegmentFlag: u32 {
        /// The segment's contents can be executed as instructions.
        Execute,
        /// The segment's contents can be written to by the program
        Write,
        /// The segment's contents can be read by the program.
        Read,
    }
}

/// ELF file type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, FromPrimitive, ToPrimitive)]
pub enum ElfKind {
    /// No file type
    None,
    /// Relocatable file
    Relocatable,
    /// Executable file
    Executable,
    /// Shared object file
    Dynamic,
    /// Core file
    Core,
}

/// Represents the endianness of a system, i.e. the order in which order bytes of an integer are
/// stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endianness {
    /// Little endian. Least significant byte is stored first.
    Little,
    /// Big endian. Most significant byte is stored first.
    Big,
}

impl Endianness {
    /// Converts an array of two bytes into a [`u16`] using the specified endianness.
    pub fn u16_from_bytes(&self, bytes: [u8; 2]) -> u16 {
        match self {
            Endianness::Little => u16::from_le_bytes(bytes),
            Endianness::Big => u16::from_be_bytes(bytes),
        }
    }

    /// Converts an array of four bytes into a [`u32`] using the specified endianness.
    pub fn u32_from_bytes(&self, bytes: [u8; 4]) -> u32 {
        match self {
            Endianness::Little => u32::from_le_bytes(bytes),
            Endianness::Big => u32::from_be_bytes(bytes),
        }
    }

    /// Converts an array of eight bytes into a [`u64`] using the specified endianness.
    pub fn u64_from_bytes(&self, bytes: [u8; 8]) -> u64 {
        match self {
            Endianness::Little => u64::from_le_bytes(bytes),
            Endianness::Big => u64::from_be_bytes(bytes),
        }
    }

    /// Converts a [`u16`] into an array of two bytes.
    pub fn u16_to_bytes(&self, value: u16) -> [u8; 2] {
        match self {
            Endianness::Little => u16::to_le_bytes(value),
            Endianness::Big => u16::to_be_bytes(value),
        }
    }

    /// Converts a [`u32`] into an array of two bytes.
    pub fn u32_to_bytes(&self, value: u32) -> [u8; 4] {
        match self {
            Endianness::Little => u32::to_le_bytes(value),
            Endianness::Big => u32::to_be_bytes(value),
        }
    }

    /// Converts a [`u64`] into an array of two bytes.
    pub fn u64_to_bytes(&self, value: u64) -> [u8; 8] {
        match self {
            Endianness::Little => u64::to_le_bytes(value),
            Endianness::Big => u64::to_be_bytes(value),
        }
    }
}

/// ELF segment type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, FromPrimitive, ToPrimitive)]
pub enum SegmentKind {
    /// Unused entry
    Null,
    /// The segment contents are loaded into memory at runtime
    Load,
    /// Dynamic linking information
    Dynamic,
    /// Defines the program interpreter to be used fro the executable
    Interp,
    /// Defines the location and size of extra information
    Note,
    /// Reserved
    Shlib,
    /// Defines the location and size of the program header table
    Phdr,
    /// Thread-local storage
    Tls,
}

/// ELF section type
#[derive(Debug, Clone, Copy, PartialEq, Eq, FromPrimitive, ToPrimitive)]
pub enum SectionKind {
    /// Inactive
    Null = 0,
    /// Program-specific information
    Progbits = 1,
    /// Symbol table
    SymbolTable = 2,
    /// String table
    StringTable = 3,
    /// Relocation table with addends
    Rela = 4,
    /// Symbol hash table
    Hash = 5,
    /// Dynamic linking information
    Dynamic = 6,
    /// Special information
    Note = 7,
    /// The section does not occupy any space in the file
    Nobits = 8,
    /// Relocation table without addends
    Rel = 9,
    /// Reserved
    Shlib = 10,
    /// Dynamic symbol table
    DynSym = 11,
    /// Array of pointers to initialization functions
    InitArray = 14,
    /// Array of pointers to termination functions
    FiniArray = 15,
    /// Array of pointers to pre-initialization functions
    PreinitArray = 16,
    /// Section group
    Group = 17,
    /// Contains section header indices for a symbol table
    SymTabShndx = 18,
}

/// ELF symbol type
#[derive(Debug, Clone, Copy, PartialEq, Eq, FromPrimitive, ToPrimitive)]
pub enum SymbolKind {
    /// Unspecefied type
    NoType = 0,
    /// Data
    Object = 1,
    /// Function, executable code
    Func = 2,
    /// Section
    Section = 3,
    /// The name of the symbol is the name of the source file.
    File = 4,
    /// Uninitialized common block
    Common = 5,
    /// Thread-local storage
    Tls = 6,
}

/// Operating system or ABI of an ELF file. Determines which ELF extensions are used by the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, FromPrimitive, ToPrimitive)]
#[non_exhaustive]
pub enum OsAbi {
    /// No extensions or unspecified
    None = 0,
    /// HP-UX
    HpUx = 1,
    /// NetBSD
    NetBsd = 2,
    /// GNU
    Gnu = 3,
    /// Solaris
    Solaris = 6,
    /// AIX
    Aix = 7,
    /// IRIX
    Irix = 8,
    /// FreeBSD
    FreeBsd = 9,
    /// TRU64 UNIX
    Tru64 = 10,
    /// Novell Modesto
    Modesto = 11,
    /// OpenBSD
    OpenBsd = 12,
    /// OpenVMS
    OpenVms = 13,
    /// HP Non-Stop Kernel
    Nsk = 14,
    /// Amiga Research OS
    Aros = 15,
    /// FenixOS
    FenixOs = 16,
    /// Nexi CloudABI
    CloudAbi = 17,
    /// OpenVOS
    OpenVos = 18,
}

/// The target architecture of an ELF file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, FromPrimitive, ToPrimitive)]
#[non_exhaustive]
pub enum MachineKind {
    /// No machine
    None = 0,
    /// AT&T WE 32100
    M32 = 1,
    /// SUN SPARC
    Sparc = 2,
    /// Intel 80386
    Ia386 = 3,
    /// Motorola m68k family
    M68K = 4,
    /// Motorola m88k family
    M88K = 5,
    /// Intel MCU
    IaMcu = 6,
    /// Intel 80860
    Ia860 = 7,
    /// MIPS R3000 big-endian
    Mips = 8,
    /// IBM System/370
    S370 = 9,
    /// MIPS R3000 little-endian
    MipsRs3Le = 10,
    /// HPPA
    PaRisc = 15,
    /// Fujitsu VPP500
    Vp500 = 17,
    /// Sun's "v8plus"
    Sparc32Plus = 18,
    /// Intel 80960
    Ia960 = 19,
    /// PowerPC
    Ppc = 20,
    /// PowerPC 64-bit
    Ppc64 = 21,
    /// IBM S390
    S390 = 22,
    /// IBM SPU/SPC
    Spu = 23,
    /// NEC V800 series
    V800 = 36,
    /// Fujitsu FR20
    Fr20 = 37,
    /// TRW RH-32
    Rh32 = 38,
    /// Motorola RCE
    Rce = 39,
    /// ARM
    Arm = 40,
    /// Digital Alpha
    FakeAlpha = 41,
    /// Hitachi SH
    Sh = 42,
    /// SPARC v9 64-bit
    SparcV9 = 43,
    /// Siemens Tricore
    Tricore = 44,
    /// Argonaut RISC Core
    Arc = 45,
    /// Hitachi H8/300
    H8_300 = 46,
    /// Hitachi H8/300H
    H8_300H = 47,
    /// Hitachi H8S
    H8S = 48,
    /// Hitachi H8/500
    H8_500 = 49,
    /// Intel Merced
    Ia64 = 50,
    /// Stanford MIPS-X
    MipsX = 51,
    /// Motorola Coldfire
    Coldfire = 52,
    /// Motorola M68HC12
    M68HC12 = 53,
    /// Fujitsu MMA Multimedia Accelerator
    Mma = 54,
    /// Siemens PCP
    Pcp = 55,
    /// Sony nCPU embedded RISC
    Ncpu = 56,
    /// Denso NDR1 microprocessor
    Ndr1 = 57,
    /// Motorola Start*Core processor
    StarCore = 58,
    /// Toyota ME16 processor
    Mu16 = 59,
    /// STMicroelectronic ST100 processor
    St100 = 60,
    /// Advanced Logic Corp. Tinyj emb.fam
    Tinyj = 61,
    /// AMD x86-64 architecture
    X86_64 = 62,
    /// Sony DSP Processor
    Pdsp = 63,
    /// Digital PDP-10
    Pdp10 = 64,
    /// Digital PDP-11
    Pdp11 = 65,
    /// Siemens FX66 microcontroller
    Fx66 = 66,
    /// STMicroelectronics ST9+ 8/16 mc
    St9Plus = 67,
    /// STmicroelectronics ST7 8 bit mc
    St7 = 68,
    /// Motorola MC68HC16 microcontroller
    M68HC16 = 69,
    /// Motorola MC68HC11 microcontroller
    M68HC11 = 70,
    /// Motorola MC68HC08 microcontroller
    M68HC08 = 71,
    /// Motorola MC68HC05 microcontroller
    M68HC05 = 72,
    /// Silicon Graphics SVx
    Svx = 73,
    /// STMicroelectronics ST19 8 bit mc
    St19 = 74,
    /// Digital VAX
    Vax = 75,
    /// Axis Communications 32-bit emb.proc
    Cris = 76,
    /// Infineon Technologies 32-bit emb.proc
    Javelin = 77,
    /// Element 14 64-bit DSP Processor
    Firepath = 78,
    /// LSI Logic 16-bit DSP Processor
    Zsp = 79,
    /// Donald Knuth's educational 64-bit proc
    Mmix = 80,
    /// Harvard University machine-independent object files
    Huany = 81,
    /// SiTera Prism
    Prism = 82,
    /// Atmel AVR 8-bit microcontroller
    Avr = 83,
    /// Fujitsu FR30
    Fr30 = 84,
    /// Mitsubishi D10V
    D10V = 85,
    /// Mitsubishi D30V
    D30V = 86,
    /// NEC v850
    V850 = 87,
    /// Mitsubishi M32R
    M32R = 88,
    /// Matsushita MN10300
    Mn10300 = 89,
    /// Matsushita MN10200
    Mn10200 = 90,
    /// picoJava
    PJ = 91,
    /// OpenRISC 32-bit embedded processor
    OpenRisc = 92,
    /// ARC International ARCompact
    ArcCompact = 93,
    /// Tensilica Xtensa Architecture
    Xtensa = 94,
    /// Alphamosaic VideoCore
    VideoCore = 95,
    /// Thompson Multimedia General Purpose Proc
    TmmGpp = 96,
    /// National Semi. 32000
    Ns32K = 97,
    /// Tenor Network TPC
    Tpc = 98,
    /// Trebia SNP 1000
    SnP1K = 99,
    /// STMicroelectronics ST200
    St200 = 100,
    /// Ubicom IP2xxx
    Ip2K = 101,
    /// MAX processor
    Max = 102,
    /// National Semi. CompactRISC
    Cr = 103,
    /// Fujitsu F2MC16
    F2MC16 = 104,
    /// Texas Instruments msp430
    Msp430 = 105,
    /// Analog Devices Blackfin DSP
    Blackfin = 106,
    /// Seiko Epson S1C33 family
    SeC33 = 107,
    /// Sharp embedded microprocessor
    Sep = 108,
    /// Arca RISC
    Arca = 109,
    /// PKU-Unity & MPRC Peking Uni. mc series
    Unicore = 110,
    /// eXcess configurable cpu
    Excess = 111,
    /// Icera Semi. Deep Execution Processor
    Dxp = 112,
    /// Altera Nios II
    AlteraNios2 = 113,
    /// National Semi. CompactRISC CRX
    Crx = 114,
    /// Motorola XGATE
    Xgate = 115,
    /// Infineon C16x/XC16x
    C166 = 116,
    /// Renesas M16C
    M16C = 117,
    /// Microchip Technology dsPIC30F
    DsPic30F = 118,
    /// Freescale Communication Engine RISC
    Ce = 119,
    /// Renesas M32C
    M32C = 120,
    /// Altium TSK3000
    Tsk3000 = 131,
    /// Freescale RS08
    Rs08 = 132,
    /// Analog Devices SHARC family
    Sharc = 133,
    /// Cyan Technology eCOG2
    Ecog2 = 134,
    /// Sunplus S+core7 RISC
    Score7 = 135,
    /// New Japan Radio (NJR) 24-bit DSP
    Dsp24 = 136,
    /// Broadcom VideoCore III
    VideoCore3 = 137,
    /// RISC for Lattice FPGA
    LatticeMico32 = 138,
    /// Seiko Epson C17
    SeC17 = 139,
    /// Texas Instruments TMS320C6000 DSP
    TiC6000 = 140,
    /// Texas Instruments TMS320C2000 DSP
    TiC2000 = 141,
    /// Texas Instruments TMS320C55x DSP
    TiC5500 = 142,
    /// Texas Instruments App. Specific RISC
    TiArp32 = 143,
    /// Texas Instruments Prog. Realtime Unit
    TiPru = 144,
    /// STMicroelectronics 64bit VLIW DSP
    MmdspPlus = 160,
    /// Cypress M8C
    CypressM8C = 161,
    /// Renesas R32C
    R32C = 162,
    /// NXP Semi. TriMedia
    TriMedia = 163,
    /// QUALCOMM DSP6
    Qdsp6 = 164,
    /// Intel 8051 and variants
    Ia8051 = 165,
    /// STMicroelectronics STxP7x
    StxP7x = 166,
    /// Andes Tech. compact code emb. RISC
    Nds32 = 167,
    /// Cyan Technology eCOG1X
    Ecog1X = 168,
    /// Dallas Semi. MAXQ30 mc
    Maxq30 = 169,
    /// New Japan Radio (NJR) 16-bit DSP
    Ximo16 = 170,
    /// M2000 Reconfigurable RISC
    Manik = 171,
    /// Cray NV2 vector architecture
    CrayNv2 = 172,
    /// Renesas RX
    Rx = 173,
    /// Imagination Tech. META
    Metag = 174,
    /// MCST Elbrus
    McstElbrus = 175,
    /// Cyan Technology eCOG16
    Ecog16 = 176,
    /// National Semi. CompactRISC CR16
    Cr16 = 177,
    /// Freescale Extended Time Processing Unit
    Etpu = 178,
    /// Infineon Tech. SLE9X
    Sle9X = 179,
    /// Intel L10M
    L10M = 180,
    /// Intel K10M
    K10M = 181,
    /// ARM AARCH64
    Aarch64 = 183,
    /// Amtel 32-bit microprocessor
    Avr32 = 185,
    /// STMicroelectronics STM8
    Stm8 = 186,
    /// Tilera TILE64
    Tile64 = 187,
    /// Tilera TILEPro
    TilePro = 188,
    /// Xilinx MicroBlaze
    MicroBlaze = 189,
    /// NVIDIA CUDA
    Cuda = 190,
    /// Tilera TILE-Gx
    TileGx = 191,
    /// CloudShield
    CloudShield = 192,
    /// KIPO-KAIST Core-A 1st gen.
    CoreA1st = 193,
    /// KIPO-KAIST Core-A 2nd gen.
    CoreA2nd = 194,
    /// Synopsys ARCv2 ISA.
    ArcV2 = 195,
    /// Open8 RISC
    Open8 = 196,
    /// Renesas RL78
    Rl78 = 197,
    /// Broadcom VideoCore V
    VideoCore5 = 198,
    /// Renesas 78KOR
    Renesas78Kor = 199,
    /// Freescale 56800EX DSC
    Fs56800Ex = 200,
    /// Beyond BA1
    Ba1 = 201,
    /// Beyond BA2
    Ba2 = 202,
    /// XMOS xCORE
    XCore = 203,
    /// Microchip 8-bit PIC(r)
    MchpPic = 204,
    /// Intel Graphics Technology
    IntelGt = 205,
    /// KM211 KM32
    Km32 = 210,
    /// KM211 KMX32
    Kmx32 = 211,
    /// KM211 KMX16
    Emx16 = 212,
    /// KM211 KMX8
    Emx8 = 213,
    /// KM211 KVARC
    Kvarc = 214,
    /// Paneve CDP
    Cdp = 215,
    /// Cognitive Smart Memory Processor
    Coge = 216,
    /// Bluechip CoolEngine
    Cool = 217,
    /// Nanoradio Optimized RISC
    Norc = 218,
    /// CSR Kalimba
    CsrKalimba = 219,
    /// Zilog Z80
    Z80 = 220,
    /// Controls and Data Services VISIUMcore
    Visium = 221,
    /// FTDI Chip FT32
    Ft32 = 222,
    /// Moxie processor
    Moxie = 223,
    /// AMD GPU
    Amdgpu = 224,
    /// RISC-V
    RiscV = 243,
    /// Linux BPF -- in-kernel virtual machine
    Bpf = 247,
    /// C-SKY
    CSky = 252,
    /// LoongArch
    LoongArch = 258,
    /// ChipON KungFu32
    Kf32 = 259,
    /// LAPIS nX-U16/U8
    U16U8Core = 260,
    /// Tachyum processor
    Tachyum = 261,
    /// NXP 56800EF Digital Signal Controller (DSC)
    Fs56800Ef = 262,
    /// Solana Bytecode Format
    Sbf = 263,
    /// AMD/Xilinx AIEngine architecture
    AiEngine = 264,
    /// SiMa MLA
    SimaMla = 265,
    /// Cambricon BANG
    Bang = 266,
    /// Loongson Loongarch
    LoongGpu = 267,
    /// Alpha
    Alpha = 0x9026,
}

impl MachineKind {
    /// Returns the human-readable name of the machine
    pub fn name(&self) -> &'static str {
        MACHINE_NAMES.get(&self.to_u16().unwrap()).unwrap()
    }
}

static MACHINE_NAMES: phf::Map<u16, &'static str> = phf_map! {
    0u16 => "No machine",
    1u16 => "AT&T WE 32100",
    2u16 => "SUN SPARC",
    3u16 => "Intel 80386",
    4u16 => "Motorola m68k family",
    5u16 => "Motorola m88k family",
    6u16 => "Intel MCU",
    7u16 => "Intel 80860",
    8u16 => "MIPS R3000 big-endian",
    9u16 => "IBM System/370",
    10u16 => "MIPS R3000 little-endian",
    15u16 => "HPPA",
    17u16 => "Fujitsu VPP500",
    18u16 => "Sun's \"v8plus\"",
    19u16 => "Intel 80960",
    20u16 => "PowerPC",
    21u16 => "PowerPC 64-bit",
    22u16 => "IBM S390",
    23u16 => "IBM SPU/SPC",
    36u16 => "NEC V800 series",
    37u16 => "Fujitsu FR20",
    38u16 => "TRW RH-32",
    39u16 => "Motorola RCE",
    40u16 => "ARM",
    41u16 => "Digital Alpha",
    42u16 => "Hitachi SH",
    43u16 => "SPARC v9 64-bit",
    44u16 => "Siemens Tricore",
    45u16 => "Argonaut RISC Core",
    46u16 => "Hitachi H8/300",
    47u16 => "Hitachi H8/300H",
    48u16 => "Hitachi H8S",
    49u16 => "Hitachi H8/500",
    50u16 => "Intel Merced",
    51u16 => "Stanford MIPS-X",
    52u16 => "Motorola Coldfire",
    53u16 => "Motorola M68HC12",
    54u16 => "Fujitsu MMA Multimedia Accelerator",
    55u16 => "Siemens PCP",
    56u16 => "Sony nCPU embedded RISC",
    57u16 => "Denso NDR1 microprocessor",
    58u16 => "Motorola Start*Core processor",
    59u16 => "Toyota ME16 processor",
    60u16 => "STMicroelectronic ST100 processor",
    61u16 => "Advanced Logic Corp. Tinyj emb.fam",
    62u16 => "AMD x86-64 architecture",
    63u16 => "Sony DSP Processor",
    64u16 => "Digital PDP-10",
    65u16 => "Digital PDP-11",
    66u16 => "Siemens FX66 microcontroller",
    67u16 => "STMicroelectronics ST9+ 8/16 mc",
    68u16 => "STmicroelectronics ST7 8 bit mc",
    69u16 => "Motorola MC68HC16 microcontroller",
    70u16 => "Motorola MC68HC11 microcontroller",
    71u16 => "Motorola MC68HC08 microcontroller",
    72u16 => "Motorola MC68HC05 microcontroller",
    73u16 => "Silicon Graphics SVx",
    74u16 => "STMicroelectronics ST19 8 bit mc",
    75u16 => "Digital VAX",
    76u16 => "Axis Communications 32-bit emb.proc",
    77u16 => "Infineon Technologies 32-bit emb.proc",
    78u16 => "Element 14 64-bit DSP Processor",
    79u16 => "LSI Logic 16-bit DSP Processor",
    80u16 => "Donald Knuth's educational 64-bit proc",
    81u16 => "Harvard University machine-independent object files",
    82u16 => "SiTera Prism",
    83u16 => "Atmel AVR 8-bit microcontroller",
    84u16 => "Fujitsu FR30",
    85u16 => "Mitsubishi D10V",
    86u16 => "Mitsubishi D30V",
    87u16 => "NEC v850",
    88u16 => "Mitsubishi M32R",
    89u16 => "Matsushita MN10300",
    90u16 => "Matsushita MN10200",
    91u16 => "picoJava",
    92u16 => "OpenRISC 32-bit embedded processor",
    93u16 => "ARC International ARCompact",
    94u16 => "Tensilica Xtensa Architecture",
    95u16 => "Alphamosaic VideoCore",
    96u16 => "Thompson Multimedia General Purpose Proc",
    97u16 => "National Semi. 32000",
    98u16 => "Tenor Network TPC",
    99u16 => "Trebia SNP 1000",
    100u16 => "STMicroelectronics ST200",
    101u16 => "Ubicom IP2xxx",
    102u16 => "MAX processor",
    103u16 => "National Semi. CompactRISC",
    104u16 => "Fujitsu F2MC16",
    105u16 => "Texas Instruments msp430",
    106u16 => "Analog Devices Blackfin DSP",
    107u16 => "Seiko Epson S1C33 family",
    108u16 => "Sharp embedded microprocessor",
    109u16 => "Arca RISC",
    110u16 => "PKU-Unity & MPRC Peking Uni. mc series",
    111u16 => "eXcess configurable cpu",
    112u16 => "Icera Semi. Deep Execution Processor",
    113u16 => "Altera Nios II",
    114u16 => "National Semi. CompactRISC CRX",
    115u16 => "Motorola XGATE",
    116u16 => "Infineon C16x/XC16x",
    117u16 => "Renesas M16C",
    118u16 => "Microchip Technology dsPIC30F",
    119u16 => "Freescale Communication Engine RISC",
    120u16 => "Renesas M32C",
    131u16 => "Altium TSK3000",
    132u16 => "Freescale RS08",
    133u16 => "Analog Devices SHARC family",
    134u16 => "Cyan Technology eCOG2",
    135u16 => "Sunplus S+core7 RISC",
    136u16 => "New Japan Radio (NJR) 24-bit DSP",
    137u16 => "Broadcom VideoCore III",
    138u16 => "RISC for Lattice FPGA",
    139u16 => "Seiko Epson C17",
    140u16 => "Texas Instruments TMS320C6000 DSP",
    141u16 => "Texas Instruments TMS320C2000 DSP",
    142u16 => "Texas Instruments TMS320C55x DSP",
    143u16 => "Texas Instruments App. Specific RISC",
    144u16 => "Texas Instruments Prog. Realtime Unit",
    160u16 => "STMicroelectronics 64bit VLIW DSP",
    161u16 => "Cypress M8C",
    162u16 => "Renesas R32C",
    163u16 => "NXP Semi. TriMedia",
    164u16 => "QUALCOMM DSP6",
    165u16 => "Intel 8051 and variants",
    166u16 => "STMicroelectronics STxP7x",
    167u16 => "Andes Tech. compact code emb. RISC",
    168u16 => "Cyan Technology eCOG1X",
    169u16 => "Dallas Semi. MAXQ30 mc",
    170u16 => "New Japan Radio (NJR) 16-bit DSP",
    171u16 => "M2000 Reconfigurable RISC",
    172u16 => "Cray NV2 vector architecture",
    173u16 => "Renesas RX",
    174u16 => "Imagination Tech. META",
    175u16 => "MCST Elbrus",
    176u16 => "Cyan Technology eCOG16",
    177u16 => "National Semi. CompactRISC CR16",
    178u16 => "Freescale Extended Time Processing Unit",
    179u16 => "Infineon Tech. SLE9X",
    180u16 => "Intel L10M",
    181u16 => "Intel K10M",
    183u16 => "ARM AARCH64",
    185u16 => "Amtel 32-bit microprocessor",
    186u16 => "STMicroelectronics STM8",
    187u16 => "Tilera TILE64",
    188u16 => "Tilera TILEPro",
    189u16 => "Xilinx MicroBlaze",
    190u16 => "NVIDIA CUDA",
    191u16 => "Tilera TILE-Gx",
    192u16 => "CloudShield",
    193u16 => "KIPO-KAIST Core-A 1st gen.",
    194u16 => "KIPO-KAIST Core-A 2nd gen.",
    195u16 => "Synopsys ARCv2 ISA. ",
    196u16 => "Open8 RISC",
    197u16 => "Renesas RL78",
    198u16 => "Broadcom VideoCore V",
    199u16 => "Renesas 78KOR",
    200u16 => "Freescale 56800EX DSC",
    201u16 => "Beyond BA1",
    202u16 => "Beyond BA2",
    203u16 => "XMOS xCORE",
    204u16 => "Microchip 8-bit PIC(r)",
    205u16 => "Intel Graphics Technology",
    210u16 => "KM211 KM32",
    211u16 => "KM211 KMX32",
    212u16 => "KM211 KMX16",
    213u16 => "KM211 KMX8",
    214u16 => "KM211 KVARC",
    215u16 => "Paneve CDP",
    216u16 => "Cognitive Smart Memory Processor",
    217u16 => "Bluechip CoolEngine",
    218u16 => "Nanoradio Optimized RISC",
    219u16 => "CSR Kalimba",
    220u16 => "Zilog Z80",
    221u16 => "Controls and Data Services VISIUMcore",
    222u16 => "FTDI Chip FT32",
    223u16 => "Moxie processor",
    224u16 => "AMD GPU",
    243u16 => "RISC-V",
    247u16 => "Linux BPF -- in-kernel virtual machine",
    252u16 => "C-SKY",
    258u16 => "LoongArch",
    259u16 => "ChipON KungFu32",
    260u16 => "LAPIS nX-U16/U8",
    261u16 => "Tachyum processor",
    262u16 => "NXP 56800EF Digital Signal Controller (DSC)",
    263u16 => "Solana Bytecode Format",
    264u16 => "AMD/Xilinx AIEngine architecture",
    265u16 => "SiMa MLA",
    266u16 => "Cambricon BANG",
    267u16 => "Loongson Loongarch",
    0x9026u16 => "Alpha",
};
