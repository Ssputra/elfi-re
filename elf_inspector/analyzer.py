"""Core static analysis logic for ELF x86_64 binaries."""

from __future__ import annotations

from dataclasses import dataclass

from capstone import CS_ARCH_X86, CS_MODE_64, CS_OPT_SYNTAX_INTEL, Cs, CsError
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP
from elftools.elf.constants import SH_FLAGS
from elftools.elf.dynamic import DynamicSection
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection

from .loader import (
    ByteSlice,
    InvalidELFError,
    extract_bytes_by_section,
    extract_bytes_by_vaddr_range,
)

STANDARD_ELF_SECTIONS = frozenset(
    {
        "",
        "<unnamed>",
        ".interp",
        ".note.ABI-tag",
        ".note.gnu.build-id",
        ".note.gnu.property",
        ".gnu.hash",
        ".hash",
        ".dynsym",
        ".dynstr",
        ".gnu.version",
        ".gnu.version_r",
        ".gnu.version_d",
        ".rela.dyn",
        ".rela.plt",
        ".rel.dyn",
        ".rel.plt",
        ".init",
        ".plt",
        ".plt.got",
        ".plt.sec",
        ".text",
        ".fini",
        ".rodata",
        ".eh_frame_hdr",
        ".eh_frame",
        ".gcc_except_table",
        ".init_array",
        ".fini_array",
        ".preinit_array",
        ".ctors",
        ".dtors",
        ".jcr",
        ".dynamic",
        ".got",
        ".got.plt",
        ".data",
        ".data.rel.ro",
        ".tdata",
        ".tbss",
        ".bss",
        ".comment",
        ".symtab",
        ".strtab",
        ".shstrtab",
    }
)

STANDARD_SECTION_PREFIXES = (".note.", ".gnu.", ".rela.", ".rel.", ".debug_")


@dataclass(frozen=True)
class ElfHeaderInfo:
    """Structured summary of the ELF header."""

    elf_class: str
    endianness: str
    os_abi: str
    elf_type: str
    machine: str
    arch_friendly: str
    entry_point: int
    ph_offset: int
    sh_offset: int
    ph_num: int
    sh_num: int
    is_x86_64: bool


@dataclass(frozen=True)
class SectionInfo:
    """Structured representation of an ELF section header."""

    index: int
    name: str
    sh_type: str
    vaddr: int
    offset: int
    size: int
    flags: str
    align: int
    is_alloc: bool


@dataclass(frozen=True)
class ExtractedString:
    """Represents a printable ASCII/UTF-8 string found in binary data."""

    section: str
    address: int
    file_offset: int
    value: str
    is_vaddr: bool = True


@dataclass(frozen=True)
class SymbolInfo:
    """Structured representation of an ELF symbol."""

    table: str
    name: str
    sym_type: str
    binding: str
    vaddr: int
    size: int
    section_index: str


@dataclass(frozen=True)
class ImportedFunction:
    """Represents an external imported function symbol (e.g. fgets, puts)."""

    name: str
    binding: str
    sym_type: str
    table: str


@dataclass(frozen=True)
class RelocationInfo:
    """Structured representation of an ELF relocation entry."""

    section: str
    offset: int
    reloc_type: int
    symbol_name: str
    addend: int | None


@dataclass(frozen=True)
class DisasmInstruction:
    """Single disassembled x86_64 instruction with optional symbol & XREF."""

    address: int
    raw_bytes: bytes
    mnemonic: str
    op_str: str
    symbol_label: str | None = None
    xref: str | None = None


@dataclass(frozen=True)
class TriageReport:
    """Quick triage summary for rapid static inspection."""

    header: ElfHeaderInfo
    non_standard_sections: list[SectionInfo]
    imported_libraries: list[str]
    imported_functions: list[ImportedFunction]
    important_strings: list[ExtractedString]


def _format_section_flags(flags: int) -> str:
    """Convert numeric section flags to standard readelf-like flag letters."""
    flag_map = (
        (SH_FLAGS.SHF_WRITE, "W"),
        (SH_FLAGS.SHF_ALLOC, "A"),
        (SH_FLAGS.SHF_EXECINSTR, "X"),
        (SH_FLAGS.SHF_MERGE, "M"),
        (SH_FLAGS.SHF_STRINGS, "S"),
        (SH_FLAGS.SHF_INFO_LINK, "I"),
        (SH_FLAGS.SHF_TLS, "T"),
    )
    chars = [letter for bit, letter in flag_map if flags & bit]
    return "".join(chars) if chars else "-"


def is_standard_section(name: str) -> bool:
    """Return True if the section name is a standard ELF section."""
    if name in STANDARD_ELF_SECTIONS:
        return True
    return name.startswith(STANDARD_SECTION_PREFIXES)


def get_elf_info(elf: ELFFile) -> ElfHeaderInfo:
    """Extract ELF header metadata."""
    header = elf.header
    e_ident = header["e_ident"]

    ei_class = e_ident["EI_CLASS"]
    elf_class = (
        "ELF64"
        if ei_class == "ELFCLASS64"
        else "ELF32"
        if ei_class == "ELFCLASS32"
        else str(ei_class)
    )

    ei_data = e_ident["EI_DATA"]
    endianness = (
        "Little-Endian"
        if ei_data == "ELFDATA2LSB"
        else "Big-Endian"
        if ei_data == "ELFDATA2MSB"
        else str(ei_data)
    )

    machine = str(header["e_machine"])
    arch_friendly = elf.get_machine_arch()
    is_x86_64 = machine == "EM_X86_64" or arch_friendly == "x64"

    return ElfHeaderInfo(
        elf_class=elf_class,
        endianness=endianness,
        os_abi=str(e_ident["EI_OSABI"]),
        elf_type=str(header["e_type"]),
        machine=machine,
        arch_friendly=arch_friendly,
        entry_point=int(header["e_entry"]),
        ph_offset=int(header["e_phoff"]),
        sh_offset=int(header["e_shoff"]),
        ph_num=int(header["e_phnum"]),
        sh_num=int(header["e_shnum"]),
        is_x86_64=is_x86_64,
    )


def get_sections(elf: ELFFile) -> list[SectionInfo]:
    """List all sections in the ELF file."""
    sections: list[SectionInfo] = []
    for idx, section in enumerate(elf.iter_sections()):
        flags_val = int(section["sh_flags"])
        sections.append(
            SectionInfo(
                index=idx,
                name=section.name or "<unnamed>",
                sh_type=str(section["sh_type"]),
                vaddr=int(section["sh_addr"]),
                offset=int(section["sh_offset"]),
                size=int(section["sh_size"]),
                flags=_format_section_flags(flags_val),
                align=int(section["sh_addralign"]),
                is_alloc=bool(flags_val & SH_FLAGS.SHF_ALLOC),
            )
        )
    return sections


def extract_readable_strings(
    byte_slice: ByteSlice,
    min_length: int = 4,
    section_name: str = "<range>",
    file_offset_base: int = 0,
    is_vaddr: bool = True,
) -> list[ExtractedString]:
    """Extract printable ASCII and valid printable UTF-8 strings from a ByteSlice."""
    if min_length < 1:
        raise InvalidELFError("Panjang minimum string (--min-len) harus >= 1.")

    data = byte_slice.data
    n = len(data)
    results: list[ExtractedString] = []
    current_chars: list[str] = []
    run_start = 0

    def flush(end_idx: int) -> None:
        if len(current_chars) >= min_length:
            results.append(
                ExtractedString(
                    section=section_name,
                    address=byte_slice.base_address + run_start,
                    file_offset=file_offset_base + run_start,
                    value="".join(current_chars),
                    is_vaddr=is_vaddr,
                )
            )
        current_chars.clear()

    i = 0
    while i < n:
        b = data[i]
        if 0x20 <= b <= 0x7E:
            if not current_chars:
                run_start = i
            current_chars.append(chr(b))
            i += 1
            continue

        # Attempt valid multi-byte UTF-8 decoding (2 to 4 bytes)
        seq_len = 0
        if 0xC2 <= b <= 0xDF:
            seq_len = 2
        elif 0xE0 <= b <= 0xEF:
            seq_len = 3
        elif 0xF0 <= b <= 0xF4:
            seq_len = 4

        if seq_len and i + seq_len <= n:
            try:
                ch = data[i : i + seq_len].decode("utf-8", errors="strict")
                if len(ch) == 1 and ch.isprintable() and ord(ch) >= 0x80:
                    if not current_chars:
                        run_start = i
                    current_chars.append(ch)
                    i += seq_len
                    continue
            except UnicodeDecodeError:
                pass

        if current_chars:
            flush(i)
        i += 1

    if current_chars:
        flush(n)

    return results


def extract_all_section_strings(
    elf: ELFFile,
    min_length: int = 4,
) -> list[ExtractedString]:
    """Scan all SHF_ALLOC and non-alloc data sections for readable ASCII/UTF-8 strings."""
    results: list[ExtractedString] = []
    for section in elf.iter_sections():
        if section["sh_type"] == "SHT_NOBITS" or int(section["sh_size"]) == 0:
            continue
        sec_name = section.name or "<unnamed>"
        sh_addr = int(section["sh_addr"])
        sh_offset = int(section["sh_offset"])
        has_vaddr = sh_addr != 0
        bs = ByteSlice(
            data=section.data(),
            base_address=sh_addr if has_vaddr else sh_offset,
            source_label=sec_name,
        )
        results.extend(
            extract_readable_strings(
                bs,
                min_length=min_length,
                section_name=sec_name,
                file_offset_base=sh_offset,
                is_vaddr=has_vaddr,
            )
        )
    return results


def get_symbols(
    elf: ELFFile,
    type_filter: str | None = None,
) -> list[SymbolInfo]:
    """Extract symbols from .symtab and .dynsym."""
    symbols: list[SymbolInfo] = []
    normalized_filter = type_filter.upper() if type_filter else None

    for section in elf.iter_sections():
        if not isinstance(section, SymbolTableSection):
            continue
        table_name = section.name
        for sym in section.iter_symbols():
            sym_info = sym["st_info"]
            sym_type = str(sym_info["type"]).replace("STT_", "")
            if normalized_filter and sym_type != normalized_filter:
                continue

            binding = str(sym_info["bind"]).replace("STB_", "")
            symbols.append(
                SymbolInfo(
                    table=table_name,
                    name=sym.name or "<unnamed>",
                    sym_type=sym_type,
                    binding=binding,
                    vaddr=int(sym["st_value"]),
                    size=int(sym["st_size"]),
                    section_index=str(sym["st_shndx"]),
                )
            )
    return symbols


def get_imported_functions(elf: ELFFile) -> list[ImportedFunction]:
    """Extract imported external functions (SHN_UNDEF in .dynsym or .symtab)."""
    seen: set[str] = set()
    imports: list[ImportedFunction] = []

    for section in elf.iter_sections():
        if not isinstance(section, SymbolTableSection):
            continue
        for sym in section.iter_symbols():
            name = sym.name
            if not name or str(sym["st_shndx"]) != "SHN_UNDEF":
                continue
            sym_info = sym["st_info"]
            sym_type = str(sym_info["type"]).replace("STT_", "")
            if sym_type not in ("FUNC", "NOTYPE"):
                continue
            if name in seen:
                continue
            seen.add(name)
            imports.append(
                ImportedFunction(
                    name=name,
                    binding=str(sym_info["bind"]).replace("STB_", ""),
                    sym_type=sym_type,
                    table=section.name,
                )
            )
    return imports


def get_relocations(elf: ELFFile) -> list[RelocationInfo]:
    """Extract relocation entries from .rel.* and .rela.* sections."""
    relocs: list[RelocationInfo] = []
    for section in elf.iter_sections():
        if not isinstance(section, RelocationSection):
            continue
        symtab_idx = int(section["sh_link"])
        symtab = elf.get_section(symtab_idx) if symtab_idx < elf.num_sections() else None

        for rel in section.iter_relocations():
            sym_idx = int(rel["r_info_sym"])
            sym_name = "<none>"
            if isinstance(symtab, SymbolTableSection) and sym_idx < symtab.num_symbols():
                sym_name = symtab.get_symbol(sym_idx).name or "<unnamed>"

            addend = int(rel["r_addend"]) if rel.is_RELA() else None
            relocs.append(
                RelocationInfo(
                    section=section.name,
                    offset=int(rel["r_offset"]),
                    reloc_type=int(rel["r_info_type"]),
                    symbol_name=sym_name,
                    addend=addend,
                )
            )
    return relocs


def get_imported_libraries(elf: ELFFile) -> list[str]:
    """Extract imported external shared libraries (DT_NEEDED) from .dynamic."""
    libraries: list[str] = []
    for section in elf.iter_sections():
        if not isinstance(section, DynamicSection):
            continue
        for tag in section.iter_tags():
            if tag.entry.d_tag == "DT_NEEDED":
                libraries.append(str(tag.needed))
    return libraries


def _build_symbol_address_map(elf: ELFFile) -> dict[int, str]:
    """Map virtual addresses of functions/symbols to their names."""
    addr_map: dict[int, str] = {}
    for sym in get_symbols(elf):
        if sym.vaddr != 0 and sym.name and sym.name != "<unnamed>":
            if sym.vaddr not in addr_map or sym.sym_type == "FUNC":
                addr_map[sym.vaddr] = sym.name
    return addr_map


def _build_xref_map(elf: ELFFile, symbol_map: dict[int, str]) -> dict[int, str]:
    """Build a map of virtual addresses to symbol names or string previews for XREF annotations."""
    xrefs: dict[int, str] = {}
    for addr, name in symbol_map.items():
        xrefs[addr] = name

    # Index readable strings in SHF_ALLOC non-executable sections (e.g. .rodata, .data, .secret)
    for section in elf.iter_sections():
        flags_val = int(section["sh_flags"])
        sh_addr = int(section["sh_addr"])
        if (
            section["sh_type"] == "SHT_NOBITS"
            or int(section["sh_size"]) == 0
            or sh_addr == 0
            or not (flags_val & SH_FLAGS.SHF_ALLOC)
        ):
            continue
        sec_name = section.name or "<unnamed>"
        bs = ByteSlice(data=section.data(), base_address=sh_addr, source_label=sec_name)
        for item in extract_readable_strings(
            bs, min_length=3, section_name=sec_name, file_offset_base=int(section["sh_offset"])
        ):
            preview = item.value if len(item.value) <= 40 else item.value[:37] + "..."
            label = f'"{preview}" ({sec_name})'
            if item.address in xrefs:
                xrefs[item.address] = f"{xrefs[item.address]} -> {label}"
            else:
                xrefs[item.address] = label
    return xrefs


def _resolve_instruction_xref(insn, xref_map: dict[int, str]) -> str | None:
    """Resolve RIP-relative or immediate address references for an x86_64 instruction."""
    for op in getattr(insn, "operands", ()):
        if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
            target = insn.address + insn.size + op.mem.disp
            if target in xref_map:
                return f"0x{target:x} {xref_map[target]}"
            return f"0x{target:x}"
        if op.type == X86_OP_IMM:
            target = op.imm
            if target in xref_map and target != insn.address:
                return f"0x{target:x} {xref_map[target]}"
    return None


def _find_function_slice(elf: ELFFile, function_name: str) -> ByteSlice:
    """Locate a function symbol by name and extract its machine code bytes."""
    matches = [
        sym for sym in get_symbols(elf) if sym.name == function_name and sym.vaddr != 0
    ]
    if not matches:
        raise InvalidELFError(f"Simbol fungsi '{function_name}' tidak ditemukan.")

    matches.sort(key=lambda s: (s.sym_type != "FUNC", s.size == 0))
    target = matches[0]
    read_size = target.size if target.size > 0 else 256
    return extract_bytes_by_vaddr_range(elf, target.vaddr, size=read_size)


def disassemble_x86_64(
    elf: ELFFile,
    section_name: str = ".text",
    function_name: str | None = None,
    address: int | None = None,
    size: int | None = None,
    max_instructions: int | None = None,
) -> tuple[ByteSlice, list[DisasmInstruction]]:
    """Disassemble x86_64 machine instructions (Intel syntax) with XREF annotations."""
    info = get_elf_info(elf)
    if not info.is_x86_64:
        raise InvalidELFError(
            f"Disassembler hanya mendukung arsitektur x86_64, sedangkan file ini bertipe {info.machine} ({info.arch_friendly})."
        )

    if function_name is not None:
        byte_slice = _find_function_slice(elf, function_name)
    elif address is not None:
        target_size = size if size is not None else (max_instructions * 15 if max_instructions else 256)
        byte_slice = extract_bytes_by_vaddr_range(elf, address, size=target_size)
    else:
        byte_slice = extract_bytes_by_section(elf, section_name)

    if not byte_slice.data:
        return byte_slice, []

    symbol_map = _build_symbol_address_map(elf)
    xref_map = _build_xref_map(elf, symbol_map)

    try:
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.syntax = CS_OPT_SYNTAX_INTEL
        md.detail = True
        instructions: list[DisasmInstruction] = []
        for idx, insn in enumerate(md.disasm(byte_slice.data, byte_slice.base_address)):
            if max_instructions is not None and idx >= max_instructions:
                break
            instructions.append(
                DisasmInstruction(
                    address=insn.address,
                    raw_bytes=bytes(insn.bytes),
                    mnemonic=insn.mnemonic,
                    op_str=insn.op_str,
                    symbol_label=symbol_map.get(insn.address),
                    xref=_resolve_instruction_xref(insn, xref_map),
                )
            )
        return byte_slice, instructions
    except CsError as exc:
        raise InvalidELFError(f"Gagal melakukan disassembly dengan Capstone: {exc}") from exc


def run_triage(elf: ELFFile, min_str_len: int = 4) -> TriageReport:
    """Produce a quick triage summary of non-standard sections, imports, and key strings."""
    header = get_elf_info(elf)
    sections = get_sections(elf)
    non_standard = [sec for sec in sections if not is_standard_section(sec.name)]
    non_standard_names = {sec.name for sec in non_standard}

    important_strings = [
        item
        for item in extract_all_section_strings(elf, min_length=min_str_len)
        if item.section == ".rodata" or item.section in non_standard_names
    ]

    return TriageReport(
        header=header,
        non_standard_sections=non_standard,
        imported_libraries=get_imported_libraries(elf),
        imported_functions=get_imported_functions(elf),
        important_strings=important_strings,
    )
