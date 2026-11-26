"""Terminal output formatting utilities for ELF Inspector."""

from __future__ import annotations

from typing import Sequence

from .analyzer import (
    DisasmInstruction,
    ElfHeaderInfo,
    ExtractedString,
    ImportedFunction,
    RelocationInfo,
    SectionInfo,
    SymbolInfo,
    TriageReport,
)
from .crypto import CryptoFinding, FindFlagReport
from .loader import ByteSlice


def _format_table(headers: Sequence[str], rows: Sequence[Sequence[str]]) -> str:
    """Render a clean, aligned ASCII table."""
    if not rows:
        return "(tidak ada data)"

    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            if len(cell) > widths[i]:
                widths[i] = len(cell)

    sep = "  "
    header_line = sep.join(h.ljust(widths[i]) for i, h in enumerate(headers))
    divider_line = sep.join("-" * widths[i] for i in range(len(headers)))
    body_lines = [
        sep.join(cell.ljust(widths[i]) for i, cell in enumerate(row))
        for row in rows
    ]
    return "\n".join([header_line, divider_line, *body_lines])


def format_elf_info(info: ElfHeaderInfo, file_path: str) -> str:
    """Format ELF header summary."""
    lines = [
        f"=== ELF Header Info: {file_path} ===",
        f"  Class          : {info.elf_class}",
        f"  Endianness     : {info.endianness}",
        f"  OS/ABI         : {info.os_abi}",
        f"  Type           : {info.elf_type}",
        f"  Architecture   : {info.machine} ({info.arch_friendly})",
        f"  Entry Point    : 0x{info.entry_point:016x}",
        f"  Program Headers: {info.ph_num} (offset 0x{info.ph_offset:x})",
        f"  Section Headers: {info.sh_num} (offset 0x{info.sh_offset:x})",
    ]
    if not info.is_x86_64:
        lines.append("  [!] Peringatan : Arsitektur bukan x86_64; fitur disassembler tidak tersedia.")
    return "\n".join(lines)


def format_sections(sections: Sequence[SectionInfo]) -> str:
    """Format section list as a readable table."""
    headers = ["Idx", "Name", "Type", "VirtAddr", "Offset", "Size", "Flags", "Align"]
    rows = [
        [
            str(sec.index),
            sec.name,
            sec.sh_type.replace("SHT_", ""),
            f"0x{sec.vaddr:016x}",
            f"0x{sec.offset:08x}",
            f"0x{sec.size:x} ({sec.size} B)",
            sec.flags,
            str(sec.align),
        ]
        for sec in sections
    ]
    return "=== ELF Sections ===\n" + _format_table(headers, rows)


def format_hex_dump(byte_slice: ByteSlice, bytes_per_line: int = 16) -> str:
    """Format raw bytes as a classic hex + ASCII dump."""
    header = f"=== Hex Dump ({byte_slice.source_label}, {len(byte_slice.data)} bytes) ==="
    if not byte_slice.data:
        return f"{header}\n(kosong)"

    lines = [header]
    data = byte_slice.data
    for offset in range(0, len(data), bytes_per_line):
        chunk = data[offset : offset + bytes_per_line]
        addr = byte_slice.base_address + offset
        hex_parts = [f"{b:02x}" for b in chunk]
        left = " ".join(hex_parts[:8]).ljust(23)
        right = " ".join(hex_parts[8:]).ljust(23)
        ascii_repr = "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in chunk)
        lines.append(f"0x{addr:016x}  {left}  {right}  |{ascii_repr}|")
    return "\n".join(lines)


def format_python_bytes(byte_slice: ByteSlice, items_per_line: int = 12) -> str:
    """Format raw bytes as a Python byte array literal ([0x96, 0xE8, ...])."""
    header = f"# Python Byte Array ({byte_slice.source_label}, {len(byte_slice.data)} bytes)"
    if not byte_slice.data:
        return f"{header}\ndata = []"

    hex_items = [f"0x{b:02X}" for b in byte_slice.data]
    if len(hex_items) <= items_per_line:
        return f"{header}\ndata = [{', '.join(hex_items)}]"

    lines = [header, "data = ["]
    for i in range(0, len(hex_items), items_per_line):
        chunk = ", ".join(hex_items[i : i + items_per_line])
        lines.append(f"    {chunk},")
    lines.append("]")
    return "\n".join(lines)


def format_strings(
    items: Sequence[ExtractedString],
    source_label: str,
    raw: bool = False,
) -> str:
    """Format extracted ASCII/UTF-8 strings with section and address metadata, or raw."""
    if raw:
        return "\n".join(item.value for item in items)

    header = f"=== Readable Strings ({source_label}, {len(items)} ditemukan) ==="
    if not items:
        return f"{header}\n(tidak ada string ditemukan)"

    headers = ["Section", "VirtAddr / Offset", "FileOffset", "String"]
    rows = [
        [
            item.section,
            f"0x{item.address:016x}" if item.is_vaddr else f"off:0x{item.address:08x}",
            f"0x{item.file_offset:08x}",
            item.value,
        ]
        for item in items
    ]
    return f"{header}\n" + _format_table(headers, rows)


def format_symbols(symbols: Sequence[SymbolInfo]) -> str:
    """Format symbol table entries."""
    headers = ["Table", "Type", "Bind", "VirtAddr", "Size", "Shndx", "Name"]
    rows = [
        [
            sym.table,
            sym.sym_type,
            sym.binding,
            f"0x{sym.vaddr:016x}",
            str(sym.size),
            sym.section_index,
            sym.name,
        ]
        for sym in symbols
    ]
    return f"=== Symbols ({len(symbols)}) ===\n" + _format_table(headers, rows)


def format_imported_functions(imports: Sequence[ImportedFunction]) -> str:
    """Format imported external library functions."""
    headers = ["Table", "Type", "Bind", "Function"]
    rows = [[imp.table, imp.sym_type, imp.binding, imp.name] for imp in imports]
    return f"=== Imported Functions ({len(imports)}) ===\n" + _format_table(headers, rows)


def format_relocations(relocs: Sequence[RelocationInfo]) -> str:
    """Format relocation table entries."""
    headers = ["Section", "Offset", "Type", "Addend", "Symbol"]
    rows = [
        [
            rel.section,
            f"0x{rel.offset:016x}",
            str(rel.reloc_type),
            str(rel.addend) if rel.addend is not None else "-",
            rel.symbol_name,
        ]
        for rel in relocs
    ]
    return f"=== Relocations ({len(relocs)}) ===\n" + _format_table(headers, rows)


def format_libraries(libraries: Sequence[str]) -> str:
    """Format imported shared libraries (DT_NEEDED)."""
    header = f"=== Imported Libraries ({len(libraries)}) ==="
    if not libraries:
        return f"{header}\n(tidak ada library eksternal / statically linked)"
    return "\n".join([header, *[f"  - {lib}" for lib in libraries]])


def format_disassembly(
    byte_slice: ByteSlice,
    instructions: Sequence[DisasmInstruction],
    show_bytes: bool = True,
) -> str:
    """Format disassembled x86_64 instructions cleanly with XREF annotations."""
    header = f"=== Disassembly x86_64 Intel ({byte_slice.source_label}) ==="
    if not instructions:
        return f"{header}\n(tidak ada instruksi yang dapat di-disassemble)"

    lines = [header]
    for insn in instructions:
        if insn.symbol_label:
            lines.append(f"\n<{insn.symbol_label}>:")
        addr_str = f"0x{insn.address:016x}"
        asm_text = f"{insn.mnemonic:<8} {insn.op_str}".rstrip()
        xref_suffix = f"  ; XREF -> {insn.xref}" if insn.xref else ""

        if show_bytes:
            bytes_str = " ".join(f"{b:02x}" for b in insn.raw_bytes).ljust(24)
            lines.append(f"  {addr_str}:  {bytes_str}  {asm_text:<32}{xref_suffix}".rstrip())
        else:
            lines.append(f"  {addr_str}:  {asm_text:<32}{xref_suffix}".rstrip())
    return "\n".join(lines)


def format_triage(report: TriageReport, file_path: str) -> str:
    """Format quick triage report."""
    parts = [
        f"=== Quick Triage: {file_path} ===",
        f"  Arch/Type  : {report.header.elf_class} {report.header.machine} ({report.header.elf_type}, {report.header.endianness})",
        f"  Entry Point: 0x{report.header.entry_point:016x}",
    ]

    # Non-standard sections
    if report.non_standard_sections:
        sec_headers = ["Idx", "Name", "Type", "VirtAddr", "Offset", "Size", "Flags"]
        sec_rows = [
            [
                str(s.index),
                s.name,
                s.sh_type.replace("SHT_", ""),
                f"0x{s.vaddr:016x}",
                f"0x{s.offset:08x}",
                f"{s.size} B",
                s.flags,
            ]
            for s in report.non_standard_sections
        ]
        parts.append(
            f"\n[1] Section Tidak Standar ({len(report.non_standard_sections)} ditemukan)\n"
            + _format_table(sec_headers, sec_rows)
        )
    else:
        parts.append("\n[1] Section Tidak Standar (0 ditemukan)\n  (hanya section ELF standar)")

    # Imported libraries & functions
    libs_str = ", ".join(report.imported_libraries) if report.imported_libraries else "(tidak ada / static)"
    parts.append(f"\n[2] Library & Fungsi Impor\n  DT_NEEDED : {libs_str}")
    if report.imported_functions:
        func_names = ", ".join(f.name for f in report.imported_functions)
        parts.append(f"  Functions ({len(report.imported_functions)}): {func_names}")
    else:
        parts.append("  Functions : (tidak ada fungsi impor eksternal)")

    # Important strings (.rodata & custom sections)
    parts.append(
        "\n[3] String Penting (.rodata & section kustom)\n"
        + format_strings(report.important_strings, ".rodata & custom", raw=False)
    )

    return "\n".join(parts)


def format_find_flag(report: FindFlagReport, file_path: str) -> str:
    """Format universal find-flag analysis, anti-decoy scoring, and --trace-check template."""
    parts = [
        f"=== Universal Find-Flag Analysis: {file_path} ===",
        f"  Regex Pattern : {report.pattern}",
        f"  Printable Mode: {'Aktif (>90% ASCII)' if report.printable_only else 'Nonaktif'}",
        f"  Strict Mode   : {'Aktif (abaikan plaintext statis .rodata/.data)' if report.strict else 'Nonaktif'}",
    ]
    if report.prefix:
        parts.append(f"  Known Prefix  : {report.prefix}")

    # 1. Ranked candidates by Anti-Decoy & Verification Scoring
    if report.ranked_candidates:
        r_headers = ["Tier", "Label", "Source", "Method", "XREF", "Flag Candidate"]
        r_rows = [
            [
                f"[{c.tier}]",
                c.label,
                c.source,
                c.method,
                c.xref_info,
                c.value,
            ]
            for c in report.ranked_candidates
        ]
        parts.append(
            f"\n[1] Kandidat Flag Terurut (Anti-Decoy & Verification Scoring, {len(report.ranked_candidates)} kandidat)\n"
            + _format_table(r_headers, r_rows)
        )
    else:
        parts.append("\n[1] Kandidat Flag Terurut (0 kandidat ditemukan)")

    # 2. Ciphertext & Target Buffer candidates
    if report.ciphertext_candidates:
        c_headers = ["Section", "VirtAddr", "Size", "Entropy", "Reason"]
        c_rows = [
            [
                c.section,
                f"0x{c.address:016x}",
                f"{len(c.data)} B",
                f"{c.entropy:.2f}",
                c.reason,
            ]
            for c in report.ciphertext_candidates
        ]
        parts.append(
            f"\n[2] Target Buffer & Kandidat Ciphertext ({len(report.ciphertext_candidates)} ditemukan)\n"
            + _format_table(c_headers, c_rows)
        )
    else:
        parts.append("\n[2] Target Buffer & Kandidat Ciphertext (0 ditemukan)")

    keys_preview = ", ".join(report.key_candidates[:12]) if report.key_candidates else "(tidak ada)"
    if len(report.key_candidates) > 12:
        keys_preview += f" ... (+{len(report.key_candidates) - 12} lainnya)"
    imms_preview = ", ".join(f"0x{x:x}" for x in report.imm_constants[:12]) if report.imm_constants else "(tidak ada)"
    if len(report.imm_constants) > 12:
        imms_preview += f" ... (+{len(report.imm_constants) - 12} lainnya)"
    parts.append(f"\n[3] Kandidat Kunci & Konstanta")
    parts.append(f"  ASCII Keys ({len(report.key_candidates)}): {keys_preview}")
    parts.append(f"  Scalar Imms ({len(report.imm_constants)}): {imms_preview}")

    # 4. Auto-decryption results
    if report.decrypted_flags:
        d_headers = ["Algorithm", "Key / Param", "Source", "VirtAddr", "Plaintext"]
        d_rows = [
            [
                d.algorithm,
                d.key_repr,
                d.source_section,
                f"0x{d.source_address:016x}",
                d.plaintext,
            ]
            for d in report.decrypted_flags
        ]
        parts.append(
            f"\n[4] Hasil Auto-Decoder Berlapis ({len(report.decrypted_flags)} ditemukan!)\n"
            + _format_table(d_headers, d_rows)
        )
    else:
        parts.append("\n[4] Hasil Auto-Decoder Berlapis (tidak ada kandidat yang cocok)")

    # 5. Verification logic trace & Python solver template
    if report.trace_functions:
        parts.append(f"\n[5] Ringkasan Logika Verifikasi (--trace-check, {len(report.trace_functions)} fungsi)")
        for tf in report.trace_functions:
            parts.append(f"\n  --- Fungsi: {tf.name} (0x{tf.start_address:016x}) ---")
            parts.append(f"  Calls : {', '.join(tf.called_targets) if tf.called_targets else '-'}")
            parts.append(f"  Imms  : {', '.join(f'0x{x:x}' for x in tf.scalar_imms) if tf.scalar_imms else '-'}")
            for line in tf.disasm_lines:
                parts.append(f"    {line}")

        # Ready-to-use Python template (no leading indentation so it's directly copy-pasteable)
        parts.append("\n=== Template Skrip Python Siap Pakai ===")
        parts.append("```python")
        parts.append("# Auto-generated template dari --trace-check")
        for idx, buf in enumerate(report.ciphertext_candidates[:4]):
            arr = ", ".join(f"0x{b:02X}" for b in buf.data)
            parts.append(f"target_{idx} = bytes([{arr}])  # {buf.section} @ 0x{buf.address:x}")
        imms_py = ", ".join(f"0x{x:x}" for x in report.imm_constants[:16])
        parts.append(f"imms = [{imms_py}]")
        parts.append("")
        parts.append("def invert(data: bytes) -> bytes:")
        parts.append("    # TODO: Implementasikan kebalikan operasi dari disassembly di atas")
        parts.append("    return data")
        parts.append("")
        if report.ciphertext_candidates:
            parts.append("print(invert(target_0))")
        parts.append("```")

    return "\n".join(parts)


def format_crypto_scan(findings: Sequence[CryptoFinding], file_path: str) -> str:
    """Format detected cryptographic constants and instruction patterns."""
    header = f"=== Crypto Scan: {file_path} ({len(findings)} temuan) ==="
    if not findings:
        return f"{header}\n(tidak ada konstanta/pola kriptografi khas yang terdeteksi)"

    headers = ["Category", "Section", "Address", "Function", "Detail"]
    rows = [
        [
            f.category,
            f.section,
            f"0x{f.address:016x}",
            f.function or "-",
            f.detail,
        ]
        for f in findings
    ]
    return f"{header}\n" + _format_table(headers, rows)
