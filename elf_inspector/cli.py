"""Argparse-based CLI interface for ELF Inspector."""

from __future__ import annotations

import argparse
import sys
from typing import Sequence

from . import __version__
from .analyzer import (
    disassemble_x86_64,
    extract_all_section_strings,
    extract_readable_strings,
    get_elf_info,
    get_imported_functions,
    get_imported_libraries,
    get_relocations,
    get_sections,
    get_symbols,
    run_triage,
)
from .crypto import DEFAULT_FLAG_PATTERN, run_crypto_scan, run_find_flag
from .formatter import (
    format_crypto_scan,
    format_disassembly,
    format_elf_info,
    format_find_flag,
    format_hex_dump,
    format_imported_functions,
    format_libraries,
    format_python_bytes,
    format_relocations,
    format_sections,
    format_strings,
    format_symbols,
    format_triage,
)
from .loader import (
    InvalidELFError,
    extract_bytes_by_section,
    extract_bytes_by_vaddr_range,
    get_section_or_raise,
    open_elf,
)


def _parse_int(value: str) -> int:
    """Parse decimal or hexadecimal integer strings (e.g. '0x401000' or '64')."""
    try:
        return int(value, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"Nilai angka tidak valid: '{value}'") from exc


def build_parser() -> argparse.ArgumentParser:
    """Build and configure the argument parser."""
    parser = argparse.ArgumentParser(
        prog="elfi",
        description="Aplikasi CLI untuk analisis statis file biner ELF (x86_64).",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
        metavar="COMMAND",
        help="Sub-command analisis yang tersedia",
    )

    # 1. info
    p_info = subparsers.add_parser(
        "info",
        help="Tampilkan informasi ELF Header (entry point, arsitektur, endianness).",
    )
    p_info.add_argument("file", help="Path ke file biner ELF.")

    # 2. sections
    p_sec = subparsers.add_parser(
        "sections",
        help="Tampilkan daftar seluruh section beserta alamat virtual, offset, dan ukuran.",
    )
    p_sec.add_argument("file", help="Path ke file biner ELF.")

    # 3. strings
    p_str = subparsers.add_parser(
        "strings",
        help="Ekstrak string ASCII/UTF-8 yang dapat dibaca dari section atau rentang alamat.",
    )
    p_str.add_argument("file", help="Path ke file biner ELF.")
    str_target = p_str.add_mutually_exclusive_group()
    str_target.add_argument(
        "-s",
        "--section",
        help="Nama section target (default: pindai semua section alloc & non-alloc).",
    )
    str_target.add_argument(
        "--start",
        type=_parse_int,
        help="Alamat virtual awal untuk ekstraksi string.",
    )
    p_str.add_argument(
        "--end",
        type=_parse_int,
        help="Alamat virtual akhir (eksklusif), digunakan bersama --start.",
    )
    p_str.add_argument(
        "--size",
        type=_parse_int,
        help="Jumlah byte yang dipindai dari --start.",
    )
    p_str.add_argument(
        "-n",
        "--min-len",
        type=int,
        default=4,
        help="Panjang minimum karakter string (default: 4).",
    )
    p_str.add_argument(
        "--raw",
        action="store_true",
        help="Cetak daftar string berurutan tanpa metadata (mirip GNU strings).",
    )

    # 4. dump
    p_dump = subparsers.add_parser(
        "dump",
        help="Ekstrak byte mentah (hex dump atau array byte Python) dari section atau rentang alamat.",
    )
    p_dump.add_argument("file", help="Path ke file biner ELF.")
    dump_target = p_dump.add_mutually_exclusive_group(required=True)
    dump_target.add_argument(
        "-s",
        "--section",
        help="Nama section yang akan di-dump (misal: .rodata, .data, .secret).",
    )
    dump_target.add_argument(
        "--start",
        type=_parse_int,
        help="Alamat virtual awal (desimal atau hex, misal: 0x402000).",
    )
    p_dump.add_argument(
        "--end",
        type=_parse_int,
        help="Alamat virtual akhir (eksklusif), digunakan bersama --start.",
    )
    p_dump.add_argument(
        "--size",
        type=_parse_int,
        help="Jumlah byte yang dibaca dari --start.",
    )
    p_dump.add_argument(
        "--format",
        choices=["hex", "py"],
        default="hex",
        help="Format output: 'hex' (hex dump klasik) atau 'py' (array byte Python [0x96, ...]).",
    )

    # 5. symbols
    p_sym = subparsers.add_parser(
        "symbols",
        help="Tampilkan tabel simbol (.symtab/.dynsym), fungsi impor, relokasi, dan library.",
    )
    p_sym.add_argument("file", help="Path ke file biner ELF.")
    p_sym.add_argument(
        "--type",
        choices=["func", "object", "notype", "all"],
        default="all",
        help="Filter tipe simbol (default: all).",
    )
    p_sym.add_argument(
        "--only",
        choices=["symbols", "imports", "relocs", "libs", "all"],
        default="all",
        help="Pilih bagian yang ditampilkan (default: all).",
    )

    # 6. disasm
    p_dis = subparsers.add_parser(
        "disasm",
        help="Disassemble instruksi mesin x86_64 (sintaks Intel) beserta anotasi XREF.",
    )
    p_dis.add_argument("file", help="Path ke file biner ELF.")
    dis_target = p_dis.add_mutually_exclusive_group()
    dis_target.add_argument(
        "-s",
        "--section",
        default=".text",
        help="Nama section yang di-disassemble (default: .text).",
    )
    dis_target.add_argument(
        "-f",
        "--function",
        help="Nama simbol fungsi spesifik yang ingin di-disassemble (misal: main).",
    )
    dis_target.add_argument(
        "-a",
        "--address",
        type=_parse_int,
        help="Alamat virtual awal untuk disassembly (misal: 0x401000).",
    )
    p_dis.add_argument(
        "--size",
        type=_parse_int,
        help="Jumlah byte yang di-disassemble saat menggunakan --address.",
    )
    p_dis.add_argument(
        "-c",
        "--count",
        type=int,
        help="Maksimum jumlah instruksi yang ditampilkan.",
    )
    p_dis.add_argument(
        "--no-bytes",
        action="store_true",
        help="Sembunyikan kolom opcode hex mentah.",
    )

    # 7. triage
    p_tri = subparsers.add_parser(
        "triage",
        help="Quick triage: ringkasan section tidak standar, fungsi impor, dan string penting.",
    )
    p_tri.add_argument("file", help="Path ke file biner ELF.")
    p_tri.add_argument(
        "-n",
        "--min-len",
        type=int,
        default=4,
        help="Panjang minimum karakter string pada triage (default: 4).",
    )

    # 8. find-flag
    p_ff = subparsers.add_parser(
        "find-flag",
        help="Pencarian & auto-dekripsi flag universal (Base64/32/58, Hex, ROT, XOR, RC4, --trace-check).",
    )
    p_ff.add_argument("file", help="Path ke file biner ELF.")
    p_ff.add_argument(
        "--pattern",
        default=DEFAULT_FLAG_PATTERN,
        help=f"Regex format flag (default: {DEFAULT_FLAG_PATTERN}).",
    )
    p_ff.add_argument(
        "--printable-only",
        action="store_true",
        help="Aktifkan mode heuristik string ASCII printable (>90%%) tanpa harus memakai {}.",
    )
    p_ff.add_argument(
        "--prefix",
        help="Prefix flag yang diketahui untuk crib-dragging Repeating XOR (misal: 'CTF{').",
    )
    p_ff.add_argument(
        "--trace-check",
        action="store_true",
        help="Tampilkan disassembly fungsi verifikasi & template skrip Python siap pakai.",
    )

    # 9. crypto-scan
    p_cs = subparsers.add_parser(
        "crypto-scan",
        help="Pindai konstanta kriptografi, S-Box, rotasi bit (ROL/ROR), & pola loop RC4 di .text/.rodata.",
    )
    p_cs.add_argument("file", help="Path ke file biner ELF.")

    return parser


def _handle_command(args: argparse.Namespace) -> str:
    """Execute the parsed CLI subcommand and return formatted output."""
    with open_elf(args.file) as elf:
        if args.command == "info":
            return format_elf_info(get_elf_info(elf), args.file)

        if args.command == "sections":
            return format_sections(get_sections(elf))

        if args.command == "dump":
            if args.section:
                byte_slice = extract_bytes_by_section(elf, args.section)
            else:
                byte_slice = extract_bytes_by_vaddr_range(
                    elf,
                    start_vaddr=args.start,
                    end_vaddr=args.end,
                    size=args.size,
                )
            if args.format == "py":
                return format_python_bytes(byte_slice)
            return format_hex_dump(byte_slice)

        if args.command == "strings":
            if args.section:
                sec = get_section_or_raise(elf, args.section)
                byte_slice = extract_bytes_by_section(elf, args.section)
                sh_addr = int(sec["sh_addr"])
                sh_offset = int(sec["sh_offset"])
                has_vaddr = sh_addr != 0
                effective_slice = byte_slice if has_vaddr else type(byte_slice)(
                    data=byte_slice.data,
                    base_address=sh_offset,
                    source_label=byte_slice.source_label,
                )
                found = extract_readable_strings(
                    effective_slice,
                    min_length=args.min_len,
                    section_name=args.section,
                    file_offset_base=sh_offset,
                    is_vaddr=has_vaddr,
                )
                return format_strings(found, byte_slice.source_label, raw=args.raw)

            if args.start is not None:
                byte_slice = extract_bytes_by_vaddr_range(
                    elf,
                    start_vaddr=args.start,
                    end_vaddr=args.end,
                    size=args.size,
                )
                found = extract_readable_strings(
                    byte_slice,
                    min_length=args.min_len,
                    section_name=byte_slice.source_label,
                    file_offset_base=0,
                    is_vaddr=True,
                )
                return format_strings(found, byte_slice.source_label, raw=args.raw)

            all_found = extract_all_section_strings(elf, min_length=args.min_len)
            return format_strings(all_found, "seluruh section", raw=args.raw)

        if args.command == "symbols":
            parts: list[str] = []
            type_filter = None if args.type == "all" else args.type
            if args.only in ("symbols", "all"):
                parts.append(format_symbols(get_symbols(elf, type_filter=type_filter)))
            if args.only in ("imports", "all"):
                parts.append(format_imported_functions(get_imported_functions(elf)))
            if args.only in ("relocs", "all"):
                parts.append(format_relocations(get_relocations(elf)))
            if args.only in ("libs", "all"):
                parts.append(format_libraries(get_imported_libraries(elf)))
            return "\n\n".join(parts)

        if args.command == "disasm":
            byte_slice, instructions = disassemble_x86_64(
                elf,
                section_name=args.section,
                function_name=args.function,
                address=args.address,
                size=args.size,
                max_instructions=args.count,
            )
            return format_disassembly(
                byte_slice,
                instructions,
                show_bytes=not args.no_bytes,
            )

        if args.command == "triage":
            report = run_triage(elf, min_str_len=args.min_len)
            return format_triage(report, args.file)

        if args.command == "find-flag":
            report = run_find_flag(
                elf,
                pattern_str=args.pattern,
                printable_only=args.printable_only,
                prefix=args.prefix,
                trace_check=args.trace_check,
            )
            return format_find_flag(report, args.file)

        if args.command == "crypto-scan":
            findings = run_crypto_scan(elf)
            return format_crypto_scan(findings, args.file)

        raise InvalidELFError(f"Perintah tidak dikenal: {args.command}")


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        output = _handle_command(args)
        print(output)
        return 0
    except InvalidELFError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\n[INFO] Dibatalkan oleh pengguna.", file=sys.stderr)
        return 130
