"""Unit tests for ELF Inspector CLI and core analysis modules."""

from __future__ import annotations

import io
import struct
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from elf_inspector.cli import main
from elf_inspector.crypto import (
    decode_base58,
    rc4_decrypt,
    rol_bytes,
    ror_bytes,
    xor_repeating_key,
    xor_single_byte,
)


def build_rich_x86_64_elf() -> bytes:
    """Build a valid minimal 64-bit x86_64 ELF binary with custom section, imports, UTF-8, and RIP-relative XREF."""
    # .text at 0x401000:
    #   0x401000: 55                    push rbp
    #   0x401001: 48 89 e5              mov rbp, rsp
    #   0x401004: 48 8d 3d f5 0f 00 00  lea rdi, [rip + 0xff5] -> 0x40100b + 0xff5 = 0x402000 (.rodata "Hello, ELF!")
    #   0x40100b: 31 c0                 xor eax, eax
    #   0x40100d: 5d                    pop rbp
    #   0x40100e: c3                    ret
    text_data = b"\x55\x48\x89\xe5\x48\x8d\x3d\xf5\x0f\x00\x00\x31\xc0\x5d\xc3"
    rodata_data = "Hello, ELF!\x00Halo Dunia 🌍\x00".encode("utf-8")
    secret_data = b"\x96\xe8flag{test_secret}\x00"

    shstrtab = b"\x00.text\x00.rodata\x00.secret\x00.symtab\x00.strtab\x00.shstrtab\x00"
    strtab = b"\x00main\x00banner\x00puts\x00"

    text_vaddr = 0x401000
    rodata_vaddr = 0x402000
    secret_vaddr = 0x403000

    # Elf64_Sym: st_name(I), st_info(B), st_other(B), st_shndx(H), st_value(Q), st_size(Q)
    sym_null = struct.pack("<IBBHQQ", 0, 0, 0, 0, 0, 0)
    sym_main = struct.pack("<IBBHQQ", 1, 0x12, 0, 1, text_vaddr, len(text_data))
    sym_banner = struct.pack("<IBBHQQ", 6, 0x11, 0, 2, rodata_vaddr, 12)
    sym_puts = struct.pack("<IBBHQQ", 13, 0x12, 0, 0, 0, 0)  # SHN_UNDEF external import
    symtab_data = sym_null + sym_main + sym_banner + sym_puts

    ehdr_size = 64
    shdr_size = 64
    num_sections = 7

    text_off = ehdr_size
    rodata_off = text_off + len(text_data)
    secret_off = rodata_off + len(rodata_data)
    symtab_off = secret_off + len(secret_data)
    strtab_off = symtab_off + len(symtab_data)
    shstrtab_off = strtab_off + len(strtab)
    shdr_off = shstrtab_off + len(shstrtab)

    e_ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    ehdr = struct.pack(
        "<16sHHIQQQIHHHHHH",
        e_ident,
        2,              # ET_EXEC
        62,             # EM_X86_64
        1,              # EV_CURRENT
        text_vaddr,     # e_entry
        0,              # e_phoff
        shdr_off,       # e_shoff
        0,              # e_flags
        ehdr_size,
        56,
        0,
        shdr_size,
        num_sections,
        6,              # .shstrtab
    )

    def pack_shdr(
        sh_name: int,
        sh_type: int,
        sh_flags: int,
        sh_addr: int,
        sh_offset: int,
        sh_size: int,
        sh_link: int = 0,
        sh_info: int = 0,
        sh_addralign: int = 1,
        sh_entsize: int = 0,
    ) -> bytes:
        return struct.pack(
            "<IIQQQQIIQQ",
            sh_name,
            sh_type,
            sh_flags,
            sh_addr,
            sh_offset,
            sh_size,
            sh_link,
            sh_info,
            sh_addralign,
            sh_entsize,
        )

    sh_null = pack_shdr(0, 0, 0, 0, 0, 0, sh_addralign=0)
    sh_text = pack_shdr(shstrtab.index(b".text"), 1, 0x6, text_vaddr, text_off, len(text_data), sh_addralign=16)
    sh_rodata = pack_shdr(shstrtab.index(b".rodata"), 1, 0x2, rodata_vaddr, rodata_off, len(rodata_data), sh_addralign=4)
    sh_secret = pack_shdr(shstrtab.index(b".secret"), 1, 0x2, secret_vaddr, secret_off, len(secret_data), sh_addralign=1)
    sh_symtab = pack_shdr(
        shstrtab.index(b".symtab"),
        2,
        0,
        0,
        symtab_off,
        len(symtab_data),
        sh_link=5,
        sh_info=1,
        sh_addralign=8,
        sh_entsize=24,
    )
    sh_strtab = pack_shdr(shstrtab.index(b".strtab"), 3, 0, 0, strtab_off, len(strtab), sh_addralign=1)
    sh_shstrtab = pack_shdr(shstrtab.index(b".shstrtab"), 3, 0, 0, shstrtab_off, len(shstrtab), sh_addralign=1)

    return (
        ehdr
        + text_data
        + rodata_data
        + secret_data
        + symtab_data
        + strtab
        + shstrtab
        + sh_null
        + sh_text
        + sh_rodata
        + sh_secret
        + sh_symtab
        + sh_strtab
        + sh_shstrtab
    )


def _run_capture(argv: list[str]) -> tuple[int, str]:
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(argv)
    return rc, buf.getvalue()


class TestElfInspectorCLI(unittest.TestCase):
    """End-to-end tests for all CLI subcommands and error handling."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmpdir.name)
        self.elf_path = self.tmp_path / "sample.elf"
        self.elf_path.write_bytes(build_rich_x86_64_elf())

        self.invalid_path = self.tmp_path / "not_elf.txt"
        self.invalid_path.write_text("Bukan file ELF", encoding="utf-8")

        self.corrupt_path = self.tmp_path / "corrupt.elf"
        self.corrupt_path.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 10)

    def tearDown(self) -> None:
        self.tmpdir.cleanup()

    def test_info_and_sections(self) -> None:
        rc, out = _run_capture(["info", str(self.elf_path)])
        self.assertEqual(rc, 0)
        self.assertIn("EM_X86_64", out)

        rc, out = _run_capture(["sections", str(self.elf_path)])
        self.assertEqual(rc, 0)
        self.assertIn(".secret", out)

    def test_strings_utf8_and_raw(self) -> None:
        rc, out = _run_capture(["strings", str(self.elf_path)])
        self.assertEqual(rc, 0)
        self.assertIn("Halo Dunia", out)
        self.assertIn(".secret", out)

        rc, raw_out = _run_capture(["strings", str(self.elf_path), "--section", ".rodata", "--raw"])
        self.assertEqual(rc, 0)
        self.assertEqual(raw_out.strip().splitlines(), ["Hello, ELF!", "Halo Dunia 🌍"])

    def test_dump_hex_and_python_array(self) -> None:
        rc, hex_out = _run_capture(["dump", str(self.elf_path), "--section", ".secret"])
        self.assertEqual(rc, 0)
        self.assertIn("|..flag{test_secr|", hex_out)
        self.assertIn("|et}.|", hex_out)

        rc, py_out = _run_capture(["dump", str(self.elf_path), "--start", "0x403000", "--size", "4", "--format", "py"])
        self.assertEqual(rc, 0)
        self.assertIn("[0x96, 0xE8, 0x66, 0x6C]", py_out)

    def test_symbols_and_imports(self) -> None:
        rc, out = _run_capture(["symbols", str(self.elf_path), "--only", "imports"])
        self.assertEqual(rc, 0)
        self.assertIn("puts", out)

    def test_disasm_with_xref(self) -> None:
        rc, out = _run_capture(["disasm", str(self.elf_path), "--function", "main"])
        self.assertEqual(rc, 0)
        self.assertIn("XREF -> 0x402000", out)
        self.assertIn("Hello, ELF!", out)

    def test_triage_command(self) -> None:
        rc, out = _run_capture(["triage", str(self.elf_path)])
        self.assertEqual(rc, 0)
        self.assertIn(".secret", out)
        self.assertIn("puts", out)
        self.assertIn("flag{test_secret}", out)

    def test_find_flag_and_crypto_scan(self) -> None:
        # Build a binary with:
        # - .text: rol eax, 3 (c1 c0 03); mov ecx, 0x24924925 (b9 25 49 92 24); cmp eax, 0x100 (3d 00 01 00 00); ret (c3)
        # - .rodata: candidate key "my_secret_key_12" and decoy "CTF{decoy_flag}"
        # - .secret: RC4-encrypted "CTF{real_rc4_flag}" using "my_secret_key_12"
        key = b"my_secret_key_12"
        real_flag = b"CTF{real_rc4_flag}"
        enc_flag = rc4_decrypt(real_flag, key)  # RC4 is symmetric

        text_data = b"\xc1\xc0\x03\xb9\x25\x49\x92\x24\x3d\x00\x01\x00\x00\xc3"
        rodata_data = b"my_secret_key_12\x00CTF{decoy_flag}\x00"
        secret_data = enc_flag

        shstrtab = b"\x00.text\x00.rodata\x00.secret\x00.symtab\x00.strtab\x00.shstrtab\x00"
        strtab = b"\x00crypto_func\x00"
        text_vaddr = 0x401000
        rodata_vaddr = 0x402000
        secret_vaddr = 0x403000

        sym_null = struct.pack("<IBBHQQ", 0, 0, 0, 0, 0, 0)
        sym_fn = struct.pack("<IBBHQQ", 1, 0x12, 0, 1, text_vaddr, len(text_data))
        symtab_data = sym_null + sym_fn

        ehdr_size = 64
        shdr_size = 64
        text_off = ehdr_size
        rodata_off = text_off + len(text_data)
        secret_off = rodata_off + len(rodata_data)
        symtab_off = secret_off + len(secret_data)
        strtab_off = symtab_off + len(symtab_data)
        shstrtab_off = strtab_off + len(strtab)
        shdr_off = shstrtab_off + len(shstrtab)

        e_ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
        ehdr = struct.pack(
            "<16sHHIQQQIHHHHHH",
            e_ident, 2, 62, 1, text_vaddr, 0, shdr_off, 0, ehdr_size, 56, 0, shdr_size, 7, 6,
        )

        def shdr(name_b: bytes, stype: int, flags: int, addr: int, off: int, sz: int, link: int = 0, info: int = 0, esz: int = 0) -> bytes:
            return struct.pack("<IIQQQQIIQQ", shstrtab.index(name_b), stype, flags, addr, off, sz, link, info, 1, esz)

        elf_bytes = (
            ehdr
            + text_data
            + rodata_data
            + secret_data
            + symtab_data
            + strtab
            + shstrtab
            + struct.pack("<IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
            + shdr(b".text", 1, 0x6, text_vaddr, text_off, len(text_data))
            + shdr(b".rodata", 1, 0x2, rodata_vaddr, rodata_off, len(rodata_data))
            + shdr(b".secret", 1, 0x2, secret_vaddr, secret_off, len(secret_data))
            + shdr(b".symtab", 2, 0, 0, symtab_off, len(symtab_data), link=5, info=1, esz=24)
            + shdr(b".strtab", 3, 0, 0, strtab_off, len(strtab))
            + shdr(b".shstrtab", 3, 0, 0, shstrtab_off, len(shstrtab))
        )

        crypto_elf = self.tmp_path / "crypto.elf"
        crypto_elf.write_bytes(elf_bytes)

        rc, ff_out = _run_capture(["find-flag", str(crypto_elf), "--pattern", r"CTF\{[^}]+\}"])
        self.assertEqual(rc, 0)
        self.assertIn("POTENSI DECOY (.rodata)", ff_out)
        self.assertIn("RC4 (KSA+PRGA)", ff_out)
        self.assertIn("CTF{real_rc4_flag}", ff_out)

        rc, cs_out = _run_capture(["crypto-scan", str(crypto_elf)])
        self.assertEqual(rc, 0)
        self.assertIn("Bit Rotation", cs_out)
        self.assertIn("0x24924925", cs_out)
        self.assertIn("RC4-like Loop Bound", cs_out)
        self.assertIn("crypto_func", cs_out)

        # Also verify single-byte XOR & bit-rotation helpers
        self.assertEqual(xor_single_byte(xor_single_byte(b"CTF{abc}", 0x5A), 0x5A), b"CTF{abc}")
        self.assertEqual(ror_bytes(rol_bytes(b"CTF{rot}", 3), 3), b"CTF{rot}")
        self.assertIsNotNone(decode_base58("2NEpo7TZRRrLZSi2U"))

    def test_find_flag_universal_encodings_crib_and_trace(self) -> None:
        import base64

        # Base64 flag in .rodata + crib-dragged repeating XOR in .secret + --trace-check
        b64_flag = base64.b64encode(b"FLAG{base64_decoded_ok}")
        crib_plain = b"FLAG{crib_drag_works}"
        crib_enc = xor_repeating_key(crib_plain, b"K3y!")

        # .text: lea rdi, [rip + disp] -> points to .secret, cmp al, 0x42, ret
        text_data = b"\x48\x8d\x3d\xf9\x1f\x00\x00\x3c\x42\xc3"
        rodata_data = b64_flag + b"\x00plain_secret_token_no_braces\x00"
        secret_data = crib_enc

        shstrtab = b"\x00.text\x00.rodata\x00.secret\x00.symtab\x00.strtab\x00.shstrtab\x00"
        strtab = b"\x00check_flag\x00"
        text_vaddr = 0x401000
        rodata_vaddr = 0x402000
        secret_vaddr = 0x403000

        symtab_data = (
            struct.pack("<IBBHQQ", 0, 0, 0, 0, 0, 0)
            + struct.pack("<IBBHQQ", 1, 0x12, 0, 1, text_vaddr, len(text_data))
        )

        ehdr_size = 64
        text_off = ehdr_size
        rodata_off = text_off + len(text_data)
        secret_off = rodata_off + len(rodata_data)
        symtab_off = secret_off + len(secret_data)
        strtab_off = symtab_off + len(symtab_data)
        shstrtab_off = strtab_off + len(strtab)
        shdr_off = shstrtab_off + len(shstrtab)

        e_ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
        ehdr = struct.pack(
            "<16sHHIQQQIHHHHHH",
            e_ident, 2, 62, 1, text_vaddr, 0, shdr_off, 0, ehdr_size, 56, 0, 64, 7, 6,
        )

        def shdr(name_b: bytes, stype: int, flags: int, addr: int, off: int, sz: int, link: int = 0, info: int = 0, esz: int = 0) -> bytes:
            return struct.pack("<IIQQQQIIQQ", shstrtab.index(name_b), stype, flags, addr, off, sz, link, info, 1, esz)

        elf_bytes = (
            ehdr + text_data + rodata_data + secret_data + symtab_data + strtab + shstrtab
            + struct.pack("<IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
            + shdr(b".text", 1, 0x6, text_vaddr, text_off, len(text_data))
            + shdr(b".rodata", 1, 0x2, rodata_vaddr, rodata_off, len(rodata_data))
            + shdr(b".secret", 1, 0x2, secret_vaddr, secret_off, len(secret_data))
            + shdr(b".symtab", 2, 0, 0, symtab_off, len(symtab_data), link=5, info=1, esz=24)
            + shdr(b".strtab", 3, 0, 0, strtab_off, len(strtab))
            + shdr(b".shstrtab", 3, 0, 0, shstrtab_off, len(shstrtab))
        )

        uni_elf = self.tmp_path / "universal.elf"
        uni_elf.write_bytes(elf_bytes)

        rc, out = _run_capture(
            ["find-flag", str(uni_elf), "--prefix", "FLAG{", "--printable-only", "--trace-check"]
        )
        self.assertEqual(rc, 0)
        self.assertIn("FLAG{base64_decoded_ok}", out)
        self.assertIn("FLAG{crib_drag_works}", out)
        self.assertIn("plain_secret_token_no_braces", out)
        self.assertIn("Template Skrip Python Siap Pakai", out)

    def test_invalid_elf_handling(self) -> None:
        self.assertEqual(main(["info", str(self.invalid_path)]), 1)
        self.assertEqual(main(["info", str(self.corrupt_path)]), 1)
        self.assertEqual(main(["info", str(self.tmp_path / "missing.elf")]), 1)


if __name__ == "__main__":
    unittest.main()
