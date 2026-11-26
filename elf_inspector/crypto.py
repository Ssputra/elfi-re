"""Static cryptographic analysis, auto-decryption, and pattern triage for ELF x86_64."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass

from capstone import CS_ARCH_X86, CS_MODE_64, CS_OPT_SYNTAX_INTEL, Cs, CsError
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP
from elftools.elf.constants import SH_FLAGS
from elftools.elf.elffile import ELFFile

from .analyzer import (
    _build_symbol_address_map,
    extract_all_section_strings,
    get_elf_info,
    get_symbols,
    is_standard_section,
)
from .loader import ByteSlice, InvalidELFError

DEFAULT_FLAG_PATTERN = r"[A-Za-z0-9_]+\{[^}]+\}"

# Common compiler division/modulo magic constants & standard crypto constants
KNOWN_CRYPTO_AND_MAGIC_CONSTANTS: dict[int, str] = {
    0x24924925: "Compiler magic constant (div/mod by 7)",
    0xAAAAAAAB: "Compiler magic constant (div/mod by 3)",
    0xCCCCCCCD: "Compiler magic constant (div/mod by 5)",
    0x55555556: "Compiler magic constant (signed div by 3)",
    0x66666667: "Compiler magic constant (signed div by 5)",
    0xEDB88320: "CRC32 polynomial (IEEE 802.3)",
    0x04C11DB7: "CRC32 polynomial (normal)",
    0x67452301: "MD5 / SHA-1 init constant (H0)",
    0xEFCDAB89: "MD5 / SHA-1 init constant (H1)",
    0x6A09E667: "SHA-256 init constant (H0)",
    0x9E3779B9: "TEA / XXTEA golden ratio delta",
    0x61707865: "ChaCha20 / Salsa20 constant ('expa')",
}

AES_SBOX_PREFIX = bytes([0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5])


@dataclass(frozen=True)
class FlagMatch:
    """Direct regex flag match found inside a section."""

    section: str
    address: int
    value: str
    is_potential_decoy: bool
    xref_functions: list[str]


@dataclass(frozen=True)
class CiphertextCandidate:
    """Candidate encrypted byte buffer extracted from ELF data."""

    section: str
    address: int
    data: bytes
    entropy: float
    reason: str


@dataclass(frozen=True)
class DecryptedFlagResult:
    """Successful auto-decryption result matching the flag regex."""

    algorithm: str
    key_repr: str
    source_section: str
    source_address: int
    plaintext: str


@dataclass(frozen=True)
class FindFlagReport:
    """Complete output of the find-flag static crypto triage."""

    pattern: str
    direct_matches: list[FlagMatch]
    ciphertext_candidates: list[CiphertextCandidate]
    key_candidates: list[str]
    decrypted_flags: list[DecryptedFlagResult]


@dataclass(frozen=True)
class CryptoFinding:
    """Cryptographic constant or instruction pattern detected in .text / .rodata."""

    category: str
    address: int
    section: str
    function: str | None
    detail: str


def _shannon_entropy(data: bytes) -> float:
    """Compute Shannon entropy (bits per byte) for a byte sequence."""
    if not data:
        return 0.0
    counts: dict[int, int] = {}
    for b in data:
        counts[b] = counts.get(b, 0) + 1
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def _is_mostly_non_ascii(data: bytes) -> bool:
    """Return True if a significant portion of bytes are non-printable ASCII."""
    if not data:
        return False
    non_print = sum(1 for b in data if not (0x20 <= b <= 0x7E))
    return (non_print / len(data)) >= 0.25


def _build_function_ranges(elf: ELFFile) -> list[tuple[int, int, str]]:
    """Return sorted (start, end, name) tuples for known FUNC symbols."""
    ranges: list[tuple[int, int, str]] = []
    for sym in get_symbols(elf, type_filter="func"):
        if sym.vaddr != 0 and sym.size > 0 and sym.name != "<unnamed>":
            ranges.append((sym.vaddr, sym.vaddr + sym.size, sym.name))
    ranges.sort()
    return ranges


def _find_containing_function(addr: int, func_ranges: list[tuple[int, int, str]]) -> str | None:
    """Find the function name containing a virtual address."""
    for start, end, name in func_ranges:
        if start <= addr < end:
            return name
    return None


def _collect_text_xrefs(elf: ELFFile) -> dict[int, list[str]]:
    """Map referenced data virtual addresses to functions in .text that reference them."""
    info = get_elf_info(elf)
    if not info.is_x86_64:
        return {}
    text_sec = elf.get_section_by_name(".text")
    if text_sec is None or text_sec["sh_type"] == "SHT_NOBITS":
        return {}

    func_ranges = _build_function_ranges(elf)
    xrefs: dict[int, list[str]] = {}
    try:
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.syntax = CS_OPT_SYNTAX_INTEL
        md.detail = True
        for insn in md.disasm(text_sec.data(), int(text_sec["sh_addr"])):
            fn = _find_containing_function(insn.address, func_ranges) or f"0x{insn.address:x}"
            for op in getattr(insn, "operands", ()):
                target: int | None = None
                if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                    target = insn.address + insn.size + op.mem.disp
                elif op.type == X86_OP_IMM and op.imm > 0x1000:
                    target = op.imm
                if target is not None:
                    lst = xrefs.setdefault(target, [])
                    if fn not in lst:
                        lst.append(fn)
    except CsError:
        return {}
    return xrefs


def xor_single_byte(data: bytes, key: int) -> bytes:
    """XOR every byte with a single byte key."""
    return bytes(b ^ key for b in data)


def xor_repeating_key(data: bytes, key: bytes) -> bytes:
    """XOR data with a repeating multi-byte key."""
    if not key:
        return data
    klen = len(key)
    return bytes(b ^ key[i % klen] for i, b in enumerate(data))


def rc4_decrypt(data: bytes, key: bytes) -> bytes:
    """Standard RC4 (KSA + PRGA) stream cipher decryption."""
    if not key:
        return data
    s = list(range(256))
    j = 0
    klen = len(key)
    for i in range(256):
        j = (j + s[i] + key[i % klen]) & 0xFF
        s[i], s[j] = s[j], s[i]

    out = bytearray(len(data))
    i = 0
    j = 0
    for idx, byte in enumerate(data):
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        k = s[(s[i] + s[j]) & 0xFF]
        out[idx] = byte ^ k
    return bytes(out)


def caesar_rot(text: str, shift: int) -> str:
    """Apply Caesar/ROT shift to ASCII letters."""
    out: list[str] = []
    for ch in text:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - ord("a") - shift) % 26 + ord("a")))
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - ord("A") - shift) % 26 + ord("A")))
        else:
            out.append(ch)
    return "".join(out)


def _extract_key_candidates(elf: ELFFile) -> list[str]:
    """Collect alphanumeric/slug ASCII strings (len 8..64) from .rodata and .data."""
    key_re = re.compile(r"^[A-Za-z0-9_\-]{8,64}$")
    seen: set[str] = set()
    keys: list[str] = []
    for item in extract_all_section_strings(elf, min_length=8):
        if item.section not in (".rodata", ".data"):
            continue
        if len(item.value) <= 64 and key_re.match(item.value):
            if item.value not in seen:
                seen.add(item.value)
                keys.append(item.value)
    return keys


def _extract_ciphertext_candidates(elf: ELFFile) -> list[CiphertextCandidate]:
    """Identify high-entropy or non-ASCII byte buffers in custom sections or .data."""
    candidates: list[CiphertextCandidate] = []
    for section in elf.iter_sections():
        if section["sh_type"] == "SHT_NOBITS":
            continue
        sec_name = section.name or "<unnamed>"
        sh_size = int(section["sh_size"])
        if sh_size < 6 or sh_size > 4096:
            continue

        is_custom = not is_standard_section(sec_name)
        if not is_custom and sec_name not in (".data", ".rodata"):
            continue

        data = section.data()
        # Trim trailing null padding if present
        trimmed = data.rstrip(b"\x00")
        if len(trimmed) < 6:
            continue

        entropy = _shannon_entropy(trimmed)
        non_ascii = _is_mostly_non_ascii(trimmed)

        if is_custom and (non_ascii or entropy >= 3.2):
            candidates.append(
                CiphertextCandidate(
                    section=sec_name,
                    address=int(section["sh_addr"]) or int(section["sh_offset"]),
                    data=trimmed,
                    entropy=entropy,
                    reason=f"Section kustom '{sec_name}'",
                )
            )
        elif sec_name == ".data" and entropy >= 4.2 and non_ascii:
            candidates.append(
                CiphertextCandidate(
                    section=sec_name,
                    address=int(section["sh_addr"]) or int(section["sh_offset"]),
                    data=trimmed,
                    entropy=entropy,
                    reason="Buffer entropi tinggi di .data",
                )
            )
    return candidates


def _try_match_flag(raw: bytes, compiled_re: re.Pattern[str]) -> str | None:
    """Decode bytes as UTF-8/ASCII and return matching flag substring if printable."""
    try:
        decoded = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return None
    if not all(ch.isprintable() or ch in "\x00" for ch in decoded):
        return None
    clean = decoded.rstrip("\x00")
    match = compiled_re.search(clean)
    return match.group(0) if match else None


def run_find_flag(elf: ELFFile, pattern_str: str = DEFAULT_FLAG_PATTERN) -> FindFlagReport:
    """Run automated static flag search, candidate extraction, and classic decryption."""
    try:
        compiled_re = re.compile(pattern_str)
    except re.error as exc:
        raise InvalidELFError(f"Regex --pattern tidak valid: {exc}") from exc

    xrefs = _collect_text_xrefs(elf)
    all_strings = extract_all_section_strings(elf, min_length=4)

    direct_matches: list[FlagMatch] = []
    for item in all_strings:
        m = compiled_re.search(item.value)
        if m:
            direct_matches.append(
                FlagMatch(
                    section=item.section,
                    address=item.address,
                    value=m.group(0),
                    is_potential_decoy=(item.section == ".rodata"),
                    xref_functions=xrefs.get(item.address, []),
                )
            )

    ciphertext_candidates = _extract_ciphertext_candidates(elf)
    key_candidates = _extract_key_candidates(elf)
    decrypted_flags: list[DecryptedFlagResult] = []
    seen_plaintexts: set[tuple[str, str]] = set()

    def record_decryption(
        algo: str, key_repr: str, cand: CiphertextCandidate, pt: str
    ) -> None:
        sig = (algo, pt)
        if sig not in seen_plaintexts:
            seen_plaintexts.add(sig)
            decrypted_flags.append(
                DecryptedFlagResult(
                    algorithm=algo,
                    key_repr=key_repr,
                    source_section=cand.section,
                    source_address=cand.address,
                    plaintext=pt,
                )
            )

    # 1. Test Caesar/ROT on printable strings (e.g. ROT13 flags)
    for item in all_strings:
        if "{" not in item.value or "}" not in item.value:
            continue
        for shift in range(1, 26):
            shifted = caesar_rot(item.value, shift)
            m = compiled_re.search(shifted)
            if m:
                sig = (f"Caesar/ROT-{shift}", m.group(0))
                if sig not in seen_plaintexts:
                    seen_plaintexts.add(sig)
                    decrypted_flags.append(
                        DecryptedFlagResult(
                            algorithm=f"Caesar/ROT-{shift}",
                            key_repr=f"shift={shift}",
                            source_section=item.section,
                            source_address=item.address,
                            plaintext=m.group(0),
                        )
                    )

    # 2. Test XOR & RC4 on ciphertext candidates
    for cand in ciphertext_candidates:
        # Single-byte XOR brute-force (0x01..0xFF)
        for key_byte in range(1, 256):
            pt = _try_match_flag(xor_single_byte(cand.data, key_byte), compiled_re)
            if pt:
                record_decryption("Single-Byte XOR", f"0x{key_byte:02X}", cand, pt)

        # Candidate key-based Repeating XOR & RC4
        for key_str in key_candidates:
            key_bytes = key_str.encode("utf-8")
            pt_xor = _try_match_flag(xor_repeating_key(cand.data, key_bytes), compiled_re)
            if pt_xor:
                record_decryption("Repeating-Key XOR", f'"{key_str}"', cand, pt_xor)

            pt_rc4 = _try_match_flag(rc4_decrypt(cand.data, key_bytes), compiled_re)
            if pt_rc4:
                record_decryption("RC4 (KSA+PRGA)", f'"{key_str}"', cand, pt_rc4)

    return FindFlagReport(
        pattern=pattern_str,
        direct_matches=direct_matches,
        ciphertext_candidates=ciphertext_candidates,
        key_candidates=key_candidates,
        decrypted_flags=decrypted_flags,
    )


def run_crypto_scan(elf: ELFFile) -> list[CryptoFinding]:
    """Scan .text and .rodata for cryptographic constants, bit rotations, and RC4-like loops."""
    info = get_elf_info(elf)
    if not info.is_x86_64:
        raise InvalidELFError(
            f"crypto-scan hanya mendukung arsitektur x86_64 (file ini: {info.machine})."
        )

    findings: list[CryptoFinding] = []
    func_ranges = _build_function_ranges(elf)

    # 1. Scan .text instructions
    text_sec = elf.get_section_by_name(".text")
    if text_sec is not None and text_sec["sh_type"] != "SHT_NOBITS":
        try:
            md = Cs(CS_ARCH_X86, CS_MODE_64)
            md.syntax = CS_OPT_SYNTAX_INTEL
            md.detail = True
            for insn in md.disasm(text_sec.data(), int(text_sec["sh_addr"])):
                fn = _find_containing_function(insn.address, func_ranges)

                # Bit rotation instructions
                if insn.mnemonic in ("rol", "ror"):
                    findings.append(
                        CryptoFinding(
                            category="Bit Rotation",
                            address=insn.address,
                            section=".text",
                            function=fn,
                            detail=f"{insn.mnemonic} {insn.op_str}",
                        )
                    )

                # Immediate constants: crypto/magic constants & 256-iteration loop bounds
                for op in getattr(insn, "operands", ()):
                    if op.type != X86_OP_IMM:
                        continue
                    imm_u32 = op.imm & 0xFFFFFFFF
                    if imm_u32 in KNOWN_CRYPTO_AND_MAGIC_CONSTANTS:
                        findings.append(
                            CryptoFinding(
                                category="Magic/Crypto Constant",
                                address=insn.address,
                                section=".text",
                                function=fn,
                                detail=f"0x{imm_u32:08x} ({KNOWN_CRYPTO_AND_MAGIC_CONSTANTS[imm_u32]})",
                            )
                        )
                    elif insn.mnemonic == "cmp" and op.imm in (0xFF, 0x100):
                        findings.append(
                            CryptoFinding(
                                category="RC4-like Loop Bound",
                                address=insn.address,
                                section=".text",
                                function=fn,
                                detail=f"{insn.mnemonic} {insn.op_str} (indikasi loop 256 iterasi / S-Box)",
                            )
                        )
        except CsError as exc:
            raise InvalidELFError(f"Gagal memindai instruksi .text: {exc}") from exc

    # 2. Scan .rodata / .data for AES S-Box or 4-byte magic constants
    for sec_name in (".rodata", ".data"):
        sec = elf.get_section_by_name(sec_name)
        if sec is None or sec["sh_type"] == "SHT_NOBITS":
            continue
        data = sec.data()
        base = int(sec["sh_addr"]) or int(sec["sh_offset"])

        idx = data.find(AES_SBOX_PREFIX)
        if idx != -1:
            findings.append(
                CryptoFinding(
                    category="S-Box Signature",
                    address=base + idx,
                    section=sec_name,
                    function=None,
                    detail="AES S-Box prefix (63 7c 77 7b f2 6b 6f c5)",
                )
            )

        for const_val, desc in KNOWN_CRYPTO_AND_MAGIC_CONSTANTS.items():
            packed = const_val.to_bytes(4, "little")
            pos = data.find(packed)
            if pos != -1:
                findings.append(
                    CryptoFinding(
                        category="Data Constant",
                        address=base + pos,
                        section=sec_name,
                        function=None,
                        detail=f"0x{const_val:08x} ({desc})",
                    )
                )

    return findings
