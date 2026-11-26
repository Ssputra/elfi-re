"""Static cryptographic analysis, universal auto-decryption, and verification trace for ELF x86_64."""

from __future__ import annotations

import base64
import binascii
import math
import re
from dataclasses import dataclass

from capstone import CS_ARCH_X86, CS_MODE_64, CS_OPT_SYNTAX_INTEL, Cs, CsError
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP
from elftools.elf.elffile import ELFFile

from .analyzer import (
    extract_all_section_strings,
    get_elf_info,
    get_relocations,
    get_symbols,
    is_standard_section,
)
from .loader import InvalidELFError

DEFAULT_FLAG_PATTERN = r"[A-Za-z0-9_-]{2,20}\{[!-~]{4,100}\}"

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BASE58_MAP = {ch: idx for idx, ch in enumerate(BASE58_ALPHABET)}

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
COMPARE_SYMBOLS = ("memcmp", "strncmp", "strcmp", "puts")


@dataclass(frozen=True)
class FlagMatch:
    """Direct regex or printable heuristic match found inside a section."""

    section: str
    address: int
    value: str
    is_potential_decoy: bool
    xref_functions: list[str]
    match_kind: str = "regex"


@dataclass(frozen=True)
class CiphertextCandidate:
    """Candidate encrypted/encoded buffer extracted from ELF data."""

    section: str
    address: int
    data: bytes
    entropy: float
    reason: str


@dataclass(frozen=True)
class DecryptedFlagResult:
    """Successful auto-decoding/decryption result."""

    algorithm: str
    key_repr: str
    source_section: str
    source_address: int
    plaintext: str


@dataclass(frozen=True)
class TraceFunctionInfo:
    """Verification function summary for --trace-check."""

    name: str
    start_address: int
    called_targets: list[str]
    scalar_imms: list[int]
    referenced_buffers: list[tuple[int, str, bytes]]
    disasm_lines: list[str]


@dataclass(frozen=True)
class FindFlagReport:
    """Complete output of the universal find-flag pipeline."""

    pattern: str
    printable_only: bool
    prefix: str | None
    direct_matches: list[FlagMatch]
    ciphertext_candidates: list[CiphertextCandidate]
    key_candidates: list[str]
    imm_constants: list[int]
    decrypted_flags: list[DecryptedFlagResult]
    trace_functions: list[TraceFunctionInfo]


@dataclass(frozen=True)
class CryptoFinding:
    """Cryptographic constant or instruction pattern detected in .text / .rodata."""

    category: str
    address: int
    section: str
    function: str | None
    detail: str


def _shannon_entropy(data: bytes) -> float:
    """Compute Shannon entropy (bits per byte)."""
    if not data:
        return 0.0
    counts: dict[int, int] = {}
    for b in data:
        counts[b] = counts.get(b, 0) + 1
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _printable_ratio(data: bytes) -> float:
    """Return fraction of bytes that are printable ASCII (0x20..0x7E)."""
    if not data:
        return 0.0
    return sum(1 for b in data if 0x20 <= b <= 0x7E) / len(data)


def _is_mostly_non_ascii(data: bytes) -> bool:
    return _printable_ratio(data) < 0.75


def _build_function_ranges(elf: ELFFile) -> list[tuple[int, int, str]]:
    ranges: list[tuple[int, int, str]] = []
    for sym in get_symbols(elf, type_filter="func"):
        if sym.vaddr != 0 and sym.size > 0 and sym.name != "<unnamed>":
            ranges.append((sym.vaddr, sym.vaddr + sym.size, sym.name))
    ranges.sort()
    return ranges


def _find_containing_function(addr: int, func_ranges: list[tuple[int, int, str]]) -> str | None:
    for start, end, name in func_ranges:
        if start <= addr < end:
            return name
    return None


def _build_call_target_map(elf: ELFFile) -> dict[int, str]:
    """Map known function addresses (and PLT/GOT relocations if resolvable) to names."""
    call_map: dict[int, str] = {}
    for sym in get_symbols(elf):
        if sym.vaddr != 0 and sym.name and sym.name != "<unnamed>":
            call_map[sym.vaddr] = sym.name

    # Map .plt entries via .rela.plt order when standard x86_64 PLT layout is used
    plt_sec = elf.get_section_by_name(".plt")
    if plt_sec is not None and plt_sec["sh_addr"] != 0:
        plt_addr = int(plt_sec["sh_addr"])
        plt_relocs = [r for r in get_relocations(elf) if r.section in (".rela.plt", ".rel.plt")]
        for idx, rel in enumerate(plt_relocs):
            if rel.symbol_name and rel.symbol_name != "<none>":
                # Standard x86_64 PLT stub is 16 bytes, entry 0 is resolver
                call_map.setdefault(plt_addr + (idx + 1) * 16, f"{rel.symbol_name}@plt")
    return call_map


def _read_vaddr_bytes(elf: ELFFile, vaddr: int, max_len: int = 64) -> tuple[str, bytes] | None:
    """Read up to max_len bytes starting at vaddr from a physical data section."""
    for section in elf.iter_sections():
        sh_addr = int(section["sh_addr"])
        sh_size = int(section["sh_size"])
        if sh_addr == 0 or sh_size == 0 or section["sh_type"] == "SHT_NOBITS":
            continue
        if sh_addr <= vaddr < sh_addr + sh_size:
            off = vaddr - sh_addr
            data = section.data()[off : off + max_len]
            return (section.name or "<unnamed>", data)
    return None


def _analyze_text_structure(
    elf: ELFFile,
) -> tuple[dict[int, list[str]], list[int], list[CiphertextCandidate], list[TraceFunctionInfo]]:
    """Inspect .text for XREFs, scalar immediates, target buffers, and comparison functions."""
    info = get_elf_info(elf)
    if not info.is_x86_64:
        return {}, [], [], []

    text_sec = elf.get_section_by_name(".text")
    if text_sec is None or text_sec["sh_type"] == "SHT_NOBITS":
        return {}, [], [], []

    func_ranges = _build_function_ranges(elf)
    call_map = _build_call_target_map(elf)
    xrefs: dict[int, list[str]] = {}
    imms_set: set[int] = set()
    target_buffers: list[CiphertextCandidate] = []
    seen_buf_addrs: set[int] = set()
    func_insns: dict[str, list] = {}

    try:
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.syntax = CS_OPT_SYNTAX_INTEL
        md.detail = True
        insns = list(md.disasm(text_sec.data(), int(text_sec["sh_addr"])))
    except CsError:
        return {}, [], [], []

    # If binary is stripped (no .symtab FUNC symbols), segment .text at ret/int3 boundaries
    if not func_ranges and insns:
        seg_start = 0
        for idx, insn in enumerate(insns):
            if insn.mnemonic in ("ret", "retn", "hlt") or (
                idx + 1 < len(insns) and insns[idx + 1].mnemonic == "endbr64"
            ):
                end_idx = idx + 1
                seg_insns = insns[seg_start:end_idx]
                if seg_insns:
                    func_insns[f"sub_{seg_insns[0].address:x}"] = seg_insns
                seg_start = end_idx
        if seg_start < len(insns):
            seg_insns = insns[seg_start:]
            func_insns[f"sub_{seg_insns[0].address:x}"] = seg_insns

        # Rebuild xrefs using inferred sub_<addr> names
        xrefs.clear()
        for sub_name, sub_list in func_insns.items():
            for insn in sub_list:
                for op in getattr(insn, "operands", ()):
                    target = None
                    if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                        target = insn.address + insn.size + op.mem.disp
                    elif op.type == X86_OP_IMM and op.imm > 0x1000:
                        target = op.imm
                    if target is not None:
                        lst = xrefs.setdefault(target, [])
                        if sub_name not in lst:
                            lst.append(sub_name)
    else:
        for insn in insns:
            fn = _find_containing_function(insn.address, func_ranges) or f"sub_{insn.address:x}"
            func_insns.setdefault(fn, []).append(insn)

            for op in getattr(insn, "operands", ()):
                target = None
                if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                    target = insn.address + insn.size + op.mem.disp
                elif op.type == X86_OP_IMM and op.imm > 0x1000:
                    target = op.imm
                if target is not None:
                    lst = xrefs.setdefault(target, [])
                    if fn not in lst:
                        lst.append(fn)

    for insn in insns:
        if insn.mnemonic in ("mov", "xor", "add", "sub", "rol", "ror", "cmp"):
            for op in getattr(insn, "operands", ()):
                if op.type == X86_OP_IMM and 0 < op.imm <= 0xFFFFFFFF:
                    imms_set.add(int(op.imm))

    # Identify functions calling memcmp/strncmp/strcmp/puts or having cmp/xor byte loops
    trace_functions: list[TraceFunctionInfo] = []
    for fn_name, fn_list in func_insns.items():
        called: list[str] = []
        fn_imms: list[int] = []
        fn_refs: list[tuple[int, str, bytes]] = []
        has_cmp_loop = False

        for insn in fn_list:
            if insn.mnemonic == "call":
                for op in getattr(insn, "operands", ()):
                    if op.type == X86_OP_IMM:
                        cname = call_map.get(op.imm, f"0x{op.imm:x}")
                        if cname not in called:
                            called.append(cname)
            if insn.mnemonic in ("cmp", "xor", "rol", "ror"):
                has_cmp_loop = True
            for op in getattr(insn, "operands", ()):
                if op.type == X86_OP_IMM and 0 < op.imm <= 0xFFFFFFFF:
                    val = int(op.imm)
                    if val not in fn_imms:
                        fn_imms.append(val)
                if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                    taddr = insn.address + insn.size + op.mem.disp
                    read_res = _read_vaddr_bytes(elf, taddr, max_len=64)
                    if read_res is not None:
                        sec_n, raw = read_res
                        if taddr not in [r[0] for r in fn_refs]:
                            fn_refs.append((taddr, sec_n, raw))
                        if taddr not in seen_buf_addrs and sec_n != ".text":
                            seen_buf_addrs.add(taddr)
                            trimmed = raw.split(b"\x00", 1)[0] if _printable_ratio(raw[:8]) > 0.8 else raw.rstrip(b"\x00")
                            if len(trimmed) >= 4:
                                target_buffers.append(
                                    CiphertextCandidate(
                                        section=sec_n,
                                        address=taddr,
                                        data=trimmed,
                                        entropy=_shannon_entropy(trimmed),
                                        reason=f"Direferensikan di fungsi '{fn_name}'",
                                    )
                                )

        calls_compare = any(any(cs in c for cs in COMPARE_SYMBOLS) for c in called)
        if calls_compare or (has_cmp_loop and fn_refs):
            disasm_lines = [
                f"0x{i.address:016x}: {i.mnemonic:<7} {i.op_str}".rstrip()
                for i in fn_list[:40]
            ]
            trace_functions.append(
                TraceFunctionInfo(
                    name=fn_name,
                    start_address=fn_list[0].address,
                    called_targets=called,
                    scalar_imms=fn_imms[:16],
                    referenced_buffers=fn_refs[:8],
                    disasm_lines=disasm_lines,
                )
            )

    return xrefs, sorted(imms_set), target_buffers, trace_functions


# --- Primitive Decoders & Decryptors ---

def xor_single_byte(data: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in data)


def xor_repeating_key(data: bytes, key: bytes) -> bytes:
    if not key:
        return data
    klen = len(key)
    return bytes(b ^ key[i % klen] for i, b in enumerate(data))


def add_sub_mod256(data: bytes, delta: int) -> bytes:
    return bytes((b + delta) & 0xFF for b in data)


def ror_bytes(data: bytes, bits: int) -> bytes:
    bits %= 8
    return bytes(((b >> bits) | (b << (8 - bits))) & 0xFF for b in data)


def rol_bytes(data: bytes, bits: int) -> bytes:
    bits %= 8
    return bytes(((b << bits) | (b >> (8 - bits))) & 0xFF for b in data)


def rc4_decrypt(data: bytes, key: bytes) -> bytes:
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
        out[idx] = byte ^ s[(s[i] + s[j]) & 0xFF]
    return bytes(out)


def caesar_rot(text: str, shift: int) -> str:
    out: list[str] = []
    for ch in text:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - ord("a") - shift) % 26 + ord("a")))
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - ord("A") - shift) % 26 + ord("A")))
        else:
            out.append(ch)
    return "".join(out)


def rot47(text: str) -> str:
    out: list[str] = []
    for ch in text:
        code = ord(ch)
        if 33 <= code <= 126:
            out.append(chr(33 + ((code - 33 + 47) % 94)))
        else:
            out.append(ch)
    return "".join(out)


def decode_base58(text: str) -> bytes | None:
    if not text or any(ch not in BASE58_MAP for ch in text):
        return None
    num = 0
    for ch in text:
        num = num * 58 + BASE58_MAP[ch]
    raw = num.to_bytes((num.bit_length() + 7) // 8, "big") if num > 0 else b""
    leading_zeros = len(text) - len(text.lstrip("1"))
    return (b"\x00" * leading_zeros) + raw


def _try_encodings(text: str) -> list[tuple[str, bytes]]:
    """Attempt Base64, Base32, Base58, Hex, and Reverse on an ASCII candidate string."""
    results: list[tuple[str, bytes]] = []
    stripped = text.strip()
    if len(stripped) < 6:
        return results

    # Reverse string
    results.append(("Reverse String", stripped[::-1].encode("utf-8", errors="ignore")))

    # Hex
    if len(stripped) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", stripped):
        try:
            results.append(("Hex Decode", bytes.fromhex(stripped)))
        except ValueError:
            pass

    # Base64
    if len(stripped) >= 8 and len(stripped) % 4 == 0 and re.fullmatch(r"[A-Za-z0-9+/=_-]+", stripped):
        try:
            b64 = base64.b64decode(stripped, validate=True)
            results.append(("Base64", b64))
        except (binascii.Error, ValueError):
            pass

    # Base32
    if len(stripped) >= 8 and len(stripped) % 8 == 0 and re.fullmatch(r"[A-Z2-7=]+", stripped):
        try:
            b32 = base64.b32decode(stripped)
            results.append(("Base32", b32))
        except (binascii.Error, ValueError):
            pass

    # Base58
    if len(stripped) >= 8 and all(ch in BASE58_MAP for ch in stripped):
        b58 = decode_base58(stripped)
        if b58:
            results.append(("Base58", b58))

    return results


def _crib_drag_repeating_xor(data: bytes, prefix: bytes) -> list[tuple[bytes, bytes]]:
    """Recover repeating XOR key of length 2..min(16, len(prefix)) using known prefix."""
    if len(prefix) < 2 or len(data) < len(prefix):
        return []
    derived_full = bytes(data[i] ^ prefix[i] for i in range(len(prefix)))
    results: list[tuple[bytes, bytes]] = []
    # Test candidate key lengths dividing or up to len(prefix)
    for klen in range(2, len(prefix) + 1):
        key = derived_full[:klen]
        # Verify key reproduces prefix
        if xor_repeating_key(data[: len(prefix)], key) == prefix:
            results.append((key, xor_repeating_key(data, key)))
    return results


def _extract_key_candidates(elf: ELFFile) -> list[str]:
    key_re = re.compile(r"^[A-Za-z0-9_\-]{4,64}$")
    seen: set[str] = set()
    keys: list[str] = []
    for item in extract_all_section_strings(elf, min_length=4):
        if item.section not in (".rodata", ".data"):
            continue
        if len(item.value) <= 64 and key_re.match(item.value):
            if item.value not in seen:
                seen.add(item.value)
                keys.append(item.value)
    return keys


def _extract_section_cipher_candidates(elf: ELFFile) -> list[CiphertextCandidate]:
    candidates: list[CiphertextCandidate] = []
    for section in elf.iter_sections():
        if section["sh_type"] == "SHT_NOBITS":
            continue
        sec_name = section.name or "<unnamed>"
        sh_size = int(section["sh_size"])
        if sh_size < 6 or sh_size > 4096:
            continue
        is_custom = not is_standard_section(sec_name)
        if not is_custom and sec_name != ".data":
            continue

        trimmed = section.data().rstrip(b"\x00")
        if len(trimmed) < 6:
            continue
        entropy = _shannon_entropy(trimmed)
        if is_custom and (_is_mostly_non_ascii(trimmed) or entropy >= 3.0):
            candidates.append(
                CiphertextCandidate(
                    section=sec_name,
                    address=int(section["sh_addr"]) or int(section["sh_offset"]),
                    data=trimmed,
                    entropy=entropy,
                    reason=f"Section kustom '{sec_name}'",
                )
            )
        elif sec_name == ".data" and entropy >= 4.0 and _is_mostly_non_ascii(trimmed):
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


def _validate_plaintext(
    raw: bytes,
    compiled_re: re.Pattern[str],
    printable_only: bool,
    prefix: str | None,
) -> str | None:
    """Validate decoded bytes against regex, optional prefix, or >90% printable heuristic."""
    clean_bytes = raw.rstrip(b"\x00")
    if len(clean_bytes) < 4:
        return None
    if _printable_ratio(clean_bytes) < 0.90:
        return None
    try:
        decoded = clean_bytes.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return None
    if not all(ch.isprintable() for ch in decoded):
        return None

    m = compiled_re.search(decoded)
    if m:
        return m.group(0)
    if prefix and prefix in decoded:
        return decoded
    if printable_only and len(decoded) >= 8:
        return decoded
    return None


def run_find_flag(
    elf: ELFFile,
    pattern_str: str = DEFAULT_FLAG_PATTERN,
    printable_only: bool = False,
    prefix: str | None = None,
    trace_check: bool = False,
) -> FindFlagReport:
    """Run universal static flag finder, layered auto-decoder, and optional trace-check."""
    try:
        compiled_re = re.compile(pattern_str)
    except re.error as exc:
        raise InvalidELFError(f"Regex --pattern tidak valid: {exc}") from exc

    xrefs, imm_constants, text_target_bufs, trace_functions = _analyze_text_structure(elf)
    all_strings = extract_all_section_strings(elf, min_length=4)

    direct_matches: list[FlagMatch] = []
    for item in all_strings:
        m = compiled_re.search(item.value)
        if m:
            item_xrefs = xrefs.get(item.address, [])
            is_decoy = item.section in (".rodata", ".data") or not item_xrefs
            direct_matches.append(
                FlagMatch(
                    section=item.section,
                    address=item.address,
                    value=m.group(0),
                    is_potential_decoy=is_decoy,
                    xref_functions=item_xrefs,
                    match_kind="regex",
                )
            )
        elif printable_only and len(item.value) >= 8 and item.section not in (".strtab", ".shstrtab", ".dynstr"):
            raw_b = item.value.encode("utf-8", errors="ignore")
            if _printable_ratio(raw_b) >= 0.90:
                item_xrefs = xrefs.get(item.address, [])
                direct_matches.append(
                    FlagMatch(
                        section=item.section,
                        address=item.address,
                        value=item.value,
                        is_potential_decoy=item.section in (".rodata", ".data") or not item_xrefs,
                        xref_functions=item_xrefs,
                        match_kind="printable-heuristic",
                    )
                )

    # Merge ciphertext candidates from sections and .text comparison references
    sec_candidates = _extract_section_cipher_candidates(elf)
    seen_addrs = {c.address for c in sec_candidates}
    ciphertext_candidates = list(sec_candidates)
    for tb in text_target_bufs:
        if tb.address not in seen_addrs:
            seen_addrs.add(tb.address)
            ciphertext_candidates.append(tb)

    key_candidates = _extract_key_candidates(elf)
    decrypted_flags: list[DecryptedFlagResult] = []
    seen_plaintexts: set[tuple[str, str]] = set()

    def record(algo: str, key_repr: str, sec: str, addr: int, pt: str) -> None:
        sig = (algo, pt)
        if sig not in seen_plaintexts:
            seen_plaintexts.add(sig)
            decrypted_flags.append(
                DecryptedFlagResult(
                    algorithm=algo,
                    key_repr=key_repr,
                    source_section=sec,
                    source_address=addr,
                    plaintext=pt,
                )
            )

    # Layer 1: String-level encodings (Base64, Base32, Base58, Hex, Reverse, ROT13, ROT47)
    for item in all_strings:
        if item.section in (".strtab", ".shstrtab", ".dynstr"):
            continue
        for enc_name, decoded_bytes in _try_encodings(item.value):
            pt = _validate_plaintext(decoded_bytes, compiled_re, printable_only, prefix)
            if pt:
                record(enc_name, "-", item.section, item.address, pt)

        # Caesar/ROT1..25 & ROT47
        for shift in range(1, 26):
            shifted = caesar_rot(item.value, shift)
            m = compiled_re.search(shifted)
            if m:
                record(f"Caesar/ROT-{shift}", f"shift={shift}", item.section, item.address, m.group(0))
        r47 = rot47(item.value)
        m47 = compiled_re.search(r47)
        if m47:
            record("ROT47", "shift=47", item.section, item.address, m47.group(0))

    # Layer 2: Byte-buffer bitwise, arithmetic, endianness swap, XOR, & RC4
    prefix_bytes = prefix.encode("utf-8") if prefix else None
    for cand in ciphertext_candidates:
        # Reverse & 32-bit/64-bit endianness swap
        for rev_name, rev_data in [
            ("Reverse Bytes", cand.data[::-1]),
            (
                "32-bit Endian Swap",
                b"".join(cand.data[i : i + 4][::-1] for i in range(0, len(cand.data), 4)),
            ),
        ]:
            pt = _validate_plaintext(rev_data, compiled_re, printable_only, prefix)
            if pt:
                record(rev_name, "-", cand.section, cand.address, pt)

        # Single-byte XOR (0x01..0xFF)
        for k in range(1, 256):
            pt = _validate_plaintext(xor_single_byte(cand.data, k), compiled_re, printable_only, prefix)
            if pt:
                record("Single-Byte XOR", f"0x{k:02X}", cand.section, cand.address, pt)

        # ADD/SUB modulo 256 (1..255)
        for delta in range(1, 256):
            pt = _validate_plaintext(add_sub_mod256(cand.data, delta), compiled_re, printable_only, prefix)
            if pt:
                record("ADD/SUB Mod 256", f"+{delta} (-{(256 - delta) & 0xFF})", cand.section, cand.address, pt)

        # Bit rotation ROL/ROR 1..7
        for bits in range(1, 8):
            pt_rol = _validate_plaintext(rol_bytes(cand.data, bits), compiled_re, printable_only, prefix)
            if pt_rol:
                record("Bit Rotation ROL", f"{bits} bit", cand.section, cand.address, pt_rol)
            pt_ror = _validate_plaintext(ror_bytes(cand.data, bits), compiled_re, printable_only, prefix)
            if pt_ror:
                record("Bit Rotation ROR", f"{bits} bit", cand.section, cand.address, pt_ror)

        # Crib-dragging Repeating XOR if --prefix is specified
        if prefix_bytes:
            for derived_key, dec_bytes in _crib_drag_repeating_xor(cand.data, prefix_bytes):
                pt = _validate_plaintext(dec_bytes, compiled_re, printable_only, prefix)
                if pt:
                    record("Crib-Drag Repeating XOR", repr(derived_key), cand.section, cand.address, pt)

        # Candidate key-based Repeating XOR & RC4
        for key_str in key_candidates:
            key_bytes = key_str.encode("utf-8")
            pt_xor = _validate_plaintext(xor_repeating_key(cand.data, key_bytes), compiled_re, printable_only, prefix)
            if pt_xor:
                record("Repeating-Key XOR", f'"{key_str}"', cand.section, cand.address, pt_xor)
            pt_rc4 = _validate_plaintext(rc4_decrypt(cand.data, key_bytes), compiled_re, printable_only, prefix)
            if pt_rc4:
                record("RC4 (KSA+PRGA)", f'"{key_str}"', cand.section, cand.address, pt_rc4)

    return FindFlagReport(
        pattern=pattern_str,
        printable_only=printable_only,
        prefix=prefix,
        direct_matches=direct_matches,
        ciphertext_candidates=ciphertext_candidates,
        key_candidates=key_candidates,
        imm_constants=imm_constants,
        decrypted_flags=decrypted_flags,
        trace_functions=trace_functions if (trace_check or not decrypted_flags) else [],
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

    text_sec = elf.get_section_by_name(".text")
    if text_sec is not None and text_sec["sh_type"] != "SHT_NOBITS":
        try:
            md = Cs(CS_ARCH_X86, CS_MODE_64)
            md.syntax = CS_OPT_SYNTAX_INTEL
            md.detail = True
            for insn in md.disasm(text_sec.data(), int(text_sec["sh_addr"])):
                fn = _find_containing_function(insn.address, func_ranges)

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
