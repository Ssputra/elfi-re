"""Safe ELF file loading, validation, and section/address resolution."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from elftools.common.exceptions import ELFError
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import Section

ELF_MAGIC = b"\x7fELF"


class InvalidELFError(Exception):
    """Raised when the input file is missing, unreadable, or not a valid ELF."""


@dataclass(frozen=True)
class ByteSlice:
    """Represents a slice of bytes extracted from an ELF file with its base address."""

    data: bytes
    base_address: int
    source_label: str


def validate_elf_path(file_path: str | Path) -> Path:
    """Validate that the path exists, is a regular file, and starts with ELF magic bytes."""
    path = Path(file_path)
    if not path.exists():
        raise InvalidELFError(f"File tidak ditemukan: {path}")
    if not path.is_file():
        raise InvalidELFError(f"Path bukan file reguler: {path}")

    try:
        with path.open("rb") as f:
            magic = f.read(4)
    except OSError as exc:
        raise InvalidELFError(f"Gagal membaca file '{path}': {exc}") from exc

    if len(magic) < 4 or magic != ELF_MAGIC:
        raise InvalidELFError(
            f"File '{path}' bukan file ELF yang valid (magic bytes tidak cocok)."
        )
    return path


@contextmanager
def open_elf(file_path: str | Path) -> Iterator[ELFFile]:
    """Context manager to safely open and parse an ELF file."""
    path = validate_elf_path(file_path)
    try:
        with path.open("rb") as stream:
            elf = ELFFile(stream)
            # Trigger header parsing early to catch malformed headers immediately.
            _ = elf.header
            yield elf
    except ELFError as exc:
        raise InvalidELFError(f"Format ELF tidak valid atau korup pada '{path}': {exc}") from exc
    except OSError as exc:
        raise InvalidELFError(f"Gagal membuka file '{path}': {exc}") from exc


def get_section_or_raise(elf: ELFFile, section_name: str) -> Section:
    """Return a section by name or raise InvalidELFError if not found."""
    section = elf.get_section_by_name(section_name)
    if section is None:
        raise InvalidELFError(f"Section '{section_name}' tidak ditemukan dalam file ELF.")
    return section


def extract_bytes_by_section(elf: ELFFile, section_name: str) -> ByteSlice:
    """Extract raw bytes from a named section."""
    section = get_section_or_raise(elf, section_name)
    if section["sh_type"] == "SHT_NOBITS":
        raise InvalidELFError(
            f"Section '{section_name}' bertipe SHT_NOBITS (tidak memiliki data fisik di file)."
        )
    data = section.data()
    return ByteSlice(
        data=data,
        base_address=int(section["sh_addr"]),
        source_label=f"section {section_name}",
    )


def extract_bytes_by_vaddr_range(
    elf: ELFFile,
    start_vaddr: int,
    end_vaddr: int | None = None,
    size: int | None = None,
) -> ByteSlice:
    """Extract raw bytes from a virtual address range using section mappings."""
    if end_vaddr is None and size is None:
        raise InvalidELFError("Harus menyertakan --end atau --size untuk rentang alamat.")
    if end_vaddr is not None and size is not None:
        raise InvalidELFError("Gunakan salah satu antara --end atau --size, bukan keduanya.")

    if size is not None:
        if size <= 0:
            raise InvalidELFError("Ukuran (--size) harus lebih besar dari 0.")
        end_vaddr = start_vaddr + size
    else:
        assert end_vaddr is not None
        if end_vaddr <= start_vaddr:
            raise InvalidELFError("Alamat akhir (--end) harus lebih besar dari --start.")

    target_size = end_vaddr - start_vaddr

    for section in elf.iter_sections():
        sh_addr = int(section["sh_addr"])
        sh_size = int(section["sh_size"])
        if sh_addr == 0 or sh_size == 0 or section["sh_type"] == "SHT_NOBITS":
            continue
        sec_end = sh_addr + sh_size
        if sh_addr <= start_vaddr < sec_end:
            offset_in_sec = start_vaddr - sh_addr
            available = sec_end - start_vaddr
            read_len = min(target_size, available)
            data = section.data()[offset_in_sec : offset_in_sec + read_len]
            return ByteSlice(
                data=data,
                base_address=start_vaddr,
                source_label=f"vaddr 0x{start_vaddr:x}-0x{start_vaddr + len(data):x} ({section.name})",
            )

    raise InvalidELFError(
        f"Alamat virtual 0x{start_vaddr:x} tidak berada dalam section yang memiliki data fisik."
    )
