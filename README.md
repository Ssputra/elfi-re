# `elfi` — ELF x86_64 Static Inspector & Crypto Triage CLI

Aplikasi CLI berbasis Python untuk analisis statis (*static inspection*) file biner ELF (*Executable and Linkable Format*) pada arsitektur `x86_64`, dibangun menggunakan `pyelftools` dan `capstone`.

---

## Fitur Utama

1. **Inspeksi Header & Section (`info`, `sections`)** — Menampilkan ELF Header (`e_entry`, arsitektur, endianness, tipe file) serta daftar seluruh section (`.text`, `.rodata`, `.data`, `.bss`, dan section kustom seperti `.secret`) lengkap dengan alamat virtual, file offset, ukuran, dan flags.
2. **Ekstraksi String Terurut (`strings`)** — Memindai seluruh section berflag `SHF_ALLOC` maupun non-alloc untuk string **ASCII & UTF-8** yang dapat dibaca (`--min-len`, default `4`), lengkap dengan nama section asal, alamat virtual, file offset, dan opsi `--raw` (mirip GNU `strings`).
3. **Ekstraksi Byte & Hex Dump (`dump`)** — Mengekstrak byte mentah dalam format hex dump klasik (`--format hex`) atau array byte Python (`--format py`, menghasilkan `[0x96, 0xE8, ...]`) berdasarkan nama section atau rentang alamat virtual.
4. **Tabel Simbol, Impor & Relokasi (`symbols`)** — Menampilkan `.symtab` / `.dynsym`, daftar fungsi library eksternal yang diimpor (`SHN_UNDEF` seperti `fgets`, `memcmp`, `puts`), relokasi, dan library `DT_NEEDED`.
5. **Disassembler Fungsi + XREF (`disasm`)** — Disassembly `x86_64` sintaks Intel dengan anotasi referensi alamat data (`; XREF -> 0x... "..."`) untuk `.text`, fungsi tertentu (`--function`), atau rentang alamat (`--address`).
6. **Quick Triage (`triage`)** — Ringkasan satu kali jalan untuk section tidak standar, library & fungsi impor utama, serta string penting dari `.rodata` dan section kustom.
7. **Auto Flag Finder & Decryptor (`find-flag`)** — Memindai pola regex flag (`--pattern`), menandai potensi *decoy* di `.rodata`, mengekstrak kandidat kunci & ciphertext otomatis, lalu menguji dekripsi **Single-Byte XOR**, **Repeating-Key XOR**, **RC4 (KSA+PRGA)**, dan **Caesar/ROT**.
8. **Pemindaian Konstanta Kriptografi (`crypto-scan`)** — Mendeteksi konstanta pembagian modulo/kriptografi (`0x24924925`, CRC32, MD5/SHA, ChaCha20), signature **AES S-Box**, rotasi bit (`rol`/`ror`), dan loop 256 iterasi khas inisialisasi S-Box RC4.

---

## Struktur Proyek

```text
.
├── elf_inspector/
│   ├── __init__.py      # Metadata versi paket
│   ├── __main__.py      # Entry point `python -m elf_inspector`
│   ├── analyzer.py      # Header, section, UTF-8 strings, simbol, disasm XREF, & triage
│   ├── cli.py           # Antarmuka CLI berbasis argparse
│   ├── crypto.py        # Logika find-flag (XOR, RC4, ROT) & crypto-scan
│   ├── formatter.py     # Pemformatan tabel, hex dump, array Python, & laporan
│   └── loader.py        # Validasi magic bytes & pembacaan file ELF yang aman
├── tests/
│   └── test_elf_inspector.py  # Unit test seluruh fitur & error handling
├── elfi.cmd             # Wrapper CLI cepat untuk Windows
├── main.py              # Script runner utama
├── pyproject.toml       # Konfigurasi paket & console script `elfi`
├── requirements.txt     # Daftar dependensi
└── README.md
```

---

## Instalasi

### Linux / Kali WSL
```bash
git clone https://github.com/Ssputra/elfi-re.git
cd elfi-re
pip3 install --user --break-system-packages -e .
```
Pastikan `~/.local/bin` terdaftar di `PATH` (misal di `~/.zshrc` atau `~/.bashrc`):
```bash
export PATH="$HOME/.local/bin:$PATH"
```

### Windows (PowerShell / CMD)
```powershell
git clone https://github.com/Ssputra/elfi-re.git
cd elfi-re
pip install -e .
```

Cek instalasi:
```bash
elfi --version
```

---

## Cara Penggunaan

Ganti `<file_elf>` dengan path atau nama file biner ELF target Anda (misalnya `chall` atau `/mnt/c/Users/nama/Downloads/chall`).

### 1. Quick Triage (`triage`)
```bash
elfi triage <file_elf>
```

### 2. Pencarian & Auto-Dekripsi Flag (`find-flag`)
```bash
elfi find-flag <file_elf>
elfi find-flag <file_elf> --pattern "CTF\{[^}]+\}"
```

### 3. Pemindaian Konstanta Kriptografi (`crypto-scan`)
```bash
elfi crypto-scan <file_elf>
```

### 4. Inspeksi Header & Section (`info`, `sections`)
```bash
elfi info <file_elf>
elfi sections <file_elf>
```

### 5. Ekstraksi String (`strings`)
```bash
elfi strings <file_elf>
elfi strings <file_elf> --section .rodata --min-len 5
elfi strings <file_elf> --start 0x402000 --size 128
elfi strings <file_elf> --raw
```

### 6. Hex Dump & Array Byte Python (`dump`)
```bash
elfi dump <file_elf> --section .secret
elfi dump <file_elf> --section .secret --format py
elfi dump <file_elf> --start 0x402000 --size 64
elfi dump <file_elf> --start 0x402000 --end 0x402040
```

### 7. Tabel Simbol, Impor & Relokasi (`symbols`)
```bash
elfi symbols <file_elf>
elfi symbols <file_elf> --type func --only symbols
elfi symbols <file_elf> --only imports
elfi symbols <file_elf> --only libs
elfi symbols <file_elf> --only relocs
```

### 8. Disassembler x86_64 Intel + XREF (`disasm`)
```bash
elfi disasm <file_elf>
elfi disasm <file_elf> --function main
elfi disasm <file_elf> --address 0x401000 --count 20
elfi disasm <file_elf> --section .init --no-bytes
```

---

## Menjalankan Pengujian

```bash
python3 -m unittest discover -s tests -v
```
