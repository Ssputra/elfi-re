"""Convenience entry point for ELF Inspector CLI."""

import sys

from elf_inspector.cli import main

if __name__ == "__main__":
    sys.exit(main())
