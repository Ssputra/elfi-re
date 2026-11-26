"""Allow running via `python -m elf_inspector`."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
