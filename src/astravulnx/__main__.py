"""Allow ``python -m astravulnx``."""

import sys

from astravulnx.cli import main

if __name__ == "__main__":
    sys.exit(main())
