"""``python -m dnscope`` entry point.

Allows the CLI to be invoked without installing the console script::

    python -m dnscope scan example.com
"""

from __future__ import annotations

import sys


def _run() -> int:
    # Imported lazily so that ``python -m dnscope --help`` does not pay the
    # cost of importing the whole engine when the user only wants help text.
    from dnscope.cli.app import main

    return main()


if __name__ == "__main__":  # pragma: no cover - thin wrapper
    sys.exit(_run())
