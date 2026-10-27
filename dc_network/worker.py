"""Internal worker entry point, not a user-facing command."""

import json
import sys

from .probes import probe


def main():
    payload = json.load(sys.stdin)
    print(json.dumps(probe(**payload), allow_nan=False))


if __name__ == "__main__":
    main()
