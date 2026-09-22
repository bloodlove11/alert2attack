"""Write the API's OpenAPI document to a file.

    uv run python -m alert2attack.api.openapi openapi.json

The console's TypeScript types are generated from this document, so it needs to
be exactly JSON and nothing else.

Python writes the file itself rather than the shell redirecting stdout, because
building the app emits log lines — the auth module warns when no credential is
configured — and a redirect would put that warning inside the JSON, where it
breaks the generator at line 3.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

DEFAULT_PATH = Path("openapi.json")


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    out = Path(args[0]) if args else DEFAULT_PATH

    from alert2attack.api.app import create_app

    document = create_app().openapi()
    out.write_text(json.dumps(document, indent=2), encoding="utf-8")
    # Progress goes to stderr so stdout stays free for piping if anyone wants it.
    print(f"wrote {out} ({len(document.get('paths', {}))} paths)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
