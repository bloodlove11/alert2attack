"""Deterministic PowerShell -EncodedCommand decoder. No LLM involved."""

import base64
import binascii
import re

from pydantic import BaseModel

# PowerShell accepts any unambiguous prefix of -EncodedCommand; ``-e`` and ``-ec`` are the
# short forms attackers actually use. ``-ExecutionPolicy`` starts with ``-e`` too, hence the
# explicit alternation instead of a bare prefix match.
_ENC_FLAG_RE = re.compile(
    r"(?:^|\s)[-/](?:e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|"
    r"encodedcomm|encodedcomma|encodedcomman|encodedcommand)\s+([A-Za-z0-9+/=]+|\S+)",
    re.IGNORECASE,
)


class DecodeResult(BaseModel):
    encoded: bool
    decoded: str | None = None
    error: str | None = None


def decode_powershell(command_line: str) -> DecodeResult:
    m = _ENC_FLAG_RE.search(command_line)
    if m is None:
        return DecodeResult(encoded=False)
    payload = m.group(1)
    try:
        raw = base64.b64decode(payload, validate=True)
        return DecodeResult(encoded=True, decoded=raw.decode("utf-16-le"))
    except (binascii.Error, ValueError, UnicodeDecodeError) as exc:
        return DecodeResult(encoded=True, error=f"could not decode payload: {exc}")
