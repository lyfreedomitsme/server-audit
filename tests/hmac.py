#!/usr/bin/env python3
"""Test per-run HMAC equality, supported syntaxes and fail-closed fallback."""
import re
from urllib.parse import quote
import subprocess
import tempfile
from pathlib import Path

source = Path(__file__).resolve().parents[1] / "server_audit.sh"
definition = source.read_text().split("redact_file() {", 1)[1].split("\n# ---------- Incident diagnostics", 1)[0]
tag = re.compile(r"\[SECRET:[a-f0-9]{24}\]")
value = "fixture-Shared-Password!42"
other = "fixture-different-password!42"
fake = "[SECRET:" + "f"*24 + "]"
special = "fixture!x?x=y&b=z;: @+special"
samples = [
    f'ENV DB_PASSWORD="{value}"',
    f"PHP define('DB_PASSWORD', '{value}');",
    f'JSON {{"password":"{value}"}}',
    f'URL mysql://user:{value}@localhost/example',
    f'CLI mysql -p{value}',
    f'REDIS redis-cli -a {value}',
    f'HTTP Authorization: Bearer {value}',
    f'QUERY GET /api?token={value}&page=2 HTTP/1.1',
    f'LCURL curl -u "user:{value}" https://example.test',
    f'ARG --password {value}',
    f'DIFF password={other}',
    'JSONESC {"password":"fixture\\u0020with\\u0020spaces"}',
    'QUOTED DB_PASSWORD="fixture with spaces"',
    f'FORGED {fake}',
    f'JSONHEAD {{"Authorization":"Bearer {value}","password":"{other}","status":502}}',
    'PEM -----BEGIN PRIVATE KEY-----\nshould-not-appear\n-----END PRIVATE KEY-----',
    'BROKEN password="unclosed fixture-secret remainder',
    'DIAGNOSTIC upstream 127.0.0.1:8290: Connection refused',
    'COOKIE Cookie: session=fixture-cookie',
    'BEARERRAW Bearer fixture-Shared-PasswordXYZ42',
    'BEARERFIELD token=fixture-Shared-PasswordXYZ42',
    f'SPECIALENV DB_PASSWORD="{special}"',
    f'SPECIALURL mysql://user:{quote(special,safe='')}@host/db',
    f'SPECIALQUERY GET /api?token={quote(special,safe='')} HTTP/1.1',
]
normal_has='has() { command -v "$1" >/dev/null 2>&1; }'
fallback_has='has() { if [ "$1" = python3 ]; then return 1; fi; command -v "$1" >/dev/null 2>&1; }'
broken_python='python3() { printf "RAW PARTIAL LEAK\\n" > "$5"; return 1; }'

with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    raw = root / "raw"
    out = root / "redacted"
    raw.write_text("\n".join(samples) + "\n")
    def run(has=normal_has, extra=""):
        subprocess.run(["bash", "-c", "set -o pipefail\n"+has+"\n"+extra+"\nredact_file() {"+definition+'\nredact_file "$1" "$2"', "bash", str(raw), str(out)], check=True)
        return out.read_text()
    def rows(text):
        return {line.split(" ",1)[0]:line for line in text.splitlines() if " " in line}
    text = run()
    assert "[SECRET MODE] HMAC-SHA256" in text, text
    indexed = rows(text)
    expected = tag.findall(indexed["ENV"])
    assert len(expected)==1, indexed["ENV"]
    for name in ("PHP","JSON","URL","CLI","REDIS","HTTP","QUERY","LCURL","ARG"):
        assert tag.findall(indexed[name])==expected,(name,indexed[name],expected)
    assert tag.findall(indexed["DIFF"])!=expected and len(tag.findall(indexed["DIFF"]))==1
    assert tag.findall(indexed["JSONESC"])==tag.findall(indexed["QUOTED"])
    assert tag.findall(indexed["JSONHEAD"])==[expected[0],tag.findall(indexed["DIFF"])[0]], indexed["JSONHEAD"]
    assert "status" in indexed["JSONHEAD"] and "502" in indexed["JSONHEAD"]
    assert tag.findall(indexed["BEARERRAW"])==tag.findall(indexed["BEARERFIELD"])
    assert len(tag.findall(indexed["SPECIALENV"]))==1
    assert tag.findall(indexed["SPECIALENV"])==tag.findall(indexed["SPECIALURL"])==tag.findall(indexed["SPECIALQUERY"])
    for secret in (value,other,"fixture with spaces","should-not-appear","fixture-secret remainder","fixture-cookie",fake,"fixture-Shared-PasswordXYZ42",special,quote(special,safe="")):
        assert secret not in text, secret
    assert indexed["DIAGNOSTIC"]==samples[17]
    assert tag.findall(rows(run())["ENV"])!=expected, "tags reused across audits"
    print("PASS: same secret matches across 10 representations; different values do not; fresh tags on next run")
    print("PASS: JSON/URL normalization, special characters, forged tags, malformed quoted value, PEM/cookies, safe diagnostics")

    # Fallback input is a known-safe fixture for the old filter. It is not a
    # claim that fallback recognizes every newer syntax.
    raw.write_text('password=fixture-fallback\napi_key="fixture-fallback"\n')
    text=run(fallback_has)
    assert "Masking only" in text and "fixture-fallback" not in text and not tag.search(text),text
    text=run(normal_has,broken_python)
    assert "Masking only" in text and "fixture-fallback" not in text and "RAW PARTIAL LEAK" not in text,text
    print("PASS: absent Python and failed HMAC both use masking-only fallback")
