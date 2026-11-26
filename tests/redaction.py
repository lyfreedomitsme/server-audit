#!/usr/bin/env python3
"""Synthetic secrets only. Assert redaction and preserved diagnostics."""
import subprocess
import tempfile
from pathlib import Path

source = Path(__file__).resolve().parents[1] / "server_audit.sh"
definition = source.read_text().split("redact_file() {", 1)[1].split("\n# ---------- Incident diagnostics", 1)[0]
samples = [
    ('DB_PASSWORD="two words fixture01"', 'two words fixture01'),
    ("DB_PASS='two words fixture02'", 'two words fixture02'),
    ('{"password":"fixture03","clientSecret":"fixture04"}', 'fixture03', 'fixture04'),
    (r'{"token":"before\"fixture05 after","status":502}', 'before', 'fixture05 after'),
    ("define('DB_PASSWORD', 'fixture06');", 'fixture06'),
    ('requirepass "fixture07 and more"', 'fixture07 and more'),
    ("mysqldump -p'fixture08 and more' database", 'fixture08 and more'),
    ('redis-cli -a "fixture09 and more" info', 'fixture09 and more'),
    ('curl -u "myuser:fixture10 and more" https://example.test', 'myuser:fixture10 and more'),
    ('mongodb://username:fixture11@host/db', 'username:fixture11'),
    ('https://fixture12@host/db', 'fixture12'),
    ('GET /?moderation-hash=fixture13&x=fixture14 HTTP/1.1', 'fixture13', 'fixture14'),
    ('Authorization: Basic Zml4dHVyZTE1', 'Zml4dHVyZTE1'),
    ('{"Cookie":"session=fixture16; id=more"}', 'fixture16'),
    ('github_pat_' + 'A'*30, 'github_pat_' + 'A'*30),
    ('ASIA' + 'A'*16, 'ASIA' + 'A'*16),
    ('sk-proj-' + 'A'*35, 'sk-proj-' + 'A'*35),
    ('xoxb-' + '9'*30, 'xoxb-' + '9'*30),
    ('https://api.telegram.org/bot123456789:' + 'A'*35 + '/sendMessage', '123456789:' + 'A'*35),
    ('-----BEGIN OPENSSH PRIVATE KEY-----\nfixture21\n-----END OPENSSH PRIVATE KEY-----', 'fixture21'),
    ('embedded -----BEGIN PRIVATE KEY----- fixture22 -----END PRIVATE KEY-----', 'fixture22'),
    ('SERVICE_ROLE_KEY=fixture23; MYSQL_PWD=fixture24', 'fixture23', 'fixture24'),
    ('session_id=fixture25, refresh_token=fixture26', 'fixture25', 'fixture26'),
    ('--password "fixture27 and more"', 'fixture27 and more'),
    ('sk_live_'+'A'*24, 'sk_live_'+'A'*24),
    ('redis://:fixture29@127.0.0.1:6379/0', 'fixture29'),
    ('eyJaaaaaaaa.eyJbbbbbbbb.cccccccccc', 'eyJaaaaaaaa.eyJbbbbbbbb.cccccccccc'),
]
diagnostics = [
    'Apache inactive (dead)',
    'upstream: "https://127.0.0.1:8290/" connection refused',
    'php-fpm [pool www] reached pm.max_children',
    'Out of memory: Killed process 123 (mariadbd)',
    'psql -p5432 --version',
    'client 192.0.2.1 server example.test status 502',
]
with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    raw = root / "raw"
    out = root / "redacted"
    raw.write_text("\n".join([s[0] for s in samples] + diagnostics) + "\n")
    subprocess.run(["bash", "-c", "set -o pipefail\nhas() { command -v \"$1\" >/dev/null 2>&1; }\nredact_file() {" + definition + '\nredact_file "$1" "$2"', "bash", str(raw), str(out)], check=True)
    text = out.read_text()
    assert "[SECRET MODE] HMAC-SHA256" in text, "HMAC filter silently fell back"
    missed = [(i+1, v) for i, sample in enumerate(samples) for v in sample[1:] if v in text]
    for n,v in missed:
        print(f"FAIL fixture {n}: {v}")
    assert not missed, "synthetic secret escaped filter"
    assert all(d in text for d in diagnostics), "diagnostic lost"
    print(f"PASS: {sum(len(s)-1 for s in samples)} synthetic secret values removed; {len(diagnostics)} diagnostic lines retained")
