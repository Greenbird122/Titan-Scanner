"""Track E browsing tests — sqlidump sessions viewed interactively.

Covers the REPL commands (/rows, /csv, /transcript, /dump, /files), the
one-shot CLI path (browse_session), and the data-session guard that refuses
to queue agent jobs against a sqli-extraction session (no agent polls them).
"""

import asyncio
from pathlib import Path

import pytest

from titan.exploit.listener import JobQueue
from titan.exploit.repl import (
    BROWSE_COMMANDS,
    SessionREPL,
    browse_session,
    export_session,
    parse_limit,
    read_dump_samples,
    render_rows_table,
    render_transcript,
)
from titan.exploit.session import SessionStore

DUMP_ROWS = [
    ["admin", "admin@lab.local", "admin"],
    ["alice", "alice@lab.local", "user"],
    ["bob", "bob@lab.local", "user"],
]
DUMP_COLS = ["username", "email", "role"]
CSV_TEXT = "username,email,role\nadmin,admin@lab.local,admin\nalice,alice@lab.local,user\nbob,bob@lab.local,user"


def _seed_session(tmp_path: Path, session_id: str = "abc123") -> SessionStore:
    store = SessionStore(tmp_path / "sessions", session_id=session_id)
    store.init_meta(
        target="http://lab.local",
        channel="sqli-extraction",
        consent_ref="consent/lab.local.json",
        extra={"dump": {"technique": "union", "table": "users", "rows": 3}},
    )
    store.save_sample("sqli_dump_users_union", {"rows": DUMP_ROWS, "columns": DUMP_COLS})
    store.save_sample("sqli_dump_users_union", CSV_TEXT, suffix=".csv")
    store.log("JOB probe1: SELECT count(*) FROM users")
    store.log("RESULT probe1: exit=0 output:\n3")
    return store


def _reader(lines: list):
    """Injected REPL input: yields lines, then EOF ends the session."""
    it = iter(lines)

    def read(prompt: str) -> str:
        try:
            return next(it)
        except StopIteration:
            raise EOFError

    return read


async def _run_repl(store: SessionStore, lines: list) -> str:
    """Drive a SessionREPL with injected input, capturing its print output."""
    import builtins

    captured: list = []
    orig = builtins.print

    def fake_print(*a, **kw):
        captured.append(" ".join(str(x) for x in a))

    builtins.print = fake_print
    try:
        repl = SessionREPL(store.session_id, JobQueue(), store.dir, read=_reader(lines))
        await repl.run()
    finally:
        builtins.print = orig
    return "\n".join(captured)


# ---------------------------------------------------------------------------
# Limit parsing + table rendering (pure)
# ---------------------------------------------------------------------------


def test_parse_limit():
    assert parse_limit([], 10) == 10
    assert parse_limit(["5"], 10) == 5
    assert parse_limit(["all"], 10) is None
    assert parse_limit(["bogus"], 10) == 10
    assert parse_limit(["0"], 10) == 0


def test_render_rows_table_headers_and_truncation():
    lines = render_rows_table(DUMP_COLS, DUMP_ROWS, limit=2)
    assert "username" in lines[0] and "email" in lines[0] and "role" in lines[0]
    assert len(lines) == 3  # header + 2 rows
    assert "admin@lab.local" in lines[1]
    assert "bob" not in "\n".join(lines), "limit must cap the rows shown"


def test_render_rows_table_long_cell_stays_aligned():
    """A cell between the truncation threshold and the old width cap must not
    overflow its column: every row's first " | " separator sits exactly under
    the header's (regression for the width/truncation mismatch)."""
    long_val = "x" * 40  # > 32 (old width cap) but < 48 (truncation cap)
    rows = [["admin", long_val, "role"], ["bob", "short", "user"]]
    lines = render_rows_table(["user", "email", "role"], rows, limit=None)
    sep = lines[0].index(" | ")
    for line in lines[1:]:
        assert line.index(" | ") == sep, f"column misaligned: {line!r}"
    assert long_val in lines[1], "sub-cap cell must render in full, not truncated"


# ---------------------------------------------------------------------------
# REPL commands
# ---------------------------------------------------------------------------


async def test_repl_rows_command(tmp_path: Path, capsys):
    store = _seed_session(tmp_path)
    out = await _run_repl(store, ["/rows all", "exit"])
    assert "rows from users (union)" in out
    assert "admin@lab.local" in out and "alice@lab.local" in out
    assert "username" in out  # header row rendered


async def test_repl_rows_capped(tmp_path: Path):
    store = _seed_session(tmp_path)
    out = await _run_repl(store, ["/rows 1", "exit"])
    assert "admin@lab.local" in out
    assert "alice@lab.local" not in out


async def test_repl_csv_command(tmp_path: Path):
    store = _seed_session(tmp_path)
    out = await _run_repl(store, ["/csv all", "exit"])
    assert "sqli_dump_users_union.csv" in out
    assert "username,email,role" in out
    assert "bob,bob@lab.local,user" in out


async def test_repl_transcript_command(tmp_path: Path):
    store = _seed_session(tmp_path)
    out = await _run_repl(store, ["/transcript all", "exit"])
    assert "JOB probe1: SELECT count(*) FROM users" in out
    assert "RESULT probe1" in out


def test_transcript_zero_limit_prints_nothing(tmp_path: Path):
    """lines[-0:] would return the WHOLE file — /transcript 0 must print none."""
    store = _seed_session(tmp_path)
    assert render_transcript(store, 0) == []


async def test_repl_dump_command(tmp_path: Path):
    store = _seed_session(tmp_path)
    out = await _run_repl(store, ["/dump", "exit"])
    assert "users via union: 3 rows, 3 cols" in out
    assert "sqli_dump_users_union.json" in out


async def test_repl_files_command(tmp_path: Path):
    store = _seed_session(tmp_path)
    out = await _run_repl(store, ["/files", "exit"])
    assert "session.json" in out and "transcript.log" in out
    assert "sqli_dump_users_union.csv" in out


async def test_data_session_refuses_agent_commands(tmp_path: Path):
    """A sqli-extraction session has no agent: shell lines must be refused and
    never queued, and the banner must explain the session kind."""
    store = _seed_session(tmp_path)
    queue = JobQueue()

    import builtins

    captured = []
    orig = builtins.print

    def fake_print(*a, **kw):
        captured.append(" ".join(str(x) for x in a))

    builtins.print = fake_print
    try:
        repl = SessionREPL(store.session_id, queue, store.dir, read=_reader(["whoami", "exit"]))
        await repl.run()
    finally:
        builtins.print = orig
    text = "\n".join(captured)
    assert "data session" in text
    assert "no agent" in text or "/rows" in text
    assert queue.pending_count() == 0, "no job may be queued for a data session"


# ---------------------------------------------------------------------------
# One-shot CLI browsing
# ---------------------------------------------------------------------------


def test_browse_rows_one_shot(tmp_path: Path, capsys):
    store = _seed_session(tmp_path)
    rc = browse_session(store.dir, "rows", ["all"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "admin@lab.local" in out and "username" in out


def test_browse_csv_one_shot(tmp_path: Path, capsys):
    store = _seed_session(tmp_path)
    rc = browse_session(store.dir, "csv", ["2"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "username,email,role" in out
    assert "bob,bob@lab.local,user" not in out  # capped at 2 data lines + header


def test_browse_dump_one_shot(tmp_path: Path, capsys):
    store = _seed_session(tmp_path)
    rc = browse_session(store.dir, "dump", [])
    assert rc == 0
    assert "users via union: 3 rows" in capsys.readouterr().out


def test_browse_unknown_command(tmp_path: Path):
    store = _seed_session(tmp_path)
    assert browse_session(store.dir, "nonsense", []) == 2


def test_browse_no_dump_sample(tmp_path: Path, capsys):
    store = SessionStore(tmp_path / "sessions", session_id="nodump")
    store.init_meta(target="http://lab.local", channel="rce-agent", consent_ref="c")
    assert browse_session(store.dir, "rows", []) == 1
    assert "no sqli dump" in capsys.readouterr().out


def test_browse_commands_exposed():
    assert {"rows", "csv", "transcript", "dump", "files", "samples"} <= set(BROWSE_COMMANDS)


def test_find_browse_parses_ordering():
    """`--store` before or after the browse command must resolve to the same
    (command, args); a flag VALUE is never mistaken for a command."""
    import titan_exploit_cli as cli

    # session <id> rows 5
    assert cli._find_browse(["abc123", "rows", "5"]) == ("rows", ["5"])
    # session <id> --store findings rows 5  (flag value shadows nothing)
    assert cli._find_browse(["abc123", "--store", "findings", "rows", "5"]) == ("rows", ["5"])
    # session <id> rows 5 --store findings — after the command everything
    # passes through verbatim (harmless for rows, required for export).
    assert cli._find_browse(["abc123", "rows", "5", "--store", "findings"]) == (
        "rows",
        ["5", "--store", "findings"],
    )
    # No browse command -> interactive REPL
    assert cli._find_browse(["abc123"]) is None
    assert cli._find_browse(["abc123", "--store", "findings"]) is None
    # An unknown first token is not a browse command
    assert cli._find_browse(["abc123", "whatever", "rows"]) is None


def test_find_browse_export_preserves_flag_and_value():
    """`export --out <path>` must pass BOTH the flag and its value through."""
    import titan_exploit_cli as cli

    assert cli._find_browse(["abc123", "export", "--out", "/tmp/x.zip"]) == (
        "export",
        ["--out", "/tmp/x.zip"],
    )


# ---------------------------------------------------------------------------
# /export — evidence handoff zip
# ---------------------------------------------------------------------------


def test_export_session_bundles_evidence(tmp_path: Path):
    store = _seed_session(tmp_path)
    out = export_session(store.dir, tmp_path / "handoff")
    assert out.suffix == ".zip" and out.exists()

    import zipfile

    with zipfile.ZipFile(out) as zf:
        names = set(zf.namelist())
    # Rooted at the session id; every artifact present.
    assert "abc123/session.json" in names
    assert "abc123/transcript.log" in names
    assert "abc123/data_samples/sqli_dump_users_union.json" in names
    assert "abc123/data_samples/sqli_dump_users_union.csv" in names


async def test_repl_export_command(tmp_path: Path):
    store = _seed_session(tmp_path)
    out_zip = tmp_path / "repl-export.zip"
    out = await _run_repl(store, [f"/export --out {out_zip}", "exit"])
    assert "exported" in out and str(out_zip) in out
    assert out_zip.exists()


def test_browse_export_one_shot(tmp_path: Path):
    store = _seed_session(tmp_path)
    out_zip = tmp_path / "one-shot.zip"
    rc = browse_session(store.dir, "export", ["--out", str(out_zip)])
    assert rc == 0
    assert out_zip.exists()


def test_export_default_path_sits_next_to_session(tmp_path: Path):
    store = _seed_session(tmp_path)
    out = export_session(store.dir)
    assert out == store.dir.with_suffix(".zip")
    assert out.parent == store.dir.parent


def test_export_missing_session_dir_raises(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        export_session(tmp_path / "nope", tmp_path / "o.zip")


def test_export_empty_session_raises_without_leaving_zip(tmp_path: Path):
    """A session dir with no files must raise BEFORE any archive is created —
    no orphaned empty zip may remain on disk."""
    # SessionStore() alone creates the dir (and empty data_samples/) but no
    # files until init_meta writes session.json.
    store = SessionStore(tmp_path / "sessions", session_id="empty1")
    out = tmp_path / "handoff.zip"
    with pytest.raises(ValueError, match="no files to export"):
        export_session(store.dir, out)
    assert not out.exists(), "empty session must not leave a zip behind"


def test_read_dump_samples_parses_names(tmp_path: Path):
    """Dump names sqli_dump_<table>_<technique>.json decode table + technique,
    including tables whose own name contains underscores."""
    store = SessionStore(tmp_path / "sessions", session_id="multi")
    store.init_meta(target="http://lab.local", channel="sqli-extraction", consent_ref="c")
    store.save_sample(
        "sqli_dump_user_profiles_boolean",
        {"rows": [["a"]], "columns": ["x"]},
    )
    samples = read_dump_samples(store)
    assert len(samples) == 1
    assert samples[0]["table"] == "user_profiles"
    assert samples[0]["technique"] == "boolean"
