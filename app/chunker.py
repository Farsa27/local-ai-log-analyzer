"""Split a log file into parts that fit the model's token budget.

* Every line keeps its original 1-based line number (sent to the model as `L<n>: ...`).
* Multi-line entries (stack traces, indented continuation lines) are kept together.
* Parts are stored as line ranges only; the text is re-read from disk when needed,
  so the whole log is never duplicated in memory.
* Token counts come from the model's own tokenizer (llama-server /tokenize).
"""
import json
import re
from pathlib import Path
from urllib.parse import unquote
from typing import Callable, Iterator

CONTINUATION = re.compile(r"^(\s+|at\s|Caused by|Traceback|File\s\"|\.\.\.\s)")
MAX_LINE_CHARS = 1500  # very long single lines are trimmed (noted as a known limit)


def iter_lines(path: Path) -> Iterator[tuple[int, str]]:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for n, raw in enumerate(f, start=1):
            line = raw.rstrip("\r\n")
            if len(line) > MAX_LINE_CHARS:
                line = line[:MAX_LINE_CHARS] + " ...[trimmed]"
            yield n, line


def iter_entries(path: Path) -> Iterator[list[tuple[int, str]]]:
    """Group physical lines into logical entries."""
    entry: list[tuple[int, str]] = []
    for n, line in iter_lines(path):
        if not line.strip():
            continue
        if entry and CONTINUATION.match(line):
            entry.append((n, line))
            continue
        if entry:
            yield entry
        entry = [(n, line)]
    if entry:
        yield entry


DROP_KEYS = {"host", "request_id", "response_bytes", "duration_ms", "time", "service", "level",
             "client_ip", "method", "path", "status", "user_agent", "app"}


def _ua(ua: str) -> str:
    if not ua:
        return ""
    return "browser" if ua.startswith("Mozilla/") else ua.split(" ")[0][:40]


def compact(line: str) -> str:
    """Shorter, model-friendly view of one JSON log line (saves ~65% tokens).
    Keeps every security-relevant field, URL-decodes paths (twice, to expose double encoding)
    and drops noise (host, request_id, sizes, full browser user agent).
    Non-JSON lines are returned unchanged. The original line is still used for evidence."""
    s = line.strip()
    if not s.startswith("{"):
        return line
    try:
        d = json.loads(s)
    except ValueError:
        return line
    if not isinstance(d, dict):
        return line
    t = str(d.get("time", ""))
    t = t[11:23].replace(".000", "") if len(t) >= 19 else t
    parts = [t, str(d.get("app", "")).replace("cultive8 workspace", "workspace"),
             str(d.get("service", "")), str(d.get("level", ""))]
    if d.get("client_ip"):
        parts.append(f"ip={d['client_ip']}")
    if d.get("method") or d.get("path"):
        path = str(d.get("path", ""))
        decoded = unquote(unquote(path))
        parts.append(f"{d.get('method', '')} {decoded}".strip())
    if "status" in d:
        parts.append(str(d["status"]))
    if d.get("user_agent"):
        parts.append(f"ua={_ua(str(d['user_agent']))}")
    for k, v in d.items():
        if k in DROP_KEYS:
            continue
        v = json.dumps(v) if isinstance(v, (list, dict)) else str(v)
        parts.append(f"{k}={v[:200]}")
    return " ".join(p for p in parts if p)


def fmt(n: int, line: str) -> str:
    return f"L{n}: {compact(line)}"


def plan_chunks(path: Path, budget: int, count_tokens: Callable[[str], int]) -> tuple[list[dict], dict]:
    """Return (chunks, stats). Each chunk = {index, start, end, tokens}."""
    chunks: list[dict] = []
    cur_start, cur_end, cur_tokens = None, None, 0
    stats = {"lines": 0, "entries": 0, "total_tokens": 0, "split_entries": 0}

    def flush():
        nonlocal cur_start, cur_end, cur_tokens
        if cur_start is not None:
            chunks.append({"index": len(chunks), "start": cur_start, "end": cur_end, "tokens": cur_tokens})
        cur_start, cur_end, cur_tokens = None, None, 0

    for entry in iter_entries(path):
        stats["entries"] += 1
        # +1 per line for the newline join
        line_tokens = [(n, count_tokens(fmt(n, l)) + 1) for n, l in entry]
        stats["lines"] += len(entry)
        entry_tokens = sum(t for _, t in line_tokens)
        stats["total_tokens"] += entry_tokens

        if entry_tokens <= budget:
            if cur_tokens + entry_tokens > budget:
                flush()
            if cur_start is None:
                cur_start = entry[0][0]
            cur_end = entry[-1][0]
            cur_tokens += entry_tokens
            continue

        # Entry alone is bigger than a part: split it at line boundaries (rare).
        stats["split_entries"] += 1
        flush()
        for n, t in line_tokens:
            if cur_tokens + t > budget:
                flush()
            if cur_start is None:
                cur_start = n
            cur_end = n
            cur_tokens += t
        flush()
    flush()
    stats["chunks"] = len(chunks)
    return chunks, stats


def read_chunk_text(path: Path, start: int, end: int) -> str:
    out = []
    for n, line in iter_lines(path):
        if n < start:
            continue
        if n > end:
            break
        if line.strip():
            out.append(fmt(n, line))
    return "\n".join(out)


def read_lines(path: Path, wanted: set[int]) -> dict[int, str]:
    """Fetch specific lines (for evidence checks / report snippets)."""
    found = {}
    if not wanted:
        return found
    last = max(wanted)
    for n, line in iter_lines(path):
        if n in wanted:
            found[n] = line
        if n >= last:
            break
    return found
