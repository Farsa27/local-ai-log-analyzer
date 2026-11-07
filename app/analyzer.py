"""Analysis pipeline: plan parts -> one model call per part (sequential) -> merge -> correlate -> report.

State is saved to data/jobs/<id>.json after every model call, so a crash or restart
keeps completed findings and the job can resume from the next unfinished part.
"""
import json
import os
import queue
import re
import threading
import time
import traceback
import uuid
from pathlib import Path

from . import chunker, config, llm, prompts
from .jsonfix import parse_model_json

SEV_RANK = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
RANK_SEV = {v: k for k, v in SEV_RANK.items()}
IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

ACTIONS = {
    "brute_force_compromise": "Lock/reset the affected account, kill its sessions, block the IP, review activity after the successful login, enforce MFA.",
    "failed_login": "Rate-limit or block the IP, enable account lockout / CAPTCHA, check for credential stuffing.",
    "sql_injection": "Block the IP, confirm queries are parameterised, review DB logs for data access, add WAF rules.",
    "scanning": "Block or rate-limit the IP at the firewall/WAF; make sure probed paths are not exposed.",
    "unauthorized_access": "Verify access controls on the targeted resources, review the account/IP, block if not legitimate.",
    "high_request_rate": "Apply rate limiting; investigate for DoS or automated abuse.",
    "path_traversal": "Block the IP, validate/normalise file paths, check whether any file was served.",
    "xss": "Block the IP, check output encoding / CSP on the targeted pages.",
    "command_injection": "Isolate the host if any request succeeded, block the IP, review input handling.",
    "suspicious_other": "Review the cited lines manually and monitor the source.",
    "recon_then_exploit": "Block the IP, review all requests from it, patch the targeted endpoints.",
}
TITLES = {
    "failed_login": "Repeated failed logins (possible brute force)",
    "successful_login": "Successful login",
    "sql_injection": "SQL injection attempt",
    "scanning": "Scanning / reconnaissance",
    "unauthorized_access": "Unauthorized access attempt",
    "high_request_rate": "Unusual request rate",
    "path_traversal": "Path traversal attempt",
    "xss": "Cross-site scripting attempt",
    "command_injection": "Command injection attempt",
    "suspicious_other": "Suspicious activity",
}

_lock = threading.Lock()
_queue: "queue.Queue[str]" = queue.Queue()
_cancel: set[str] = set()


# ---------------------------------------------------------------- persistence
def job_path(job_id: str) -> Path:
    return config.JOB_DIR / f"{job_id}.json"


def save_job(job: dict) -> None:
    job["updated"] = time.time()
    tmp = job_path(job["id"]).with_suffix(".tmp")
    with _lock:
        tmp.write_text(json.dumps(job, indent=1), encoding="utf-8")
        os.replace(tmp, job_path(job["id"]))  # atomic


def load_job(job_id: str) -> dict | None:
    if not re.fullmatch(r"[a-f0-9]{12}", job_id or ""):
        return None
    p = job_path(job_id)
    if not p.exists():
        return None
    with _lock:
        return json.loads(p.read_text(encoding="utf-8"))


def list_jobs() -> list[dict]:
    out = []
    for p in sorted(config.JOB_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
        try:
            j = json.loads(p.read_text(encoding="utf-8"))
            out.append({k: j.get(k) for k in ("id", "filename", "status", "created", "progress")})
        except Exception:  # noqa: BLE001
            continue
    return out


def new_job(filename: str, path: Path) -> dict:
    job = {
        "id": uuid.uuid4().hex[:12], "filename": filename, "path": str(path),
        "status": "uploaded", "created": time.time(), "chunks": [], "events": [],
        "progress": {"done": 0, "total": 0, "failed": 0}, "log": [], "report": None,
        "stats": {}, "model": None, "ip_counts": {},
    }
    save_job(job)
    return job


def log(job: dict, msg: str) -> None:
    job["log"].append(f"{time.strftime('%H:%M:%S')} {msg}")
    job["log"] = job["log"][-200:]


# ---------------------------------------------------------------- worker
def enqueue(job_id: str) -> None:
    _cancel.discard(job_id)
    _queue.put(job_id)


def cancel(job_id: str) -> None:
    _cancel.add(job_id)


def start_worker() -> None:
    threading.Thread(target=_worker, daemon=True, name="analyzer").start()
    # resume interrupted jobs after a restart
    for p in config.JOB_DIR.glob("*.json"):
        try:
            j = json.loads(p.read_text(encoding="utf-8"))
            if j.get("status") in ("queued", "planning", "running"):
                j["status"] = "queued"
                log(j, "Resuming after restart; completed parts are kept.")
                save_job(j)
                _queue.put(j["id"])
        except Exception:  # noqa: BLE001
            continue


def _worker() -> None:
    while True:
        job_id = _queue.get()  # one job and one model call at a time -> bounded RAM
        job = load_job(job_id)
        if not job:
            continue
        try:
            run_job(job)
        except Exception as e:  # noqa: BLE001
            job["status"] = "failed"
            log(job, f"Job failed: {e}")
            job["error"] = traceback.format_exc()[-2000:]
            save_job(job)


# ---------------------------------------------------------------- budget
def base_prompt_tokens() -> int:
    """Tokens used by system prompt + template + wrapper with an empty log and empty carry."""
    rendered = llm.render_prompt(prompts.CHUNK_SYSTEM, prompts.CHUNK_USER.format(carry="", log=""))
    return llm.count_tokens(rendered)


def run_job(job: dict) -> None:
    path = Path(job["path"])
    job["model"] = llm.model_name()

    # 1. plan parts (only once; reused on resume)
    if not job["chunks"]:
        job["status"] = "planning"
        save_job(job)
        base = base_prompt_tokens()
        budget = config.CTX_LIMIT - config.OUTPUT_RESERVE - config.CARRY_BUDGET - config.SAFETY_MARGIN - base
        if budget < 200:
            raise RuntimeError(f"Token budget too small ({budget}). Lower OUTPUT_RESERVE/CARRY_BUDGET.")
        chunks, stats = chunker.plan_chunks(path, budget, llm.count_tokens)
        if not chunks:
            raise RuntimeError("The file contains no log lines.")
        for c in chunks:
            c.update(status="pending", error=None, timing=None, attempts=0)
        job["chunks"] = chunks
        job["stats"] = {**stats, "budget": {
            "context": config.CTX_LIMIT, "base_prompt": base, "carry": config.CARRY_BUDGET,
            "output_reserve": config.OUTPUT_RESERVE, "safety": config.SAFETY_MARGIN, "log_per_part": budget}}
        job["progress"] = {"done": 0, "total": len(chunks), "failed": 0}
        log(job, f"Planned {len(chunks)} parts from {stats['lines']} lines / {stats['total_tokens']} tokens "
                 f"(log budget {budget} tokens per call).")

    job["status"] = "running"
    save_job(job)

    # 2. analyse parts sequentially
    for c in job["chunks"]:
        if job["id"] in _cancel:
            job["status"] = "cancelled"
            log(job, "Cancelled by user. Completed findings kept.")
            save_job(job)
            return
        if c["status"] == "done":
            continue
        analyse_chunk(job, c, path)
        job["progress"]["done"] = sum(1 for x in job["chunks"] if x["status"] == "done")
        job["progress"]["failed"] = sum(1 for x in job["chunks"] if x["status"] == "failed")
        save_job(job)  # findings saved after every call

    # 3. merge + correlate + final review
    job["status"] = "reporting"
    save_job(job)
    job["report"] = build_report(job, path)
    job["status"] = "done"
    log(job, "Report ready.")
    save_job(job)


# ---------------------------------------------------------------- per part
def carry_context(job: dict) -> str:
    """Compact facts from earlier parts, trimmed to CARRY_BUDGET tokens."""
    merged = merge_events(job["events"])
    rows = sorted(merged.values(), key=lambda m: (-SEV_RANK[m["severity"]], -m["count"]))
    lines = []
    for m in rows:
        ln = m["lines"]
        lines.append(f"- {m['source']}: {m['type']} x{m['count']} (L{ln[0]}..L{ln[-1]}, max {m['severity']})")
    top_ips = sorted(job["ip_counts"].items(), key=lambda kv: -kv[1])[:3]
    if top_ips:
        lines.append("- busiest IPs so far: " + ", ".join(f"{ip} {n} lines" for ip, n in top_ips))
    if not lines:
        return "none yet"
    text = ""
    for row in lines:
        candidate = (text + "\n" + row).strip()
        if llm.count_tokens(candidate) > config.CARRY_BUDGET:
            break
        text = candidate
    return text or "none yet"


def analyse_chunk(job: dict, c: dict, path: Path) -> None:
    text = chunker.read_chunk_text(path, c["start"], c["end"])
    line_map = {}
    for row in text.split("\n"):
        m = re.match(r"L(\d+): (.*)", row)
        if m:
            line_map[int(m.group(1))] = m.group(2)
    # cheap per-IP counter (facts for the carried context, not a detection result)
    for line in line_map.values():
        for ip in set(IPV4.findall(line)):
            job["ip_counts"][ip] = job["ip_counts"].get(ip, 0) + 1

    carry = carry_context(job)
    user = prompts.CHUNK_USER.format(carry=carry, log=text)
    prompt = llm.render_prompt(prompts.CHUNK_SYSTEM, user)
    used = llm.count_tokens(prompt)
    n_predict = min(config.OUTPUT_RESERVE, config.CTX_LIMIT - used - 8)
    if n_predict < 128:
        c.update(status="failed", error=f"prompt too large ({used} tokens)")
        log(job, f"Part {c['index'] + 1}: skipped, prompt {used} tokens too large.")
        return

    c["attempts"] = c.get("attempts", 0) + 1
    try:
        raw, timing = llm.complete(prompt, prompts.CHUNK_SCHEMA, n_predict)
    except llm.LLMError as e:
        c.update(status="failed", error=str(e))
        log(job, f"Part {c['index'] + 1}: model call failed ({e}). Other parts continue.")
        return

    data, repaired = parse_model_json(raw, "events")
    events = validate_events(data.get("events", []), c, line_map)
    for e in events:
        e["chunk"] = c["index"]
    job["events"] = [e for e in job["events"] if e.get("chunk") != c["index"]] + events
    timing.update(prompt_tokens_counted=used, repaired_json=repaired)
    c.update(status="done", error=None, timing=timing, found=len(events))
    log(job, f"Part {c['index'] + 1}/{len(job['chunks'])} L{c['start']}-L{c['end']}: "
             f"{len(events)} events, {used}+{timing.get('output_tokens')} tokens, {timing['seconds']}s"
             + (" (JSON repaired)" if repaired else ""))


LOGIN = re.compile(r"login|signin|/auth|sshd|password", re.I)
LOGIN_FAIL = re.compile(r"\b401\b|invalid|fail|denied|wrong", re.I)
LOGIN_OK = re.compile(r"auth_result=success|Accepted password|login success", re.I)
PROBE = re.compile(r"/\.env|/\.git|wp-admin|phpmyadmin|/backup|\.sql\b|server-status|/actuator|config\.json", re.I)
TRAVERSAL = re.compile(r"\.\./|\.\.\\")
SQLI = re.compile(r"('|%27)\s*(or|and)\s+\d=\d|union\s+select|sleep\(|;\s*select|--\s*$", re.I)
RATE = re.compile(r"requests_in_window=\d+|\b429\b")
STATUS = re.compile(r"\s(\d{3})(\s|$)")


def evidence_type(model_type: str, text: str) -> str:
    """Correct the model's label using what the cited line actually shows.
    Small models often call a failed login 'unauthorized_access'; the evidence decides."""
    if LOGIN.search(text):
        if LOGIN_OK.search(text):
            return "successful_login"
        if LOGIN_FAIL.search(text):
            return "failed_login"
    if SQLI.search(text):
        return "sql_injection"
    if TRAVERSAL.search(text):
        return "path_traversal"
    if PROBE.search(text):
        return "scanning"
    if RATE.search(text):
        return "high_request_rate"
    return model_type


def is_server_error_only(lines: list[int], line_map: dict[int, str]) -> bool:
    codes = [STATUS.search(line_map[n]) for n in lines]
    return bool(codes) and all(m and m.group(1).startswith("5") for m in codes)


def validate_events(raw_events, c: dict, line_map: dict[int, str]) -> list[dict]:
    """Drop hallucinated line numbers, keep only lines that mention the source,
    correct event types from the evidence, and merge per (source, type)."""
    grouped: dict[tuple, dict] = {}
    for ev in _validate_raw(raw_events, line_map):
        src_known = ev["source"] != "unknown"
        lines = [n for n in ev["lines"] if not src_known or ev["source"] in line_map[n]] or ev["lines"]
        for n in lines:
            etype = evidence_type(ev["type"], line_map[n])
            key = (ev["source"], etype)
            g = grouped.setdefault(key, {**ev, "type": etype, "lines": []})
            g["lines"].append(n)
            if SEV_RANK[ev["severity"]] > SEV_RANK[g["severity"]]:
                g["severity"] = ev["severity"]
    out = []
    for g in grouped.values():
        g["lines"] = sorted(set(g["lines"]))
        if g["type"] == "high_request_rate" and is_server_error_only(g["lines"], line_map):
            continue  # 5xx outage errors (e.g. during a deployment) are not an attack by themselves
        out.append(g)
    return out


def _validate_raw(raw_events, line_map: dict[int, str]) -> list[dict]:
    out = []
    if not isinstance(raw_events, list):
        return out
    for ev in raw_events:
        if not isinstance(ev, dict):
            continue
        etype = ev.get("type")
        if etype not in prompts.EVENT_TYPES:
            continue
        src = str(ev.get("source", "")).strip()[:60] or "unknown"
        lines = sorted({int(n) for n in ev.get("lines", []) if isinstance(n, (int, float)) and int(n) in line_map})
        if not lines:
            continue  # no evidence inside this part -> not reported
        verified = src != "unknown" and any(src in line_map[n] for n in lines)
        if not verified and src != "unknown":
            # source may be correct but cited lines slightly off: look for it in this part
            hits = [n for n, t in line_map.items() if src in t]
            if hits:
                verified = True
        sev = ev.get("severity") if ev.get("severity") in SEV_RANK else "Low"
        if not verified and SEV_RANK[sev] > 2:
            sev = "Medium"  # unverified claims cannot be High/Critical
        out.append({"type": etype, "source": src, "lines": lines, "severity": sev,
                    "reason": str(ev.get("reason", ""))[:160], "verified": verified})
    return out


# ---------------------------------------------------------------- merge + correlate
def merge_events(events: list[dict]) -> dict:
    merged: dict[tuple, dict] = {}
    for e in events:
        key = (e["source"], e["type"])
        m = merged.setdefault(key, {"source": e["source"], "type": e["type"], "count": 0, "lines": [],
                                    "severity": "Low", "reasons": [], "chunks": [], "verified": False})
        m["count"] += len(e["lines"])
        m["lines"] = sorted(set(m["lines"]) | set(e["lines"]))
        if SEV_RANK[e["severity"]] > SEV_RANK[m["severity"]]:
            m["severity"] = e["severity"]
        if e["reason"] and e["reason"] not in m["reasons"] and len(m["reasons"]) < 3:
            m["reasons"].append(e["reason"])
        if e["chunk"] not in m["chunks"]:
            m["chunks"].append(e["chunk"])
        m["verified"] = m["verified"] or e.get("verified", False)
    return merged


def evidence(path: Path, lines: list[int], limit: int = 8) -> list[dict]:
    pick = lines if len(lines) <= limit else lines[: limit // 2] + lines[-limit // 2:]
    text = chunker.read_lines(path, set(pick))
    return [{"line": n, "text": text.get(n, "")[:300]} for n in pick]


def build_report(job: dict, path: Path) -> dict:
    merged = merge_events(job["events"])
    by_source: dict[str, dict] = {}
    for (src, typ), m in merged.items():
        by_source.setdefault(src, {})[typ] = m

    findings, used = [], set()

    # Rule A: failed logins then a later success from the same source (may span parts)
    for src, types in by_source.items():
        fails, ok = types.get("failed_login"), types.get("successful_login")
        if fails and ok and fails["count"] >= config.BRUTE_FORCE_MIN_FAILS:
            later = [n for n in ok["lines"] if n > fails["lines"][0]]
            if later:
                after = post_login_activity(path, src, later[0])
                lines = sorted(set(fails["lines"]) | set(later) | set(after))
                extra = f" After login the same source made {len(after)} more request(s) (e.g. L{after[0]})." if after else ""
                findings.append(_finding(
                    "Brute force followed by possible account compromise", "Critical", src, lines, path,
                    f"{fails['count']} failed logins (L{fails['lines'][0]}..L{fails['lines'][-1]}, "
                    f"{len(fails['chunks'])} part(s)) then a successful login at L{later[0]}.{extra}",
                    ACTIONS["brute_force_compromise"], sorted(set(fails["chunks"]) | set(ok["chunks"])),
                    fails["verified"] and ok["verified"]))
                used |= {(src, "failed_login"), (src, "successful_login")}

    # Rule B: scanning followed by an exploitation attempt from the same source
    for src, types in by_source.items():
        scan = types.get("scanning")
        exploit = [types[t] for t in ("sql_injection", "path_traversal", "command_injection", "xss",
                                      "unauthorized_access") if t in types]
        if scan and exploit:
            ex_lines = sorted({n for e in exploit for n in e["lines"]})
            if ex_lines and ex_lines[-1] > scan["lines"][0]:
                lines = sorted(set(scan["lines"]) | set(ex_lines))
                kinds = ", ".join(e["type"] for e in exploit)
                findings.append(_finding(
                    "Reconnaissance followed by exploitation attempt", "High", src, lines, path,
                    f"Scanning from L{scan['lines'][0]} then {kinds} up to L{ex_lines[-1]}.",
                    ACTIONS["recon_then_exploit"], sorted(set(scan["chunks"]) | {c for e in exploit for c in e["chunks"]}),
                    scan["verified"]))

    # Remaining merged findings
    for (src, typ), m in merged.items():
        if (src, typ) in used or typ == "successful_login":
            continue  # a normal successful login alone is not an attack
        if any(f["source"] == src and set(m["lines"]) <= set(f["evidence_lines"]) for f in findings):
            continue  # already part of an attack-chain finding for this source
        sev = m["severity"]
        if typ == "failed_login":
            if m["count"] < 3:
                continue  # a couple of failed logins is normal user error
            sev = RANK_SEV[max(SEV_RANK[sev], 3 if m["count"] >= config.BRUTE_FORCE_MIN_FAILS else 2)]
        if not m["verified"] and SEV_RANK[sev] > 2:
            sev = "Medium"
        findings.append(_finding(TITLES[typ], sev, src, m["lines"], path,
                                 " ".join(m["reasons"]) or TITLES[typ],
                                 ACTIONS[typ], m["chunks"], m["verified"]))

    findings.sort(key=lambda f: (-SEV_RANK[f["severity"]], -len(f["evidence_lines"])))

    review = final_review(job, findings)
    failed_parts = [c["index"] + 1 for c in job["chunks"] if c["status"] != "done"]
    return {
        "generated": time.time(),
        "model": job.get("model"),
        "summary": review.get("summary") or f"{len(findings)} finding(s).",
        "model_chains": review.get("chains", []),
        "findings": findings,
        "counts": {s: sum(1 for f in findings if f["severity"] == s) for s in SEV_RANK},
        "parts": {"total": len(job["chunks"]), "failed": failed_parts},
        "note": ("Some parts failed; findings for those lines are missing. Use Retry failed parts."
                 if failed_parts else ""),
    }


def post_login_activity(path: Path, src: str, after_line: int, limit: int = 10) -> list[int]:
    """Evidence gathering (not detection): lines after a suspicious login that mention the same source."""
    hits = []
    for n, line in chunker.iter_lines(path):
        if n > after_line and src in line:
            hits.append(n)
            if len(hits) >= limit:
                break
    return hits


def _finding(title, sev, src, lines, path, reason, action, chunks, verified):
    return {"attack_type": title, "severity": sev, "source": src,
            "evidence_lines": lines, "evidence": evidence(path, lines),
            "reason": reason, "suggested_action": action,
            "parts": [c + 1 for c in chunks], "cross_part": len(chunks) > 1,
            "verified_in_log": verified}


def final_review(job: dict, findings: list[dict]) -> dict:
    """One extra model call: overall summary + attack chains, using merged facts only."""
    if not findings:
        return {"summary": "No security findings with supporting evidence were detected.", "chains": []}
    rows, budget = [], config.CTX_LIMIT - config.OUTPUT_RESERVE - config.SAFETY_MARGIN - 250
    for f in findings[:25]:
        ln = f["evidence_lines"]
        row = (f"- {f['severity']} | {f['attack_type']} | {f['source']} | L{ln[0]}..L{ln[-1]} "
               f"({len(ln)} lines, parts {f['parts']}) | {f['reason'][:120]}")
        if llm.count_tokens("\n".join(rows + [row])) > budget:
            break
        rows.append(row)
    try:
        prompt = llm.render_prompt(prompts.FINAL_SYSTEM, prompts.FINAL_USER.format(findings="\n".join(rows)))
        used = llm.count_tokens(prompt)
        raw, timing = llm.complete(prompt, prompts.FINAL_SCHEMA, min(config.OUTPUT_RESERVE, config.CTX_LIMIT - used - 8))
        data, _ = parse_model_json(raw, "chains")
        known = {f["source"] for f in findings}
        chains = [c for c in data.get("chains", []) if isinstance(c, dict) and c.get("source") in known]
        log(job, f"Final review: {used} prompt tokens, {timing['seconds']}s.")
        return {"summary": str(data.get("summary", ""))[:600], "chains": chains}
    except Exception as e:  # noqa: BLE001
        log(job, f"Final review call failed ({e}); report built from merged findings only.")
        return {}


def retry_failed(job: dict) -> None:
    for c in job["chunks"]:
        if c["status"] == "failed":
            c["status"] = "pending"
    job["status"] = "queued"
    save_job(job)
    enqueue(job["id"])
