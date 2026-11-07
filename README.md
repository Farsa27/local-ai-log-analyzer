# Local AI Security Log Analyzer

A web app that finds possible attacks in server logs using a **local language model** (no cloud AI).
The log is larger than the model's 2,048-token context, so the app splits it into parts, analyses
each part with the model, carries facts forward between calls, and merges everything into one report
that links events across the whole file (e.g. failed logins at the start + a successful login at the end).

## Architecture

```
Browser (static/index.html)
   │  upload / start / poll progress / read report
   ▼
FastAPI backend (app/main.py)  ── single worker thread, one model call at a time
   │  app/chunker.py   split log by tokens, keep line numbers, keep multi-line entries together
   │  app/analyzer.py  per-part analysis, carried context, validation, merge, cross-part correlation
   │  app/jsonfix.py   tolerant JSON parsing / repair
   ▼
llama.cpp llama-server (localhost:8080, -c 2048, 2 threads)  ← GGUF model on disk
```

## Setup (works offline after these steps)

1. **Install llama.cpp**
   - Windows/Linux: download a CPU build from https://github.com/ggml-org/llama.cpp/releases and unzip it.
   - macOS: `brew install llama.cpp`
2. **Download a model (GGUF)**: Qwen3.5-2B, Q4_K_M quantisation (~1.3 GB) from Hugging Face,
   saved to `models/`. Qwen3.5-0.8B also works (faster, less accurate).
3. **Start the model server** with the 2,048-token context and the 2-vCPU limit:
   ```
   llama-server -m models/<model>.gguf -c 2048 -t 2 --parallel 1 --port 8080 --jinja
   ```
4. **Start the app** (Windows: or just double-click `start.bat`, which starts both)
   ```
   python -m venv .venv
   .venv\Scripts\activate          # Windows   (macOS/Linux: source .venv/bin/activate)
   pip install -r requirements.txt
   python -m uvicorn app.main:app --port 8000
   ```
5. Open http://127.0.0.1:8000, upload the `.log` / `.txt` file and click **Start analysis**.

Settings can be changed with environment variables (see `app/config.py`), e.g. `LLM_URL`, `CTX_LIMIT`,
`OUTPUT_RESERVE`, `CARRY_BUDGET`, `LLM_TIMEOUT`, `LLM_RETRIES`.

## Model details

| Item | Value |
|---|---|
| Runtime | llama.cpp `llama-server` (CPU only) |
| Model | Qwen3.5-2B (GGUF, Q4_K_M) — swap by restarting llama-server with another `-m` file |
| Context | 2,048 tokens per call (`-c 2048`), `--parallel 1` |
| Threads | 2 (`-t 2`) to match 2 vCPU |
| Output | constrained by a JSON schema (llama.cpp grammar), temperature 0.1 |
| RAM | model ≈ 1.3–1.8 GB + backend ≈ 60–100 MB, well under 4 GB (shown live in the header) |

## Token budget plan (per call, counted with the model's own tokenizer)

| Part of the prompt | Tokens |
|---|---|
| System prompt + chat template + wrapper (measured at start via `/apply-template` + `/tokenize`) | 409 (measured) |
| Carried facts from earlier parts (trimmed to fit) | ≤ 220 |
| Reserved for the model's reply (`n_predict`) | 448 |
| Safety margin | 64 |
| **Log text** | **2048 − the above = 907** |

Before each call the full rendered prompt is counted again; `n_predict` is set to whatever space is left,
so a call can never exceed 2,048 tokens. The actual numbers are shown on the dashboard.

## Measured run (supplied log, Qwen3.5-2B Q4_K_M, 2 threads, CPU only)

| Metric | Value |
|---|---|
| Log | 258 lines, 92 KB raw |
| Tokens after compaction | 13,010 (raw JSON would be ~3.6× more) |
| Parts / model calls | 15 parts + 1 final review |
| Time per call | ~25–30 s |
| RAM | ~2.0 GB total (model ~1.95 GB + backend ~55 MB) of the 4 GB limit |

## Line compaction (fewer tokens, fewer model calls)

JSON log lines are long and mostly noise (request IDs, host names, byte counts, full browser user agents).
Before counting tokens, each JSON line is rewritten into a short form that keeps every security-relevant
field and URL-decodes the path (twice, so double-encoded attacks like `%252e%252e%252f` become `../`):

```
L5: 08:02:30 workspace gateway INFO ip=203.0.113.44 POST /api/v1/auth/login 401 ua=python-requests/2.32.3 username=workspace.admin auth_result=invalid_password
```

This cut the log by ~73% in characters, so the file needs far fewer calls. The original line is still used for the
evidence shown in the report. Non-JSON lines are sent unchanged.

## Log splitting method

1. The upload is streamed to disk in 64 KB pieces (never held fully in RAM).
2. Lines are read one at a time and grouped into **entries**: a line starting with whitespace,
   `at `, `Caused by`, `Traceback`, etc. is attached to the previous line, so stack traces are not cut.
3. Each line is compacted (see above), formatted as `L<original line number>: <text>` and counted with the model tokenizer.
4. Entries are packed into a part until the log budget is full; then a new part starts. A part never cuts
   an entry unless that single entry is larger than a whole part (then it is split at line boundaries).
5. Parts are stored only as line ranges (`start`, `end`). The text is re-read from disk when the part is
   analysed — no extra copies of the log in memory.

## Linking events across parts

* After every call the validated events are saved and merged by **(source, event type)**.
* A compact summary of what is known so far (e.g. `203.0.113.9: failed_login x10 (L50..L59, max Medium)`,
  busiest IPs) is put into the next prompt as **EARLIER CONTEXT**, so the model can link the same source.
* After all parts, correlation rules on the merged data produce chain findings:
  * many `failed_login` + a later `successful_login` from the same source → **Brute force followed by possible
    account compromise (Critical)**, even if the events are in different parts;
  * `scanning` followed by SQLi / traversal / unauthorized access from the same source → **Recon then exploit (High)**.
* One final model call reviews the merged findings and writes a summary + attack chains (only sources that
  really exist in the findings are accepted).

## Accuracy safeguards

* Line numbers returned by the model must belong to the analysed part; others are dropped.
* The cited source (IP/user) must appear in the cited lines (or in the part); otherwise the finding is
  marked "not verified" and cannot be High/Critical.
* One or two failed logins and a normal successful login alone are **not** reported as attacks.
* Log text is wrapped in `<LOG>…</LOG>` and the prompt says it is untrusted data. Output is forced to a JSON
  schema and the app never executes anything from the log, so injected instructions cannot trigger actions.

## Reliability

* Invalid uploads: wrong extension, empty file, binary content, > 10 MB → clear error.
* Model unreachable → start is refused with a message; timeouts / failed calls → retried with backoff
  (`LLM_RETRIES`), then the part is marked **failed** and the other parts continue.
* Broken or truncated JSON → repaired (cut back to the last complete object), never crashes.
* Job state is written atomically to `data/jobs/<id>.json` after every call. After a restart, unfinished jobs
  resume automatically from the next pending part. **Resume / retry failed parts** button re-runs only failed parts.

## Report format

Each finding: `attack_type`, `severity` (Low/Medium/High/Critical), `source` (IP or ID),
`evidence_lines` + evidence text, `reason`, `suggested_action`, `parts`, `cross_part`, `verified_in_log`.
Download as JSON from the dashboard (`/api/jobs/<id>/report`).

## Optional extras implemented

Resume after restart · live RAM use (backend + model server) · per-call timing and token counts ·
model switching (restart llama-server with another GGUF; the model name is shown in the header).

## Known limits

* Small models (0.8B–2B) miss subtle attacks and sometimes mislabel types; the validation step reduces but
  does not remove false positives. Results should be reviewed by a person.
* "Unusual request rate" depends on the model seeing a burst inside one part; there is no timestamp-based
  rate calculation across parts yet.
* Lines longer than 1,500 characters are trimmed.
* Only one analysis runs at a time (by design, to stay within RAM).
* `tests/fake_llm.py` is a test stub that imitates the llama-server API so the pipeline can be tested without a
  model. It is **not** used by the app.
