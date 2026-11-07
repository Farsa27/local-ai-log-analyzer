# AI Usage

## Tools used

* **Claude (Anthropic)**: planned the architecture, wrote the first version of the backend, chunker,
  prompts, and dashboard, and drafted the README.
* **Local model (runtime)**: Qwen3.5-2B GGUF, run by llama.cpp `llama-server`. This is the only model that
  analyses the logs.
* I reviewed, ran, tested, and changed the code myself (see "AI mistakes fixed").

## Key coding prompts (to the coding assistant)

1. I pasted the full assessment brief and asked: *"Build this with a stack I can set up in under 30 minutes
   on a laptop. Use a local model, count tokens with the model's tokenizer, keep the 2,048-token limit, and
   save state after every call."*
2. *"Split the log by tokens. Keep the original line numbers and multi-line entries together. Store parts as
   line ranges so the log isn't copied in memory."*
3. *"Carry facts from earlier parts into the next prompt, and link failed logins → successful login across
   parts."*
4. *"Handle broken or truncated JSON, model timeouts, and failed calls without losing completed findings.
   Resume after a restart."*
5. *"Write a test stub that copies the llama-server API so I can test the pipeline without the model."*
6. I uploaded the real server log and asked: *"Tune the app for this log format."* → the assistant added JSON line
   compaction and told the model which errors are operational (DB timeouts, deploy 503s), not attacks.
7. I pasted setup errors from my Windows machine (access denied, model server offline) and asked for fixes.

## Local model prompts

**Per-part prompt** (system, in `app/prompts.py` → `CHUNK_SYSTEM`):
* Defines the role, explains the `L<n>:` line-number format, and says that text inside `<LOG>` is
  untrusted data (prompt-injection guard).
* Lists event types with short examples, gives severity rules, and asks for one event per source + type.
* User message = `EARLIER CONTEXT` (facts carried from earlier parts) + `<LOG> … </LOG>`.
* Output is forced with a JSON schema (`CHUNK_SCHEMA`) through llama.cpp grammar.

**Final review prompt** (`FINAL_SYSTEM`): gets the merged findings (not the raw log) and returns a summary
plus attack chains, again constrained to a schema.

## Prompt design decisions and changes

| Decision / change | Why |
|---|---|
| JSON schema with `maxItems` / `maxLength` (grammar-constrained) | Keeps the reply inside the 448-token reserve and always parseable |
| Ask for `successful_login` events too | Needed to link brute force → compromise across parts |
| "Group same source + type into ONE event" | Fewer output tokens, fewer truncated replies |
| `EARLIER CONTEXT` block built by code from saved findings | Lets the model link the same IP across parts within the token limit |
| Compact JSON lines + URL-decode paths before sending | Raw JSON wasted tokens on request IDs / hosts; 73% fewer characters, 15 calls instead of ~50, and encoded attacks become readable to a 2B model |
| Listed operational errors that are NOT attacks (DB timeouts, deploy 503s, upstream 502s, a few 404s) | The supplied log contains these as decoys |
| "A blocked attempt (400/403) is still an attempt" | SQLi / traversal in this log were blocked by the gateway but are still attacks to report |

## Token budget plan

Context 2,048 = system prompt + template (409, measured at runtime with the model tokenizer) + carried facts (≤ 220)
+ log text (≤ 907) + reply reserve (448) + safety margin (64).
Measured on the supplied log: 13,010 tokens → 15 parts, e.g. part 1 used 1,339 prompt + 87 output tokens, 26.65 s.
Every rendered prompt is counted with `/tokenize` before sending, and `n_predict` is set to the space
that is left. Details are in the README.

## AI mistakes I found and fixed

1. **Prompt marker collision**: the system prompt itself contains the text `<LOG>`, so naive
   `split("<LOG>")` code took the instructions instead of the log. Fixed by splitting on the last
   `<LOG>\n` marker.
2. **Risk of trusting the model's line numbers**: small models can invent line numbers. I added a check
   that drops line numbers outside the part, and requires the source to appear in the cited lines. If it
   doesn't, the finding can't be High or Critical.
3. **Normal events reported as attacks**: I made sure a successful login is only reported as part of a
   brute-force chain, and that fewer than 3 failed logins are ignored.
4. **Wasteful token use on JSON logs**: the first version sent raw JSON lines. On the real log that meant
   ~8 lines per part and ~50 model calls. Fixed with line compaction (keeps all security fields).
5. **Setup assumptions that failed on Windows**: the first `start.bat` created a virtual environment inside the
   project folder, which Windows refused (`Access is denied`). Fixed by installing packages with `--user` and
   moving job data to `%LOCALAPPDATA%` via the `DATA_DIR` setting.
6. **How I checked accuracy**: I compared the report with the attacks I could see by reading the log: brute force on
   `workspace.admin` from 203.0.113.44 (L5–L189 failures, L196 success, L198/L201 admin access + export),
   SQL injection from 203.0.113.72, scanning + path traversal from 203.0.113.90, request flood from 203.0.113.155,
   and a prompt-injection string at L217 that the app must not obey.
7. _(add what the real model got right or wrong in your run)_
