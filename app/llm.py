"""Thin client for a local llama.cpp `llama-server`.

Uses three endpoints:
  /apply-template  -> render chat messages with the model's own chat template
  /tokenize        -> count tokens with the model's own tokenizer
  /completion      -> generate, constrained by a JSON schema (grammar)
Only the standard library is used, so there is no hidden cloud dependency.
"""
import json
import time
import urllib.error
import urllib.request

from . import config


class LLMError(Exception):
    pass


def _post(path: str, payload: dict, timeout: float) -> dict:
    req = urllib.request.Request(
        config.LLM_URL + path,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, ConnectionError, json.JSONDecodeError) as e:
        raise LLMError(f"{path}: {e}") from e


def health() -> dict:
    try:
        with urllib.request.urlopen(config.LLM_URL + "/health", timeout=5) as r:
            return {"ok": True, "status": json.loads(r.read().decode() or "{}")}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)}


def model_name() -> str:
    try:
        with urllib.request.urlopen(config.LLM_URL + "/props", timeout=5) as r:
            props = json.loads(r.read().decode())
        path = props.get("model_path") or props.get("default_generation_settings", {}).get("model", "")
        return str(path).replace("\\", "/").split("/")[-1] or "unknown"
    except Exception:  # noqa: BLE001
        return "unknown"


def count_tokens(text: str) -> int:
    if not text:
        return 0
    res = _post("/tokenize", {"content": text, "add_special": False}, 30)
    return len(res.get("tokens", []))


def render_prompt(system: str, user: str) -> str:
    """Render with the model's chat template so token counts are exact."""
    res = _post("/apply-template", {"messages": [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]}, 30)
    prompt = res.get("prompt")
    if not prompt:
        raise LLMError("apply-template returned no prompt")
    return prompt


def complete(prompt: str, schema: dict, n_predict: int) -> tuple[str, dict]:
    """One generation call with retry + backoff. Returns (text, timing info)."""
    last_err = None
    for attempt in range(config.LLM_RETRIES + 1):
        t0 = time.time()
        try:
            res = _post("/completion", {
                "prompt": prompt,
                "n_predict": n_predict,
                "temperature": 0.1,
                "top_k": 20,
                "json_schema": schema,       # grammar-constrained JSON output
                "cache_prompt": False,
                "stream": False,
            }, config.LLM_TIMEOUT)
            info = {
                "seconds": round(time.time() - t0, 2),
                "prompt_tokens": res.get("tokens_evaluated"),
                "output_tokens": res.get("tokens_predicted"),
                "truncated": bool(res.get("truncated")) or res.get("stop_type") == "limit",
                "attempt": attempt + 1,
            }
            return res.get("content", ""), info
        except LLMError as e:
            last_err = e
            time.sleep(min(2 ** attempt, 8))
    raise LLMError(f"model call failed after {config.LLM_RETRIES + 1} attempts: {last_err}")
