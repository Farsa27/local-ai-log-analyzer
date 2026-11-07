"""Tolerant JSON parsing for model replies (truncated output, code fences, extra text)."""
import json
import re

FENCE = re.compile(r"^```(?:json)?|```$", re.MULTILINE)


def parse_model_json(text: str, list_key: str = "events"):
    """Return (dict, repaired: bool). Never raises; returns ({list_key: []}, True) on total failure."""
    if not isinstance(text, str):
        return {list_key: []}, True
    s = FENCE.sub("", text).strip()
    # drop any <think>...</think> block some models emit
    s = re.sub(r"<think>.*?</think>", "", s, flags=re.DOTALL).strip()
    start = s.find("{")
    if start == -1:
        return {list_key: []}, True
    s = s[start:]

    try:
        obj = json.loads(s)
        if isinstance(obj, dict):
            return obj, False
    except json.JSONDecodeError:
        pass

    # Truncated reply: cut back to the last complete object inside the list and close brackets.
    for cut in _cut_points(s):
        head = s[:cut]
        for tail in ("]}", "}]}", "\"}]}", "]}}"):
            try:
                obj = json.loads(head + tail)
                if isinstance(obj, dict):
                    return obj, True
            except json.JSONDecodeError:
                continue
    return {list_key: []}, True


def _cut_points(s: str):
    """Positions just after each '}' scanning from the end (max 40 tries)."""
    tries = 0
    i = len(s)
    while tries < 40:
        i = s.rfind("}", 0, i)
        if i == -1:
            break
        yield i + 1
        tries += 1
    # also try cutting at the opening of the list (empty list)
    j = s.find("[")
    if j != -1:
        yield j + 1
