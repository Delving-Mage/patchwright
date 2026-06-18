"""Thin Anthropic Messages API client, shared by the discovery + remediation
engines. stdlib-only (urllib) so the core stays dependency-free.

Returns None on any failure (no key, network, bad JSON) so callers degrade
gracefully -- AI discovery is additive; if it's unavailable the OSS scanners
and deterministic fixes still run."""
from __future__ import annotations

import json
import os
import re
import urllib.request

API_URL = "https://api.anthropic.com/v1/messages"
DEFAULT_MODEL = os.environ.get("PW_MODEL", "claude-opus-4-8")


def available() -> bool:
    return bool(os.environ.get("ANTHROPIC_API_KEY"))


def complete(prompt: str, max_tokens: int = 4000,
             model: str | None = None, timeout: int = 120) -> str | None:
    """Single-turn completion -> assistant text, or None on any failure."""
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        return None
    body = json.dumps({
        "model": model or DEFAULT_MODEL,
        "max_tokens": max_tokens,
        "messages": [{"role": "user", "content": prompt}],
    }).encode()
    req = urllib.request.Request(
        API_URL, data=body,
        headers={"content-type": "application/json",
                 "x-api-key": key,
                 "anthropic-version": "2023-06-01"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
    except Exception:
        return None
    return "".join(b.get("text", "") for b in data.get("content", [])
                   if b.get("type") == "text") or None


def complete_json(prompt: str, max_tokens: int = 4000,
                  model: str | None = None):
    """Completion expected to return JSON. Strips ``` fences and parses.
    Returns the parsed object or None."""
    text = complete(prompt, max_tokens=max_tokens, model=model)
    if not text:
        return None
    text = text.strip()
    text = re.sub(r"^```(?:json)?", "", text).strip()
    text = re.sub(r"```$", "", text).strip()
    # tolerate leading prose before the JSON body
    for opener, closer in (("[", "]"), ("{", "}")):
        if opener in text:
            start = text.index(opener)
            end = text.rfind(closer)
            if end > start:
                try:
                    return json.loads(text[start:end + 1])
                except json.JSONDecodeError:
                    break
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None
