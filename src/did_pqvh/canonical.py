"""Canonical JSON helpers for WebVH-like payload signing."""

from __future__ import annotations

import json
from typing import Any


def canonicalize_json(value: Any) -> bytes:
    """Return deterministic UTF-8 bytes for JSON value."""
    # separators remove whitespace; sort_keys enables deterministic ordering.
    text = json.dumps(value, separators=(",", ":"), sort_keys=True, ensure_ascii=False)
    return text.encode("utf-8")
