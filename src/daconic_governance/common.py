"""Strict Python canonical format v1 (not RFC 8785), JSON Pointer utilities."""
import hashlib
import json
import re
from typing import Any


def canonical(value: Any) -> bytes:
    def check(v):
        if v is None or type(v) in (str, int, bool):
            return
        if isinstance(v, list):
            for item in v:
                check(item)
            return
        if isinstance(v, dict) and all(type(k) is str for k in v):
            for item in v.values():
                check(item)
            return
        raise ValueError("Canonical data supports JSON with integers only; no floats or implicit coercion")
    check(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def digest(value):
    return hashlib.sha256(value if isinstance(value, bytes) else canonical(value)).hexdigest()


def pointer_escape(value):
    return str(value).replace("~", "~0").replace("/", "~1")


def flatten(value, path=""):
    if isinstance(value, dict) and value:
        return [pair for k in sorted(value) for pair in flatten(value[k], path + "/" + pointer_escape(k))]
    if isinstance(value, list) and value:
        return [pair for i, v in enumerate(value) for pair in flatten(v, path + "/" + str(i))]
    return [(path, value)]  # Empty containers are committed explicitly.


def get_path(value, path):
    if not path:
        return value
    if not path.startswith("/"):
        raise ValueError("Paths must use JSON Pointer")
    for part in path[1:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        value = value[int(part)] if isinstance(value, list) else value[part]
    return value


def identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", value):
        raise ValueError("Invalid configured identifier")
    return value


class GovernanceError(RuntimeError):
    pass


class EvidenceUnavailable(GovernanceError):
    pass


class Conflict(GovernanceError):
    pass


class OutcomeUnknown(GovernanceError):
    """An attempt may have reached the target. Do not automatically redispatch."""

