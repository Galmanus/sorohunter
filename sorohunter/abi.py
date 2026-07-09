"""Parse a Soroban contract spec (`stellar contract info interface --output json`)
into a probe plan.

The spec is an array of SCSpecEntry. We keep `function_v0` entries. Each input's
`type_` is either a bare string (primitive) or a one-key object (composite). v1
can synthesize test args for primitives, address, and fixed bytes; anything else
(custom structs/enums, vec/map/tuple/option) is flagged, so a function is skipped
with a stated reason rather than probed with a bogus arg.
"""
from __future__ import annotations

from typing import Any

# Primitives for which the Rust harness has a default Val.
_PRIMITIVES = {
    "address", "u32", "u64", "u128", "i32", "i64", "i128",
    "bool", "symbol", "string", "bytes", "void",
}


def type_name(type_spec: Any) -> str:
    """Canonical label for a type: 'address', 'bytes_n:32', 'udt:Name', 'vec<...>'."""
    if isinstance(type_spec, str):
        return type_spec
    if isinstance(type_spec, dict) and type_spec:
        key = next(iter(type_spec))
        body = type_spec[key]
        if key == "bytes_n":
            return f"bytes_n:{body.get('n')}"
        if key == "udt":
            return f"udt:{body.get('name')}"
        if key == "vec":
            inner = body.get("element_type")
            return f"vec<{type_name(inner)}>" if inner is not None else "vec"
        return key
    return "unknown"


def synthesizable(type_spec: Any) -> bool:
    """Whether v1 can build a default test value for this type."""
    if isinstance(type_spec, str):
        return type_spec in _PRIMITIVES
    if isinstance(type_spec, dict):
        return next(iter(type_spec)) == "bytes_n"
    return False


def parse_spec(entries: list[dict]) -> list[dict]:
    """Return the probe plan: one entry per exported function."""
    plan: list[dict] = []
    for entry in entries:
        fn = entry.get("function_v0")
        if not fn:
            continue
        raw_types = [inp.get("type_") for inp in fn.get("inputs", [])]
        inputs = [type_name(t) for t in raw_types]
        unsynth = [type_name(t) for t in raw_types if not synthesizable(t)]
        plan.append({
            "name": fn["name"],
            "inputs": inputs,
            "synthesizable": len(unsynth) == 0,
            "skip_reason": None if not unsynth else "unsynthesizable args: " + ", ".join(unsynth),
        })
    return plan
