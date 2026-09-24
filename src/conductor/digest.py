"""Canonical JSON digests for Conductor content addressing.

This module provides :func:`canonical_json_digest`, the single definition of
how Conductor turns a JSON-shaped payload into a content digest. A digest
depends on the payload's data alone — never on key insertion order, on
formatting choices, or on the machine that computed it.

Canonical form: JSON with sorted keys and tight separators, encoded as
UTF-8 (``ensure_ascii=True``, so the byte stream is identical on every
host), digested with SHA-256 and spelled ``sha256:<hex>`` — matching the
workflow-hash convention in ``engine.run_manifest``.

A stdlib-only leaf (like ``duration.py``, ``console.py``,
``filesystem.py``) with no Conductor imports, so ``config/`` and the
``bundle/`` package can depend on it without an import cycle.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any

__all__ = ["canonical_json_digest"]


def canonical_json_digest(payload: Mapping[str, Any]) -> str:
    """Digest a JSON-shaped mapping in canonical form.

    Canonicalization: ``json.dumps(payload, sort_keys=True,
    separators=(",", ":"), ensure_ascii=True)`` → UTF-8 →
    ``"sha256:" + hexdigest``. Two payloads with equal data therefore
    digest identically regardless of insertion order or host.

    Args:
        payload: The JSON-object-shaped mapping to digest. Callers pass
            plain data (``model_dump(mode="json")`` output, literals) —
            anything ``json.dumps`` with default handling serializes.

    Returns:
        The digest, spelled ``sha256:<hex>``.
    """
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return f"sha256:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"
