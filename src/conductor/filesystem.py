"""Filesystem probes with pre-3.14 ``pathlib`` error semantics.

Python 3.14 rewrote ``pathlib`` so that ``Path.exists()``,
``Path.is_dir()`` and ``Path.is_file()`` delegate to ``os.path`` and
swallow *every* ``OSError`` — including ``PermissionError`` — returning
``False``. On Python 3.13 and earlier those probes re-raised any error
outside a small allowlist (``ENOENT``/``ENOTDIR``/``EBADF``/``ELOOP``,
plus a few Windows error codes), so a permissions problem surfaced
instead of impersonating a missing path.

Conductor's path diagnostics distinguish "does not exist" from "could
not be read", which requires the older semantics on every supported
interpreter; the helpers below provide them. This is a leaf module
(like :mod:`conductor.duration`) with no Conductor imports, so any
package layer can depend on it.
"""

from __future__ import annotations

import errno
import os
import stat
from pathlib import Path

__all__ = ["exists_strict", "is_dir_strict", "is_file_strict", "stat_or_none"]

# The allowlist CPython 3.13's pathlib used to decide which stat()
# failures read as "absent" rather than propagating
# (Lib/pathlib/_abc.py::_ignore_error). Mirrored here so behaviour is
# identical on every interpreter, not just the one that happens to be
# running.
_IGNORED_ERRNOS = frozenset({errno.ENOENT, errno.ENOTDIR, errno.EBADF, errno.ELOOP})

_IGNORED_WINERRORS = frozenset(
    {
        21,  # ERROR_NOT_READY — drive exists but is not accessible
        123,  # ERROR_INVALID_NAME — bpo-35306
        1921,  # ERROR_CANT_RESOLVE_FILENAME — symlink pointing to itself
    }
)


def stat_or_none(path: Path) -> os.stat_result | None:
    """Stat ``path``, returning ``None`` where pathlib would say False.

    Follows symlinks, matching ``Path.exists()`` / ``Path.is_dir()`` /
    ``Path.is_file()``. Failures inside the pre-3.14 pathlib allowlist
    (missing or unresolvable path components) return ``None``; anything
    else — notably ``PermissionError`` — propagates, so an unreadable
    path is never mistaken for an absent one.

    Args:
        path: The path to stat.

    Returns:
        The ``os.stat_result``, or ``None`` when the path reads as
        absent.

    Raises:
        OSError: If the path cannot be inspected for a reason outside
            the allowlist.
    """
    try:
        return path.stat()
    except OSError as exc:
        if exc.errno in _IGNORED_ERRNOS or getattr(exc, "winerror", None) in _IGNORED_WINERRORS:
            return None
        raise
    except ValueError:
        # Non-encodable path — pathlib's probes read this as absent too.
        return None


def exists_strict(path: Path) -> bool:
    """``Path.exists()`` that re-raises permission errors on any Python."""
    return stat_or_none(path) is not None


def is_dir_strict(path: Path) -> bool:
    """``Path.is_dir()`` that re-raises permission errors on any Python."""
    info = stat_or_none(path)
    return info is not None and stat.S_ISDIR(info.st_mode)


def is_file_strict(path: Path) -> bool:
    """``Path.is_file()`` that re-raises permission errors on any Python."""
    info = stat_or_none(path)
    return info is not None and stat.S_ISREG(info.st_mode)
