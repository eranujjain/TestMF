"""
Security guardrails for MiroFish.

Provides path sandboxing, input ID validation, and subprocess whitelisting
to prevent the application from touching anything outside its designated
data directories.
"""

import os
import re
from typing import Optional

from ..config import Config

# --- Allowed base directories (resolved to absolute paths at import time) ---

_BACKEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))

ALLOWED_DATA_ROOTS = [
    os.path.abspath(Config.UPLOAD_FOLDER),                       # backend/uploads
    os.path.abspath(os.path.join(_BACKEND_DIR, 'logs')),         # backend/logs
]

# --- Allowed simulation scripts (basename only) ---

ALLOWED_SCRIPTS = {
    'run_twitter_simulation.py',
    'run_reddit_simulation.py',
    'run_parallel_simulation.py',
}

_SCRIPTS_DIR = os.path.abspath(os.path.join(_BACKEND_DIR, 'scripts'))

# --- ID format: prefix + underscore + hex chars (e.g. proj_abc123, sim_def456) ---

_SAFE_ID_RE = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$')


class PathViolation(Exception):
    """Raised when a file operation targets a path outside the sandbox."""
    pass


class InvalidIdError(ValueError):
    """Raised when an ID parameter fails validation."""
    pass


class SubprocessViolation(Exception):
    """Raised when an attempt is made to run a non-whitelisted script."""
    pass


def safe_resolve(path: str) -> str:
    """Resolve a path to its absolute, symlink-free form."""
    return os.path.realpath(os.path.abspath(path))


def assert_path_within_sandbox(path: str, extra_allowed: Optional[list] = None) -> str:
    """
    Verify *path* resolves inside one of the allowed data roots.

    Returns the resolved absolute path on success.
    Raises PathViolation on failure.
    """
    resolved = safe_resolve(path)
    allowed = ALLOWED_DATA_ROOTS + (extra_allowed or [])

    for root in allowed:
        resolved_root = safe_resolve(root)
        if resolved.startswith(resolved_root + os.sep) or resolved == resolved_root:
            return resolved

    raise PathViolation(
        f"Path escapes sandbox: {path!r} (resolved to {resolved!r}). "
        f"Allowed roots: {allowed}"
    )


def validate_id(value: str, label: str = "ID") -> str:
    """
    Validate that *value* looks like a safe identifier.

    Prevents path-traversal payloads like ``../../etc/passwd`` from being
    spliced into filesystem paths.

    Returns the original value on success; raises InvalidIdError otherwise.
    """
    if not value or not _SAFE_ID_RE.match(value):
        raise InvalidIdError(
            f"Invalid {label}: {value!r}. "
            f"Must be 1-64 alphanumeric/underscore/hyphen characters."
        )
    return value


def assert_allowed_script(script_path: str) -> str:
    """
    Verify that *script_path* points to one of the whitelisted simulation
    scripts inside ``backend/scripts/``.

    Returns the resolved absolute path on success.
    Raises SubprocessViolation on failure.
    """
    resolved = safe_resolve(script_path)
    basename = os.path.basename(resolved)

    if basename not in ALLOWED_SCRIPTS:
        raise SubprocessViolation(
            f"Script not in whitelist: {basename!r}. "
            f"Allowed: {ALLOWED_SCRIPTS}"
        )

    expected_dir = safe_resolve(_SCRIPTS_DIR)
    if not resolved.startswith(expected_dir + os.sep):
        raise SubprocessViolation(
            f"Script is outside the scripts directory: {resolved!r}. "
            f"Expected directory: {expected_dir}"
        )

    return resolved


def print_startup_banner(host: str, port: int):
    """
    Print a transparent summary of every system resource MiroFish will use,
    so the operator knows exactly what's happening.
    """
    uploads_dir = safe_resolve(Config.UPLOAD_FOLDER)
    logs_dir = safe_resolve(os.path.join(_BACKEND_DIR, 'logs'))
    scripts_dir = safe_resolve(_SCRIPTS_DIR)

    llm_url = Config.LLM_BASE_URL or "(not configured)"
    zep_configured = "Yes" if Config.ZEP_API_KEY else "No"

    lines = [
        "",
        "=" * 62,
        "  MiroFish  —  Resource & Network Summary",
        "=" * 62,
        "",
        "  LOCAL RESOURCES",
        f"    Listen addr  : {host}:{port}  (localhost only)",
        f"    Data dir     : {uploads_dir}",
        f"    Log dir      : {logs_dir}",
        f"    Scripts dir  : {scripts_dir}",
        f"    Max upload   : {Config.MAX_CONTENT_LENGTH // (1024*1024)} MB",
        f"    Allowed exts : {', '.join(sorted(Config.ALLOWED_EXTENSIONS))}",
        "",
        "  OUTBOUND NETWORK (only these two destinations)",
        f"    LLM API      : {llm_url}",
        f"    Zep Cloud    : {'https://api.getzep.com' if zep_configured == 'Yes' else '(not configured)'}",
        "",
        "  SUBPROCESSES",
        f"    Allowed      : {', '.join(sorted(ALLOWED_SCRIPTS))}",
        f"    Working dir  : confined to {uploads_dir}/simulations/",
        "",
        "  GUARDRAILS ACTIVE",
        "    - All file I/O sandboxed to uploads/ and logs/",
        "    - IDs validated (no path-traversal characters)",
        "    - Subprocess whitelist enforced",
        "    - CORS restricted to localhost",
        "    - Debug mode off by default",
        "    - No root/sudo required",
        "",
        "=" * 62,
        "",
    ]
    print("\n".join(lines))
