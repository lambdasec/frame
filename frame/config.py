"""Frame's settings: one schema, one precedence order.

Every setting lives in a table of the project's config file (`.frame.toml`, or `[tool.frame]`
in `pyproject.toml`). A setting the environment naturally owns (the model endpoint and key, the
knowledge base's switch, sources and caches) can also come from a `FRAME_*` variable, and some
have a command-line flag. When several are given, the first of these wins:

    command-line flag  >  environment variable  >  config file  >  built-in default

A command loads its config file and makes it active (`activate`); code reads a setting with
`setting(section, key)` (passing the flag's value as `flag=` where there is one). With no file
active, settings come from the environment and the defaults, so the library API and the tests
behave as before.

Variables that used to hold agent and engine knobs are retired: they are not read, and a set one
is warned about with the key that replaces it (`warn_retired`), never silently ignored.
"""

from __future__ import annotations

import os
import warnings
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple


class FrameConfigWarning(UserWarning):
    """A setting Frame no longer reads, or one given in a form it does not use."""


# (type, environment variable or None, default). `type` is bool, int, float, str, or a tuple
# of allowed strings. An int whose default is None may be left unset.
_Spec = Tuple[Any, Optional[str], Any]

SCHEMA: Dict[str, Dict[str, _Spec]] = {
    "llm": {
        "base_url": (str, "FRAME_LLM_BASE_URL", ""),
        "model": (str, "FRAME_LLM_MODEL", ""),
        # The key itself never goes in a file: name the variable that holds it.
        "api_key_env": (str, None, "FRAME_LLM_API_KEY"),
        "temperature": (float, None, 0.0),
        "max_tokens": (int, None, 4096),
        "timeout": (int, None, 60),
        "total_timeout": (int, None, 0),
        "json_mode": (("json_schema", "json_object", "off"), None, "json_schema"),
        "stream": (bool, None, False),
        "stream_stall_timeout": (int, None, 60),
        "outage_wait": (int, None, 0),
        "cache_path": (str, None, ""),
        "context_lines": (int, None, 12),
        "max_context_chars": (int, None, 6000),
        "drop_threshold": (float, None, 0.75),
        "triage_agentic": (bool, None, False),
        "max_tool_steps": (int, None, 30),
        "agent_max_tokens": (int, None, 16000),
        "agent_context_budget_chars": (int, None, 400000),
        "agent_retries": (int, None, 5),
        "exploit_max_steps": (int, None, 250),
        "hunt_max_steps": (int, None, 200),
    },
    "hunt": {
        "max_units": (int, None, None),
        "unit_steps": (int, None, 24),
        "concurrency": (int, None, 8),
        "scout_steps": (int, None, 30),
        "max_scouts": (int, None, 16),
        "coverage_readers": (int, None, 2),
        "trajectory_dir": (str, None, ""),
    },
    "kb": {
        "enabled": (bool, "FRAME_KB", True),
        "source": (str, "FRAME_KB_SOURCE", ""),
        "cache": (str, "FRAME_KB_CACHE", ""),
    },
    "sca": {
        "advisories_source": (str, "FRAME_ADVISORIES_SOURCE", ""),
        "registry_cache": (str, "FRAME_REGISTRY_CACHE", ""),
        "backport_cache": (str, "FRAME_BACKPORT_CACHE", ""),
    },
    "engine": {
        "generated_line_threshold": (int, None, 2000),
        "aggressive_detectors": (bool, None, False),
    },
}

# Variables Frame no longer reads, and the key that replaced each.
RETIRED = {
    "FRAME_LLM_TEMPERATURE": "llm.temperature",
    "FRAME_LLM_MAX_TOKENS": "llm.max_tokens",
    "FRAME_LLM_TIMEOUT": "llm.timeout",
    "FRAME_LLM_TOTAL_TIMEOUT": "llm.total_timeout",
    "FRAME_LLM_JSON_MODE": "llm.json_mode",
    "FRAME_LLM_STREAM": "llm.stream",
    "FRAME_LLM_STREAM_STALL": "llm.stream_stall_timeout",
    "FRAME_LLM_OUTAGE_WAIT": "llm.outage_wait",
    "FRAME_LLM_CACHE": "llm.cache_path",
    "FRAME_LLM_CONTEXT_LINES": "llm.context_lines",
    "FRAME_LLM_MAX_CONTEXT_CHARS": "llm.max_context_chars",
    "FRAME_LLM_DROP_THRESHOLD": "llm.drop_threshold",
    "FRAME_LLM_TRIAGE_AGENTIC": "llm.triage_agentic",
    "FRAME_LLM_MAX_TOOL_STEPS": "llm.max_tool_steps",
    "FRAME_LLM_AGENT_MAX_TOKENS": "llm.agent_max_tokens",
    "FRAME_LLM_AGENT_CONTEXT_BUDGET_CHARS": "llm.agent_context_budget_chars",
    "FRAME_LLM_AGENT_RETRIES": "llm.agent_retries",
    "FRAME_LLM_EXPLOIT_MAX_STEPS": "llm.exploit_max_steps",
    "FRAME_LLM_HUNT_MAX_STEPS": "llm.hunt_max_steps",
    "FRAME_LLM_TRAJECTORY_DIR": "hunt.trajectory_dir",
    "FRAME_LLM_REPO_ROOT": "scan --root",
    "FRAME_GENERATED_LINE_THRESHOLD": "engine.generated_line_threshold",
    "FRAME_AGGRESSIVE_DETECTORS": "engine.aggressive_detectors",
}

_FALSE = ("off", "0", "false", "no")
_TRUE = ("on", "1", "true", "yes")


class SettingsError(ValueError):
    """A config table with an unknown key or a value of the wrong type."""


@dataclass
class Settings:
    """The validated tables of one config file (`values[section][key]`), plus the values a
    command's flags set for this run (`flags`, highest precedence)."""
    values: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    source: Optional[str] = None
    flags: Dict[Tuple[str, str], Any] = field(default_factory=dict)


def _check(section: str, key: str, value: Any, source: str) -> Any:
    kind = SCHEMA[section][key][0]
    where = f"{source}: {section}.{key}"
    if isinstance(kind, tuple):
        if value not in kind:
            raise SettingsError(f"{where} must be one of {list(kind)}")
        return value
    if kind is bool:
        if not isinstance(value, bool):
            raise SettingsError(f"{where} must be true or false")
        return value
    if kind is int:
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise SettingsError(f"{where} must be a non-negative integer")
        return value
    if kind is float:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise SettingsError(f"{where} must be a number")
        return float(value)
    if not isinstance(value, str):
        raise SettingsError(f"{where} must be a string")
    return value


def parse_tables(table: Dict[str, Any], source: str) -> Settings:
    """Validate the setting tables (`[llm]`, `[hunt]`, ...) of a config table. Keys of any
    other table are left to their own loader."""
    out = Settings(source=source)
    for section in SCHEMA:
        raw = table.get(section)
        if raw is None:
            continue
        if not isinstance(raw, dict):
            raise SettingsError(f"{source}: [{section}] must be a table")
        unknown = set(raw) - set(SCHEMA[section])
        if unknown:
            raise SettingsError(f"{source}: [{section}] has unknown key(s) {sorted(unknown)}; "
                                f"expected {sorted(SCHEMA[section])}")
        out.values[section] = {k: _check(section, k, v, source) for k, v in raw.items()}
    return out


_active = Settings()


def activate(settings: Optional[Settings]) -> None:
    """Make a config file's settings the ones `setting` reads (None: no file)."""
    global _active
    _active = settings or Settings()


def active() -> Settings:
    return _active


def override(section: str, key: str, value: Any) -> None:
    """Record a command-line flag's value for this run (ignored when None)."""
    if key not in SCHEMA.get(section, {}):
        raise KeyError(f"{section}.{key}")
    if value is not None:
        _active.flags[(section, key)] = value


def _from_env(section: str, key: str) -> Any:
    kind, env, _ = SCHEMA[section][key]
    raw = os.environ.get(env) if env else None
    if raw is None or raw == "":
        return None
    if kind is bool:
        low = raw.strip().lower()
        if low in _FALSE:
            return False
        if low in _TRUE:
            return True
        return None
    return raw


def setting(section: str, key: str, flag: Any = None) -> Any:
    """The setting's value: the flag's (`flag`, or one recorded with `override`), else its
    environment variable's, else the active config file's, else the default."""
    if key not in SCHEMA.get(section, {}):
        raise KeyError(f"{section}.{key}")
    if flag is not None:
        return flag
    if (section, key) in _active.flags:
        return _active.flags[(section, key)]
    env = _from_env(section, key)
    if env is not None:
        return env
    file_value = _active.values.get(section, {}).get(key)
    if file_value is not None:
        return file_value
    return SCHEMA[section][key][2]


def section(name: str) -> Dict[str, Any]:
    """Every key of a section, resolved."""
    return {k: setting(name, k) for k in SCHEMA[name]}


_warned: set = set()


def retired_messages() -> list:
    """One message per retired variable that is set and not yet reported."""
    out = []
    for var, key in RETIRED.items():
        if os.environ.get(var) is not None and var not in _warned:
            _warned.add(var)
            where = (f"set {key} in .frame.toml (or [tool.frame])" if "." in key.split()[0]
                     else f"use {key}")
            out.append(f"{var} is no longer read; {where} instead")
    return out


def warn_retired() -> None:
    """Warn (FrameConfigWarning), once per variable, about every retired variable that is set.
    The command line prints `retired_messages()` itself."""
    for message in retired_messages():
        warnings.warn(message, FrameConfigWarning, stacklevel=2)
