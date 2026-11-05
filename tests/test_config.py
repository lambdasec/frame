"""One config file and one precedence order (frame/config.py): flag > environment > config file
> default for every setting, strict validation of the settings tables, and retired variables
warned about rather than silently ignored."""

from pathlib import Path

import pytest

from frame import config
from frame.sil.llm_client import LLMConfig
from frame.sil.suppressions import ConfigError, find_config, load_config_file

EXAMPLES = Path(__file__).resolve().parent.parent / "examples" / "configs"


def _load(tmp_path, text, name=".frame.toml"):
    p = tmp_path / name
    p.write_text(text)
    cfg = load_config_file(p)
    config.activate(cfg.settings if cfg else None)
    return cfg


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for var in ("FRAME_LLM_BASE_URL", "FRAME_LLM_MODEL", "FRAME_LLM_API_KEY", "FRAME_KB",
                *config.RETIRED):
        monkeypatch.delenv(var, raising=False)


def test_defaults_without_a_file():
    assert config.setting("llm", "max_tokens") == 4096
    assert config.setting("hunt", "scout_steps") == 30
    assert config.setting("kb", "enabled") is True


def test_precedence_flag_env_file_default(tmp_path, monkeypatch):
    _load(tmp_path, '[llm]\nmodel = "file-model"\n')
    assert config.setting("llm", "model") == "file-model"            # file over default
    monkeypatch.setenv("FRAME_LLM_MODEL", "env-model")
    assert config.setting("llm", "model") == "env-model"             # env over file
    assert config.setting("llm", "model", flag="flag-model") == "flag-model"
    config.override("llm", "model", "run-flag")
    assert config.setting("llm", "model") == "run-flag"              # a recorded flag too


def test_file_settings_reach_the_llm_config(tmp_path, monkeypatch):
    monkeypatch.setenv("FRAME_LLM_BASE_URL", "http://localhost:8080/v1/")
    monkeypatch.setenv("MY_KEY", "secret-value")
    _load(tmp_path, '[llm]\nmodel = "m"\nmax_tokens = 900\nstream = true\n'
                    'outage_wait = 3600\napi_key_env = "MY_KEY"\n')
    c = LLMConfig.from_env()
    assert (c.base_url, c.model, c.max_tokens, c.stream, c.outage_wait) == \
        ("http://localhost:8080/v1", "m", 900, True, 3600)
    assert c.api_key == "secret-value" and c.enabled


def test_pyproject_tool_frame_tables(tmp_path):
    _load(tmp_path, '[tool.frame]\nfail_on = "high"\n\n[tool.frame.hunt]\nconcurrency = 3\n',
          name="pyproject.toml")
    assert config.setting("hunt", "concurrency") == 3


def test_engine_and_kb_settings_are_read(tmp_path):
    from frame.kb.store import kb_enabled
    from frame.sil.scanner import is_generated_source
    _load(tmp_path, "[engine]\ngenerated_line_threshold = 10\n\n[kb]\nenabled = false\n")
    assert is_generated_source("x = '" + "a" * 20 + "'\n")
    assert not kb_enabled()


def test_kb_switch_from_the_environment_beats_the_file(tmp_path, monkeypatch):
    from frame.kb.store import kb_enabled
    _load(tmp_path, "[kb]\nenabled = true\n")
    monkeypatch.setenv("FRAME_KB", "off")
    assert not kb_enabled()


@pytest.mark.parametrize("text, message", [
    ('[llm]\nmodle = "m"\n', "unknown key"),
    ("[hunt]\nconcurrency = \"8\"\n", "non-negative integer"),
    ("[llm]\nstream = 1\n", "true or false"),
    ('[llm]\njson_mode = "yaml"\n', "must be one of"),
    ("llm = 3\n", "must be a table"),
])
def test_bad_tables_are_rejected_with_the_file_named(tmp_path, text, message):
    with pytest.raises(ConfigError) as e:
        _load(tmp_path, text)
    assert message in str(e.value) and ".frame.toml" in str(e.value)


def test_retired_variable_is_warned_about_and_not_read(monkeypatch):
    monkeypatch.setenv("FRAME_LLM_MAX_TOKENS", "5")
    monkeypatch.setattr(config, "_warned", set())
    with pytest.warns(config.FrameConfigWarning, match="llm.max_tokens"):
        c = LLMConfig.from_env()
    assert c.max_tokens == 4096


def test_every_retired_variable_names_a_real_key():
    for var, key in config.RETIRED.items():
        if "." in key.split()[0]:
            section, name = key.split(".")
            assert name in config.SCHEMA[section], var


def test_a_command_activates_the_nearest_config(tmp_path):
    from frame.cli import main
    (tmp_path / ".frame.toml").write_text('[hunt]\ntrajectory_dir = "traces"\n')
    (tmp_path / "a.py").write_text("x = 1\n")
    assert main(["inventory", str(tmp_path)]) == 0
    assert config.setting("hunt", "trajectory_dir") == "traces"


def test_a_bad_config_stops_the_command(tmp_path, capsys):
    from frame.cli import main
    (tmp_path / ".frame.toml").write_text("[engine]\naggressive_detectors = 2\n")
    assert main(["inventory", str(tmp_path)]) == 2
    assert "aggressive_detectors" in capsys.readouterr().err


@pytest.mark.parametrize("path", sorted(EXAMPLES.glob("*.toml")), ids=lambda p: p.name)
def test_example_configs_load(path):
    cfg = load_config_file(path)
    assert cfg is not None and cfg.source == str(path)


def test_examples_exist():
    assert {p.name for p in EXAMPLES.glob("*.toml")} >= {"minimal.toml", "ai.toml",
                                                        "dependencies.toml", "hunt.toml"}


def test_find_config_carries_the_settings(tmp_path):
    (tmp_path / ".frame.toml").write_text("[llm]\ntemperature = 0.2\n")
    cfg = find_config(tmp_path)
    assert cfg.settings.values["llm"]["temperature"] == 0.2
