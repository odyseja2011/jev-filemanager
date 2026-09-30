import copy

import pytest

from migrator.config import ConfigError, normalize_and_validate, parse_config_text
from tests.helpers import base_config


def cfg(tmp_path, **kw):
    return base_config(tmp_path, **kw)


def problems(raw):
    with pytest.raises(ConfigError) as ei:
        normalize_and_validate(raw)
    return "\n".join(ei.value.problems)


def test_valid_config_normalizes_and_hash_is_stable(tmp_path):
    a = normalize_and_validate(cfg(tmp_path))
    b = normalize_and_validate(copy.deepcopy(cfg(tmp_path)))
    assert a.sha256() == b.sha256()
    assert a.model == "typesafe/jev-1.13"
    assert a.threshold == 0.90
    assert [t.id for t in a.targets] == ["MOVIES", "SERIES", "MUSIC", "BOOKS"]
    changed = cfg(tmp_path, routing={"confidence_threshold": 0.8})
    assert normalize_and_validate(changed).sha256() != a.sha256()


def test_key_order_does_not_change_hash(tmp_path):
    raw = cfg(tmp_path)
    reordered = dict(reversed(list(raw.items())))
    assert normalize_and_validate(raw).sha256() == normalize_and_validate(reordered).sha256()


def test_relative_source_rejected(tmp_path):
    raw = cfg(tmp_path)
    raw["scope"]["sources"][0]["path"] = "relative/dir"
    assert "source media: path must be absolute" in problems(raw)


def test_relative_target_rejected(tmp_path):
    raw = cfg(tmp_path)
    raw["scope"]["targets"][0]["path"] = "MOVIES"
    assert "target MOVIES: path must be absolute" in problems(raw)


def test_duplicate_ids_and_paths(tmp_path):
    raw = cfg(tmp_path)
    raw["scope"]["sources"].append(dict(raw["scope"]["sources"][0]))
    raw["scope"]["targets"].append(dict(raw["scope"]["targets"][0]))
    p = problems(raw)
    assert "duplicate source id: media" in p
    assert "duplicate target id: MOVIES" in p
    assert "duplicate destination path" in p


def test_overlapping_sources_rejected_unless_allowed(tmp_path):
    raw = cfg(tmp_path)
    raw["scope"]["sources"].append({"id": "inner", "path": str(tmp_path / "MEDIA" / "inner")})
    assert "source roots overlap" in problems(raw)
    raw["scope"]["allow_overlapping_sources"] = True
    normalize_and_validate(raw)


def test_target_inside_source_rejected_unless_allowed(tmp_path):
    raw = cfg(tmp_path)
    raw["scope"]["targets"][0]["path"] = str(tmp_path / "MEDIA" / "MOVIES")
    assert "nested inside source" in problems(raw)
    raw["scope"]["allow_targets_in_sources"] = True
    normalize_and_validate(raw)


@pytest.mark.parametrize("value", [0, -0.1, 1.5, "high", True, None])
def test_invalid_threshold(tmp_path, value):
    assert "confidence_threshold" in problems(cfg(tmp_path, routing={"confidence_threshold": value}))


@pytest.mark.parametrize("value", [0, -1, 1.5, "x"])
def test_invalid_batch_size(tmp_path, value):
    assert "batches.max_operations" in problems(cfg(tmp_path, batches={"max_operations": value}))


def test_unsupported_checksum_algorithm(tmp_path):
    assert "unsupported checksum algorithm" in problems(
        cfg(tmp_path, inventory={"checksum": {"algorithm": "md5"}}))


def test_missing_target_description(tmp_path):
    raw = cfg(tmp_path)
    raw["scope"]["targets"][1]["description"] = "  "
    assert "target SERIES: description is required" in problems(raw)


def test_reserved_target_id(tmp_path):
    raw = cfg(tmp_path)
    raw["scope"]["targets"][0]["id"] = "DESCEND"
    assert "reserved" in problems(raw)


def test_workspace_must_not_overlap_roots(tmp_path):
    raw = cfg(tmp_path)
    raw["workspace"]["path"] = str(tmp_path / "MEDIA" / "ws")
    assert "workspace overlaps" in problems(raw)


def test_unknown_keys_and_unsafe_flags_rejected(tmp_path):
    assert "unknown configuration key" in problems(cfg(tmp_path, bogus={}))
    assert "NO OVERWRITE" in problems(cfg(tmp_path, batches={"overwrite_existing_targets": True}))
    assert "copy_verify_delete" in problems(cfg(tmp_path, batches={"copy_verify_delete": False}))
    assert "preserve_source_acl" in problems(cfg(tmp_path, permissions={"preserve_source_acl": True}))


def test_yaml_parse_error():
    with pytest.raises(ConfigError):
        parse_config_text("a: [unclosed")


def test_secrets_are_env_names_only(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-secret-value")
    assert "sk-secret-value" not in normalize_and_validate(cfg(tmp_path)).canonical()
