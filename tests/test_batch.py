import pytest

from recon.batch import TargetConfig, load_batch


def test_target_config_minimal():
    cfg = TargetConfig.from_dict({"domain": "example.com"})
    assert cfg.domain == "example.com"
    assert cfg.output == "output/example.com"
    assert cfg.active is False
    assert cfg.nuclei is False
    assert cfg.skip == []


def test_target_config_full():
    cfg = TargetConfig.from_dict({
        "domain": "foo.com",
        "output": "out/foo",
        "active": True,
        "nuclei": True,
        "skip": ["wayback"],
        "notify": {"webhook": "https://hooks.example/abc"},
    })
    assert cfg.output == "out/foo"
    assert cfg.active is True
    assert cfg.nuclei is True
    assert cfg.skip == ["wayback"]
    assert cfg.notify["webhook"] == "https://hooks.example/abc"


def test_target_config_missing_domain():
    with pytest.raises(ValueError, match="domain"):
        TargetConfig.from_dict({"output": "x"})


def test_load_batch(tmp_path):
    f = tmp_path / "batch.yml"
    f.write_text("""
targets:
  - domain: a.com
    output: out/a
  - domain: b.com
    active: true
""")
    cfgs = load_batch(f)
    assert len(cfgs) == 2
    assert cfgs[0].domain == "a.com"
    assert cfgs[1].active is True


def test_load_batch_no_targets_key(tmp_path):
    f = tmp_path / "bad.yml"
    f.write_text("foo: bar\n")
    with pytest.raises(ValueError, match="targets"):
        load_batch(f)


def test_load_batch_targets_not_list(tmp_path):
    f = tmp_path / "bad.yml"
    f.write_text("targets: 'oops'\n")
    with pytest.raises(ValueError, match="list"):
        load_batch(f)
