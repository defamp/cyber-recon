import json
from pathlib import Path

import pytest

from recon.batch import TargetConfig
from recon.cli import run, run_one
from recon.diff import diff_results
from recon.monitor import alert_items, format_alert, latest_snapshot, save_snapshot
from recon.notify import _build_alert_payload


def test_save_snapshot_names_collisions_and_prunes(tmp_path: Path):
    res = {"timestamp": "2026-09-29T10:00:00+00:00"}
    first = save_snapshot(tmp_path, res, keep=0)
    second = save_snapshot(tmp_path, res, keep=0)
    assert first.name == "2026-09-29T10-00-00_00-00_000.json"
    assert second.name == "2026-09-29T10-00-00_00-00_001.json"

    for hour in range(11, 16):
        save_snapshot(tmp_path, {"timestamp": f"2026-09-29T{hour}:00:00+00:00"}, keep=3)
    names = sorted(p.name for p in (tmp_path / "history").glob("*.json"))
    assert names == [
        "2026-09-29T13-00-00_00-00_000.json",
        "2026-09-29T14-00-00_00-00_000.json",
        "2026-09-29T15-00-00_00-00_000.json",
    ]


def test_same_second_snapshots_keep_order(tmp_path: Path):
    for n in range(12):
        save_snapshot(tmp_path, {"timestamp": "2026-09-29T10:00:00", "n": n}, keep=5)
    assert latest_snapshot(tmp_path)["n"] == 11
    kept = sorted(json.loads(p.read_text())["n"] for p in (tmp_path / "history").glob("*.json"))
    assert kept == [7, 8, 9, 10, 11]


def test_latest_snapshot_prefers_history_then_results_json(tmp_path: Path):
    assert latest_snapshot(tmp_path) is None
    (tmp_path / "results.json").write_text(json.dumps({"timestamp": "old"}))
    assert latest_snapshot(tmp_path) == {"timestamp": "old"}
    save_snapshot(tmp_path, {"timestamp": "2026-01-01T00:00:00"})
    assert latest_snapshot(tmp_path) == {"timestamp": "2026-01-01T00:00:00"}


def test_latest_snapshot_skips_corrupt_file(tmp_path: Path):
    (tmp_path / "history").mkdir()
    (tmp_path / "history" / "2026.json").write_text("{not json")
    (tmp_path / "results.json").write_text(json.dumps({"timestamp": "ok"}))
    assert latest_snapshot(tmp_path) == {"timestamp": "ok"}


def _res(**kw):
    base = {
        "subdomains": [],
        "alive": [],
        "urls": [],
        "secrets": [],
        "header_findings": [],
        "nuclei": [],
    }
    base.update(kw)
    return base


def test_alert_items_only_new_and_meaningful():
    baseline = _res(subdomains=["a.x.com", "gone.x.com"])
    current = _res(
        subdomains=["a.x.com", "new.x.com"],
        alive=[{"host": "new.x.com", "url": "https://new.x.com/", "status": 200}],
        urls=["https://x.com/new-page"],  # URLs alone are too noisy to alert on
        header_findings=[
            {"host": "a.x.com", "check": "hsts-missing", "severity": "low", "detail": "d"},
            {"host": "a.x.com", "check": "referrer-policy-missing", "severity": "info"},
        ],
        nuclei=[
            {"template-id": "t1", "matched-at": "https://a.x.com/", "info": {"severity": "high"}},
            {"_warning": "nuclei binary not found in PATH"},
        ],
        cors_reflective={"a.x.com": {"reflects": True}},
    )
    alerts = alert_items(diff_results(baseline, current))
    assert alerts == {
        "subdomains": ["new.x.com"],
        "live hosts": ["https://new.x.com/ [200]"],
        "header issues": ["a.x.com: hsts-missing (low)"],
        "nuclei": ["high: t1 at https://a.x.com/"],
        "CORS reflection": ["a.x.com"],
    }


def test_no_alerts_when_nothing_new():
    same = _res(subdomains=["a.x.com"])
    assert alert_items(diff_results(same, same)) == {}
    # removals are in diff.json but never alerted on
    assert alert_items(diff_results(same, _res())) == {}


def test_diff_tracks_nuclei_per_finding():
    one = {"template-id": "t1", "matched-at": "https://a.x.com/", "host": "a.x.com"}
    two = {"template-id": "t2", "matched-at": "https://a.x.com/", "host": "a.x.com"}
    delta = diff_results(_res(nuclei=[one]), _res(nuclei=[one, two]))
    assert delta["added"]["nuclei"] == [two]
    assert delta["unchanged_counts"]["nuclei"] == 1


def test_format_alert_truncates_long_categories():
    text = format_alert("x.com", {"subdomains": [f"h{i}.x.com" for i in range(15)]}, limit=10)
    assert "*subdomains* (+15)" in text
    assert "h9.x.com" in text and "h10.x.com" not in text
    assert "… and 5 more (see diff.json)" in text


def test_alert_payloads():
    alerts = {"subdomains": [f"{'a' * 150}{i}.x.com" for i in range(40)]}
    discord = _build_alert_payload("x.com", alerts, "discord")
    assert len(discord["content"]) <= 2000
    slack = _build_alert_payload("x.com", {"subdomains": ["a.x.com"]}, "slack")
    assert slack["text"].startswith(":rotating_light: New since last scan of x.com")


class _Scan:
    """Drives run_one with controllable passive results and records webhook calls."""

    def __init__(self, monkeypatch, tmp_path: Path):
        self.subs = ["a.x.com"]
        self.calls: list[tuple[str, object]] = []
        self.out = tmp_path / "x"

        async def fake_subs(domain, errors, **_):
            return list(self.subs)

        async def fake_alert(url, target, alerts, **_):
            self.calls.append(("alert", alerts))
            return True

        async def fake_summary(url, results, **_):
            self.calls.append(("summary", len(results["subdomains"])))
            return True

        monkeypatch.setattr("recon.cli.enumerate_subdomains", fake_subs)
        monkeypatch.setattr("recon.cli.notify_alert", fake_alert)
        monkeypatch.setattr("recon.cli.notify_webhook", fake_summary)

    async def __call__(self, keep=30):
        cfg = TargetConfig(
            domain="x.com",
            output=str(self.out),
            skip=["http", "wayback", "secrets"],
            monitor=True,
        )
        return await run_one(cfg, no_html=True, webhook="https://hooks.example/x", keep=keep)


@pytest.mark.asyncio
async def test_monitor_flow(tmp_path: Path, monkeypatch):
    scan = _Scan(monkeypatch, tmp_path)

    # 1st run: baseline, normal summary notification
    first = await scan()
    assert "changes" not in first
    assert scan.calls == [("summary", 1)]
    assert not (scan.out / "diff.json").exists()

    # 2nd run: nothing new — no notification at all
    second = await scan()
    assert second["changes"]["summary"] == "no changes"
    assert scan.calls == [("summary", 1)]

    # 3rd run: a new subdomain — alert with only the new item
    scan.subs = ["a.x.com", "new.x.com"]
    third = await scan()
    assert scan.calls[-1] == ("alert", {"subdomains": ["new.x.com"]})
    assert third["changes"]["new"] == {"subdomains": 1}
    delta = json.loads((scan.out / "diff.json").read_text())
    assert delta["added"]["subdomains"] == ["new.x.com"]
    saved = json.loads((scan.out / "results.json").read_text())
    assert saved["changes"]["baseline_timestamp"] == second["timestamp"]
    assert len(list((scan.out / "history").glob("*.json"))) == 3


@pytest.mark.asyncio
async def test_monitor_keep_prunes_history(tmp_path: Path, monkeypatch):
    scan = _Scan(monkeypatch, tmp_path)
    for _ in range(4):
        await scan(keep=2)
    assert len(list((scan.out / "history").glob("*.json"))) == 2


@pytest.mark.asyncio
async def test_without_monitor_no_history(tmp_path: Path):
    cfg = TargetConfig(
        domain="x.com", output=str(tmp_path / "x"), skip=["subdomains", "wayback", "http"]
    )
    result = await run_one(cfg, no_html=True)
    assert "changes" not in result
    assert not (tmp_path / "x" / "history").exists()


@pytest.mark.asyncio
async def test_cli_rejects_negative_keep(tmp_path: Path, fake_http):
    from test_integration import _args

    fake = fake_http({})
    assert await run(_args(tmp_path, keep=-1)) == 2
    assert fake.urls == []


def test_batch_config_reads_monitor():
    assert TargetConfig.from_dict({"domain": "a.com", "monitor": True}).monitor is True
    assert TargetConfig.from_dict({"domain": "a.com"}).monitor is False
