from recon.notify import (
    _build_discord_payload,
    _build_slack_payload,
    parse_webhook_target,
)


def _results():
    return {
        "target": "example.com",
        "subdomains": ["a.example.com", "b.example.com"],
        "alive": [{"host": "a.example.com", "url": "https://a.example.com/", "status": 200}],
        "urls": [],
        "secrets": [
            {
                "url": "https://example.com/app.js",
                "pattern": "aws_access_key",
                "match": "AKIAIOSFODNN7EXAMPLE",
            },
        ],
        "nuclei": [],
    }


def test_slack_payload_has_summary():
    p = _build_slack_payload(_results())
    assert "Recon finished" in p["text"]
    assert "example.com" in p["text"]
    assert len(p["attachments"]) >= 1
    fields = p["attachments"][0]["fields"]
    field_map = {f["title"]: f["value"] for f in fields}
    assert field_map["Subdomains"] == "2"
    assert field_map["Live hosts"] == "1"
    assert field_map["Secrets"] == "1"


def test_slack_payload_includes_secrets_attachment():
    p = _build_slack_payload(_results())
    text_blob = " ".join(a.get("text", "") for a in p["attachments"])
    assert "aws_access_key" in text_blob
    assert "example.com/app.js" in text_blob


def test_slack_payload_color_red_when_secrets():
    p = _build_slack_payload(_results())
    assert p["attachments"][0]["color"] == "#f85149"


def test_slack_payload_color_green_when_no_secrets():
    res = _results()
    res["secrets"] = []
    p = _build_slack_payload(res)
    assert p["attachments"][0]["color"] == "#3fb950"


def test_discord_payload_structure():
    p = _build_discord_payload(_results())
    assert "Recon finished" in p["content"]
    assert "example.com" in p["content"]
    assert len(p["embeds"]) == 1
    assert p["embeds"][0]["color"] == 0xF85149


def test_parse_webhook_with_platform_prefix():
    platform, url = parse_webhook_target("slack:https://hooks.slack.com/x")
    assert platform == "slack"
    assert url == "https://hooks.slack.com/x"


def test_parse_webhook_with_protocol_prefix():
    platform, url = parse_webhook_target("https://hooks.slack.com/x")
    assert platform == "slack"
    assert url == "https://hooks.slack.com/x"


def test_parse_webhook_discord():
    platform, url = parse_webhook_target("discord:https://discord.com/api/webhooks/x")
    assert platform == "discord"
    assert url == "https://discord.com/api/webhooks/x"
