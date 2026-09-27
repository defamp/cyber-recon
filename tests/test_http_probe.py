import pytest

from recon.modules.http_probe import _fingerprint_tech


def test_fingerprint_wordpress():
    body = '<html><body><script src="/wp-content/themes/foo.js"></script></body></html>'
    techs = _fingerprint_tech({}, body.lower())
    assert "wordpress" in techs


def test_fingerprint_drupal_settings():
    body = 'drupal.settings = {"path":{"baseUrl":"\\/"},"user":{"uid":0}}'
    techs = _fingerprint_tech({}, body.lower())
    assert "drupal" in techs


def test_fingerprint_django_csrf():
    body = '<input name="csrfmiddlewaretoken" value="abc">'
    techs = _fingerprint_tech({}, body.lower())
    assert "django" in techs


def test_fingerprint_server_header():
    techs = _fingerprint_tech({"Server": "nginx/1.25.1"}, "")
    assert any("nginx" in t for t in techs)


def test_fingerprint_cloudflare():
    techs = _fingerprint_tech({"CF-RAY": "abc123"}, "")
    assert any("cloudflare" in t for t in techs)


def test_fingerprint_empty():
    assert _fingerprint_tech({}, "") == []


def test_fingerprint_dedup():
    body = "wp-content wp-includes"
    techs = _fingerprint_tech({}, body.lower())
    assert techs.count("wordpress") == 1
