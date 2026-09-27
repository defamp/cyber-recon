"""Shared fixtures."""

import pytest


@pytest.fixture
def sample_hosts():
    return [
        "a.example.com",
        "b.example.com",
        "*.example.com",
        "unrelated.org",
        "foo.bar.example.com",
    ]
