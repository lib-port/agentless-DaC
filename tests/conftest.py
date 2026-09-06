"""Keep core execution tests inside the verified, offline test image."""

import pytest

from detection_goggles.errors import ContractError
from detection_goggles.runtime_guard import require_container


def pytest_configure(config):
    config.addinivalue_line("markers", "container: requires the verified Podman test image")
    config.addinivalue_line("markers", "host_only: verifies refusal outside the worker runtime")


def pytest_collection_modifyitems(items):
    try:
        require_container("test")
        inside = True
    except ContractError:
        inside = False
    for item in items:
        if item.get_closest_marker("container") and not inside:
            item.add_marker(pytest.mark.skip(reason="Run core tests with scripts/container-test"))
        if item.get_closest_marker("host_only") and inside:
            item.add_marker(pytest.mark.skip(reason="This check exercises the host refusal path"))
