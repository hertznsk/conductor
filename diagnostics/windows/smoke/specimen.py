"""Tiny service-only workload used by the supervisor smoke."""

import os

import pytest


@pytest.mark.parametrize("number", (1, 2))
def test_sample(number: int) -> None:
    # Requirement: the diagnostic plugin preserves an ordinary pass or assertion failure.
    should_fail = os.environ.get("DIAG_SMOKE_FAIL") == "1"
    assert not should_fail
