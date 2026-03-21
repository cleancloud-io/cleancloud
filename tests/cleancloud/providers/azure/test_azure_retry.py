"""
Tests for Azure rule retry logic on transient HTTP errors (429, 500, 503).
"""

from unittest.mock import MagicMock, call, patch

import pytest
from azure.core.exceptions import HttpResponseError

from cleancloud.providers.azure.scan import _run_rule_with_retry


def _make_http_error(status_code: int, retry_after: str = None) -> HttpResponseError:
    error = HttpResponseError()
    error.status_code = status_code
    response = MagicMock()
    response.headers = {"Retry-After": retry_after} if retry_after else {}
    error.response = response
    return error


def _make_rule(side_effects):
    """Rule that raises errors on first N calls then returns findings."""
    mock = MagicMock(side_effect=side_effects)
    mock.__name__ = "mock_rule"
    return mock


@pytest.mark.parametrize("status_code", [429, 500, 503])
def test_retries_on_transient_error_then_succeeds(status_code):
    """Transient errors are retried; success on second attempt returns findings."""
    rule = _make_rule([_make_http_error(status_code), []])

    with patch("cleancloud.providers.azure.scan.time.sleep") as mock_sleep:
        result = _run_rule_with_retry(rule, "sub-1", MagicMock(), None)

    assert result == []
    assert rule.call_count == 2
    mock_sleep.assert_called_once()


def test_retries_exhaust_then_raises():
    """After _MAX_RETRIES attempts all failing, the error is re-raised."""
    rule = _make_rule([_make_http_error(429)] * 3)

    with patch("cleancloud.providers.azure.scan.time.sleep"):
        with pytest.raises(HttpResponseError):
            _run_rule_with_retry(rule, "sub-1", MagicMock(), None)

    assert rule.call_count == 3


def test_non_transient_error_not_retried():
    """404 is not a transient error — raised immediately, no retry."""
    rule = _make_rule([_make_http_error(404)])

    with patch("cleancloud.providers.azure.scan.time.sleep") as mock_sleep:
        with pytest.raises(HttpResponseError):
            _run_rule_with_retry(rule, "sub-1", MagicMock(), None)

    assert rule.call_count == 1
    mock_sleep.assert_not_called()


def test_respects_retry_after_header():
    """Retry-After header value is used as sleep duration."""
    rule = _make_rule([_make_http_error(429, retry_after="10"), []])

    with patch("cleancloud.providers.azure.scan.time.sleep") as mock_sleep:
        _run_rule_with_retry(rule, "sub-1", MagicMock(), None)

    mock_sleep.assert_called_once_with(10)


def test_exponential_backoff_without_retry_after_header():
    """Without Retry-After header, sleep uses exponential backoff (1s, 2s)."""
    rule = _make_rule(
        [
            _make_http_error(429),
            _make_http_error(500),
            [],
        ]
    )

    with patch("cleancloud.providers.azure.scan.time.sleep") as mock_sleep:
        _run_rule_with_retry(rule, "sub-1", MagicMock(), None)

    assert mock_sleep.call_args_list == [call(1), call(2)]


def test_retry_after_capped_at_60_seconds():
    """Retry-After values above 60s are capped to prevent excessive waits."""
    rule = _make_rule([_make_http_error(429, retry_after="120"), []])

    with patch("cleancloud.providers.azure.scan.time.sleep") as mock_sleep:
        _run_rule_with_retry(rule, "sub-1", MagicMock(), None)

    mock_sleep.assert_called_once_with(60)


def test_403_not_retried():
    """403 is a permission error, not transient — should not be retried."""
    rule = _make_rule([_make_http_error(403)])

    with patch("cleancloud.providers.azure.scan.time.sleep") as mock_sleep:
        with pytest.raises(HttpResponseError):
            _run_rule_with_retry(rule, "sub-1", MagicMock(), None)

    assert rule.call_count == 1
    mock_sleep.assert_not_called()
