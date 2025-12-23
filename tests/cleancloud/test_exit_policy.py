from dataclasses import dataclass

from cleancloud.exit_policy import determine_exit_code


@dataclass
class FakeResult:
    confidence: str


def test_exit_policy_no_issues():
    results = []
    assert determine_exit_code(results) == 0


def test_exit_policy_low_only():
    results = [FakeResult(confidence="Low")]
    assert determine_exit_code(results) == 0


def test_exit_policy_medium_only():
    results = [FakeResult(confidence="Medium")]
    assert determine_exit_code(results) == 0


def test_exit_policy_high_only():
    results = [FakeResult(confidence="High")]
    assert determine_exit_code(results) == 2


def test_exit_policy_mixed_low_medium():
    results = [
        FakeResult(confidence="Low"),
        FakeResult(confidence="Medium"),
    ]
    assert determine_exit_code(results) == 0


def test_exit_policy_mixed_medium_high():
    results = [
        FakeResult(confidence="Medium"),
        FakeResult(confidence="High"),
    ]
    assert determine_exit_code(results) == 2


def test_exit_policy_all_levels():
    results = [
        FakeResult(confidence="Low"),
        FakeResult(confidence="Medium"),
        FakeResult(confidence="High"),
    ]
    assert determine_exit_code(results) == 2
