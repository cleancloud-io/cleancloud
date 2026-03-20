import textwrap

import pytest

from cleancloud.config.accounts import (
    load_accounts_config,
    parse_inline_accounts,
)


def test_load_basic_accounts(tmp_path):
    config_file = tmp_path / "accounts.yaml"
    config_file.write_text(
        textwrap.dedent(
            """\
        role_name: CleanCloudReadOnlyRole
        accounts:
          - id: "111111111111"
            name: prod
          - id: "222222222222"
            name: dev
    """
        )
    )

    config = load_accounts_config(str(config_file))

    assert len(config.accounts) == 2
    assert config.accounts[0].id == "111111111111"
    assert config.accounts[0].name == "prod"
    assert config.accounts[1].id == "222222222222"
    assert config.accounts[1].name == "dev"
    assert config.role_name == "CleanCloudReadOnlyRole"


def test_load_external_id(tmp_path):
    config_file = tmp_path / "accounts.yaml"
    config_file.write_text(
        textwrap.dedent(
            """\
        role_name: CleanCloudReadOnlyRole
        external_id: cleancloud-secret
        accounts:
          - id: "111111111111"
            name: prod
    """
        )
    )

    config = load_accounts_config(str(config_file))

    assert config.external_id == "cleancloud-secret"


def test_load_scan_timeout(tmp_path):
    config_file = tmp_path / "accounts.yaml"
    config_file.write_text(
        textwrap.dedent(
            """\
        scan_timeout: 7200
        accounts:
          - id: "111111111111"
            name: prod
    """
        )
    )

    config = load_accounts_config(str(config_file))

    assert config.scan_timeout == 7200


def test_default_role_name_when_omitted(tmp_path):
    config_file = tmp_path / "accounts.yaml"
    config_file.write_text(
        textwrap.dedent(
            """\
        accounts:
          - id: "111111111111"
            name: prod
    """
        )
    )

    config = load_accounts_config(str(config_file))

    assert config.role_name == "CleanCloudReadOnlyRole"
    assert config.external_id is None
    assert config.scan_timeout == 3600


def test_account_name_defaults_to_id_when_omitted(tmp_path):
    config_file = tmp_path / "accounts.yaml"
    config_file.write_text(
        textwrap.dedent(
            """\
        accounts:
          - id: "111111111111"
    """
        )
    )

    config = load_accounts_config(str(config_file))

    assert config.accounts[0].name == "111111111111"


def test_account_id_coerced_to_string(tmp_path):
    config_file = tmp_path / "accounts.yaml"
    config_file.write_text(
        textwrap.dedent(
            """\
        accounts:
          - id: 111111111111
            name: prod
    """
        )
    )

    config = load_accounts_config(str(config_file))

    assert isinstance(config.accounts[0].id, str)
    assert config.accounts[0].id == "111111111111"


def test_empty_accounts_raises(tmp_path):
    config_file = tmp_path / "accounts.yaml"
    config_file.write_text(
        textwrap.dedent(
            """\
        role_name: CleanCloudReadOnlyRole
        accounts: []
    """
        )
    )

    with pytest.raises(ValueError, match="No accounts found"):
        load_accounts_config(str(config_file))


def test_parse_inline_accounts_basic():
    accounts = parse_inline_accounts("111111111111,222222222222")

    assert len(accounts) == 2
    assert accounts[0].id == "111111111111"
    assert accounts[1].id == "222222222222"


def test_parse_inline_accounts_strips_whitespace():
    accounts = parse_inline_accounts("111111111111 , 222222222222 ")

    assert accounts[0].id == "111111111111"
    assert accounts[1].id == "222222222222"


def test_parse_inline_accounts_single():
    accounts = parse_inline_accounts("111111111111")

    assert len(accounts) == 1
    assert accounts[0].id == "111111111111"


def test_parse_inline_accounts_empty_raises():
    with pytest.raises(ValueError, match="--accounts"):
        parse_inline_accounts("")


def test_parse_inline_accounts_name_equals_id():
    accounts = parse_inline_accounts("111111111111")

    assert accounts[0].name == "111111111111"
