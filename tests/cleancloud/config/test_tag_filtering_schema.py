from cleancloud.config.schema import load_config


def test_tag_filtering_config_loaded():
    raw = {
        "version": 1,
        "tag_filtering": {
            "enabled": True,
            "ignore": [
                {"key": "env", "value": "production"},
                {"key": "team"},
            ],
        },
    }

    cfg = load_config(raw)

    assert cfg.tag_filtering.enabled is True
    assert len(cfg.tag_filtering.ignore) == 2
    assert cfg.tag_filtering.ignore[0].key == "env"
    assert cfg.tag_filtering.ignore[0].value == "production"
    assert cfg.tag_filtering.ignore[1].key == "team"
    assert cfg.tag_filtering.ignore[1].value is None


def test_tag_filtering_optional():
    raw = {"version": 1}

    cfg = load_config(raw)

    assert cfg.tag_filtering is None
