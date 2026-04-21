from cleancloud.providers.aws import region_cache


def test_region_cache_scopes_entries_by_include_ai(tmp_path, monkeypatch):
    monkeypatch.setattr(region_cache, "CACHE_PATH", tmp_path / "region_cache.json")

    region_cache.set_cached_regions("123456789012", ["us-east-1"], include_ai=False)
    region_cache.set_cached_regions("123456789012", ["us-west-2"], include_ai=True)

    assert region_cache.get_cached_regions("123456789012", include_ai=False) == ["us-east-1"]
    assert region_cache.get_cached_regions("123456789012", include_ai=True) == ["us-west-2"]
