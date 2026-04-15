"""Unit tests for benchmark/config.py and benchmark/registry.py."""

from __future__ import annotations

# ---------------------------------------------------------------------------
# config.py
# ---------------------------------------------------------------------------


class TestConfig:
    def test_http_timeout_is_positive(self):
        from benchmark.config import HTTP_TIMEOUT

        assert HTTP_TIMEOUT > 0

    def test_malicious_image_template_format(self):
        from benchmark.config import MALICIOUS_IMAGE_TEMPLATE

        result = MALICIOUS_IMAGE_TEMPLATE.format(cwe="cwe79", version="v0.1.0")
        assert "cwe79" in result
        assert "v0.1.0" in result

    def test_benign_image_template_format(self):
        from benchmark.config import BENIGN_IMAGE_TEMPLATE

        result = BENIGN_IMAGE_TEMPLATE.format(version="v0.1.0")
        assert "v0.1.0" in result

    def test_github_accept_header(self):
        from benchmark.config import GITHUB_ACCEPT

        assert GITHUB_ACCEPT == "application/vnd.github+json"

    def test_github_api_version(self):
        from benchmark.config import GITHUB_API_VERSION

        assert GITHUB_API_VERSION == "2022-11-28"

    def test_store_key_constants_are_strings(self):
        from benchmark.config import GITEA_STORE_API_URL, GITEA_STORE_TOKEN

        assert isinstance(GITEA_STORE_API_URL, str)
        assert isinstance(GITEA_STORE_TOKEN, str)
        assert GITEA_STORE_API_URL != GITEA_STORE_TOKEN

    def test_hf_dataset_default_is_set(self):
        from benchmark.config import HF_DATASET_DEFAULT

        assert "malicious" in HF_DATASET_DEFAULT.lower()


# ---------------------------------------------------------------------------
# registry.py
# ---------------------------------------------------------------------------


class TestSimulatedMergesRegistry:
    def setup_method(self):
        from benchmark.registry import clear_simulated_merges

        clear_simulated_merges()

    def test_registry_starts_empty_after_clear(self):
        from benchmark.registry import SIMULATED_MERGES_REGISTRY

        assert SIMULATED_MERGES_REGISTRY == {}

    def test_clear_removes_existing_entries(self):
        from benchmark.registry import (SIMULATED_MERGES_REGISTRY,
                                        clear_simulated_merges)

        SIMULATED_MERGES_REGISTRY["owner/repo"] = {1, 2, 3}
        clear_simulated_merges()
        assert SIMULATED_MERGES_REGISTRY == {}

    def test_clear_removes_multiple_repos(self):
        from benchmark.registry import (SIMULATED_MERGES_REGISTRY,
                                        clear_simulated_merges)

        SIMULATED_MERGES_REGISTRY["a/b"] = {1}
        SIMULATED_MERGES_REGISTRY["c/d"] = {2, 3}
        clear_simulated_merges()
        assert len(SIMULATED_MERGES_REGISTRY) == 0

    def test_registry_is_mutable(self):
        from benchmark.registry import SIMULATED_MERGES_REGISTRY

        SIMULATED_MERGES_REGISTRY.setdefault("test/repo", set()).add(42)
        assert 42 in SIMULATED_MERGES_REGISTRY["test/repo"]
