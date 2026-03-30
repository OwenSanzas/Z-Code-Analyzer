"""Tests for JoernBackend."""

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from z_code_analyzer.backends.joern_backend import JoernBackend


class TestJoernBackend:
    def test_name(self):
        backend = JoernBackend()
        assert backend.name == "joern"

    def test_supported_languages(self):
        backend = JoernBackend()
        assert "c" in backend.supported_languages
        assert "cpp" in backend.supported_languages

    def test_check_prerequisites_missing(self):
        """When joern-parse is not found, prerequisites should report it."""
        backend = JoernBackend()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1)
            missing = backend.check_prerequisites("/tmp")
            assert len(missing) > 0

    def test_extract_section(self):
        text = "before\nSTART\nhello world\nEND\nafter"
        result = JoernBackend._extract_section(text, "START", "END")
        assert result == "hello world"

    def test_extract_section_missing(self):
        result = JoernBackend._extract_section("no markers", "START", "END")
        assert result is None

    def test_get_descriptor(self):
        backend = JoernBackend()
        desc = backend.get_descriptor()
        assert desc is not None
        assert desc.name == "joern"
        assert desc.precision_score < 1.0  # Joern is less precise than SVF
        assert desc.speed_score > 0.5  # But faster


class TestProjectConfigs:
    def test_get_config_known(self):
        from z_code_analyzer.project_configs import get_config
        cfg = get_config("arrow")
        assert cfg is not None
        assert cfg.preferred_backend == "joern"
        assert "csv_fuzz" in cfg.fuzzer_entry_functions

    def test_get_config_unknown(self):
        from z_code_analyzer.project_configs import get_config
        cfg = get_config("nonexistent_project_xyz")
        assert cfg is None

    def test_get_all_configs(self):
        from z_code_analyzer.project_configs import get_all_configs
        configs = get_all_configs()
        assert len(configs) == 46
        svf_count = sum(1 for c in configs.values() if c.preferred_backend == "svf")
        joern_count = sum(1 for c in configs.values() if c.preferred_backend == "joern")
        assert svf_count == 16
        assert joern_count == 30


class TestAutoBackendSelection:
    def test_resolve_backend_explicit(self):
        from z_code_analyzer.auto_pipeline import AutoAnalysisRequest, AutoPipeline
        pipeline = AutoPipeline.__new__(AutoPipeline)
        req = AutoAnalysisRequest(backend="joern")
        assert pipeline._resolve_backend(req, "anything") == "joern"

    def test_resolve_backend_from_config(self):
        from z_code_analyzer.auto_pipeline import AutoAnalysisRequest, AutoPipeline
        pipeline = AutoPipeline.__new__(AutoPipeline)
        req = AutoAnalysisRequest()
        assert pipeline._resolve_backend(req, "arrow") == "joern"
        assert pipeline._resolve_backend(req, "brotli") == "svf"

    def test_resolve_backend_default(self):
        from z_code_analyzer.auto_pipeline import AutoAnalysisRequest, AutoPipeline
        pipeline = AutoPipeline.__new__(AutoPipeline)
        req = AutoAnalysisRequest()
        # Unknown project defaults to SVF
        assert pipeline._resolve_backend(req, "unknown_project") == "svf"
