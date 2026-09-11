"""Tests for the performance optimizer module."""

from datetime import datetime
from unittest.mock import MagicMock

import pytest

from mitre_gap_analyzer.monitor import SystemStats
from mitre_gap_analyzer.optimizer import (
    OptimizationSuggestion,
    PerformanceOptimizer,
    Priority,
    check_gpu_availability,
)


class TestOptimizationSuggestion:
    """Tests for OptimizationSuggestion dataclass."""

    def test_to_dict(self):
        """Test conversion to dictionary."""
        suggestion = OptimizationSuggestion(
            priority=Priority.HIGH,
            metric="vram",
            current_value=90.0,
            threshold=85.0,
            suggested_action="Reduce batch size",
            impact="medium",
        )

        result = suggestion.to_dict()

        assert result["priority"] == "HIGH"
        assert result["metric"] == "vram"
        assert result["current_value"] == 90.0
        assert result["threshold"] == 85.0


class TestPerformanceOptimizer:
    """Tests for PerformanceOptimizer class."""

    @pytest.fixture
    def mock_monitor(self):
        """Create a mock monitor with predefined stats."""
        monitor = MagicMock()
        monitor.get_system_stats.return_value = SystemStats(
            timestamp=datetime.now(),
            gpu_memory_used=20480,  # 85% of 24000
            gpu_memory_total=24000,
            gpu_utilization=50.0,
            gpu_temperature=70.0,
            cpu_percent=50.0,
            cpu_load_avg=(1.0, 1.5, 2.0),
        )
        return monitor

    def test_init_default_thresholds(self, mock_monitor):
        """Test initialization with default thresholds."""
        optimizer = PerformanceOptimizer(mock_monitor)

        assert "vram" in optimizer.thresholds
        assert "temperature" in optimizer.thresholds
        assert "cpu" in optimizer.thresholds

    def test_init_custom_thresholds(self, mock_monitor):
        """Test initialization with custom thresholds."""
        custom_thresholds = {
            "vram": {"warning": 80.0, "critical": 90.0},
            "temperature": {"warning": 75.0, "critical": 80.0},
            "cpu": {"warning": 85.0, "critical": 95.0},
        }

        optimizer = PerformanceOptimizer(mock_monitor, thresholds=custom_thresholds)

        assert optimizer.thresholds["vram"]["warning"] == 80.0

    def test_evaluate_performance(self, mock_monitor):
        """Test performance evaluation."""
        optimizer = PerformanceOptimizer(mock_monitor)
        result = optimizer.evaluate_performance()

        assert "vram_utilization" in result
        assert "temperature" in result
        assert "cpu_utilization" in result
        assert "status" in result

    def test_suggest_optimizations_vram_warning(self, mock_monitor):
        """Test optimization suggestions for VRAM warning."""
        optimizer = PerformanceOptimizer(mock_monitor)
        optimizer.evaluate_performance()

        suggestions = optimizer.suggest_optimizations()

        # Should have at least one suggestion for 85% VRAM
        vram_suggestions = [s for s in suggestions if s.metric == "vram"]
        assert len(vram_suggestions) > 0

    def test_suggest_optimizations_vram_critical(self):
        """Test optimization suggestions for VRAM critical."""
        monitor = MagicMock()
        monitor.get_system_stats.return_value = SystemStats(
            timestamp=datetime.now(),
            gpu_memory_used=23000,  # 95%+ of 24000
            gpu_memory_total=24000,
            gpu_utilization=95.0,
            gpu_temperature=70.0,
            cpu_percent=50.0,
            cpu_load_avg=(1.0, 1.5, 2.0),
        )

        optimizer = PerformanceOptimizer(monitor)
        optimizer.evaluate_performance()

        suggestions = optimizer.suggest_optimizations()

        critical_vram = [s for s in suggestions if s.metric == "vram" and s.priority == Priority.CRITICAL]
        assert len(critical_vram) > 0

    def test_calculate_optimal_batch_size(self, mock_monitor):
        """Test batch size calculation."""
        optimizer = PerformanceOptimizer(mock_monitor)
        optimizer.evaluate_performance()

        batch_size = optimizer.calculate_optimal_batch_size(base_batch=4096)

        assert batch_size > 0
        assert batch_size <= 4096

    def test_calculate_optimal_batch_size_low_memory(self):
        """Test batch size calculation with low memory."""
        monitor = MagicMock()
        monitor.get_system_stats.return_value = SystemStats(
            timestamp=datetime.now(),
            gpu_memory_used=23500,  # Almost full
            gpu_memory_total=24000,
            gpu_utilization=98.0,
            gpu_temperature=70.0,
            cpu_percent=50.0,
            cpu_load_avg=(1.0, 1.5, 2.0),
        )

        optimizer = PerformanceOptimizer(monitor)
        optimizer.evaluate_performance()

        batch_size = optimizer.calculate_optimal_batch_size(base_batch=4096, min_batch=1)

        assert batch_size >= 1

    def test_calculate_gpu_layers(self, mock_monitor):
        """Test GPU layers calculation."""
        optimizer = PerformanceOptimizer(mock_monitor)
        optimizer.evaluate_performance()

        layers = optimizer.calculate_gpu_layers(max_layers=100)

        assert layers >= 0
        assert layers <= 100

    def test_should_pause_processing_critical(self):
        """Test pause decision with critical conditions."""
        monitor = MagicMock()
        monitor.get_system_stats.return_value = SystemStats(
            timestamp=datetime.now(),
            gpu_memory_used=23500,  # Critical VRAM
            gpu_memory_total=24000,
            gpu_utilization=98.0,
            gpu_temperature=90.0,  # Critical temp
            cpu_percent=50.0,
            cpu_load_avg=(1.0, 1.5, 2.0),
        )

        optimizer = PerformanceOptimizer(monitor)
        optimizer.evaluate_performance()

        assert optimizer.should_pause_processing() is True

    def test_should_pause_processing_ok(self, mock_monitor):
        """Test pause decision with normal conditions."""
        optimizer = PerformanceOptimizer(mock_monitor)
        optimizer.evaluate_performance()

        assert optimizer.should_pause_processing() is False

    def test_get_optimization_report(self, mock_monitor):
        """Test optimization report generation."""
        optimizer = PerformanceOptimizer(mock_monitor)
        optimizer.evaluate_performance()

        report = optimizer.get_optimization_report()

        assert "current_stats" in report
        assert "suggestions" in report
        assert "can_process" in report
        assert "recommended_batch_size" in report
        assert "recommended_gpu_layers" in report

    def test_get_optimization_history(self, mock_monitor):
        """Test optimization history."""
        optimizer = PerformanceOptimizer(mock_monitor)
        optimizer.evaluate_performance()
        optimizer.suggest_optimizations()

        history = optimizer.get_optimization_history()

        assert len(history) > 0


class TestCheckGpuAvailability:
    """Tests for GPU availability check function."""

    def test_returns_required_fields(self):
        """Test that function returns all required fields."""
        # This test uses the actual implementation
        result = check_gpu_availability()

        assert "gpu_available" in result
        assert "available_memory_mb" in result
        assert "temperature_ok" in result
        assert "memory_utilization" in result

    def test_memory_utilization_calculation(self):
        """Test memory utilization is calculated correctly."""
        result = check_gpu_availability()

        assert 0 <= result["memory_utilization"] <= 100