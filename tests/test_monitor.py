"""Tests for the system monitor module."""

import time
from unittest.mock import MagicMock, patch

import pytest

from mitre_gap_analyzer.monitor import SystemMonitor, SystemStats, check_gpu_availability


class TestSystemStats:
    """Tests for SystemStats dataclass."""

    def test_to_dict(self):
        """Test conversion to dictionary."""
        from datetime import datetime

        stats = SystemStats(
            timestamp=datetime.now(),
            gpu_memory_used=4096,
            gpu_memory_total=24000,
            gpu_utilization=45.5,
            gpu_temperature=65.0,
            cpu_percent=30.0,
            cpu_load_avg=(1.0, 1.5, 2.0),
        )

        result = stats.to_dict()

        assert "timestamp" in result
        assert result["gpu_memory_used_mb"] == 4096
        assert result["gpu_memory_total_mb"] == 24000
        assert result["gpu_utilization_percent"] == 45.5
        assert result["gpu_temperature_c"] == 65.0
        assert result["cpu_percent"] == 30.0


class TestSystemMonitor:
    """Tests for SystemMonitor class."""

    def test_init_default_interval(self):
        """Test initialization with default interval."""
        monitor = SystemMonitor()
        assert monitor.interval == 1.0

    def test_init_custom_interval(self):
        """Test initialization with custom interval."""
        monitor = SystemMonitor(interval=2.0)
        assert monitor.interval == 2.0

    @patch("subprocess.run")
    def test_get_gpu_stats_success(self, mock_run):
        """Test successful GPU stats retrieval."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="Tesla P40, 4096, 24000, 17, 45, 65\n",
        )

        monitor = SystemMonitor()
        stats = monitor.get_gpu_stats()

        assert stats["name"] == "Tesla P40"
        assert stats["memory_used"] == 4096
        assert stats["memory_total"] == 24000
        assert stats["temperature"] == 65.0

    @patch("subprocess.run")
    def test_get_gpu_stats_failure(self, mock_run):
        """Test GPU stats retrieval failure."""
        mock_run.side_effect = Exception("nvidia-smi not found")

        monitor = SystemMonitor()
        stats = monitor.get_gpu_stats()

        assert stats["memory_total"] == 24000  # Default P40

    def test_get_cpu_stats(self):
        """Test CPU stats retrieval."""
        monitor = SystemMonitor()
        stats = monitor.get_cpu_stats()

        assert "percent" in stats
        assert "load_avg" in stats
        assert len(stats["load_avg"]) == 3

    def test_get_system_stats(self):
        """Test comprehensive system stats retrieval."""
        monitor = SystemMonitor()
        stats = monitor.get_system_stats()

        assert isinstance(stats, SystemStats)
        assert stats.gpu_memory_total > 0

    def test_start_stop_monitoring(self):
        """Test monitoring start and stop."""
        monitor = SystemMonitor(interval=0.1)

        callback_calls = []

        def callback(stats):
            callback_calls.append(stats)

        thread = monitor.start_monitoring(callback)
        assert thread is not None
        assert thread.is_alive()

        time.sleep(0.3)
        monitor.stop_monitoring()

        assert len(callback_calls) >= 2

    def test_get_stats_history(self):
        """Test stats history collection."""
        monitor = SystemMonitor(interval=0.1)
        monitor.start_monitoring()

        time.sleep(0.3)
        monitor.stop_monitoring()

        history = monitor.get_stats_history()
        assert len(history) >= 2

        limited = monitor.get_stats_history(max_samples=2)
        assert len(limited) == 2

    def test_get_average_stats(self):
        """Test average stats calculation."""
        monitor = SystemMonitor(interval=0.1)
        monitor.start_monitoring()

        time.sleep(0.3)
        monitor.stop_monitoring()

        avg = monitor.get_average_stats(duration_seconds=1.0)
        assert isinstance(avg, SystemStats)


class TestCheckGpuAvailability:
    """Tests for GPU availability check."""

    @patch("subprocess.run")
    def test_gpu_available(self, mock_run):
        """Test when GPU has sufficient memory."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="Tesla P40, 4096, 24000, 17, 45, 65\n",
        )

        result = check_gpu_availability()

        assert "gpu_available" in result
        assert "available_memory_mb" in result
        assert "temperature_ok" in result

    @patch("subprocess.run")
    def test_gpu_unavailable(self, mock_run):
        """Test when GPU memory is low."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="Tesla P40, 23000, 24000, 95, 45, 85\n",
        )

        result = check_gpu_availability()

        assert result["available_memory_mb"] < 2048