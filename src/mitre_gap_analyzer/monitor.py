"""System monitoring module for GPU/CPU metrics."""

import json
import logging
import subprocess
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class SystemStats:
    """Container for system performance metrics."""

    timestamp: datetime
    gpu_memory_used: int
    gpu_memory_total: int
    gpu_utilization: float
    gpu_temperature: float
    cpu_percent: float
    cpu_load_avg: Tuple[float, float, float]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "gpu_memory_used_mb": self.gpu_memory_used,
            "gpu_memory_total_mb": self.gpu_memory_total,
            "gpu_utilization_percent": round(self.gpu_utilization, 2),
            "gpu_temperature_c": round(self.gpu_temperature, 1),
            "cpu_percent": round(self.cpu_percent, 2),
            "cpu_load_avg_1m": round(self.cpu_load_avg[0], 2),
            "cpu_load_avg_5m": round(self.cpu_load_avg[1], 2),
            "cpu_load_avg_15m": round(self.cpu_load_avg[2], 2),
        }


class SystemMonitor:
    """Monitors system resources including GPU and CPU metrics."""

    def __init__(self, interval: float = 1.0):
        """
        Initialize the system monitor.

        Args:
            interval: Sampling interval in seconds (default: 1.0)
        """
        self.interval = interval
        self._monitoring = False
        self._monitor_thread: Optional[threading.Thread] = None
        self._stats_history: List[SystemStats] = []
        self._callback: Optional[Callable[[SystemStats], None]] = None

    def get_gpu_stats(self) -> Dict[str, Any]:
        """
        Get GPU statistics using nvidia-smi.

        Returns:
            Dictionary with GPU memory, utilization, and temperature.
        """
        try:
            result = subprocess.run(
                [
                    "nvidia-smi",
                    "--query-gpu=name,memory.used,memory.total,memory.util,gpu.util,temperature.gpu",
                    "--format=csv,noheader,nounits",
                ],
                capture_output=True,
                text=True,
                timeout=5,
            )

            if result.returncode != 0:
                logger.warning(f"nvidia-smi failed: {result.stderr}")
                return self._get_default_gpu_stats()

            lines = result.stdout.strip().split("\n")
            if not lines:
                return self._get_default_gpu_stats()

            # Parse first GPU (P40 is cuda:0)
            parts = lines[0].split(",")
            if len(parts) >= 6:
                return {
                    "name": parts[0].strip(),
                    "memory_used": int(parts[1].strip()),
                    "memory_total": int(parts[2].strip()),
                    "memory_util": float(parts[3].strip()),
                    "utilization": float(parts[4].strip()),
                    "temperature": float(parts[5].strip()),
                }

            return self._get_default_gpu_stats()

        except (subprocess.TimeoutExpired, subprocess.SubprocessError, ValueError, Exception) as e:
            logger.warning(f"Error getting GPU stats: {e}")
            return self._get_default_gpu_stats()

    def _get_default_gpu_stats(self) -> Dict[str, Any]:
        """Return default GPU stats when nvidia-smi fails."""
        return {
            "name": "unknown",
            "memory_used": 0,
            "memory_total": 24000,  # Default P40
            "memory_util": 0.0,
            "utilization": 0.0,
            "temperature": 0.0,
        }

    def get_cpu_stats(self) -> Dict[str, Any]:
        """
        Get CPU statistics.

        Returns:
            Dictionary with CPU usage and load average.
        """
        try:
            # Get CPU usage
            with open("/proc/stat", "r") as f:
                line = f.readline()
                parts = line.split()
                if len(parts) >= 5:
                    user, nice, system, idle, iowait = map(int, parts[1:6])
                    total = user + nice + system + idle + iowait
                    usage = ((total - idle) / total * 100) if total > 0 else 0.0
                else:
                    usage = 0.0

            # Get load average
            try:
                with open("/proc/loadavg", "r") as f:
                    parts = f.read().split()
                    load_avg = (float(parts[0]), float(parts[1]), float(parts[2]))
            except (FileNotFoundError, ValueError, IndexError):
                load_avg = (0.0, 0.0, 0.0)

            return {
                "percent": usage,
                "load_avg": load_avg,
            }

        except Exception as e:
            logger.warning(f"Error getting CPU stats: {e}")
            return {"percent": 0.0, "load_avg": (0.0, 0.0, 0.0)}

    def get_system_stats(self) -> SystemStats:
        """
        Get comprehensive system statistics.

        Returns:
            SystemStats dataclass with all metrics.
        """
        gpu = self.get_gpu_stats()
        cpu = self.get_cpu_stats()

        return SystemStats(
            timestamp=datetime.now(),
            gpu_memory_used=gpu["memory_used"],
            gpu_memory_total=gpu["memory_total"],
            gpu_utilization=gpu["utilization"],
            gpu_temperature=gpu["temperature"],
            cpu_percent=cpu["percent"],
            cpu_load_avg=cpu["load_avg"],
        )

    def start_monitoring(
        self, callback: Optional[Callable[[SystemStats], None]] = None
    ) -> threading.Thread:
        """
        Start continuous monitoring in a background thread.

        Args:
            callback: Optional callback function called with each stats sample.

        Returns:
            The monitoring thread.
        """
        if self._monitoring:
            logger.warning("Monitoring already running")
            return self._monitor_thread

        self._callback = callback
        self._monitoring = True
        self._stats_history = []

        def monitor_loop():
            while self._monitoring:
                stats = self.get_system_stats()
                self._stats_history.append(stats)

                if self._callback:
                    try:
                        self._callback(stats)
                    except Exception as e:
                        logger.error(f"Callback error: {e}")

                time.sleep(self.interval)

        self._monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        self._monitor_thread.start()
        logger.info(f"Started monitoring with {self.interval}s interval")

        return self._monitor_thread

    def stop_monitoring(self) -> None:
        """Stop the monitoring thread."""
        self._monitoring = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=2.0)
        logger.info("Stopped monitoring")

    def get_stats_history(self, max_samples: Optional[int] = None) -> List[SystemStats]:
        """
        Get collected statistics history.

        Args:
            max_samples: Maximum number of samples to return (None = all).

        Returns:
            List of SystemStats objects.
        """
        if max_samples is None:
            return self._stats_history
        return self._stats_history[-max_samples:]

    def get_average_stats(self, duration_seconds: float = 10.0) -> SystemStats:
        """
        Get average statistics over a duration.

        Args:
            duration_seconds: Duration to average over.

        Returns:
            Average SystemStats over the period.
        """
        relevant_stats = [
            s
            for s in self._stats_history
            if (datetime.now() - s.timestamp).total_seconds() <= duration_seconds
        ]

        if not relevant_stats:
            return self.get_system_stats()

        avg_gpu_mem = sum(s.gpu_memory_used for s in relevant_stats) / len(relevant_stats)
        avg_gpu_util = sum(s.gpu_utilization for s in relevant_stats) / len(relevant_stats)
        avg_gpu_temp = sum(s.gpu_temperature for s in relevant_stats) / len(relevant_stats)
        avg_cpu = sum(s.cpu_percent for s in relevant_stats) / len(relevant_stats)
        avg_load = tuple(
            sum(s.cpu_load_avg[i] for s in relevant_stats) / len(relevant_stats)
            for i in range(3)
        )

        return SystemStats(
            timestamp=datetime.now(),
            gpu_memory_used=int(avg_gpu_mem),
            gpu_memory_total=relevant_stats[0].gpu_memory_total,
            gpu_utilization=avg_gpu_util,
            gpu_temperature=avg_gpu_temp,
            cpu_percent=avg_cpu,
            cpu_load_avg=avg_load,
        )


def check_gpu_availability() -> Dict[str, Any]:
    """
    Check GPU availability for heavy tasks.

    Returns:
        Dictionary with GPU status and available memory.
    """
    monitor = SystemMonitor()
    stats = monitor.get_system_stats()

    available_memory = stats.gpu_memory_total - stats.gpu_memory_used

    return {
        "gpu_available": available_memory > 2048,  # At least 2GB free
        "available_memory_mb": available_memory,
        "temperature_ok": stats.gpu_temperature < 85,
        "memory_utilization": (
            stats.gpu_memory_used / stats.gpu_memory_total * 100
            if stats.gpu_memory_total > 0
            else 0
        ),
    }