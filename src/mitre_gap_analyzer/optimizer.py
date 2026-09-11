"""Performance optimizer for dynamic parameter tuning."""

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

from .monitor import SystemMonitor, SystemStats

logger = logging.getLogger(__name__)


class Priority(Enum):
    """Priority levels for optimization suggestions."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class OptimizationSuggestion:
    """Represents an optimization suggestion."""

    priority: Priority
    metric: str
    current_value: float
    threshold: float
    suggested_action: str
    impact: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "priority": self.priority.value,
            "metric": self.metric,
            "current_value": self.current_value,
            "threshold": self.threshold,
            "suggested_action": self.suggested_action,
            "impact": self.impact,
        }


class PerformanceOptimizer:
    """Optimizes system performance based on real-time metrics."""

    def __init__(
        self,
        monitor: SystemMonitor,
        thresholds: Optional[Dict[str, Dict[str, float]]] = None,
    ):
        """
        Initialize the optimizer.

        Args:
            monitor: SystemMonitor instance for collecting metrics.
            thresholds: Optional custom thresholds. Defaults are used if not provided.
        """
        self.monitor = monitor

        # Default thresholds
        self.thresholds = thresholds or {
            "vram": {"warning": 85.0, "critical": 95.0},
            "temperature": {"warning": 80.0, "critical": 85.0},
            "cpu": {"warning": 90.0, "critical": 95.0},
        }

        self._last_stats: Optional[SystemStats] = None
        self._optimization_history: List[OptimizationSuggestion] = []

    def evaluate_performance(self) -> Dict[str, Any]:
        """
        Evaluate current system performance state.

        Returns:
            Dictionary with performance metrics and status.
        """
        stats = self.monitor.get_system_stats()
        self._last_stats = stats

        vram_util = (
            stats.gpu_memory_used / stats.gpu_memory_total * 100
            if stats.gpu_memory_total > 0
            else 0
        )

        return {
            "timestamp": stats.timestamp.isoformat(),
            "vram_utilization": round(vram_util, 2),
            "temperature": stats.gpu_temperature,
            "cpu_utilization": stats.cpu_percent,
            "status": self._get_status(vram_util, stats.gpu_temperature, stats.cpu_percent),
        }

    def _get_status(
        self, vram_util: float, temperature: float, cpu_util: float
    ) -> str:
        """Determine overall system status."""
        if (
            vram_util >= self.thresholds["vram"]["critical"]
            or temperature >= self.thresholds["temperature"]["critical"]
            or cpu_util >= self.thresholds["cpu"]["critical"]
        ):
            return "CRITICAL"
        elif (
            vram_util >= self.thresholds["vram"]["warning"]
            or temperature >= self.thresholds["temperature"]["warning"]
            or cpu_util >= self.thresholds["cpu"]["warning"]
        ):
            return "WARNING"
        return "OK"

    def suggest_optimizations(self) -> List[OptimizationSuggestion]:
        """
        Suggest optimization actions based on current metrics.

        Returns:
            List of optimization suggestions sorted by priority.
        """
        if not self._last_stats:
            self.evaluate_performance()

        suggestions = []

        # VRAM optimization
        vram_util = (
            self._last_stats.gpu_memory_used
            / self._last_stats.gpu_memory_total * 100
            if self._last_stats.gpu_memory_total > 0
            else 0
        )

        if vram_util >= self.thresholds["vram"]["critical"]:
            suggestions.append(
                OptimizationSuggestion(
                    priority=Priority.CRITICAL,
                    metric="vram",
                    current_value=vram_util,
                    threshold=self.thresholds["vram"]["critical"],
                    suggested_action="Reduce batch size by 50% or pause processing",
                    impact="high",
                )
            )
        elif vram_util >= self.thresholds["vram"]["warning"]:
            suggestions.append(
                OptimizationSuggestion(
                    priority=Priority.HIGH,
                    metric="vram",
                    current_value=vram_util,
                    threshold=self.thresholds["vram"]["warning"],
                    suggested_action="Reduce batch size by 25%",
                    impact="medium",
                )
            )

        # Temperature optimization
        if self._last_stats.gpu_temperature >= self.thresholds["temperature"]["critical"]:
            suggestions.append(
                OptimizationSuggestion(
                    priority=Priority.CRITICAL,
                    metric="temperature",
                    current_value=self._last_stats.gpu_temperature,
                    threshold=self.thresholds["temperature"]["critical"],
                    suggested_action="Reduce GPU load immediately, check cooling",
                    impact="high",
                )
            )
        elif self._last_stats.gpu_temperature >= self.thresholds["temperature"]["warning"]:
            suggestions.append(
                OptimizationSuggestion(
                    priority=Priority.HIGH,
                    metric="temperature",
                    current_value=self._last_stats.gpu_temperature,
                    threshold=self.thresholds["temperature"]["warning"],
                    suggested_action="Monitor temperature, consider reducing load",
                    impact="medium",
                )
            )

        # CPU optimization
        if self._last_stats.cpu_percent >= self.thresholds["cpu"]["critical"]:
            suggestions.append(
                OptimizationSuggestion(
                    priority=Priority.CRITICAL,
                    metric="cpu",
                    current_value=self._last_stats.cpu_percent,
                    threshold=self.thresholds["cpu"]["critical"],
                    suggested_action="Reduce concurrent processes",
                    impact="high",
                )
            )
        elif self._last_stats.cpu_percent >= self.thresholds["cpu"]["warning"]:
            suggestions.append(
                OptimizationSuggestion(
                    priority=Priority.HIGH,
                    metric="cpu",
                    current_value=self._last_stats.cpu_percent,
                    threshold=self.thresholds["cpu"]["warning"],
                    suggested_action="Monitor CPU usage",
                    impact="low",
                )
            )

        # Sort by priority
        priority_order = {Priority.CRITICAL: 0, Priority.HIGH: 1, Priority.MEDIUM: 2, Priority.LOW: 3}
        suggestions.sort(key=lambda x: priority_order[x.priority])

        self._optimization_history.extend(suggestions)
        return suggestions

    def calculate_optimal_batch_size(
        self,
        base_batch: int,
        min_batch: int = 1,
        safety_margin_gb: float = 2.0,
    ) -> int:
        """
        Calculate optimal batch size based on available VRAM.

        Args:
            base_batch: Base batch size to adjust.
            min_batch: Minimum allowed batch size.
            safety_margin_gb: Safety margin in GB to reserve.

        Returns:
            Optimal batch size.
        """
        if not self._last_stats:
            self.evaluate_performance()

        available_memory = (
            self._last_stats.gpu_memory_total - self._last_stats.gpu_memory_used
        )
        available_memory_gb = available_memory / 1024

        # Reserve safety margin
        usable_memory = max(0, available_memory_gb - safety_margin_gb)

        if usable_memory <= 0:
            logger.warning("Insufficient VRAM for processing")
            return min_batch

        # Estimate memory per batch item (rough estimate: 0.5GB per batch unit)
        memory_per_batch = 0.5

        optimal_batch = int((usable_memory / memory_per_batch) * 0.8)
        optimal_batch = max(min_batch, min(optimal_batch, base_batch))

        logger.debug(
            f"Calculated optimal batch size: {optimal_batch} "
            f"(available: {usable_memory:.1f}GB, base: {base_batch})"
        )

        return optimal_batch

    def calculate_gpu_layers(
        self,
        max_layers: int,
        safety_margin_gb: float = 2.0,
        memory_per_layer_gb: float = 0.5,
    ) -> int:
        """
        Calculate optimal GPU layers based on available VRAM.

        Args:
            max_layers: Maximum GPU layers to use.
            safety_margin_gb: Safety margin in GB to reserve.
            memory_per_layer_gb: Estimated memory per layer in GB.

        Returns:
            Optimal number of GPU layers.
        """
        if not self._last_stats:
            self.evaluate_performance()

        available_memory = (
            self._last_stats.gpu_memory_total - self._last_stats.gpu_memory_used
        )
        available_memory_gb = available_memory / 1024

        # Reserve safety margin
        usable_memory = max(0, available_memory_gb - safety_margin_gb)

        if usable_memory <= 0:
            return 0

        optimal_layers = int(usable_memory / memory_per_layer_gb)
        optimal_layers = max(0, min(optimal_layers, max_layers))

        logger.debug(
            f"Calculated optimal GPU layers: {optimal_layers} "
            f"(available: {usable_memory:.1f}GB, max: {max_layers})"
        )

        return optimal_layers

    def get_optimization_report(self) -> Dict[str, Any]:
        """
        Generate a comprehensive optimization report.

        Returns:
            Dictionary with optimization recommendations.
        """
        if not self._last_stats:
            self.evaluate_performance()

        suggestions = self.suggest_optimizations()

        return {
            "current_stats": self._last_stats.to_dict() if self._last_stats else None,
            "suggestions": [s.to_dict() for s in suggestions],
            "can_process": len([s for s in suggestions if s.priority == Priority.CRITICAL]) == 0,
            "recommended_batch_size": self.calculate_optimal_batch_size(4096),
            "recommended_gpu_layers": self.calculate_gpu_layers(100),
        }

    def should_pause_processing(self) -> bool:
        """
        Check if processing should be paused due to critical conditions.

        Returns:
            True if processing should be paused.
        """
        suggestions = self.suggest_optimizations()
        return any(s.priority == Priority.CRITICAL for s in suggestions)

    def get_optimization_history(self) -> List[OptimizationSuggestion]:
        """
        Get history of all optimization suggestions.

        Returns:
            List of all optimization suggestions.
        """
        return self._optimization_history.copy()


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
        "gpu_available": available_memory > 2048,
        "available_memory_mb": available_memory,
        "temperature_ok": stats.gpu_temperature < 85,
        "memory_utilization": (
            stats.gpu_memory_used / stats.gpu_memory_total * 100
            if stats.gpu_memory_total > 0
            else 0
        ),
    }