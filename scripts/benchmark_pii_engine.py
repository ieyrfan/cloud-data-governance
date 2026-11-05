"""Measure local detector throughput and peak traced memory at four input sizes."""

from __future__ import annotations

import json
import sys
import time
import tracemalloc
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from src.pii_engine import PIIEngine  # noqa: E402


def main() -> int:
    engine = PIIEngine()
    sizes = (1_000, 100_000, 1_000_000, 10_000_000)
    seed = "application event completed status=200 duration=42ms request sequence normal\n"
    results = []
    failed = False
    for size in sizes:
        payload = (seed * ((size // len(seed)) + 1))[:size]
        markers = (
            "employee_id: EMP-START-1001\n",
            "\npassport_number: ZX928173\n",
            "\nnational_id: GLOBAL-END-991\n",
        )
        middle = max(len(markers[0]), len(payload) // 2)
        payload = (
            markers[0]
            + payload[len(markers[0]) : middle]
            + markers[1]
            + payload[middle + len(markers[1]) : max(middle + len(markers[1]), size - len(markers[2]))]
            + markers[2]
        )[:size]
        tracemalloc.start()
        started = time.perf_counter()
        result = engine.scan(payload)
        elapsed = time.perf_counter() - started
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        required_detected = result.summary.total_findings >= 3
        failed = failed or not required_detected
        results.append({
            "bytes": size,
            "seconds": round(elapsed, 4),
            "throughput_mb_s": round((size / 1_000_000) / max(elapsed, 0.000001), 2),
            "peak_memory_mb": round(peak / 1_000_000, 2),
            "findings": result.summary.total_findings,
            "start_middle_end_detected": required_detected,
        })
    print(json.dumps(results, indent=2))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
