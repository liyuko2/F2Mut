"""Passive timing and provider-reported token accounting for LLM generation.

Counts application-level API calls, including responses rejected by validation.
Unknown usage is represented by None in totals, rather than an assumed zero.
SDK-internal retries are not exposed by this accounting.
"""

import time
from collections.abc import Mapping


TOKEN_KEYS = ("prompt_tokens", "completion_tokens", "total_tokens")


def response_usage(response):
    """Read token usage from SDK objects or dict responses without estimating it."""
    result = {}
    try:
        usage = response.get("usage") if isinstance(response, Mapping) else getattr(response, "usage", None)
        for key in TOKEN_KEYS:
            value = usage.get(key) if isinstance(usage, Mapping) else getattr(usage, key, None)
            if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                result[key] = value
    except Exception:
        # Optional provider metadata must not interrupt generation or trigger retries.
        pass
    return result


class GenerationMetrics:
    """Observe requests without changing their arguments, return values or errors."""

    def __init__(self, timer_scope):
        self.timer_scope = timer_scope
        self.started_at = time.perf_counter()
        self.attempts = []

    def call(self, create, **kwargs):
        started_at = time.perf_counter()
        response = None
        received = False
        error_type = None
        try:
            response = create(**kwargs)
            received = True
            return response
        except Exception as exc:
            error_type = type(exc).__name__
            raise
        finally:
            elapsed = time.perf_counter() - started_at
            entry = {
                "attempt": len(self.attempts) + 1,
                "duration_sec": round(elapsed, 6),
                "response_received": received,
                "usage": response_usage(response),
            }
            if error_type:
                entry["error_type"] = error_type
            self.attempts.append(entry)

    def snapshot(self):
        totals = {}
        for key in TOKEN_KEYS:
            observed = [entry["usage"][key] for entry in self.attempts if key in entry["usage"]]
            totals[key] = sum(observed) if observed else None
        return {
            "timer_scope": self.timer_scope,
            "duration_sec": round(time.perf_counter() - self.started_at, 6),
            "llm_duration_sec": round(sum(entry["duration_sec"] for entry in self.attempts), 6),
            "attempt_count": len(self.attempts),
            "responses_with_usage": sum(bool(entry["usage"]) for entry in self.attempts),
            "usage_complete": bool(self.attempts) and all(
                all(key in entry["usage"] for key in TOKEN_KEYS) for entry in self.attempts
            ),
            "usage": totals,
            "attempts": [dict(entry, usage=dict(entry["usage"])) for entry in self.attempts],
        }


def add_metrics_to_timing_record(record, metrics):
    """Add metrics while retaining the CLI's existing end-to-end duration_sec."""
    if metrics is not None:
        record["llm_metrics"] = metrics
        record["usage"] = metrics["usage"]

