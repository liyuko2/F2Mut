import random
import os
import json
import sys
import importlib
import importlib.util
import hashlib
import inspect
import time
import re
import threading
import gc
import ctypes
import signal
from collections import deque

import llm_config
from template_safety import validate_template_memory_safety

FALLBACK_TEMPLATE_EXECUTOR_ENV = "AFL_LLM_FALLBACK_TEMPLATE_EXECUTOR"
BASE_TEMPLATE_EXECUTOR_ENV = "AFL_LLM_BASE_TEMPLATE_EXECUTOR"
DEFAULT_FALLBACK_TEMPLATE_EXECUTOR = "elf_template_executor"
_EARLY_BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def _early_abs_template_executor_path(path):
    if not isinstance(path, str) or not path.strip():
        return None
    path = path.strip()
    if not os.path.isabs(path):
        path = os.path.join(_EARLY_BASE_DIR, path)
    path = os.path.abspath(path)
    if path.endswith(".json"):
        sibling = os.path.splitext(path)[0] + ".py"
        if os.path.exists(sibling):
            path = sibling
    return path


def _early_load_module_from_path(path, module_name):
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("invalid template executor module spec")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _early_template_executor_validation_error(module):
    handlers = getattr(module, "OP_HANDLERS", None)
    if not (
        callable(getattr(module, "execute_template_plan", None)) and
        isinstance(handlers, dict) and
        isinstance(getattr(module, "DEFAULT_PLAN", None), dict)
    ):
        return "missing execute_template_plan/DEFAULT_PLAN/OP_HANDLERS"
    max_output_size = int(getattr(module, "MAX_OUTPUT_SIZE", 1024 * 1024))
    for op_name, handler in handlers.items():
        if not callable(handler):
            return f"OP_HANDLERS[{op_name!r}] is not callable"
        try:
            inspect.signature(handler).bind(bytearray(), {}, {}, max_output_size)
        except (TypeError, ValueError) as e:
            return f"OP_HANDLERS[{op_name!r}] has incompatible signature: {e}"
    return None


def _load_template_executor_reference(reference, module_name):
    path = _early_abs_template_executor_path(reference)
    if path and os.path.isfile(path):
        return _early_load_module_from_path(path, module_name)
    return importlib.import_module(reference)


def _load_fallback_template_executor():
    reference = (
        os.environ.get(FALLBACK_TEMPLATE_EXECUTOR_ENV) or
        os.environ.get(BASE_TEMPLATE_EXECUTOR_ENV)
    )
    if reference:
        try:
            module = _load_template_executor_reference(
                reference,
                "_afl_llm_fallback_template_executor",
            )
            validation_error = _early_template_executor_validation_error(module)
            if validation_error:
                raise RuntimeError(validation_error)
            return module
        except Exception as e:
            sys.stderr.write(
                f"[MutatorMin] Failed to load fallback template executor "
                f"{reference!r}: {e}; falling back to "
                f"{DEFAULT_FALLBACK_TEMPLATE_EXECUTOR}\n"
            )
    return importlib.import_module(DEFAULT_FALLBACK_TEMPLATE_EXECUTOR)


_fallback_template_executor = _load_fallback_template_executor()


def _template_executor_display_name(module, default_name):
    module_name = getattr(module, "__name__", None)
    if (
        isinstance(module_name, str)
        and module_name
        and not module_name.startswith("_afl_llm_")
    ):
        return module_name
    module_path = getattr(module, "__file__", None)
    if isinstance(module_path, str) and module_path:
        return os.path.basename(module_path)
    return default_name


_fallback_template_executor_name = _template_executor_display_name(
    _fallback_template_executor,
    DEFAULT_FALLBACK_TEMPLATE_EXECUTOR,
)

__mutator__ = None
__seed__ = "RANDOM"
MUTATORS_DIR_NAME = "generated_mutators"
MUTATORS_DIR_ENV = "AFL_LLM_MUTATORS_DIR"
TEMPLATE_PLAN_DIR_NAME = "template_plans"
TEMPLATE_PLAN_INDEX_FILE = "template_plan_index.json"
TEMPLATE_PLAN_ARTIFACT_TYPE = "elf_template_plan"
MUTATOR_COVERAGE_INDEX = "mutator_coverage.json"
RUNTIME_STATUS_FILE = "template_runtime_status.json"
MUTATORMIN_PROGRESS_FILE = "mutatormin_progress_state.json"
TEMPLATE_EXECUTOR_FEEDBACK_FILE = "template_executor_feedback.json"
ASYNC_TRIGGER_REQUEST_FILE = "async_trigger_request.json"
TEMPLATE_STALL_TRIGGER_FILE = "template_stall_trigger.json"
OP_REGISTRY_DIR_NAME = "op_registry"
CURRENT_REGISTRY_FILE = "current_registry.json"
ACCEPTED_OPS_MODULE = "accepted_ops_module.py"
FORMAT_EXECUTOR_DIR_NAME = "generated_format_executors"
FORMAT_EXECUTOR_DIR_ENV = "AFL_LLM_FORMAT_EXECUTOR_DIR"
TEMPLATE_EXECUTOR_DIR_ENV = "AFL_LLM_TEMPLATE_EXECUTOR_DIR"
TEMPLATE_EXECUTOR_ENV = "AFL_LLM_TEMPLATE_EXECUTOR"
TEMPLATE_DYNAMIC_RELOAD_ENV = "AFL_LLM_TEMPLATE_DYNAMIC_RELOAD"
TEMPLATE_MODE_ENV = "AFL_LLM_TEMPLATE_MODE"
TEMPLATE_PLAN_MODE_ENV = "AFL_LLM_TEMPLATE_PLAN_MODE"
TEMPLATE_INITIAL_ONLY_ENV = "AFL_LLM_TEMPLATE_INITIAL_ONLY"
TEMPLATE_POOL_ENV = "AFL_LLM_TEMPLATE_POOL"
TEMPLATE_POOL_REFRESH_ENV = "AFL_LLM_TEMPLATE_POOL_REFRESH"
TEMPLATE_POOL_WEIGHTED_ENV = "AFL_LLM_TEMPLATE_POOL_WEIGHTED"
TEMPLATE_POOL_SCHEDULE_ENV = "AFL_LLM_TEMPLATE_POOL_SCHEDULE"
TEMPLATE_POOL_EXPLORE_ENV = "AFL_LLM_TEMPLATE_POOL_EXPLORE"
TEMPLATE_FEEDBACK_FLUSH_STAGES_ENV = "AFL_LLM_TEMPLATE_FEEDBACK_FLUSH_STAGES"
TEMPLATE_VERBOSE_ENV = "AFL_LLM_TEMPLATE_VERBOSE"
TEMPLATE_EXEC_TIMEOUT_MS_ENV = "AFL_LLM_TEMPLATE_EXEC_TIMEOUT_MS"
MEMORY_TRIM_STAGES_ENV = "AFL_LLM_MEMORY_TRIM_STAGES"
RUNTIME_STATUS_WRITES_ENV = "AFL_LLM_RUNTIME_STATUS_WRITES"
PROGRESS_WRITES_ENV = "AFL_LLM_PROGRESS_WRITES"
TEMPLATE_FEEDBACK_WRITES_ENV = "AFL_LLM_TEMPLATE_FEEDBACK_WRITES"
CURRENT_TEMPLATE_EXECUTOR_FILE = "current_template_executor.json"
DISABLE_DYNAMIC_TEMPLATE_ENV = "AFL_LLM_DISABLE_DYNAMIC_TEMPLATE"
SEED_ARTIFACTS_DIR_NAME = "generated_seed_data"
SEED_ARTIFACTS_DIR_ENV = "AFL_LLM_SEED_DIR"
SEED_GENERATOR_DIR_NAME = "seed_generators"
GENERATED_SEEDS_DIR_NAME = "generated_seeds"
SEED_INPUT_DIR_NAME = "seed_inputs"
SEED_FEATURES_FILE = "seed_features.json"
MUTATION_PAIRS_FILE = "mutation_pairs.jsonl"
ONLINE_SEED_STATUS_FILE = "online_seed_status.json"
SEED_POOL_MUTATOR_ID = "__seed_pool__"
SEED_GEN_ENV = "AFL_LLM_SEED_GEN"
SEED_FORMAT_ENV = "AFL_LLM_SEED_FORMAT"
SEED_INPUT_ENV = "AFL_LLM_SEED_INPUT"
SEED_SOURCE_MODE_ENV = "AFL_LLM_SEED_SOURCE_MODE"
SEED_MAX_FILES_ENV = "AFL_LLM_SEED_MAX_FILES"
SEED_ASYNC_GEN_ENV = "AFL_LLM_SEED_ASYNC_GEN"
MUTATOR_STALL_ENABLE_ENV = "AFL_LLM_MUTATOR_STALL_ENABLE"
MUTATOR_STALL_WINDOW_ENV = "AFL_LLM_MUTATOR_STALL_WINDOW_SECS"
MUTATOR_STALL_MIN_STAGES_ENV = "AFL_LLM_MUTATOR_STALL_MIN_STAGES"
MUTATOR_STALL_MAX_FINDS_ENV = "AFL_LLM_MUTATOR_STALL_MAX_FINDS"
MUTATOR_STALL_COOLDOWN_ENV = "AFL_LLM_MUTATOR_STALL_COOLDOWN_SECS"
MUTATOR_ASYNC_PREGEN_ENV = "AFL_LLM_MUTATOR_ASYNC_PREGEN"
MUTATOR_PREGEN_COUNT_ENV = "AFL_LLM_MUTATOR_PREGEN_COUNT"
MUTATOR_PREGEN_WORKERS_ENV = "AFL_LLM_MUTATOR_PREGEN_WORKERS"
MUTATOR_PREGEN_MAX_MB_ENV = "AFL_LLM_MUTATOR_PREGEN_MAX_MB"
MUTATOR_PREGEN_MAX_TASKS_ENV = "AFL_LLM_MUTATOR_PREGEN_MAX_TASKS"
FEATURE_SCORE_REFRESH_ENV = "AFL_LLM_FEATURE_SCORE_REFRESH"
FEATURE_SCORE_REFRESH_INTERVAL_ENV = "AFL_LLM_FEATURE_SCORE_REFRESH_INTERVAL"
BOTTLENECK_EXPANSION_ENV = "AFL_LLM_BOTTLENECK_EXPANSION"
BOTTLENECK_WINDOW_ENV = "AFL_LLM_BOTTLENECK_WINDOW_SECS"
BOTTLENECK_BACKOFF_ENV = "AFL_LLM_BOTTLENECK_BACKOFF_SECS"
DEBUG = 0
__no_found_counter__ = 0
__seed_no_found_counter__ = 0
__last_seed_context__ = None
__stage_feedback__ = {}
__queue_seed_path__ = None
__counter_stage__ = None

MAX_EXEC_TIME = 40960
BOOTSTRAP_RETRY_INTERVAL = 512
DARWIN_STACK_COUNTS = [1, 2, 4, 8]
DARWIN_STACK_WEIGHTS = [8, 4, 2, 1]
MAX_OUTPUT_SIZE = int(getattr(_fallback_template_executor, "MAX_OUTPUT_SIZE", 1024 * 1024))
FORMAT_REPAIR_ENV = "AFL_LLM_FORCE_FORMAT_REPAIR"
FEATURE_MASK_ENV = "AFL_LLM_FEATURE_MASK"
FORMAT_REPAIR_OPS = set()
FORMAT_REPAIR_DEFAULT_PROB = 0
# Fixed number of AFL calls for each Python custom-mutator stage. Keeping this
# deterministic makes template-plan cost and feedback easier to compare.
STAGE_EXEC_COUNT = 64
TEMPLATE_POOL_SCHEDULES = {
    "random": "uniform",
    "coverage_per_call": "new_coverage_finds_per_call",
    "coverage": "new_coverage_finds",
}
TEMPLATE_SELECTION_WEIGHT_FLOOR = 1e-6

# One AFL custom-mutator stage can call fuzz() thousands of times. Keep the
# slow JSON state in memory for that stage, then flush it at the next stage
# boundary. `stage_mutator` pins one selected plan for the whole stage so the
# aggregated result is credited to the same plan that produced it.
__batch_cache__ = {
    "active": False,
    "index": {},
    "index_signature": None,
    "coverage": {},
    "index_dirty": False,
    "index_dirty_keys": set(),
    "coverage_dirty": False,
    "seed_features": {},
    "seed_features_signature": None,
    "seed_features_dirty": False,
    "plans": {},
    "stage_mutator": None,
    "optimizer_stage": {},
    "mutatormin_direct_finds": 0,
    "async_pregen_stage": {},
}
_template_executor = _fallback_template_executor
__template_executor_info__ = {
    "path": getattr(_fallback_template_executor, "__file__", None),
    "signature": None,
    "name": _fallback_template_executor_name,
}
__core_op_handlers__ = dict(getattr(_template_executor, "OP_HANDLERS", {}))
__template_pool__ = {
    "executors": [_fallback_template_executor],
    "paths": [getattr(_fallback_template_executor, "__file__", None)],
    "names": [_fallback_template_executor_name],
    "signatures": [None],
    "last_refresh_ns": 0,
}
__template_feedback__ = {
    "loaded": False,
    "executors": {},
    "dirty_stages": 0,
}
__disabled_template_executors__ = set()
__template_timeout_state__ = {
    "active": False,
    "triggered": False,
}
__online_op_registry__ = {
    "current_signature": None,
    "registry_hash": None,
    "module_path": None,
    "manifest_path": None,
    "manifest": {},
    "handlers": {},
    "metadata": {},
    "runtime_stats": {},
}
__pregen_lock__ = threading.RLock()
__pregen_tasks__ = {}
__pregen_current_key__ = None
__pregen_stats__ = {
    "enabled": False,
    "scheduled": 0,
    "ready": 0,
    "skipped_empty": 0,
    "consumed": 0,
    "cache_hits": 0,
    "cache_misses": 0,
    "fallback_sync": 0,
    "stale_drops": 0,
    "cancelled_decisions": 0,
    "worker_errors": 0,
    "last_key": None,
    "last_mutator": None,
    "last_skip_reason": None,
}
__pregen_thread_local__ = threading.local()
__memory_housekeeping__ = {
    "stages": 0,
    "malloc_trim": None,
    "malloc_trim_loaded": False,
}
__bottleneck_expansion__ = {
    "last_queue_growth_ts": int(time.time()),
    "last_queue_name": None,
    "last_trigger_ts": 0,
    "trigger_count": 0,
    "worker": None,
    "last_worker_exit_code": None,
}


def _template_runtime_context():
    return {
        "executor": _template_executor,
        "executor_info": dict(__template_executor_info__),
        "core_op_handlers": dict(__core_op_handlers__),
        "format_repair_ops": set(FORMAT_REPAIR_OPS),
    }


def _active_template_context():
    context = getattr(__pregen_thread_local__, "template_context", None)
    return context if isinstance(context, dict) else None


def _active_template_executor():
    context = _active_template_context()
    executor = context.get("executor") if isinstance(context, dict) else None
    return executor if executor is not None else _template_executor


def _active_template_executor_info():
    context = _active_template_context()
    info = context.get("executor_info") if isinstance(context, dict) else None
    return info if isinstance(info, dict) else __template_executor_info__


def _active_format_repair_ops():
    context = _active_template_context()
    repair_ops = context.get("format_repair_ops") if isinstance(context, dict) else None
    return set(repair_ops) if isinstance(repair_ops, (set, list, tuple)) else set(FORMAT_REPAIR_OPS)


def _counter_op_metadata():
    return {}


def _sync_counter_ops(reset=False):
    del reset
    return []


def _normalize_index_entry(entry):
    if isinstance(entry, list):
        return {
            "files": list(entry),
            "constraints": [],
        }

    if isinstance(entry, dict):
        files = entry.get("files", [])
        constraints = entry.get("constraints", [])
        return {
            "files": list(files) if isinstance(files, list) else [],
            "constraints": list(constraints) if isinstance(constraints, list) else [],
        }

    return {
        "files": [],
        "constraints": [],
    }


def _base_dir():
    return os.path.dirname(os.path.abspath(__file__))


def _mutators_dir():
    path = os.environ.get(MUTATORS_DIR_ENV)
    if isinstance(path, str) and path.strip():
        path = path.strip()
        if not os.path.isabs(path):
            path = os.path.join(_base_dir(), path)
        return os.path.abspath(path)
    return os.path.join(_base_dir(), MUTATORS_DIR_NAME)


def _index_path():
    return os.path.join(_mutators_dir(), TEMPLATE_PLAN_INDEX_FILE)


def _template_plan_dir():
    return os.path.join(_mutators_dir(), TEMPLATE_PLAN_DIR_NAME)


def _op_registry_dir():
    return os.path.join(_mutators_dir(), OP_REGISTRY_DIR_NAME)


def _current_registry_path():
    return os.path.join(_op_registry_dir(), CURRENT_REGISTRY_FILE)


def _coverage_index_path():
    return os.path.join(_mutators_dir(), MUTATOR_COVERAGE_INDEX)


def _runtime_status_path():
    return os.path.join(_mutators_dir(), RUNTIME_STATUS_FILE)


def _mutatormin_progress_path():
    return os.path.join(_mutators_dir(), MUTATORMIN_PROGRESS_FILE)


def _template_executor_feedback_path():
    return os.path.join(_mutators_dir(), TEMPLATE_EXECUTOR_FEEDBACK_FILE)


def _async_trigger_request_path():
    return os.path.join(_mutators_dir(), ASYNC_TRIGGER_REQUEST_FILE)


def _template_stall_trigger_path():
    return os.path.join(_mutators_dir(), TEMPLATE_STALL_TRIGGER_FILE)


def _format_executor_dir():
    path = (
        os.environ.get(FORMAT_EXECUTOR_DIR_ENV) or
        os.environ.get(TEMPLATE_EXECUTOR_DIR_ENV)
    )
    if isinstance(path, str) and path.strip():
        path = path.strip()
        if not os.path.isabs(path):
            path = os.path.join(_base_dir(), path)
        return os.path.abspath(path)
    return os.path.join(_base_dir(), FORMAT_EXECUTOR_DIR_NAME)


def _seed_artifacts_dir():
    path = os.environ.get(SEED_ARTIFACTS_DIR_ENV)
    if isinstance(path, str) and path.strip():
        path = path.strip()
        if not os.path.isabs(path):
            path = os.path.join(_base_dir(), path)
        return os.path.abspath(path)
    return os.path.join(_base_dir(), SEED_ARTIFACTS_DIR_NAME)


def _seed_generator_dir():
    return os.path.join(_seed_artifacts_dir(), SEED_GENERATOR_DIR_NAME)


def _generated_seed_dir():
    return os.path.join(_seed_artifacts_dir(), GENERATED_SEEDS_DIR_NAME)


def _seed_input_dir():
    return os.path.join(_seed_artifacts_dir(), SEED_INPUT_DIR_NAME)


def _seed_features_path():
    return os.path.join(_seed_artifacts_dir(), SEED_FEATURES_FILE)


def _mutation_pairs_path():
    return os.path.join(_seed_artifacts_dir(), MUTATION_PAIRS_FILE)


def _online_seed_status_path():
    return os.path.join(_seed_artifacts_dir(), ONLINE_SEED_STATUS_FILE)


def _feature_scores_path():
    return os.path.join(_seed_artifacts_dir(), "feature_scores.json")


def _abs_template_executor_path(path):
    if not isinstance(path, str) or not path.strip():
        return None
    path = path.strip()
    if path.endswith(".json"):
        sibling = os.path.splitext(path)[0] + ".py"
        if os.path.exists(sibling):
            path = sibling
    if not os.path.isabs(path):
        path = os.path.join(_base_dir(), path)
    return os.path.abspath(path)


def _latest_generated_executor_path():
    executor_dir = _format_executor_dir()
    if not os.path.isdir(executor_dir):
        return None
    candidates = []
    for name in os.listdir(executor_dir):
        if not name.endswith(".py") or name.startswith("__"):
            continue
        path = os.path.join(executor_dir, name)
        try:
            stat = os.stat(path)
        except OSError:
            continue
        candidates.append((stat.st_mtime_ns, path))
    if not candidates:
        return None
    return os.path.abspath(max(candidates)[1])


def _current_template_executor_path():
    pointer_path = os.path.join(_format_executor_dir(), CURRENT_TEMPLATE_EXECUTOR_FILE)
    payload = _load_json_dict(pointer_path)
    raw_path = (
        payload.get("code") or
        payload.get("executor") or
        payload.get("path")
    )
    path = _abs_template_executor_path(raw_path)
    if path and os.path.isfile(path):
        return path
    return None


def _template_executor_signature(path):
    if not path:
        return ("builtin", id(_fallback_template_executor))
    return _file_signature(path)


def _load_module_from_path(path):
    module_name = f"_afl_llm_template_executor_{abs(hash(path))}"
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("invalid template executor module spec")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _template_source_validation_error(path):
    if not isinstance(path, str) or not path.endswith(".py"):
        return None
    try:
        with open(path, "r", encoding="utf-8") as source_file:
            source = source_file.read()
    except OSError as e:
        return f"failed to read template source: {e}"
    ok, error = validate_template_memory_safety(source)
    return None if ok else error


def _template_executor_validation_error(module):
    handlers = getattr(module, "OP_HANDLERS", None)
    if not (
        callable(getattr(module, "execute_template_plan", None)) and
        isinstance(handlers, dict) and
        isinstance(getattr(module, "DEFAULT_PLAN", None), dict)
    ):
        return "missing execute_template_plan/DEFAULT_PLAN/OP_HANDLERS"
    for op_name, handler in handlers.items():
        if not callable(handler):
            return f"OP_HANDLERS[{op_name!r}] is not callable"
        try:
            inspect.signature(handler).bind(bytearray(), {}, {}, MAX_OUTPUT_SIZE)
        except (TypeError, ValueError) as e:
            return f"OP_HANDLERS[{op_name!r}] has incompatible signature: {e}"
    source_path = getattr(module, "__file__", None)
    source_error = _template_source_validation_error(source_path)
    if source_error:
        return source_error
    return None


def _is_valid_template_executor(module):
    return _template_executor_validation_error(module) is None


def _detect_repair_ops(op_handlers):
    repair_ops = set()
    for op_name in op_handlers:
        if not isinstance(op_name, str):
            continue
        lowered = op_name.lower()
        if lowered.startswith(("ensure_", "sync_", "repair_")):
            repair_ops.add(op_name)
    return repair_ops


def _architecture_op_roles(executor):
    metadata = getattr(executor, "ARCHITECTURE_OP_METADATA", None)
    if not isinstance(metadata, dict) or not metadata:
        return None
    return {
        op_name: declaration.get("role")
        for op_name, declaration in metadata.items()
        if (
            isinstance(op_name, str)
            and isinstance(declaration, dict)
            and declaration.get("role") in {"architecture_transition", "target_repair"}
        )
    }


def _filter_undeclared_architecture_repair_ops(executor, plan):
    if not isinstance(plan, dict):
        return plan
    architecture_roles = _architecture_op_roles(executor)
    ops = plan.get("ops")
    if architecture_roles is None or not isinstance(ops, list):
        return plan
    filtered_ops = [
        op
        for op in ops
        if not (
            isinstance(op, dict)
            and isinstance(op.get("op"), str)
            and op["op"].lower().startswith(("ensure_", "sync_", "repair_"))
            and op["op"] not in architecture_roles
        )
    ]
    if len(filtered_ops) == len(ops):
        return plan
    filtered_plan = dict(plan)
    filtered_plan["ops"] = filtered_ops
    return filtered_plan


def _template_feature_action_ops():
    actions = getattr(_template_executor, "FEATURE_ACTIONS", {})
    if not isinstance(actions, dict):
        return tuple()
    selected = []
    for action in actions.values():
        if not isinstance(action, dict):
            continue
        op_name = action.get("action_id") or action.get("op")
        if not isinstance(op_name, str) or not op_name:
            continue
        lowered = op_name.lower()
        if lowered.startswith(("ensure_", "sync_", "repair_")):
            continue
        if op_name in FORMAT_REPAIR_OPS or op_name not in __core_op_handlers__:
            continue
        selected.append(op_name)
    return tuple(sorted(set(selected)))


def _template_core_mutation_ops():
    feature_ops = _template_feature_action_ops()
    if feature_ops:
        return feature_ops
    return tuple(
        op_name for op_name in sorted(__core_op_handlers__)
        if op_name not in FORMAT_REPAIR_OPS
    )


def _configure_optimizer_core_ops():
    # Kept as a narrow compatibility hook for template refresh callers. The
    # Seed-OP scheduler uses accepted online handlers only.
    return None


def _refresh_template_executor():
    """Load the active format executor at stage boundaries.

    Selection order:
    1. AFL_LLM_TEMPLATE_EXECUTOR if set (.py, or .json with sibling .py).
    2. newest configured format-executor-dir/*.py unless disabled.
    3. configured fallback template executor.
    """

    global _template_executor
    global __template_executor_info__
    global __core_op_handlers__
    global FORMAT_REPAIR_OPS

    initial_only = _template_initial_only()
    env_path = None if initial_only else _abs_template_executor_path(os.environ.get(TEMPLATE_EXECUTOR_ENV))
    disabled = str(os.environ.get(DISABLE_DYNAMIC_TEMPLATE_ENV, "")).lower() in {
        "1", "true", "yes", "on",
    }
    dynamic_reload = str(os.environ.get(TEMPLATE_DYNAMIC_RELOAD_ENV, "")).lower() in {
        "1", "true", "yes", "on",
    }
    pointer_path = _current_template_executor_path() if dynamic_reload and not env_path and not initial_only else None
    candidate_path = (
        None
        if initial_only
        else env_path if env_path else (pointer_path if pointer_path else (None if disabled else _latest_generated_executor_path()))
    )
    signature = _template_executor_signature(candidate_path)
    using_loaded_fallback = (
        candidate_path is None and
        _template_executor is _fallback_template_executor
    )
    if (
        signature == __template_executor_info__.get("signature") and
        (
            candidate_path == __template_executor_info__.get("path") or
            using_loaded_fallback
        )
    ):
        return

    module = None
    loaded_path = candidate_path
    if candidate_path:
        try:
            source_error = _template_source_validation_error(candidate_path)
            if source_error:
                raise RuntimeError(source_error)
            module = _load_module_from_path(candidate_path)
            validation_error = _template_executor_validation_error(module)
            if validation_error:
                raise RuntimeError(validation_error)
            if _is_template_executor_disabled(module):
                raise RuntimeError("template executor is disabled")
        except Exception as e:
            sys.stderr.write(
                f"[MutatorMin] Failed to load template executor {candidate_path}: {e}; "
                f"falling back to {_fallback_template_executor_name}\n"
            )
            module = None
            loaded_path = None

    if module is None:
        module = _fallback_template_executor
        signature = _template_executor_signature(None)

    _template_executor = module
    __core_op_handlers__ = dict(getattr(module, "OP_HANDLERS", {}))
    FORMAT_REPAIR_OPS = _detect_repair_ops(__core_op_handlers__)
    __template_executor_info__ = {
        "path": loaded_path or getattr(_fallback_template_executor, "__file__", None),
        "signature": signature,
        "name": (
            _fallback_template_executor_name
            if module is _fallback_template_executor
            else getattr(module, "__name__", "template_executor")
        ),
    }
    __batch_cache__.setdefault("plans", {}).clear()
    _configure_optimizer_core_ops()
    sys.stderr.write(
        f"[MutatorMin] Active template executor: {__template_executor_info__['path']} "
        f"ops={len(__core_op_handlers__)} repair_ops={len(FORMAT_REPAIR_OPS)}\n"
    )


def _load_json_dict(path):
    if os.path.exists(path) is False:
        return {}

    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, ValueError, OSError):
        return {}


def _file_signature(path):
    try:
        stat = os.stat(path)
        return (stat.st_mtime_ns, stat.st_size)
    except OSError:
        return None


def _registry_abs_path(value):
    if not isinstance(value, str) or not value:
        return None
    if os.path.isabs(value):
        return value
    return os.path.join(_mutators_dir(), value)


def _write_json_dict(path, data):
    mutators_dir = _mutators_dir()
    if os.path.exists(mutators_dir) is False:
        os.makedirs(mutators_dir)

    tmp_path = f"{path}.tmp"
    with open(tmp_path, 'w', encoding='utf-8') as f:
        json.dump(data if isinstance(data, dict) else {}, f, indent=2)
    os.replace(tmp_path, path)


def _env_flag(name, default=True):
    value = os.environ.get(name)
    if value is None:
        return bool(default)
    return str(value).strip().lower() not in {"0", "false", "no", "off", "never"}


def _env_float(name, default, lower=0.0, upper=1.0):
    try:
        value = float(os.environ.get(name, default))
    except (TypeError, ValueError):
        value = float(default)
    return max(lower, min(value, upper))


def _env_int(name, default, lower=1, upper=1024):
    try:
        value = int(os.environ.get(name, default))
    except (TypeError, ValueError):
        value = int(default)
    return max(lower, min(value, upper))


def _env_nonnegative_int(name, default, upper=1024):
    try:
        value = int(os.environ.get(name, default))
    except (TypeError, ValueError):
        value = int(default)
    return max(0, min(value, upper))


def _bottleneck_expansion_config():
    return {
        "enabled": _env_flag(BOTTLENECK_EXPANSION_ENV, False) and os.path.isfile(
            os.path.join(_base_dir(), "bottleneck_expansion_manager.py")
        ),
        "window_secs": _env_int(BOTTLENECK_WINDOW_ENV, 300, lower=1, upper=86400),
        "backoff_secs": _env_nonnegative_int(BOTTLENECK_BACKOFF_ENV, 60, upper=86400),
    }


def _bottleneck_expansion_status(now=None):
    now = int(now or time.time())
    config = _bottleneck_expansion_config()
    trigger_count = int(__bottleneck_expansion__.get("trigger_count", 0) or 0)
    wait_secs = config["window_secs"] + trigger_count * config["backoff_secs"]
    worker = __bottleneck_expansion__.get("worker")
    worker_running = worker is not None and worker.poll() is None
    return {
        "enabled": config["enabled"],
        "window_secs": config["window_secs"],
        "backoff_secs": config["backoff_secs"],
        "effective_wait_secs": wait_secs,
        "last_queue_growth_ts": int(__bottleneck_expansion__.get("last_queue_growth_ts", 0) or 0),
        "seconds_since_queue_growth": max(
            0,
            now - int(__bottleneck_expansion__.get("last_queue_growth_ts", now) or now),
        ),
        "last_trigger_ts": int(__bottleneck_expansion__.get("last_trigger_ts", 0) or 0),
        "trigger_count": trigger_count,
        "worker_running": worker_running,
        "worker_pid": worker.pid if worker_running else None,
        "last_worker_exit_code": __bottleneck_expansion__.get("last_worker_exit_code"),
    }


def _bottleneck_should_trigger(now=None):
    now = int(now or time.time())
    status = _bottleneck_expansion_status(now=now)
    if not status["enabled"] or status["worker_running"]:
        return False
    wait_secs = status["effective_wait_secs"]
    if status["seconds_since_queue_growth"] < wait_secs:
        return False
    last_trigger_ts = status["last_trigger_ts"]
    return not last_trigger_ts or now - last_trigger_ts >= wait_secs


def _record_bottleneck_queue_growth(queue_name=None, now=None):
    __bottleneck_expansion__["last_queue_growth_ts"] = int(now or time.time())
    __bottleneck_expansion__["last_queue_name"] = str(queue_name) if queue_name else None


def _maybe_spawn_bottleneck_expansion(now=None):
    now = int(now or time.time())
    worker = __bottleneck_expansion__.get("worker")
    if worker is not None and worker.poll() is not None:
        __bottleneck_expansion__["last_worker_exit_code"] = worker.returncode
        __bottleneck_expansion__["worker"] = None
    if not _bottleneck_should_trigger(now=now):
        return False

    import subprocess

    _ensure_mutators_path()
    trigger_count = int(__bottleneck_expansion__.get("trigger_count", 0) or 0) + 1
    python_executable = os.environ.get("PYTHON", sys.executable)
    if "python" not in os.path.basename(python_executable).lower():
        python_executable = "python3"
    cmd = [
        python_executable,
        os.path.join(_base_dir(), "bottleneck_expansion_manager.py"),
        "--format", _seed_format(),
        "--seed-dir", _seed_artifacts_dir(),
        "--output-dir", _format_executor_dir(),
        "--state-dir", _mutators_dir(),
        "--trigger-count", str(trigger_count),
    ]
    try:
        log_path = os.path.join(_mutators_dir(), "bottleneck_expansion.log")
        with open(log_path, "ab") as log_file:
            log_file.write(b"\n[MutatorMin] spawn bottleneck expansion\n")
            worker = subprocess.Popen(
                cmd,
                cwd=_base_dir(),
                stdout=log_file,
                stderr=log_file,
                start_new_session=True,
                close_fds=True,
            )
    except OSError as exc:
        sys.stderr.write(f"[MutatorMin] Failed to spawn bottleneck expansion: {exc}\n")
        return False

    __bottleneck_expansion__["worker"] = worker
    __bottleneck_expansion__["last_trigger_ts"] = now
    __bottleneck_expansion__["trigger_count"] = trigger_count
    __bottleneck_expansion__["last_worker_exit_code"] = None
    return True


def _template_mode_enabled():
    return _env_flag(TEMPLATE_MODE_ENV, False)


def _template_initial_only():
    return _env_flag(TEMPLATE_INITIAL_ONLY_ENV, False)


def _template_plan_mode():
    return str(os.environ.get(TEMPLATE_PLAN_MODE_ENV, "default")).strip().lower()


def _compose_random_template_plan(executor):
    all_handlers = getattr(executor, "OP_HANDLERS", {})
    if not isinstance(all_handlers, dict) or not all_handlers:
        return None
    architecture_roles = _architecture_op_roles(executor)
    repair_prefix_names = []
    repair_suffix_names = []
    mutation_op_names = []
    for op_name in all_handlers:
        lowered = op_name.lower()
        role = architecture_roles.get(op_name) if architecture_roles is not None else None
        if role == "architecture_transition":
            repair_prefix_names.append(op_name)
        elif role == "target_repair":
            repair_suffix_names.append(op_name)
        elif lowered.startswith(("ensure_", "sync_", "repair_")):
            if architecture_roles is None:
                if lowered.startswith("ensure_"):
                    repair_prefix_names.append(op_name)
                else:
                    repair_suffix_names.append(op_name)
        else:
            mutation_op_names.append(op_name)
    if not mutation_op_names:
        return None
    stack_count = random.randint(1, min(len(mutation_op_names), 8))
    selected = random.sample(mutation_op_names, stack_count)
    ops = []
    for op_name in sorted(repair_prefix_names):
        ops.append(_core_runtime_op(op_name, executor=executor))
    for op_name in selected:
        ops.append(_core_runtime_op(op_name, executor=executor))
    for op_name in sorted(repair_suffix_names):
        ops.append(_core_runtime_op(op_name, executor=executor))
    max_output_size = int(getattr(executor, "MAX_OUTPUT_SIZE", 1024 * 1024))
    return {
        "template": "random_template_plan",
        "ops": ops,
        "limits": {"max_output_size": max_output_size, "max_ops_per_call": max(len(ops), 1)},
    }


def _template_pool_enabled():
    return _env_flag(TEMPLATE_POOL_ENV, False)


def _template_pool_refresh_interval():
    return _env_int(TEMPLATE_POOL_REFRESH_ENV, 30, lower=5, upper=3600)


def _template_pool_schedule():
    mode = str(os.environ.get(TEMPLATE_POOL_SCHEDULE_ENV, "")).strip().lower()
    if not mode:
        # Preserve the legacy random/weighted switch when no mode is specified.
        return "coverage_per_call" if _env_flag(TEMPLATE_POOL_WEIGHTED_ENV, True) else "random"
    if mode not in TEMPLATE_POOL_SCHEDULES:
        raise ValueError(
            f"Invalid {TEMPLATE_POOL_SCHEDULE_ENV}={mode!r}; "
            f"expected one of: {', '.join(TEMPLATE_POOL_SCHEDULES)}"
        )
    return mode


def _template_pool_weighted_enabled():
    return _template_pool_schedule() != "random"


def _template_selection_metric():
    return TEMPLATE_POOL_SCHEDULES[_template_pool_schedule()]


def _template_selection_weight_floor():
    return TEMPLATE_SELECTION_WEIGHT_FLOOR if _template_pool_schedule() == "coverage_per_call" else 1.0


def _template_pool_explore_rate():
    return _env_float(TEMPLATE_POOL_EXPLORE_ENV, 0.15)


def _template_feedback_flush_stages():
    return _env_int(TEMPLATE_FEEDBACK_FLUSH_STAGES_ENV, 8, lower=1, upper=1024)


def _template_verbose_enabled():
    return _env_flag(TEMPLATE_VERBOSE_ENV, False)


def _template_exec_timeout_ms():
    return _env_nonnegative_int(TEMPLATE_EXEC_TIMEOUT_MS_ENV, 1000, upper=60000)


def _memory_trim_interval():
    return _env_nonnegative_int(MEMORY_TRIM_STAGES_ENV, 1, upper=4096)


def _malloc_trim():
    if __memory_housekeeping__.get("malloc_trim_loaded"):
        return __memory_housekeeping__.get("malloc_trim")
    __memory_housekeeping__["malloc_trim_loaded"] = True
    try:
        trim = ctypes.CDLL(None).malloc_trim
        trim.argtypes = [ctypes.c_size_t]
        trim.restype = ctypes.c_int
    except Exception:
        trim = None
    __memory_housekeeping__["malloc_trim"] = trim
    return trim


def _run_memory_housekeeping(force=False):
    interval = _memory_trim_interval()
    if interval <= 0 and not force:
        return
    __memory_housekeeping__["stages"] = (
        int(__memory_housekeeping__.get("stages", 0) or 0) + 1
    )
    if not force and __memory_housekeeping__["stages"] % interval != 0:
        return
    gc.collect()
    trim = _malloc_trim()
    if trim is not None:
        try:
            trim(0)
        except Exception:
            pass


def _runtime_status_writes_enabled():
    return _env_flag(RUNTIME_STATUS_WRITES_ENV, True)


def _progress_writes_enabled():
    return _env_flag(PROGRESS_WRITES_ENV, True)


def _template_feedback_writes_enabled():
    return _env_flag(TEMPLATE_FEEDBACK_WRITES_ENV, True)


def _template_executor_id(executor):
    path = getattr(executor, "__file__", None)
    if isinstance(path, str) and path:
        return os.path.basename(path)
    name = getattr(executor, "__name__", None)
    return name if isinstance(name, str) and name else _fallback_template_executor_name


def _ensure_template_feedback():
    if __template_feedback__.get("loaded"):
        return __template_feedback__
    payload = _load_json_dict(_template_executor_feedback_path())
    executors = payload.get("executors", {})
    executors = executors if isinstance(executors, dict) else {}
    for entry in executors.values():
        if not isinstance(entry, dict):
            continue
        for obsolete_field in (
            "ops",
            "pool_novel_edges",
            "covered_edges",
            "exclusive_edges",
            "last_pool_novel_edges",
            "score",
        ):
            entry.pop(obsolete_field, None)
        entry.setdefault("new_coverage_finds", 0)
    __template_feedback__["executors"] = executors
    __template_feedback__["dirty_stages"] = 0
    __template_feedback__["loaded"] = True
    return __template_feedback__


def _template_feedback_entry(executor, create=False):
    state = _ensure_template_feedback()
    executor_id = _template_executor_id(executor)
    entry = state["executors"].get(executor_id)
    if not isinstance(entry, dict):
        if not create:
            return {}
        entry = {
            "executor_id": executor_id,
            "path": getattr(executor, "__file__", None),
            "stage_calls": 0,
            "calls": 0,
            "changed_calls": 0,
            "error_calls": 0,
            "direct_finds": 0,
            "new_coverage_finds": 0,
        }
        state["executors"][executor_id] = entry
    entry.pop("ops", None)
    return entry


class _TemplateExecutionTimeout(TimeoutError):
    pass


def _template_timeout_handler(signum, frame):
    del signum, frame
    __template_timeout_state__["triggered"] = True
    raise _TemplateExecutionTimeout("template executor call timed out")


def _template_timeout_supported():
    return (
        threading.current_thread() is threading.main_thread() and
        hasattr(signal, "SIGALRM") and
        hasattr(signal, "setitimer") and
        hasattr(signal, "getitimer")
    )


def _template_disabled_ids_from_feedback():
    state = _ensure_template_feedback()
    disabled = set()
    for executor_id, entry in state.get("executors", {}).items():
        if isinstance(entry, dict) and entry.get("disabled"):
            disabled.add(str(executor_id))
    return disabled


def _is_template_executor_disabled(executor):
    executor_id = _template_executor_id(executor)
    if executor_id in __disabled_template_executors__:
        return True
    entry = _template_feedback_entry(executor)
    if entry.get("disabled"):
        __disabled_template_executors__.add(executor_id)
        return True
    return False


def _prune_disabled_template_pool():
    pool = __template_pool__
    executors = pool.get("executors", [])
    paths = pool.get("paths", [])
    names = pool.get("names", [])
    signatures = pool.get("signatures", [])
    kept = []
    for idx, executor in enumerate(executors):
        if _is_template_executor_disabled(executor):
            continue
        kept.append((
            executor,
            paths[idx] if idx < len(paths) else getattr(executor, "__file__", None),
            names[idx] if idx < len(names) else _template_executor_id(executor),
            signatures[idx] if idx < len(signatures) else _template_executor_signature(getattr(executor, "__file__", None)),
        ))
    pool["executors"] = [item[0] for item in kept]
    pool["paths"] = [item[1] for item in kept]
    pool["names"] = [item[2] for item in kept]
    pool["signatures"] = [item[3] for item in kept]
    return pool["executors"]


def _disable_template_executor(executor, reason, plan=None, timeout_ms=None):
    if executor is None:
        return
    executor_id = _template_executor_id(executor)
    __disabled_template_executors__.add(executor_id)
    entry = _template_feedback_entry(executor, create=True)
    entry["executor_id"] = executor_id
    entry["path"] = getattr(executor, "__file__", None)
    entry["disabled"] = True
    entry["disabled_reason"] = reason
    entry["disabled_ts"] = int(time.time())
    entry["timeout_ms"] = int(timeout_ms or 0)
    entry["timeout_count"] = _safe_int(entry.get("timeout_count")) + 1
    if isinstance(plan, dict):
        entry["last_timeout_ops"] = _plan_op_names(plan)
    state = _ensure_template_feedback()
    state["dirty_stages"] = _safe_int(state.get("dirty_stages")) + 1
    try:
        _persist_template_feedback(force=True)
    except Exception as exc:
        sys.stderr.write(f"[MutatorMin] Failed to persist disabled template {executor_id}: {exc}\n")
    _prune_disabled_template_pool()
    sys.stderr.write(
        f"[MutatorMin] Disabled template executor {executor_id}: {reason}"
        f"{f' timeout_ms={timeout_ms}' if timeout_ms else ''}\n"
    )


def _record_template_execution_timeout(executor, plan, timeout_ms, execution_info=None):
    if isinstance(execution_info, dict):
        execution_info["execution_error"] = True
        execution_info["timeout"] = True
        execution_info["timeout_ms"] = timeout_ms
    _disable_template_executor(
        executor,
        "execute_template_plan_timeout",
        plan=plan,
        timeout_ms=timeout_ms,
    )


def _call_template_executor_with_timeout(executor, execute, data, plan, profile, limit, execution_info=None):
    timeout_ms = _template_exec_timeout_ms()
    if timeout_ms <= 0 or not _template_timeout_supported():
        return execute(data, plan, profile, limit)

    previous_handler = signal.getsignal(signal.SIGALRM)
    previous_timer = signal.getitimer(signal.ITIMER_REAL)
    timeout_reported = False
    __template_timeout_state__["active"] = True
    __template_timeout_state__["triggered"] = False
    signal.signal(signal.SIGALRM, _template_timeout_handler)
    signal.setitimer(signal.ITIMER_REAL, timeout_ms / 1000.0)
    try:
        result = execute(data, plan, profile, limit)
        if __template_timeout_state__.get("triggered"):
            timeout_reported = True
            _record_template_execution_timeout(
                executor,
                plan,
                timeout_ms,
                execution_info=execution_info,
            )
            raise _TemplateExecutionTimeout("template executor call timed out")
        return result
    except _TemplateExecutionTimeout:
        if not timeout_reported:
            _record_template_execution_timeout(
                executor,
                plan,
                timeout_ms,
                execution_info=execution_info,
            )
        raise
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)
        __template_timeout_state__["active"] = False
        __template_timeout_state__["triggered"] = False
        if previous_timer and (previous_timer[0] > 0 or previous_timer[1] > 0):
            signal.setitimer(signal.ITIMER_REAL, previous_timer[0], previous_timer[1])


def _template_feedback_score(executor):
    mode = _template_pool_schedule()
    if mode == "random":
        return 1.0
    entry = _template_feedback_entry(executor)
    finds = max(0, _safe_int(entry.get("new_coverage_finds")))
    if mode == "coverage":
        return float(finds + 1)
    calls = _safe_int(entry.get("calls"))
    # Count every fuzz() attempt, including unchanged outputs and errors, so
    # unusable mutations also consume the executor's selection budget.
    reward_per_call = finds / calls if calls > 0 else 0.0
    return max(reward_per_call, TEMPLATE_SELECTION_WEIGHT_FLOOR)


def _scan_template_pool():
    global __template_pool__
    pool = __template_pool__
    executors = [_fallback_template_executor]
    paths = [getattr(_fallback_template_executor, "__file__", None)]
    names = [_fallback_template_executor_name]
    signatures = [_template_executor_signature(None)]
    executor_dir = _format_executor_dir()
    seen_paths = set()
    for path in [paths[0]] if paths[0] else []:
        seen_paths.add(os.path.abspath(path) if path else None)
    if os.path.isdir(executor_dir) and not _template_initial_only():
        staging_dirs = []
        py_files = []
        for entry in os.listdir(executor_dir):
            full = os.path.join(executor_dir, entry)
            if entry.startswith("__") or entry.startswith("."):
                continue
            if entry.startswith("staging_") and os.path.isdir(full):
                staging_dirs.append(full)
            elif entry.endswith(".py") and os.path.isfile(full):
                py_files.append(full)
        for sdir in staging_dirs:
            for entry in os.listdir(sdir):
                if not entry.endswith(".py") or entry.startswith("__"):
                    continue
                full = os.path.join(sdir, entry)
                if os.path.isfile(full):
                    py_files.append(full)
        for py_path in sorted(py_files):
            abs_path = os.path.abspath(py_path)
            if abs_path in seen_paths:
                continue
            seen_paths.add(abs_path)
            source_error = _template_source_validation_error(py_path)
            if source_error:
                sys.stderr.write(
                    f"[template-bootstrap] skipping invalid LLM template: {py_path}: "
                    f"{source_error}\n"
                )
                continue
            try:
                module = _load_module_from_path(py_path)
            except Exception:
                continue
            validation_error = _template_executor_validation_error(module)
            if validation_error:
                sys.stderr.write(
                    f"[template-bootstrap] skipping invalid LLM template: {py_path}: "
                    f"{validation_error}\n"
                )
                continue
            op_handlers = getattr(module, "OP_HANDLERS", {})
            if not isinstance(op_handlers, dict) or not op_handlers:
                continue
            executors.append(module)
            paths.append(py_path)
            names.append(getattr(module, "__name__", os.path.basename(py_path)))
            signatures.append(_template_executor_signature(py_path))
    pool["executors"] = executors
    pool["paths"] = paths
    pool["names"] = names
    pool["signatures"] = signatures
    pool["last_refresh_ns"] = time.time_ns()
    return _prune_disabled_template_pool()


def _refresh_template_pool():
    global __template_pool__
    pool = __template_pool__
    if _template_initial_only():
        if len(pool["executors"]) != 1 or pool["executors"][0] is not _fallback_template_executor:
            return _scan_template_pool()
        return pool["executors"]
    interval = _template_pool_refresh_interval()
    elapsed = (time.time_ns() - pool["last_refresh_ns"]) / 1e9
    if elapsed < interval and len(pool["executors"]) > 1:
        return _prune_disabled_template_pool()
    executors = _scan_template_pool()
    n = len(executors)
    base_only = (n <= 1)
    if _template_verbose_enabled() and (elapsed >= interval or base_only):
        sys.stderr.write(
            f"[MutatorMin] template pool refreshed: {n} executor(s)"
            f" ({'base only' if base_only else 'pool'})\n"
        )
    return executors


def _select_random_template_executor():
    if _template_initial_only():
        return _fallback_template_executor
    if not _template_pool_enabled():
        return _template_executor
    executors = _refresh_template_pool()
    if not executors:
        return None
    executors = [
        executor for executor in executors
        if not _is_template_executor_disabled(executor)
    ]
    if not executors:
        return None
    if not _template_pool_weighted_enabled():
        return random.choice(executors)

    untried = [
        executor for executor in executors
        if _safe_int(_template_feedback_entry(executor).get("stage_calls")) <= 0
    ]
    if untried:
        return random.choice(untried)
    if random.random() < _template_pool_explore_rate():
        return random.choice(executors)
    weights = [_template_feedback_score(executor) for executor in executors]
    return random.choices(executors, weights=weights, k=1)[0]


def _persist_template_feedback(force=False):
    state = _ensure_template_feedback()
    dirty_stages = _safe_int(state.get("dirty_stages"))
    if dirty_stages <= 0:
        return False
    if not _template_feedback_writes_enabled():
        state["dirty_stages"] = 0
        return False
    if not force and dirty_stages < _template_feedback_flush_stages():
        return False
    persisted = {
        "version": 1,
        "updated_ts": int(time.time()),
        "config": {
            "weighted_pool": _template_pool_weighted_enabled(),
            "schedule_mode": _template_pool_schedule(),
            "pool_explore_rate": _template_pool_explore_rate(),
            "selection_metric": _template_selection_metric(),
            "selection_weight_floor": _template_selection_weight_floor(),
            "flush_stages": _template_feedback_flush_stages(),
        },
        "executors": state["executors"],
    }
    _write_json_dict(_template_executor_feedback_path(), persisted)
    state["dirty_stages"] = 0
    return True


def _record_template_stage_feedback(stage, feedback=None, force_persist=False):
    if not isinstance(stage, dict) or stage.get("op_name") != "__template_executor__":
        return
    executor = stage.get("template_executor") or _fallback_template_executor
    executor_id = stage.get("template_executor_id") or _template_executor_id(executor)
    entry = _template_feedback_entry(executor, create=True)
    entry["executor_id"] = executor_id
    entry["path"] = getattr(executor, "__file__", None)
    entry["stage_calls"] = _safe_int(entry.get("stage_calls")) + 1
    entry["calls"] = _safe_int(entry.get("calls")) + _safe_int(stage.get("calls"))
    entry["changed_calls"] = _safe_int(entry.get("changed_calls")) + _safe_int(stage.get("changed_calls"))
    entry["error_calls"] = _safe_int(entry.get("error_calls")) + _safe_int(stage.get("error_calls"))
    entry["direct_finds"] = _safe_int(entry.get("direct_finds")) + _safe_int(stage.get("direct_finds"))
    entry["new_coverage_finds"] = (
        _safe_int(entry.get("new_coverage_finds")) +
        _safe_int(stage.get("new_coverage_finds"))
    )
    entry["last_stage"] = {
        "calls": _safe_int(stage.get("calls")),
        "changed_calls": _safe_int(stage.get("changed_calls")),
        "error_calls": _safe_int(stage.get("error_calls")),
        "direct_finds": _safe_int(stage.get("direct_finds")),
        "new_coverage_finds": _safe_int(stage.get("new_coverage_finds")),
        "execs": _safe_int((feedback or {}).get("execs")),
        "covered_edges": _safe_int((feedback or {}).get("covered_edges")),
        "settled_ts": int(time.time()),
    }

    state = _ensure_template_feedback()
    state["dirty_stages"] = _safe_int(state.get("dirty_stages")) + 1
    _persist_template_feedback(
        force=force_persist or _safe_int(stage.get("new_coverage_finds")) > 0,
    )


def _template_feedback_status():
    executors = (
        _refresh_template_pool()
        if _template_pool_enabled()
        else [_template_executor]
    )
    rows = []
    for executor in executors if isinstance(executors, list) else []:
        entry = dict(_template_feedback_entry(executor))
        entry["selection_weight"] = _template_feedback_score(executor)
        calls = _safe_int(entry.get("calls"))
        entry["changed_rate"] = _safe_int(entry.get("changed_calls")) / max(calls, 1)
        entry["error_rate"] = _safe_int(entry.get("error_calls")) / max(calls, 1)
        rows.append(entry)
    rows.sort(key=lambda item: float(item.get("selection_weight", 0.0)), reverse=True)
    return {
        "initial_only": _template_initial_only(),
        "weighted_selection": _template_pool_weighted_enabled(),
        "schedule_mode": _template_pool_schedule(),
        "explore_rate": _template_pool_explore_rate(),
        "selection_metric": _template_selection_metric(),
        "selection_weight_floor": _template_selection_weight_floor(),
        "feedback_flush_stages": _template_feedback_flush_stages(),
        "feedback_dirty_stages": _safe_int(_ensure_template_feedback().get("dirty_stages")),
        "disabled_executor_ids": sorted(
            __disabled_template_executors__ | _template_disabled_ids_from_feedback()
        ),
        "executors": rows,
    }


def _feature_score_refresh_enabled():
    return _env_flag(FEATURE_SCORE_REFRESH_ENV, True)


def _feature_score_refresh_interval():
    return _env_int(FEATURE_SCORE_REFRESH_INTERVAL_ENV, 30, lower=1, upper=3600)


def _maybe_refresh_feature_scores(force=False):
    del force
    return None


def _pregen_enabled():
    # Deprecated. MutatorMin is back to synchronous stage-local mutation; keep
    # this helper only for old status fields and accidental env leftovers.
    return False


def _pregen_count():
    return _env_int(MUTATOR_PREGEN_COUNT_ENV, STAGE_EXEC_COUNT, lower=1, upper=max(STAGE_EXEC_COUNT, 4096))


def _pregen_workers():
    return _env_int(MUTATOR_PREGEN_WORKERS_ENV, 1, lower=1, upper=16)


def _pregen_max_bytes():
    mb = _env_int(MUTATOR_PREGEN_MAX_MB_ENV, 64, lower=1, upper=4096)
    return mb * 1024 * 1024


def _pregen_max_tasks():
    return _env_int(MUTATOR_PREGEN_MAX_TASKS_ENV, 64, lower=1, upper=4096)


def _pregen_input_key(data):
    raw = bytes(_coerce_mutated_buffer(data, bytearray()))
    template_sig = __template_executor_info__.get("signature")
    key_material = {
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size": len(raw),
        "template_path": __template_executor_info__.get("path"),
        "template_signature": list(template_sig or []),
    }
    encoded = json.dumps(key_material, sort_keys=True, default=str).encode("utf-8", errors="replace")
    return hashlib.sha256(encoded).hexdigest(), key_material


def _pregen_running_count_locked():
    return sum(1 for task in __pregen_tasks__.values() if task.get("running"))


def _pregen_total_bytes_locked():
    total = 0
    for task in __pregen_tasks__.values():
        outputs = task.get("outputs")
        if not isinstance(outputs, deque):
            continue
        for item in outputs:
            data = item.get("data") if isinstance(item, dict) else None
            if isinstance(data, (bytes, bytearray)):
                total += len(data)
    return total


def _pregen_cancel_task_decision(task, reason):
    del task, reason


def _pregen_drop_task_locked(key, reason):
    task = __pregen_tasks__.pop(key, None)
    _pregen_cancel_task_decision(task, reason)
    __pregen_stats__["stale_drops"] = int(__pregen_stats__.get("stale_drops", 0) or 0) + 1


def _pregen_prune_locked(current_key=None):
    now = int(time.time())
    for key, task in list(__pregen_tasks__.items()):
        if key == current_key or task.get("running"):
            continue
        if now - int(task.get("finished_ts", task.get("started_ts", now)) or now) > 300:
            _pregen_drop_task_locked(key, "pregen_task_ttl_expired")

    max_tasks = _pregen_max_tasks()
    if len(__pregen_tasks__) > max_tasks:
        candidates = sorted(
            (
                (int(task.get("finished_ts", task.get("started_ts", 0)) or 0), key)
                for key, task in __pregen_tasks__.items()
                if key != current_key and not task.get("running")
            ),
            key=lambda item: item[0],
        )
        for _, key in candidates[:max(0, len(__pregen_tasks__) - max_tasks)]:
            _pregen_drop_task_locked(key, "pregen_task_limit")

    max_bytes = _pregen_max_bytes()
    while _pregen_total_bytes_locked() > max_bytes:
        candidates = sorted(
            (
                (int(task.get("finished_ts", task.get("started_ts", 0)) or 0), key)
                for key, task in __pregen_tasks__.items()
                if key != current_key and not task.get("running")
            ),
            key=lambda item: item[0],
        )
        if not candidates:
            break
        _pregen_drop_task_locked(candidates[0][1], "pregen_memory_limit")


def _pregen_runtime_execution_template(mutator_file):
    selected_ops = [mutator_file] if isinstance(mutator_file, str) and mutator_file else []
    return {
        "selection_kind": "seed_op_counter",
        "arm": mutator_file,
        "selected_ops": list(selected_ops),
        "applied_ops": list(selected_ops),
        "op_applied": bool(selected_ops),
    }


def _pregen_worker(key, input_bytes, mutate, mutator_file, count, limit, execution_template, template_context):
    task = None
    start = time.time()
    previous_context = getattr(__pregen_thread_local__, "template_context", None)
    try:
        __pregen_thread_local__.template_context = template_context
        with __pregen_lock__:
            task = __pregen_tasks__.get(key)
        original = bytes(input_bytes or b"")
        for _ in range(max(1, int(count or 1))):
            call_start = time.time()
            actual_execution_info = None
            try:
                __pregen_thread_local__.last_execution_info = None
                __pregen_thread_local__.suppress_optimizer_record = True
                mutated = mutate(bytearray(original), limit)
                actual_execution_info = getattr(__pregen_thread_local__, "last_execution_info", None)
            except Exception as exc:
                with __pregen_lock__:
                    task = __pregen_tasks__.get(key)
                    if isinstance(task, dict):
                        task["errors"] = int(task.get("errors", 0) or 0) + 1
                        task["last_error"] = str(exc)[:500]
                continue
            finally:
                __pregen_thread_local__.suppress_optimizer_record = False
                __pregen_thread_local__.last_execution_info = None
            mutated = _coerce_mutated_buffer(mutated, bytearray(original))
            if not mutated or len(mutated) > limit:
                continue
            data = bytes(mutated)
            if isinstance(actual_execution_info, dict):
                execution_info = dict(actual_execution_info)
            else:
                execution_info = dict(execution_template or {})
                execution_info["output_changed"] = data != original
                if execution_info and not execution_info["output_changed"]:
                    execution_info["op_applied"] = False
                    execution_info["applied_ops"] = []
            execution_info["pregen_output_changed"] = data != original
            executor_info = _active_template_executor_info()
            execution_info["template_path"] = executor_info.get("path")
            execution_info["template_signature"] = list(executor_info.get("signature") or [])
            item = {
                "data": data,
                "execution_info": execution_info,
                "mutate_ms": (time.time() - call_start) * 1000.0,
            }
            with __pregen_lock__:
                task = __pregen_tasks__.get(key)
                if not isinstance(task, dict):
                    return
                outputs = task.get("outputs")
                if isinstance(outputs, deque):
                    outputs.append(item)
                task["produced"] = int(task.get("produced", 0) or 0) + 1
                task["produced_bytes"] = int(task.get("produced_bytes", 0) or 0) + len(data)
    except Exception as exc:
        with __pregen_lock__:
            task = __pregen_tasks__.get(key)
            if isinstance(task, dict):
                task["last_error"] = str(exc)[:500]
        __pregen_stats__["worker_errors"] = int(__pregen_stats__.get("worker_errors", 0) or 0) + 1
    finally:
        if previous_context is None:
            try:
                delattr(__pregen_thread_local__, "template_context")
            except AttributeError:
                pass
        else:
            __pregen_thread_local__.template_context = previous_context
        with __pregen_lock__:
            task = __pregen_tasks__.get(key)
            if isinstance(task, dict):
                task["running"] = False
                task["ready"] = bool(task.get("outputs"))
                task["finished_ts"] = int(time.time())
                task["duration_ms"] = (time.time() - start) * 1000.0
                if task["ready"]:
                    __pregen_stats__["ready"] = int(__pregen_stats__.get("ready", 0) or 0) + 1
            _pregen_prune_locked(current_key=key)


def _pregen_schedule_for_input(buf):
    original = bytes(_coerce_mutated_buffer(buf, bytearray()))
    if not original:
        return None
    key, key_material = _pregen_input_key(original)
    with __pregen_lock__:
        _pregen_prune_locked(current_key=key)
        existing = __pregen_tasks__.get(key)
        if isinstance(existing, dict):
            return key
        if _pregen_running_count_locked() >= _pregen_workers():
            __pregen_stats__["last_skip_reason"] = "worker_busy"
            return None

    selected_mutator = None
    mutate = None
    template_context = None
    try:
        _ensure_batch_cache()
        selected_mutator = mutator_selector(bytearray(original))
        __batch_cache__["stage_mutator"] = selected_mutator
        mutate = _load_mutate_function(selected_mutator)
        template_context = _template_runtime_context()
    except Exception as exc:
        __pregen_stats__["last_skip_reason"] = f"selector_error:{str(exc)[:120]}"
    finally:
        # This fuzz_count call is going to return 0, so AFL will not deliver a
        # stage_feedback callback. Release the temporary selector snapshot now.
        _flush_batch_cache(reset_active=True)

    if selected_mutator is None or mutate is None:
        __pregen_stats__["last_skip_reason"] = "no_mutator"
        if selected_mutator is None:
            try:
                _evolve_mutator(force=True)
            except Exception:
                pass
        return None

    execution_template = _pregen_runtime_execution_template(selected_mutator)
    task = {
        "key": key,
        "key_material": key_material,
        "mutator": selected_mutator,
        "stable_id": _stable_mutator_id(selected_mutator),
        "template_context": template_context,
        "outputs": deque(),
        "running": True,
        "ready": False,
        "started_ts": int(time.time()),
        "produced": 0,
        "consumed": 0,
        "errors": 0,
        "max_size": MAX_OUTPUT_SIZE,
    }
    with __pregen_lock__:
        __pregen_tasks__[key] = task
        __pregen_stats__["scheduled"] = int(__pregen_stats__.get("scheduled", 0) or 0) + 1
        __pregen_stats__["last_key"] = key
        __pregen_stats__["last_mutator"] = selected_mutator
    worker = threading.Thread(
        target=_pregen_worker,
        args=(
            key,
            original,
            mutate,
            selected_mutator,
            _pregen_count(),
            MAX_OUTPUT_SIZE,
            execution_template,
            template_context,
        ),
        name=f"MutatorMinPregen-{key[:8]}",
        daemon=True,
    )
    task["thread"] = worker
    worker.start()
    return key


def _pregen_prepare_stage(buf):
    global __pregen_current_key__
    key, _ = _pregen_input_key(buf)
    with __pregen_lock__:
        task = __pregen_tasks__.get(key)
        if isinstance(task, dict) and task.get("ready") and isinstance(task.get("outputs"), deque) and task["outputs"]:
            count = min(len(task["outputs"]), _pregen_count())
            __pregen_current_key__ = key
            __pregen_stats__["cache_hits"] = int(__pregen_stats__.get("cache_hits", 0) or 0) + 1
            __pregen_stats__["last_key"] = key
            __pregen_stats__["last_mutator"] = task.get("mutator")
            selected_mutator = task.get("mutator")
        else:
            __pregen_stats__["cache_misses"] = int(__pregen_stats__.get("cache_misses", 0) or 0) + 1
            __pregen_stats__["skipped_empty"] = int(__pregen_stats__.get("skipped_empty", 0) or 0) + 1
            __pregen_stats__["last_skip_reason"] = "queue_empty"
            selected_mutator = None
            count = 0
    if count <= 0:
        __pregen_current_key__ = None
        _pregen_schedule_for_input(buf)
        return 0

    _ensure_batch_cache()
    __batch_cache__["stage_mutator"] = selected_mutator
    __batch_cache__["async_pregen_stage"] = {
        "enabled": True,
        "key": key,
        "mutator": selected_mutator,
        "available_at_start": count,
        "consumed": 0,
        "empty_returns": 0,
        "mutate_ms_total": 0.0,
        "mutate_ms_max": 0.0,
    }
    return count


def _pregen_pop_output(max_size):
    global __pregen_current_key__
    key = __pregen_current_key__
    if not key:
        return None
    with __pregen_lock__:
        task = __pregen_tasks__.get(key)
        outputs = task.get("outputs") if isinstance(task, dict) else None
        if not isinstance(outputs, deque) or not outputs:
            __pregen_stats__["cache_misses"] = int(__pregen_stats__.get("cache_misses", 0) or 0) + 1
            return None
        item = outputs.popleft()
        task["consumed"] = int(task.get("consumed", 0) or 0) + 1
        if not outputs and not task.get("running"):
            task["ready"] = False
    if not isinstance(item, dict):
        return None
    data = item.get("data")
    if not isinstance(data, (bytes, bytearray)):
        return None
    if len(data) > max_size:
        return None
    execution_info = item.get("execution_info")
    selected_mutator = __batch_cache__.get("stage_mutator")
    if isinstance(execution_info, dict):
        _record_optimizer_execution(selected_mutator, execution_info)
    stage = __batch_cache__.setdefault("async_pregen_stage", {})
    if isinstance(stage, dict):
        stage["consumed"] = int(stage.get("consumed", 0) or 0) + 1
        mutate_ms = float(item.get("mutate_ms", 0.0) or 0.0)
        stage["mutate_ms_total"] = float(stage.get("mutate_ms_total", 0.0) or 0.0) + mutate_ms
        stage["mutate_ms_max"] = max(float(stage.get("mutate_ms_max", 0.0) or 0.0), mutate_ms)
    __pregen_stats__["consumed"] = int(__pregen_stats__.get("consumed", 0) or 0) + 1
    return bytearray(data)


def _pregen_stage_feedback_summary():
    stage = __batch_cache__.get("async_pregen_stage")
    if not isinstance(stage, dict) or not stage.get("enabled"):
        return None
    consumed = int(stage.get("consumed", 0) or 0)
    total_ms = float(stage.get("mutate_ms_total", 0.0) or 0.0)
    summary = dict(stage)
    summary["avg_mutate_ms"] = total_ms / max(consumed, 1)
    return summary


def _pregen_status():
    with __pregen_lock__:
        tasks = list(__pregen_tasks__.values())
        ready_tasks = sum(1 for task in tasks if task.get("ready"))
        running_tasks = sum(1 for task in tasks if task.get("running"))
        queued_outputs = 0
        queued_bytes = 0
        for task in tasks:
            outputs = task.get("outputs")
            if not isinstance(outputs, deque):
                continue
            queued_outputs += len(outputs)
            for item in outputs:
                data = item.get("data") if isinstance(item, dict) else None
                if isinstance(data, (bytes, bytearray)):
                    queued_bytes += len(data)
        status = dict(__pregen_stats__)
    status.update({
        "enabled": _pregen_enabled(),
        "task_count": len(tasks),
        "ready_tasks": ready_tasks,
        "running_tasks": running_tasks,
        "queued_outputs": queued_outputs,
        "queued_bytes": queued_bytes,
        "current_key": __pregen_current_key__,
        "pregen_count": _pregen_count(),
        "workers": _pregen_workers(),
        "max_mb": _env_int(MUTATOR_PREGEN_MAX_MB_ENV, 64, lower=1, upper=4096),
    })
    return status


def _mutatormin_stall_enabled():
    if os.environ.get(MUTATOR_STALL_ENABLE_ENV) is not None:
        return _env_flag(MUTATOR_STALL_ENABLE_ENV, True)
    return False


def _mutatormin_stall_config():
    return {
        "enabled": _mutatormin_stall_enabled(),
        "window_secs": _env_int(MUTATOR_STALL_WINDOW_ENV, 600, lower=1, upper=86400),
        "min_stages": _env_int(MUTATOR_STALL_MIN_STAGES_ENV, 512, lower=1, upper=1000000),
        "max_finds": _env_int(MUTATOR_STALL_MAX_FINDS_ENV, 1, lower=0, upper=1000000),
        "cooldown_secs": _env_int(MUTATOR_STALL_COOLDOWN_ENV, 900, lower=1, upper=86400),
    }


def _selected_op_from_stage(stage_entry):
    if not isinstance(stage_entry, dict):
        return None
    selected_op = stage_entry.get("selected_op") or stage_entry.get("mutator_file")
    return selected_op if isinstance(selected_op, str) and selected_op else None


def _safe_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return int(default)


def _mutatormin_event_effective(event):
    if not isinstance(event, dict):
        return False
    if not isinstance(event.get("selected_op"), str) or not event.get("selected_op"):
        return False
    op_calls = _safe_int(event.get("op_calls"))
    if op_calls <= 0:
        return False
    if event.get("op_applied"):
        return True
    return _safe_int(event.get("op_changed_calls")) > 0 or _safe_int(event.get("op_error_calls")) > 0


def _mutatormin_window_stats(events, config=None, now=None):
    config = config if isinstance(config, dict) else _mutatormin_stall_config()
    now = int(now or time.time())
    window_secs = int(config.get("window_secs", 600) or 600)
    recent = []
    for event in events or []:
        if not _mutatormin_event_effective(event):
            continue
        try:
            ts = int(event.get("ts", 0) or 0)
        except (TypeError, ValueError):
            continue
        if ts > 0 and now - ts <= window_secs:
            recent.append(event)
    direct_finds = 0
    op_counts = {}
    changed_calls = 0
    op_calls = 0
    for event in recent:
        try:
            direct_finds += int(event.get("stage_finds", 0) or 0)
        except (TypeError, ValueError):
            pass
        try:
            changed_calls += int(event.get("op_changed_calls", 0) or 0)
        except (TypeError, ValueError):
            pass
        try:
            op_calls += int(event.get("op_calls", 0) or 0)
        except (TypeError, ValueError):
            pass
        op_name = event.get("selected_op")
        if isinstance(op_name, str) and op_name:
            op_counts[op_name] = int(op_counts.get(op_name, 0) or 0) + 1
    stage_count = len(recent)
    return {
        "window_secs": window_secs,
        "stage_count": stage_count,
        "direct_finds": direct_finds,
        "direct_find_rate": direct_finds / max(stage_count, 1),
        "op_calls": op_calls,
        "op_changed_calls": changed_calls,
        "op_counts": dict(sorted(op_counts.items())),
        "events": recent,
    }


def _mutatormin_stall_status(config=None, now=None):
    config = config if isinstance(config, dict) else _mutatormin_stall_config()
    now = int(now or time.time())
    state = _load_json_dict(_mutatormin_progress_path())
    events = state.get("events", []) if isinstance(state.get("events"), list) else []
    stats = _mutatormin_window_stats(events, config=config, now=now)
    last_trigger_ts = int(state.get("last_trigger_ts", 0) or 0)
    cooldown_secs = int(config.get("cooldown_secs", 900) or 900)
    min_stages = int(config.get("min_stages", 512) or 512)
    max_finds = int(config.get("max_finds", 1))
    cooldown_until = last_trigger_ts + cooldown_secs if last_trigger_ts else 0
    return {
        "enabled": bool(config.get("enabled")),
        "window_secs": stats["window_secs"],
        "window_stage_count": stats["stage_count"],
        "window_direct_finds": stats["direct_finds"],
        "direct_find_rate": stats["direct_find_rate"],
        "min_stages": min_stages,
        "max_finds": max_finds,
        "cooldown_secs": cooldown_secs,
        "last_trigger_ts": last_trigger_ts,
        "cooldown_until": cooldown_until,
        "in_cooldown": bool(cooldown_until and now < cooldown_until),
        "last_trigger_reason": state.get("last_trigger_reason"),
        "last_request": state.get("last_request"),
        "op_counts": stats["op_counts"],
    }


def _handle_mutatormin_template_stall(request):
    """Reuse the G2FUZZ-style stall signal without starting online-op generation."""
    if not isinstance(request, dict):
        return
    payload = dict(request)
    payload["action"] = "refresh_template_pool"
    payload["template_executor_dir"] = _format_executor_dir()
    try:
        __template_pool__["last_refresh_ns"] = 0
        if _template_pool_enabled():
            _refresh_template_pool()
        _write_json_dict(_template_stall_trigger_path(), payload)
    except Exception as exc:
        sys.stderr.write(f"[MutatorMin] Failed to handle template stall trigger: {exc}\n")


def _record_mutatormin_stage_progress(stage_entry):
    if not _progress_writes_enabled():
        return {}
    config = _mutatormin_stall_config()
    now = int(time.time())
    state = _load_json_dict(_mutatormin_progress_path())
    events = state.get("events", []) if isinstance(state.get("events"), list) else []
    selected_op = _selected_op_from_stage(stage_entry)
    op_calls = _safe_int(stage_entry.get("op_calls"))
    op_changed_calls = _safe_int(stage_entry.get("op_changed_calls"))
    op_error_calls = _safe_int(stage_entry.get("op_error_calls"))
    event = {
        "ts": now,
        "selected_op": selected_op,
        "stage_finds": _safe_int(stage_entry.get("stage_finds")),
        "op_applied": bool(stage_entry.get("op_applied")),
        "op_calls": op_calls,
        "op_changed_calls": op_changed_calls,
        "op_error_calls": op_error_calls,
    }
    event_effective = _mutatormin_event_effective(event)
    if event_effective:
        events.append(event)
    else:
        state["ignored_stage_count"] = _safe_int(state.get("ignored_stage_count")) + 1
        state["last_ignored_stage"] = event
    stats = _mutatormin_window_stats(events, config=config, now=now)
    state.update({
        "version": 1,
        "updated_ts": now,
        "events": stats["events"],
        "window": {
            key: value for key, value in stats.items()
            if key != "events"
        },
        "config": config,
    })

    last_trigger_ts = int(state.get("last_trigger_ts", 0) or 0)
    cooldown_secs = int(config.get("cooldown_secs", 900) or 900)
    request_ttl_secs = max(cooldown_secs * 2, int(config.get("window_secs", 600) or 600) + cooldown_secs)
    min_stages = int(config.get("min_stages", 512) or 512)
    max_finds = int(config.get("max_finds", 1))
    should_trigger = (
        event_effective and
        bool(config.get("enabled")) and
        stats["stage_count"] >= min_stages and
        stats["direct_finds"] <= max_finds and
        (not last_trigger_ts or now - last_trigger_ts >= cooldown_secs)
    )
    if should_trigger:
        request = {
            "version": 1,
            "source": "MutatorMin",
            "reason": "mutatormin_low_direct_find_rate",
            "requested_ts": now,
            "expires_ts": now + request_ttl_secs,
            "window": {
                key: value for key, value in stats.items()
                if key != "events"
            },
            "config": config,
            "last_selected_op": event["selected_op"],
        }
        _handle_mutatormin_template_stall(request)
        state["last_trigger_ts"] = now
        state["last_trigger_reason"] = request["reason"]
        state["last_request"] = {
            "requested_ts": request["requested_ts"],
            "expires_ts": request["expires_ts"],
            "reason": request["reason"],
            "window": request["window"],
        }
    _write_json_dict(_mutatormin_progress_path(), state)
    return state


def _seed_generation_enabled():
    return _env_flag(SEED_GEN_ENV, True)


def _seed_pool_enabled():
    return False


def _seed_async_generation_enabled():
    return _env_flag(SEED_ASYNC_GEN_ENV, True)


def _seed_format():
    return str(os.environ.get(SEED_FORMAT_ENV, "elf") or "elf").strip().lower()


def _seed_source_mode():
    return str(os.environ.get(SEED_SOURCE_MODE_ENV, "format-only") or "format-only").strip().lower().replace("_", "-")


def _seed_sample_probability():
    return 0.0


def _seed_mutate_probability():
    return 0.0


def _seed_max_files():
    return _env_int(SEED_MAX_FILES_ENV, 8, 1, 128)


def _seed_llm_config_available():
    model = llm_config.resolve_model(default="deepseek-v4-flash")
    return bool(llm_config.resolve_api_key(model))


def _safe_seed_token(value, fallback="item"):
    token = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in str(value or ""))
    token = token.strip("._-")
    return (token or fallback)[:64]


def _load_seed_features():
    if __batch_cache__.get("active"):
        metadata = __batch_cache__.setdefault("seed_features", {})
        return _prune_missing_seed_entries(metadata)
    return _prune_missing_seed_entries(_load_json_dict(_seed_features_path()))


def _refresh_seed_features_if_changed():
    if not __batch_cache__.get("active") or __batch_cache__.get("seed_features_dirty"):
        return
    signature = _file_signature(_seed_features_path())
    if signature is None or signature == __batch_cache__.get("seed_features_signature"):
        return
    __batch_cache__["seed_features"] = _prune_missing_seed_entries(_load_json_dict(_seed_features_path()))
    __batch_cache__["seed_features_signature"] = signature


def _mark_seed_features_dirty():
    if __batch_cache__.get("active"):
        __batch_cache__["seed_features_dirty"] = True


def _write_seed_features(metadata):
    metadata = _prune_missing_seed_entries(metadata)
    if __batch_cache__.get("active"):
        __batch_cache__["seed_features"] = metadata if isinstance(metadata, dict) else {}
        __batch_cache__["seed_features_dirty"] = True
        return
    _write_json_dict(_seed_features_path(), metadata)


def _prune_missing_seed_entries(metadata):
    if not isinstance(metadata, dict):
        return {}
    seeds = metadata.get("seeds")
    if not isinstance(seeds, dict):
        return metadata
    for key, entry in list(seeds.items()):
        if isinstance(entry, dict):
            seed_path = entry.get("path") or key
        else:
            seed_path = key
        if not isinstance(seed_path, str) or not seed_path:
            seeds.pop(key, None)
            continue
        abs_path = seed_path if os.path.isabs(seed_path) else os.path.join(_base_dir(), seed_path)
        if not os.path.isfile(abs_path):
            seeds.pop(key, None)
    return metadata


def _merge_seed_features(disk_metadata, memory_metadata):
    merged = disk_metadata if isinstance(disk_metadata, dict) else {}
    if not isinstance(memory_metadata, dict):
        return _prune_missing_seed_entries(merged)
    merged.setdefault("version", 1)
    for section in ("features", "generators", "seeds"):
        disk_section = merged.setdefault(section, {})
        memory_section = memory_metadata.get(section, {})
        if not isinstance(disk_section, dict) or not isinstance(memory_section, dict):
            merged[section] = memory_section if isinstance(memory_section, dict) else disk_section
            continue
        for key, value in memory_section.items():
            if isinstance(value, dict):
                current = disk_section.get(key, {})
                if isinstance(current, dict):
                    updated = dict(current)
                    updated.update(value)
                    disk_section[key] = updated
                else:
                    disk_section[key] = value
            else:
                disk_section[key] = value
    return _prune_missing_seed_entries(merged)


def _seed_abs_path(seed_path):
    if not isinstance(seed_path, str) or not seed_path:
        return None
    if os.path.isabs(seed_path):
        return seed_path
    return os.path.join(_base_dir(), seed_path)


def _seed_pool_entries():
    _refresh_seed_features_if_changed()
    metadata = _load_seed_features()
    seeds = metadata.get("seeds", {}) if isinstance(metadata, dict) else {}
    entries = []
    if isinstance(seeds, dict):
        for rel_path, entry in seeds.items():
            if not isinstance(entry, dict):
                continue
            seed_path = _seed_abs_path(entry.get("path") or rel_path)
            if not seed_path or not os.path.isfile(seed_path):
                continue
            candidate = dict(entry)
            candidate["path"] = os.path.relpath(seed_path, _base_dir())
            entries.append(candidate)

    if entries:
        return entries

    seed_dir = _generated_seed_dir()
    if not os.path.isdir(seed_dir):
        return []
    for name in sorted(os.listdir(seed_dir)):
        path = os.path.join(seed_dir, name)
        if not os.path.isfile(path):
            continue
        entries.append({
            "path": os.path.relpath(path, _base_dir()),
            "format": _seed_format(),
            "features": ["untracked_generated_seed"],
            "generator_id": "untracked",
            "finds": 0,
            "stage_calls": 0,
        })
    return entries


def _seed_entry_weight(entry, metadata):
    try:
        seed_finds = int(entry.get("finds", 0) or 0)
    except (TypeError, ValueError):
        seed_finds = 0
    try:
        seed_calls = int(entry.get("stage_calls", 0) or 0)
    except (TypeError, ValueError):
        seed_calls = 0
    weight = 1.0 + seed_finds / max(seed_calls, 1)

    generators = metadata.get("generators", {}) if isinstance(metadata, dict) else {}
    generator_entry = generators.get(entry.get("generator_id"))
    if isinstance(generator_entry, dict):
        try:
            weight += int(generator_entry.get("finds", 0) or 0) * 0.25
        except (TypeError, ValueError):
            pass
    return max(weight, 0.01)


def _choose_seed_entry():
    entries = _seed_pool_entries()
    if not entries:
        return None
    metadata = _load_seed_features()
    weights = [_seed_entry_weight(entry, metadata) for entry in entries]
    try:
        return random.choices(entries, weights=weights, k=1)[0]
    except Exception:
        return random.choice(entries)


def _seed_pool_ready():
    return (
        _seed_pool_enabled() and
        _seed_sample_probability() > 0.0 and
        bool(_seed_pool_entries())
    )


def _seed_context_from_entry(entry, applied_template=False):
    if not isinstance(entry, dict):
        return None
    return {
        "seed_path": entry.get("path"),
        "seed_id": entry.get("seed_id") or entry.get("sha256"),
        "format": entry.get("format") or _seed_format(),
        "primary_feature": entry.get("primary_feature"),
        "features": list(entry.get("features", []) or []),
        "generator_id": entry.get("generator_id"),
        "generation_strategy": entry.get("generation_strategy"),
        "mutation_source": entry.get("mutation_source"),
        "input_sha256": entry.get("input_sha256"),
        "applied_template_mutation": bool(applied_template),
    }


def _update_seed_stats(seed_context, found=False, stage_call=False):
    if not isinstance(seed_context, dict):
        return
    metadata = _load_seed_features()
    if not isinstance(metadata, dict):
        metadata = {}
    metadata.setdefault("version", 1)
    seeds = metadata.setdefault("seeds", {})
    features = metadata.setdefault("features", {})
    generators = metadata.setdefault("generators", {})
    now = int(time.time())

    seed_path = seed_context.get("seed_path")
    seed_entry = seeds.get(seed_path, {}) if isinstance(seeds.get(seed_path), dict) else {}
    seed_entry.update({
        "path": seed_path,
        "format": seed_context.get("format") or seed_entry.get("format") or _seed_format(),
        "primary_feature": seed_context.get("primary_feature") or seed_entry.get("primary_feature"),
        "features": list(seed_context.get("features") or seed_entry.get("features") or []),
        "generator_id": seed_context.get("generator_id") or seed_entry.get("generator_id"),
        "generation_strategy": seed_context.get("generation_strategy") or seed_entry.get("generation_strategy"),
        "mutation_source": seed_context.get("mutation_source") or seed_entry.get("mutation_source"),
        "input_sha256": seed_context.get("input_sha256") or seed_entry.get("input_sha256"),
        "last_used": now,
    })
    if stage_call:
        seed_entry["stage_calls"] = int(seed_entry.get("stage_calls", 0) or 0) + 1
    if found:
        seed_entry["finds"] = int(seed_entry.get("finds", 0) or 0) + 1
    if seed_path:
        seeds[seed_path] = seed_entry

    generator_id = seed_context.get("generator_id")
    if generator_id:
        gen_entry = generators.get(generator_id, {}) if isinstance(generators.get(generator_id), dict) else {}
        gen_entry.setdefault("generator_id", generator_id)
        gen_entry.setdefault("format", seed_context.get("format") or _seed_format())
        gen_entry.setdefault("primary_feature", seed_context.get("primary_feature"))
        gen_entry.setdefault("features", list(seed_context.get("features") or []))
        if seed_context.get("generation_strategy"):
            gen_entry.setdefault("generation_strategy", seed_context.get("generation_strategy"))
        if seed_context.get("mutation_source"):
            gen_entry.setdefault("mutation_source", seed_context.get("mutation_source"))
        gen_entry["last_used"] = now
        if stage_call:
            gen_entry["stage_calls"] = int(gen_entry.get("stage_calls", 0) or 0) + 1
        if found:
            gen_entry["finds"] = int(gen_entry.get("finds", 0) or 0) + 1
        generators[generator_id] = gen_entry

    for feature in seed_context.get("features") or []:
        feature_key = _safe_seed_token(feature, "feature")
        feature_entry = features.get(feature_key, {}) if isinstance(features.get(feature_key), dict) else {}
        feature_entry.setdefault("feature", feature)
        feature_entry.setdefault("format", seed_context.get("format") or _seed_format())
        feature_entry["last_used"] = now
        if stage_call:
            feature_entry["stage_calls"] = int(feature_entry.get("stage_calls", 0) or 0) + 1
        if found:
            feature_entry["finds"] = int(feature_entry.get("finds", 0) or 0) + 1
        features[feature_key] = feature_entry

    _write_seed_features(metadata)


def _append_mutation_pair(filename_new_queue, filename_orig_queue, seed_context):
    if not isinstance(seed_context, dict):
        return
    try:
        _ensure_mutators_path()
        record = {
            "ts": int(time.time()),
            "new_queue": filename_new_queue,
            "orig_queue": filename_orig_queue,
            "mutator": __mutator__,
            "stable_id": _stable_mutator_id(__mutator__),
            "seed_context": seed_context,
        }
        with open(_mutation_pairs_path(), "a", encoding="utf-8") as f:
            f.write(json.dumps(record, sort_keys=True) + "\n")
    except OSError as e:
        sys.stderr.write(f"[MutatorMin] Failed to append mutation pair: {e}\n")


def _online_registry_diagnostics(metadata, handlers):
    del metadata, handlers
    return {}


def _record_online_op_execution(op_name, applied=False, changed=False, error=False, structure_survived=None):
    del op_name, applied, changed, error, structure_survived
    return None


def _optimizer_feature_op_diagnostics(arms):
    del arms
    return {}


def _online_seed_accepted_source(entry):
    if not isinstance(entry, dict):
        return "unknown"
    source = entry.get("accepted_source")
    if source in {"runtime_import", "startup_seed", "unknown"}:
        return source
    has_startup = False
    has_unknown = False
    for name in entry.get("accepted_queue_files") or []:
        base = os.path.basename(str(name))
        if "sync:" in base:
            return "runtime_import"
        if "orig:" in base:
            has_startup = True
        else:
            has_unknown = True
    if has_startup:
        return "startup_seed"
    return "unknown" if has_unknown else "unknown"


def _online_seed_feature_summary():
    payload = _load_json_dict(_online_seed_status_path())
    seeds = payload.get("seeds", {}) if isinstance(payload, dict) else {}
    by_feature = {}
    computed_summary = {
        "published_total": 0,
        "accepted_total": 0,
        "accepted_runtime_import_total": 0,
        "accepted_startup_total": 0,
        "accepted_unknown_total": 0,
        "pending_total": 0,
    }
    if isinstance(seeds, dict):
        for entry in seeds.values():
            if not isinstance(entry, dict):
                continue
            computed_summary["published_total"] += 1
            accepted = entry.get("status") == "accepted"
            accepted_source = _online_seed_accepted_source(entry) if accepted else ""
            if accepted:
                computed_summary["accepted_total"] += 1
                if accepted_source == "runtime_import":
                    computed_summary["accepted_runtime_import_total"] += 1
                elif accepted_source == "startup_seed":
                    computed_summary["accepted_startup_total"] += 1
                else:
                    computed_summary["accepted_unknown_total"] += 1
            else:
                computed_summary["pending_total"] += 1
            feature_ids = []
            for value in entry.get("feature_ids") or []:
                if isinstance(value, str) and value and value not in feature_ids:
                    feature_ids.append(value)
            for value in (entry.get("feature_id"), entry.get("primary_feature_id")):
                if isinstance(value, str) and value and value not in feature_ids:
                    feature_ids.append(value)
            if not feature_ids:
                feature_ids = ["unknown"]
            for feature_id in feature_ids:
                item = by_feature.setdefault(feature_id, {
                    "published": 0,
                    "accepted": 0,
                    "accepted_runtime_import": 0,
                    "accepted_startup": 0,
                    "accepted_unknown": 0,
                    "pending": 0,
                })
                item["published"] += 1
                if accepted:
                    item["accepted"] += 1
                    if accepted_source == "runtime_import":
                        item["accepted_runtime_import"] += 1
                    elif accepted_source == "startup_seed":
                        item["accepted_startup"] += 1
                    else:
                        item["accepted_unknown"] += 1
                else:
                    item["pending"] += 1
    top_features = [
        {"feature_id": feature_id, **counts}
        for feature_id, counts in sorted(
            by_feature.items(),
            key=lambda pair: (pair[1].get("accepted", 0), pair[1].get("published", 0), pair[0]),
            reverse=True,
        )
    ][:16]
    summary = dict(payload.get("summary", {}) if isinstance(payload, dict) else {})
    summary.update(computed_summary)
    return {
        "summary": summary,
        "top_features": top_features,
    }


def _write_runtime_status(reason):
    """Publish the active template snapshot outside the fuzz hot path."""
    if not _runtime_status_writes_enabled():
        return
    try:
        status = {
            "reason": reason,
            "template_executor": {
                "path": __template_executor_info__.get("path"),
                "name": __template_executor_info__.get("name"),
                "signature": list(__template_executor_info__.get("signature") or []),
                "feature_matching": "disabled_reward_driven",
            },
            "template_pool": _template_feedback_status(),
            "core_ops": sorted(_template_core_mutation_ops()),
            "repair_ops": sorted(FORMAT_REPAIR_OPS),
            "mutatormin_stall": _mutatormin_stall_status(),
            "bottleneck_expansion": _bottleneck_expansion_status(),
            "async_pregen": _pregen_status(),
        }
        _write_json_dict(_runtime_status_path(), status)
    except Exception as e:
        sys.stderr.write(f"[MutatorMin] Failed to write runtime status: {e}\n")


def _ensure_mutators_path():
    if os.path.exists(_mutators_dir()) is False:
        os.makedirs(_mutators_dir())
    if os.path.exists(_template_plan_dir()) is False:
        os.makedirs(_template_plan_dir())
    if os.path.exists(_seed_artifacts_dir()) is False:
        os.makedirs(_seed_artifacts_dir())
    if os.path.exists(_seed_generator_dir()) is False:
        os.makedirs(_seed_generator_dir())
    if os.path.exists(_generated_seed_dir()) is False:
        os.makedirs(_generated_seed_dir())
    if os.path.exists(_seed_input_dir()) is False:
        os.makedirs(_seed_input_dir())


def _refresh_online_op_registry():
    return None


def _load_batch_cache():
    global __batch_cache__

    _refresh_template_executor()

    # Stage start: take one snapshot of disk state for all fuzz() calls in this
    # AFL custom-mutator stage.
    __batch_cache__["index"] = _load_json_dict(_index_path())
    __batch_cache__["index_signature"] = _file_signature(_index_path())
    __batch_cache__["coverage"] = {}
    __batch_cache__["seed_features"] = _load_json_dict(_seed_features_path())
    __batch_cache__["seed_features_signature"] = _file_signature(_seed_features_path())
    __batch_cache__["index_dirty"] = False
    __batch_cache__["index_dirty_keys"] = set()
    __batch_cache__["coverage_dirty"] = False
    __batch_cache__["seed_features_dirty"] = False
    __batch_cache__["stage_mutator"] = None
    __batch_cache__["optimizer_stage"] = {}
    __batch_cache__["mutatormin_direct_finds"] = 0
    __batch_cache__["active"] = True
    _write_runtime_status("stage_start")


def _ensure_batch_cache():
    if __batch_cache__["active"]:
        return

    _ensure_mutators_path()
    _load_batch_cache()


def _flush_batch_cache(reset_active=True):
    global __batch_cache__
    global __pregen_current_key__

    if __batch_cache__.get("index_dirty"):
        # Merge only the entries touched by this stage so background plan
        # generation writes are not lost when this delayed flush lands.
        merged_index = _load_json_dict(_index_path())
        dirty_keys = __batch_cache__.get("index_dirty_keys") or set()
        if dirty_keys:
            for key in dirty_keys:
                if key in __batch_cache__.get("index", {}):
                    merged_index[key] = __batch_cache__["index"][key]
        else:
            merged_index = __batch_cache__.get("index", {})
        _write_json_dict(_index_path(), merged_index)
        __batch_cache__["index"] = merged_index
        __batch_cache__["index_signature"] = _file_signature(_index_path())
        __batch_cache__["index_dirty"] = False
        __batch_cache__["index_dirty_keys"] = set()

    if __batch_cache__.get("coverage_dirty"):
        _write_json_dict(_coverage_index_path(), __batch_cache__.get("coverage", {}))
        __batch_cache__["coverage_dirty"] = False

    if __batch_cache__.get("seed_features_dirty"):
        merged_seed_features = _merge_seed_features(
            _load_json_dict(_seed_features_path()),
            __batch_cache__.get("seed_features", {}),
        )
        _write_json_dict(_seed_features_path(), merged_seed_features)
        __batch_cache__["seed_features"] = merged_seed_features
        __batch_cache__["seed_features_signature"] = _file_signature(_seed_features_path())
        __batch_cache__["seed_features_dirty"] = False

    if reset_active:
        pregen_stage = __batch_cache__.get("async_pregen_stage")
        if isinstance(pregen_stage, dict) and pregen_stage.get("enabled"):
            key = pregen_stage.get("key")
            with __pregen_lock__:
                task = __pregen_tasks__.get(key)
                if isinstance(task, dict) and not task.get("running"):
                    try:
                        consumed = int(task.get("consumed", 0) or 0)
                    except (TypeError, ValueError):
                        consumed = 0
                    if consumed > 0:
                        __pregen_tasks__.pop(key, None)
        __batch_cache__.setdefault("plans", {}).clear()
        __batch_cache__["index"] = {}
        __batch_cache__["index_signature"] = None
        __batch_cache__["coverage"] = {}
        __batch_cache__["seed_features"] = {}
        __batch_cache__["seed_features_signature"] = None
        __batch_cache__["active"] = False
        __batch_cache__["stage_mutator"] = None
        __batch_cache__["optimizer_stage"] = {}
        __batch_cache__["mutatormin_direct_finds"] = 0
        __batch_cache__["async_pregen_stage"] = {}
        __pregen_current_key__ = None


def _refresh_index_cache_if_changed():
    if __batch_cache__.get("index_dirty"):
        return

    signature = _file_signature(_index_path())
    if signature is None or signature == __batch_cache__.get("index_signature"):
        return

    __batch_cache__["index"] = _load_json_dict(_index_path())
    __batch_cache__["index_signature"] = signature
    __batch_cache__.setdefault("plans", {}).clear()


def _load_coverage_index():
    # Preserve the old helper API while avoiding disk reads inside an active
    # MutatorMin stage.
    if __batch_cache__["active"]:
        return __batch_cache__["coverage"]

    index_file = _coverage_index_path()
    if os.path.exists(index_file) is False:
        return {}

    try:
        with open(index_file, 'r', encoding='utf-8') as f:
            index = json.load(f)
            return index if isinstance(index, dict) else {}
    except (json.JSONDecodeError, ValueError, OSError):
        return {}


def _write_coverage_index(index):
    # During a stage this only marks the in-memory snapshot dirty. stage_feedback
    # and deinit are the two places that publish the snapshot back to disk.
    if __batch_cache__["active"]:
        __batch_cache__["coverage"] = index if isinstance(index, dict) else {}
        __batch_cache__["coverage_dirty"] = True
        return

    _write_json_dict(_coverage_index_path(), index)


def _stable_mutator_id(mutator_name):
    if not mutator_name:
        return None

    basename = os.path.basename(mutator_name)
    stem, ext = os.path.splitext(basename)
    if ext != ".json":
        return basename

    if '_' not in stem:
        return stem

    head, tail = stem.rsplit('_', 1)
    if tail.isdigit():
        return head
    return stem


def get_stage_feedback(mutator_name=None):
    if mutator_name is None:
        return _load_coverage_index()

    stable_id = _stable_mutator_id(mutator_name)
    if stable_id is None:
        return None

    coverage_index = _load_coverage_index()
    entry = coverage_index.get(stable_id)
    if not isinstance(entry, dict):
        return None

    return dict(entry)


def _counter_op_config(op_name):
    entry = _counter_op_metadata().get(op_name, {})
    if not isinstance(entry, dict):
        return {"op": op_name}
    smoke_plan = entry.get("smoke_plan")
    if isinstance(smoke_plan, dict):
        for op in smoke_plan.get("ops", []):
            if isinstance(op, dict) and op.get("op") == op_name:
                return dict(op)
    schema = entry.get("schema")
    examples = schema.get("examples", []) if isinstance(schema, dict) else []
    for example in examples if isinstance(examples, list) else []:
        if isinstance(example, dict):
            result = dict(example)
            result["op"] = op_name
            return result
    return {"op": op_name}


def _counter_stage_progress_entry(stage, settled=None, reason=None):
    stage = stage if isinstance(stage, dict) else {}
    settled = settled if isinstance(settled, dict) else {}
    selected_op = stage.get("op_name")
    if selected_op == "__template_executor__":
        selected_op = stage.get("template_executor_id") or selected_op
    return {
        "mutator_file": selected_op,
        "selected_op": selected_op,
        "seed_id": stage.get("seed_id"),
        "seed_path": stage.get("seed_path"),
        "stage_id": stage.get("stage_id"),
        "stage_name": "MutatorMin",
        "stage_finds": int(stage.get("direct_finds", 0) or 0),
        "stage_new_coverage_finds": int(stage.get("new_coverage_finds", 0) or 0),
        "op_calls": int(stage.get("calls", 0) or 0),
        "op_changed_calls": int(stage.get("changed_calls", 0) or 0),
        "op_error_calls": int(stage.get("error_calls", 0) or 0),
        "op_applied": int(stage.get("changed_calls", 0) or 0) > 0,
        "invalid": bool(settled.get("invalid")),
        "settle_reason": reason,
    }


def _settle_counter_stage(feedback=None, reason="stage_feedback"):
    global __counter_stage__
    global __mutator__
    stage = __counter_stage__
    if not isinstance(stage, dict):
        return None
    is_template_stage = stage.get("op_name") == "__template_executor__"
    settled = None
    if is_template_stage:
        try:
            _record_template_stage_feedback(
                stage,
                feedback=feedback,
                force_persist=reason == "deinit",
            )
        except Exception as exc:
            sys.stderr.write(f"[MutatorMin] Failed to update template feedback: {exc}\n")
    progress = _counter_stage_progress_entry(stage, settled=settled, reason=reason)
    if isinstance(feedback, dict):
        progress["execs"] = int(feedback.get("execs", 0) or 0)
        progress["covered_edges"] = int(feedback.get("covered_edges", 0) or 0)
        progress["current_entry"] = int(feedback.get("current_entry", 0) or 0)
        progress["queue_cycle"] = int(feedback.get("queue_cycle", 0) or 0)
    try:
        _record_mutatormin_stage_progress(progress)
    except Exception as exc:
        sys.stderr.write(f"[MutatorMin] Failed to update MutatorMin progress: {exc}\n")
    if int(stage.get("direct_finds", 0) or 0) > 0:
        _maybe_refresh_feature_scores(force=True)
    __counter_stage__ = None
    __mutator__ = None
    _flush_batch_cache(reset_active=True)
    _run_memory_housekeeping()
    _write_runtime_status(reason)
    return settled


def init(seed):
    del seed
    mode = _template_pool_schedule()
    if _template_pool_enabled():
        sys.stderr.write(
            f"[MutatorMin] template pool schedule={mode} "
            f"metric={_template_selection_metric()}\n"
        )
    _record_bottleneck_queue_growth()
    _ensure_mutators_path()
    _refresh_template_executor()
    _write_runtime_status("init")


def deinit():
    _settle_counter_stage(reason="deinit")
    _run_memory_housekeeping(force=True)
    try:
        _persist_template_feedback(force=True)
    except Exception as exc:
        sys.stderr.write(f"[MutatorMin] Failed to persist template feedback during deinit: {exc}\n")


def queue_get(filename):
    global __queue_seed_path__
    _settle_counter_stage(reason="next_queue_entry")
    __queue_seed_path__ = str(filename) if filename else None
    return True


def describe(max_description_len):
    # Let AFL++ mark queue entries produced by this Python custom mutator. The
    # queue_new_entry() callback uses this marker to avoid crediting unrelated
    # stages.
    return b"MutatorMin"[:max_description_len]


def fuzz_count(buf):
    global __counter_stage__
    global __mutator__
    _settle_counter_stage(reason="next_fuzz_count")
    _maybe_spawn_bottleneck_expansion()

    if _template_mode_enabled():
        _refresh_template_executor()
        if _template_initial_only():
            stage_executor = _fallback_template_executor
        elif _template_pool_enabled():
            stage_executor = _select_random_template_executor()
        else:
            stage_executor = _template_executor
        if stage_executor is None or _is_template_executor_disabled(stage_executor):
            _write_runtime_status("template_executor_disabled")
            return 0
        raw = bytes(_coerce_mutated_buffer(buf, bytearray()))
        seed_id = hashlib.sha256(raw).hexdigest() if __queue_seed_path__ else None
        executor_name = getattr(stage_executor, "__name__", _fallback_template_executor_name)
        executor_id = _template_executor_id(stage_executor)
        executor_weight = _template_feedback_score(stage_executor)
        __mutator__ = "__template_executor__"
        __counter_stage__ = {
            "stage_id": f"template_{int(time.time())}",
            "op_name": "__template_executor__",
            "seed_id": seed_id,
            "seed_path": __queue_seed_path__,
            "planned_count": STAGE_EXEC_COUNT,
            "calls": 0,
            "changed_calls": 0,
            "error_calls": 0,
            "direct_finds": 0,
            "new_coverage_finds": 0,
            "selection": {
                "selection_kind": "weighted_template_executor" if _template_pool_weighted_enabled() else "random_template_executor",
                "schedule_mode": _template_pool_schedule(),
                "metric": _template_selection_metric(),
                "weight": executor_weight,
            },
            "template_executor": stage_executor,
            "template_executor_id": executor_id,
            "template_executor_name": executor_name,
        }
        pool_info = ""
        if _template_initial_only():
            pool_info = " initial-only"
        elif _template_pool_enabled():
            pool_info = f" pool={len(__template_pool__['executors'])}"
        if _template_verbose_enabled():
            sys.stderr.write(
                f"[MutatorMin] template stage: executor={executor_id} "
                f"ops={len(getattr(stage_executor, 'OP_HANDLERS', {}))}"
                f" plan={_template_plan_mode()} schedule={_template_pool_schedule()}"
                f" weight={executor_weight:.6g}{pool_info}\n"
            )
        _write_runtime_status("template_mode_stage")
        return STAGE_EXEC_COUNT
    _write_runtime_status("template_mode_disabled")
    return 0


def _coerce_mutated_buffer(value, fallback):
    if isinstance(value, bytearray):
        return value

    if isinstance(value, bytes):
        return bytearray(value)

    if isinstance(fallback, bytearray):
        return bytearray(fallback)

    if isinstance(fallback, bytes):
        return bytearray(fallback)

    return bytearray()


def _is_template_plan_file(mutator_file):
    return isinstance(mutator_file, str) and os.path.basename(mutator_file).endswith(".json")


def _is_template_plan_entry(entry):
    if not isinstance(entry, dict):
        return False
    if entry.get("artifact_type") == TEMPLATE_PLAN_ARTIFACT_TYPE:
        return True
    plan = entry.get("plan")
    return isinstance(plan, dict) and plan.get("kind") == TEMPLATE_PLAN_ARTIFACT_TYPE


def _template_plan_path(mutator_file):
    if not _is_template_plan_file(mutator_file):
        return None
    return os.path.join(_template_plan_dir(), os.path.basename(mutator_file))


def _find_template_plan_entry(mutator_file):
    if not _is_template_plan_file(mutator_file):
        return None

    index = __batch_cache__.get("index", {})
    for entry in index.values():
        if not _is_template_plan_entry(entry):
            continue
        normalized = _normalize_index_entry(entry)
        if mutator_file in normalized["files"]:
            return entry
    return None


def _load_template_plan(mutator_file):
    plan_path = _template_plan_path(mutator_file)
    if plan_path and os.path.exists(plan_path):
        try:
            with open(plan_path, "r", encoding="utf-8") as f:
                plan = json.load(f)
                if isinstance(plan, dict):
                    return plan
        except (json.JSONDecodeError, ValueError, OSError) as e:
            sys.stderr.write(f"[MutatorMin] Failed to read plan {mutator_file}: {e}\n")

    entry = _find_template_plan_entry(mutator_file)
    if isinstance(entry, dict) and isinstance(entry.get("plan"), dict):
        return entry["plan"]
    return None


def _format_repair_mode():
    value = os.environ.get(FORMAT_REPAIR_ENV)
    if value is None:
        return "probabilistic"
    normalized = str(value).strip().lower()
    if normalized in {"1", "true", "yes", "on", "force", "always"}:
        return "force"
    if normalized in {"0", "false", "no", "off", "never"}:
        return "off"
    return "probabilistic"


def _format_repair_enabled_for_call():
    mode = _format_repair_mode()
    if not _active_format_repair_ops():
        return False
    if mode == "force":
        return True
    if mode == "off":
        return False
    return random.random() < FORMAT_REPAIR_DEFAULT_PROB


def _format_repair_prefix_ops():
    executor = _active_template_executor()
    architecture_roles = _architecture_op_roles(executor)
    if architecture_roles is not None:
        return [
            {"op": op_name}
            for op_name, role in sorted(architecture_roles.items())
            if role == "architecture_transition"
        ]

    preferred = ["ensure_elf32_i386", "ensure_magic", "ensure_format_header"]
    repair_ops = _active_format_repair_ops()
    result = []
    for op_name in preferred:
        if op_name in repair_ops:
            result.append({"op": op_name})
    if result:
        return result
    for op_name in sorted(repair_ops):
        lowered = op_name.lower()
        if lowered.startswith("ensure_"):
            result.append({"op": op_name})
    return result


def _format_repair_suffix_ops():
    executor = _active_template_executor()
    architecture_roles = _architecture_op_roles(executor)
    if architecture_roles is not None:
        return [
            {"op": op_name}
            for op_name, role in sorted(architecture_roles.items())
            if role == "target_repair"
        ]

    preferred = ["sync_elf32_headers"]
    repair_ops = _active_format_repair_ops()
    result = []
    for op_name in preferred:
        if op_name in repair_ops:
            result.append({"op": op_name})
    for op_name in sorted(repair_ops):
        lowered = op_name.lower()
        if lowered.startswith(("sync_", "repair_")) and {"op": op_name} not in result:
            result.append({"op": op_name})
    return result


def _format_repair_ops_for_pre_execution():
    """Return repair ops for the standalone pre-mutation repair pass."""
    repair_ops = _active_format_repair_ops()
    architecture_roles = _architecture_op_roles(_active_template_executor()) or {}
    result = []
    seen = set()
    for op in _format_repair_prefix_ops() + _format_repair_suffix_ops():
        if not isinstance(op, dict):
            continue
        op_name = op.get("op")
        if (op_name in repair_ops or op_name in architecture_roles) and op_name not in seen:
            result.append(dict(op))
            seen.add(op_name)
    return result


def _maybe_filter_format_repair_ops(plan, repair_enabled=None):
    if not isinstance(plan, dict):
        return plan
    ops = plan.get("ops")
    if not isinstance(ops, list):
        return plan
    if repair_enabled is None:
        repair_enabled = _format_repair_enabled_for_call()
    if not repair_enabled:
        return plan
    repair_ops = {
        op.get("op")
        for op in _format_repair_ops_for_pre_execution()
        if isinstance(op, dict) and isinstance(op.get("op"), str)
    }
    filtered_ops = [
        op for op in ops
        if not (isinstance(op, dict) and op.get("op") in repair_ops)
    ]
    filtered_plan = dict(plan)
    filtered_plan["ops"] = filtered_ops
    limits = filtered_plan.get("limits")
    if isinstance(limits, dict):
        filtered_limits = dict(limits)
        try:
            old_max_ops = int(filtered_limits.get("max_ops_per_call", len(ops)))
        except (TypeError, ValueError):
            old_max_ops = len(ops)
        filtered_limits["max_ops_per_call"] = max(1, min(old_max_ops, len(filtered_ops)))
        filtered_plan["limits"] = filtered_limits
    return filtered_plan


def _apply_format_repair_before_execution(data, limit=None, repair_enabled=None):
    if repair_enabled is None:
        repair_enabled = _format_repair_enabled_for_call()
    if not repair_enabled:
        return data

    repair_ops = _format_repair_ops_for_pre_execution()
    if not repair_ops:
        return data

    repair_plan = {
        "version": 1,
        "kind": TEMPLATE_PLAN_ARTIFACT_TYPE,
        "template": getattr(_active_template_executor(), "__name__", "dynamic_template_executor"),
        "max_ops": len(repair_ops),
        "ops": repair_ops,
        "limits": {
            "max_output_size": 1048576,
            "max_ops_per_call": len(repair_ops),
        },
    }
    repaired = _execute_template_plan(data, repair_plan, limit)
    return repaired if isinstance(repaired, (bytes, bytearray)) else data


def _feature_mask_enabled():
    value = os.environ.get(FEATURE_MASK_ENV)
    if value is None:
        return True
    return str(value).strip().lower() not in {"0", "false", "no", "off"}


def _parse_template_profile(data):
    parse_profile = getattr(_active_template_executor(), "parse_profile", None)
    if not callable(parse_profile):
        return None
    try:
        profile = parse_profile(data)
    except Exception:
        return None
    return profile if isinstance(profile, dict) else None


def _mask_value_enabled(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value > 0
    if isinstance(value, str):
        return value.strip().lower() not in {"", "0", "false", "no", "off", "none"}
    return bool(value)


def _coerce_applicable_ops_mask(mask):
    if isinstance(mask, dict):
        result = {}
        for key, value in mask.items():
            if isinstance(key, str) and key:
                result[key] = _mask_value_enabled(value)
        return result
    if isinstance(mask, (list, tuple, set)):
        result = {}
        for item in mask:
            if isinstance(item, str) and item:
                result[item] = True
        return result
    return None


def _applicable_ops_mask(profile):
    if not isinstance(profile, dict):
        return None
    applicable_ops = getattr(_active_template_executor(), "applicable_ops", None)
    result = None
    if not callable(applicable_ops):
        result = None
    else:
        try:
            result = _coerce_applicable_ops_mask(applicable_ops(profile))
        except Exception:
            result = None
    return result


def _online_applicable_ops_mask(profile):
    del profile
    return {}


def _bandit_size_bucket(size):
    try:
        size = int(size or 0)
    except (TypeError, ValueError):
        size = 0
    if size < 128:
        return "tiny"
    if size < 4096:
        return "small"
    if size < 65536:
        return "medium"
    return "large"


def _bandit_token(value):
    text = str(value or "").strip().lower()
    text = re.sub(r"[^a-z0-9_.-]+", "_", text).strip("._-")
    return text[:64] or "unknown"


def _bandit_context_for_data(data):
    data = _coerce_mutated_buffer(data, bytearray())
    vector = {
        "bias": 1.0,
        f"size:{_bandit_size_bucket(len(data))}": 1.0,
    }
    profile = _parse_template_profile(data)
    applicable = None
    if isinstance(profile, dict):
        applicable = _applicable_ops_mask(profile)
        for key in ("format", "class", "endian", "machine"):
            if key in profile:
                vector[f"{key}:{_bandit_token(profile.get(key))}"] = 1.0
        features = _profile_features(profile)
        for feature_id in sorted(features):
            if isinstance(feature_id, str) and _feature_present(profile, feature_id):
                vector[f"feature:{feature_id}"] = 1.0
    context = {"vector": vector}
    if applicable is not None:
        context["applicable_ops"] = applicable
    return context


def _bandit_context_has_explicit_empty_applicable_ops(context):
    if not isinstance(context, dict) or "applicable_ops" not in context:
        return False
    raw = context.get("applicable_ops")
    if isinstance(raw, dict):
        enabled_ops = [
            op_name for op_name, value in raw.items()
            if isinstance(op_name, str) and _mask_value_enabled(value)
        ]
    elif isinstance(raw, (list, tuple, set)):
        enabled_ops = [item for item in raw if isinstance(item, str) and item]
    else:
        return False
    if not enabled_ops:
        return True
    configured_ops = set(__core_op_handlers__)
    return bool(configured_ops) and not any(op_name in configured_ops for op_name in enabled_ops)


def _profile_features(profile):
    if not isinstance(profile, dict):
        return {}
    features = profile.get("features")
    return features if isinstance(features, dict) else {}


def _feature_aliases(feature_id):
    feature_id = str(feature_id or "").strip()
    aliases = {
        "elf": ("executable_and_linking_format_elf", "header_structure"),
        "elf_header": ("header_structure", "executable_and_linking_format_elf"),
        "file_header": ("header_structure", "executable_and_linking_format_elf"),
        "header": ("header_structure", "executable_and_linking_format_elf"),
        "header_structure": ("elf_header", "executable_and_linking_format_elf"),
    }
    return aliases.get(feature_id, ())


def _feature_present(profile, feature_id):
    feature_id = str(feature_id or "").strip()
    features = _profile_features(profile)
    state = features.get(feature_id)
    if state is None:
        for alias in _feature_aliases(feature_id):
            alias_state = features.get(alias)
            if alias_state is not None:
                return _feature_present(profile, alias)
        if feature_id in {"elf", "elf_header", "file_header", "header", "header_structure"} and isinstance(profile, dict):
            return bool(profile.get("class") or profile.get("endian") or profile.get("elf_class"))
    if isinstance(state, dict):
        if "present" in state:
            return _mask_value_enabled(state.get("present"))
        if "score" in state:
            try:
                return float(state.get("score") or 0.0) > 0.0
            except (TypeError, ValueError):
                return False
        return bool(state)
    return _mask_value_enabled(state)


def _current_seed_has_template_features(data):
    if not _feature_mask_enabled():
        return True
    feature_schema = getattr(_active_template_executor(), "FEATURE_SCHEMA", None)
    if not isinstance(feature_schema, dict) or not feature_schema:
        return True
    profile = _parse_template_profile(data)
    if not isinstance(profile, dict):
        return False
    features = _profile_features(profile)
    if not features:
        return False
    for feature_id in feature_schema:
        if isinstance(feature_id, str) and _feature_present(profile, feature_id):
            return True
    return False


def _profile_regions(profile):
    if not isinstance(profile, dict):
        return {}
    regions = profile.get("regions")
    if isinstance(regions, dict):
        return {
            str(name): value for name, value in regions.items()
            if isinstance(name, str) and isinstance(value, dict)
        }
    if isinstance(regions, list):
        result = {}
        for item in regions:
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            if isinstance(name, str) and name:
                result[name] = item
        return result
    return {}


def _op_required_features_available(profile, op):
    if not isinstance(op, dict):
        return False
    op_name = op.get("op")
    required = (
        op.get("requires_features") or
        op.get("required_features")
    )
    if required is None:
        return True
    if isinstance(required, str):
        required = [required]
    if not isinstance(required, (list, tuple, set)):
        return True
    for feature_id in required:
        if isinstance(feature_id, str) and feature_id and not _feature_present(profile, feature_id):
            return False
    return True


def _op_region_available(profile, op):
    if not isinstance(profile, dict) or not isinstance(op, dict):
        return True
    op_name = op.get("op")
    regions = _profile_regions(profile)
    region_name = op.get("region") or op.get("region_name")
    if isinstance(region_name, str) and region_name and region_name != "random":
        return region_name in regions

    if op_name in {"mutate_region", "mutate_string_table", "insert_block", "duplicate_region"}:
        return bool(regions)
    return True


def _filter_plan_by_feature_mask(data, plan):
    if not _feature_mask_enabled() or not isinstance(plan, dict):
        return plan, None

    ops = plan.get("ops")
    if not isinstance(ops, list) or not ops:
        return plan, None

    profile = _parse_template_profile(data)
    if not isinstance(profile, dict):
        return plan, None

    op_mask = _applicable_ops_mask(profile)
    filtered_ops = []
    changed = False
    for op in ops:
        if not isinstance(op, dict):
            changed = True
            continue
        op_name = op.get("op")
        if not isinstance(op_name, str) or not op_name:
            changed = True
            continue
        if isinstance(op_mask, dict) and op_name in op_mask and not op_mask[op_name]:
            changed = True
            continue
        if not _op_required_features_available(profile, op):
            changed = True
            continue
        if not _op_region_available(profile, op):
            changed = True
            continue
        filtered_ops.append(op)

    if not changed and len(filtered_ops) == len(ops):
        return plan, profile

    filtered_plan = dict(plan)
    filtered_plan["ops"] = filtered_ops
    limits = filtered_plan.get("limits")
    if isinstance(limits, dict):
        filtered_limits = dict(limits)
        try:
            old_max_ops = int(filtered_limits.get("max_ops_per_call", len(ops)))
        except (TypeError, ValueError):
            old_max_ops = len(ops)
        filtered_limits["max_ops_per_call"] = max(0, min(old_max_ops, len(filtered_ops)))
        filtered_plan["limits"] = filtered_limits
    else:
        filtered_plan["limits"] = {"max_ops_per_call": len(filtered_ops)}
    return filtered_plan, profile


def _plan_op_names(plan):
    ops = plan.get("ops") if isinstance(plan, dict) else []
    if not isinstance(ops, list):
        return []
    names = []
    for op in ops:
        if isinstance(op, dict) and isinstance(op.get("op"), str) and op.get("op"):
            names.append(op.get("op"))
    return names


def _runnable_plan_op_names(executor, plan):
    names = _plan_op_names(plan)
    handlers = getattr(executor, "OP_HANDLERS", None)
    if not isinstance(handlers, dict):
        return names
    return [name for name in names if name in handlers]


def _bytes_for_execution_compare(value):
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, memoryview):
        return value.tobytes()
    return None


def _record_optimizer_execution(mutator_file, execution_info):
    if getattr(__pregen_thread_local__, "suppress_optimizer_record", False):
        if isinstance(execution_info, dict):
            __pregen_thread_local__.last_execution_info = dict(execution_info)
        return
    stable_id = _stable_mutator_id(mutator_file)
    if True:
        return
    tracker = __batch_cache__.setdefault("optimizer_stage", {})
    entry = tracker.setdefault(stable_id, {
        "calls": 0,
        "applied_calls": 0,
        "skipped_calls": 0,
        "changed_calls": 0,
        "selected_ops": [],
        "applied_ops": [],
    })
    entry["calls"] = int(entry.get("calls", 0) or 0) + 1
    selected_ops = execution_info.get("selected_ops")
    if isinstance(selected_ops, list):
        for op_name in selected_ops:
            if isinstance(op_name, str) and op_name not in entry["selected_ops"]:
                entry["selected_ops"].append(op_name)

    applied_ops = execution_info.get("applied_ops")
    if not isinstance(applied_ops, list):
        applied_ops = []
    if execution_info.get("op_applied"):
        entry["applied_calls"] = int(entry.get("applied_calls", 0) or 0) + 1
        for op_name in applied_ops:
            if isinstance(op_name, str) and op_name not in entry["applied_ops"]:
                entry["applied_ops"].append(op_name)
    else:
        entry["skipped_calls"] = int(entry.get("skipped_calls", 0) or 0) + 1

    if execution_info.get("output_changed"):
        entry["changed_calls"] = int(entry.get("changed_calls", 0) or 0) + 1


def _online_handlers_for_execution():
    return {}


def _profile_has_base_structure(profile):
    if not isinstance(profile, dict):
        return False
    for feature_id in (
        "header_structure",
        "elf_header",
        "executable_and_linkable_format_elf",
        "executable_and_linking_format_elf",
    ):
        if _feature_present(profile, feature_id):
            return True
    return str(profile.get("format") or "").lower() == "elf"


def _plan_contains_online_ops(plan):
    del plan
    return False


def _coerce_execution_limit(limit):
    try:
        value = int(limit or MAX_OUTPUT_SIZE)
    except (TypeError, ValueError):
        value = MAX_OUTPUT_SIZE
    return max(1, min(value, MAX_OUTPUT_SIZE))


def _execute_online_aware_plan(executor, data, plan, profile, limit, execution_info=None):
    execute = getattr(executor, "execute_template_plan", None)
    if not callable(execute):
        return bytes(data or b"")
    try:
        return _call_template_executor_with_timeout(
            executor,
            execute,
            data,
            plan,
            profile,
            limit,
            execution_info=execution_info,
        )
    except _TemplateExecutionTimeout:
        return bytes(data or b"")


def _execute_template_plan(data, plan=None, limit=None, execution_info=None):
    """Execute the active template executor with dynamic profile parsing."""
    executor = _active_template_executor()
    execute = getattr(executor, "execute_template_plan", None)
    input_bytes = _bytes_for_execution_compare(data) or bytes(data or b"")
    if isinstance(execution_info, dict):
        execution_info["requested_ops"] = _plan_op_names(plan) if isinstance(plan, dict) else []
        execution_info["effective_ops"] = []
        execution_info["applied_ops"] = []
        execution_info["op_applied"] = False
        execution_info["output_changed"] = False
    if not callable(execute):
        return bytes(data or b"")
    effective_plan = plan
    if effective_plan is None:
        default_plan = getattr(executor, "DEFAULT_PLAN", None)
        effective_plan = default_plan if isinstance(default_plan, dict) else None
    profile = None
    if _feature_mask_enabled() and isinstance(effective_plan, dict):
        effective_plan, profile = _filter_plan_by_feature_mask(data, effective_plan)
    if isinstance(execution_info, dict):
        effective_ops = _plan_op_names(effective_plan) if isinstance(effective_plan, dict) else []
        runnable_ops = _runnable_plan_op_names(executor, effective_plan) if isinstance(effective_plan, dict) else []
        execution_info["effective_ops"] = effective_ops
        execution_info["applied_ops"] = runnable_ops
        execution_info["op_applied"] = bool(runnable_ops)
        execution_info["profile_parsed"] = isinstance(profile, dict)
    try:
        result = _call_template_executor_with_timeout(
            executor,
            execute,
            data,
            effective_plan,
            profile,
            limit,
            execution_info=execution_info,
        )
        result_bytes = _bytes_for_execution_compare(result)
        if isinstance(execution_info, dict) and result_bytes is not None:
            execution_info["output_changed"] = result_bytes != input_bytes
        return result
    except _TemplateExecutionTimeout:
        if isinstance(execution_info, dict):
            execution_info["op_applied"] = False
            execution_info["applied_ops"] = []
        return bytes(data or b"")
    except Exception:
        if isinstance(execution_info, dict):
            execution_info["op_applied"] = False
            execution_info["applied_ops"] = []
            execution_info["execution_error"] = True
        return bytes(data or b"")


def _template_default_ops_for(op_name, executor=None):
    executor = executor if executor is not None else _active_template_executor()
    default_plan = getattr(executor, "DEFAULT_PLAN", {})
    ops = default_plan.get("ops", []) if isinstance(default_plan, dict) else []
    matches = [
        dict(op) for op in ops
        if isinstance(op, dict) and op.get("op") == op_name
    ]
    return matches


def _core_runtime_op(op_name, executor=None):
    templates = _template_default_ops_for(op_name, executor=executor)
    if templates:
        return random.choice(templates)

    if op_name == "mutate_ehdr_enum":
        return {
            "op": op_name,
            "fields": ["e_type", "e_machine", "e_entry"],
        }
    if op_name == "mutate_program_header":
        return {
            "op": op_name,
            "index": "random",
            "fields": ["p_type", "p_flags", "p_align", "p_filesz"],
        }
    if op_name == "mutate_section_header":
        return {
            "op": op_name,
            "index": "random",
            "fields": ["sh_type", "sh_flags", "sh_addralign", "sh_entsize"],
        }
    if op_name == "mutate_region":
        return {
            "op": op_name,
            "region": random.choice([".text", ".data", ".shstrtab"]),
            "max_len": random.choice([4, 8, 16, 32, 64]),
            "modes": ["bitflip", "arith", "random"],
        }
    if op_name == "mutate_shstrtab":
        return {
            "op": op_name,
            "max_len": random.choice([4, 8, 16, 32, 64]),
        }
    if op_name == "append_tail_block":
        max_len = random.choice([16, 32, 64, 128, 256])
        return {
            "op": op_name,
            "min_len": 0,
            "max_len": max_len,
            "alphabet": random.choice(["binary", "ascii", "zero"]),
        }
    return {"op": op_name}


def _darwin_runtime_op(op_name, runtime_config):
    online_templates = runtime_config.get("online_op_templates", {})
    if isinstance(online_templates, dict) and op_name in online_templates:
        template = online_templates.get(op_name)
        if isinstance(template, dict):
            return dict(template)
    return _core_runtime_op(op_name)


def _load_optimizer_genome_mutate_function(mutator_file):
    plan_cache = __batch_cache__.setdefault("plans", {})
    cached = plan_cache.get(mutator_file)
    if isinstance(cached, dict):
        mutate = cached.get("mutate")
        return mutate if callable(mutate) else None

    runtime_config = {}
    if not isinstance(runtime_config, dict):
        return None
    enabled_ops = [
        op for op in runtime_config.get("enabled_ops", [])
        if isinstance(op, str) and op
    ]
    if not enabled_ops:
        return None

    def mutate(data, limit=None):
        ops = []
        repair_ops = _active_format_repair_ops()
        repair_enabled = _format_repair_enabled_for_call()
        data = _apply_format_repair_before_execution(data, limit, repair_enabled)
        if runtime_config.get("selection_kind") == "bandit_arm":
            selected_ops = enabled_ops[:1]
        else:
            stack_count = random.choices(DARWIN_STACK_COUNTS, weights=DARWIN_STACK_WEIGHTS, k=1)[0]
            if stack_count <= len(enabled_ops):
                selected_ops = random.sample(enabled_ops, stack_count)
            else:
                selected_ops = list(enabled_ops)
                random.shuffle(selected_ops)
                selected_ops.extend(
                    random.choice(enabled_ops)
                    for _ in range(stack_count - len(selected_ops))
                )
        for op_name in selected_ops:
            op = _darwin_runtime_op(op_name, runtime_config)
            if not (isinstance(op, dict) and op.get("op") in repair_ops):
                ops.append(op)
        plan = {
            "version": 1,
            "kind": TEMPLATE_PLAN_ARTIFACT_TYPE,
            "template": getattr(_active_template_executor(), "__name__", "dynamic_template_executor"),
            "ops": ops,
            "limits": {
                "max_output_size": 1048576,
                "max_ops_per_call": max(1, len(ops)),
            },
        }
        execution_info = {
            "selection_kind": runtime_config.get("selection_kind"),
            "arm": runtime_config.get("arm"),
            "selected_ops": list(selected_ops),
        }
        result = _execute_template_plan(data, plan, limit, execution_info)
        _record_optimizer_execution(mutator_file, execution_info)
        return result

    plan_cache[mutator_file] = {
        "signature": (
            __template_executor_info__.get("path"),
            __template_executor_info__.get("signature"),
            runtime_config.get("selection_kind"),
            runtime_config.get("arm"),
            runtime_config.get("registry_hash"),
            tuple(enabled_ops),
        ),
        "mutate": mutate,
    }
    return mutate


def _plan_file_signature(mutator_file):
    plan_path = _template_plan_path(mutator_file)
    if plan_path and os.path.exists(plan_path):
        try:
            stat = os.stat(plan_path)
            return (stat.st_mtime_ns, stat.st_size)
        except OSError:
            pass

    entry = _find_template_plan_entry(mutator_file)
    if isinstance(entry, dict) and isinstance(entry.get("plan"), dict):
        serialized = json.dumps(entry["plan"], sort_keys=True)
        return ("embedded", hash(serialized))
    return None


def _load_mutate_function(mutator_file):
    if False:
        return _load_optimizer_genome_mutate_function(mutator_file)

    if not _is_template_plan_file(mutator_file):
        return None

    plan_cache = __batch_cache__.setdefault("plans", {})
    signature = _plan_file_signature(mutator_file)
    cached = plan_cache.get(mutator_file)
    if isinstance(cached, dict) and cached.get("signature") == signature:
        mutate = cached.get("mutate")
        return mutate if callable(mutate) else None

    plan = _load_template_plan(mutator_file)
    if not isinstance(plan, dict):
        sys.stderr.write(f"[MutatorMin] Missing or invalid template plan: {mutator_file}\n")
        return None

    def mutate(data, limit=None):
        repair_enabled = _format_repair_enabled_for_call()
        data = _apply_format_repair_before_execution(data, limit, repair_enabled)
        return _execute_template_plan(
            data,
            _maybe_filter_format_repair_ops(plan, repair_enabled),
            limit,
        )

    plan_cache[mutator_file] = {
        "signature": signature,
        "mutate": mutate,
    }
    return mutate


def _seed_generation_input_path(buf):
    env_path = os.environ.get(SEED_INPUT_ENV)
    if isinstance(env_path, str) and env_path.strip():
        path = env_path.strip()
        if not os.path.isabs(path):
            path = os.path.join(_base_dir(), path)
        if os.path.exists(path):
            return os.path.abspath(path)

    data = _coerce_mutated_buffer(buf, bytearray())
    if not data:
        return None
    data = bytes(data[:MAX_OUTPUT_SIZE])
    digest = hashlib.sha256(data).hexdigest()[:16]
    path = os.path.join(_seed_input_dir(), f"{_seed_format()}_{digest}.bin")
    if not os.path.exists(path):
        try:
            _ensure_mutators_path()
            with open(path, "wb") as f:
                f.write(data)
        except OSError as e:
            sys.stderr.write(f"[MutatorMin] Failed to write seed generator input: {e}\n")
            return None
    return path


def _maybe_spawn_seed_generator(buf=None, force=False):
    global __seed_no_found_counter__

    if not _seed_generation_enabled():
        return
    if not _seed_async_generation_enabled():
        return
    if not _seed_llm_config_available():
        return

    worker = getattr(_maybe_spawn_seed_generator, "_worker", None)
    if worker is not None and worker.poll() is None:
        return

    if force:
        if __seed_no_found_counter__ > 0 and __seed_no_found_counter__ % BOOTSTRAP_RETRY_INTERVAL != 0:
            return
    elif __seed_no_found_counter__ <= MAX_EXEC_TIME:
        return

    source_mode = _seed_source_mode()
    input_path = _seed_generation_input_path(buf) if source_mode == "sample" else None
    if source_mode == "sample" and not input_path:
        return

    import subprocess

    python_executable = os.environ.get("PYTHON", sys.executable)
    if "python" not in os.path.basename(python_executable).lower():
        python_executable = "python3"

    cmd = [
        python_executable,
        os.path.join(_base_dir(), "seed_generator_builder.py"),
        "--format", _seed_format(),
        "--source-mode", source_mode,
        "--output", _seed_generator_dir(),
        "--seeds-output", _generated_seed_dir(),
        "--metadata", _seed_features_path(),
        "--max-files", str(_seed_max_files()),
    ]
    if source_mode == "sample":
        cmd.extend(["--input", input_path])
    try:
        _ensure_mutators_path()
        log_path = os.path.join(_seed_artifacts_dir(), "seed_generator_builder.log")
        with open(log_path, "ab") as log_file:
            log_file.write(b"\n[MutatorMin] spawn seed_generator_builder.py\n")
            _maybe_spawn_seed_generator._worker = subprocess.Popen(
                cmd,
                cwd=_base_dir(),
                stdout=log_file,
                stderr=log_file,
                start_new_session=True,
                close_fds=True,
            )
        __seed_no_found_counter__ = 1
    except OSError as e:
        sys.stderr.write(f"[MutatorMin] Failed to spawn seed generator: {e}\n")


def _read_seed_entry(entry, max_size):
    seed_path = _seed_abs_path(entry.get("path") if isinstance(entry, dict) else None)
    if not seed_path or not os.path.isfile(seed_path):
        return None
    try:
        with open(seed_path, "rb") as f:
            data = f.read(max_size + 1)
    except OSError:
        return None
    if len(data) > max_size:
        return None
    return data


def _evolve_mutator(force=False):

    global __mutator__
    global __no_found_counter__
    del force
    __no_found_counter__ = 1
    return None

def fuzz(buf, add_buf, max_size):

    del add_buf
    global __counter_stage__
    stage = __counter_stage__
    original = bytes(_coerce_mutated_buffer(buf, bytearray()))
    if not isinstance(stage, dict):
        return bytearray()
    stage["calls"] = int(stage.get("calls", 0) or 0) + 1

    if stage.get("op_name") == "__template_executor__":
        executor = stage.get("template_executor") or _fallback_template_executor
        plan_mode = _template_plan_mode()
        if plan_mode == "random":
            plan = _compose_random_template_plan(executor)
        else:
            plan = getattr(executor, "DEFAULT_PLAN", None)
            if not isinstance(plan, dict):
                plan = None
        plan = _filter_undeclared_architecture_repair_ops(executor, plan)
        profile = getattr(executor, "SMALL_EXEC_PROFILE", None) or getattr(executor, "DEFAULT_PROFILE", None)
        execute = getattr(executor, "execute_template_plan", None)
        if not callable(execute):
            stage["error_calls"] = int(stage.get("error_calls", 0) or 0) + 1
            return bytearray()
        if _is_template_executor_disabled(executor):
            stage["error_calls"] = int(stage.get("error_calls", 0) or 0) + 1
            return bytearray()
        try:
            result = _call_template_executor_with_timeout(
                executor,
                execute,
                original,
                plan,
                profile,
                max_size,
                execution_info=stage,
            )
        except _TemplateExecutionTimeout:
            stage["error_calls"] = int(stage.get("error_calls", 0) or 0) + 1
            stage["timeout_calls"] = int(stage.get("timeout_calls", 0) or 0) + 1
            stage["template_executor_disabled"] = True
            return bytearray()
        except Exception:
            stage["error_calls"] = int(stage.get("error_calls", 0) or 0) + 1
            return bytearray()
        result_bytes = _bytes_for_execution_compare(result)
        if result_bytes is None or len(result_bytes) > max_size:
            stage["error_calls"] = int(stage.get("error_calls", 0) or 0) + 1
            return bytearray()
        if result_bytes != original:
            stage["changed_calls"] = int(stage.get("changed_calls", 0) or 0) + 1
        return bytearray(result_bytes)

    stage["error_calls"] = int(stage.get("error_calls", 0) or 0) + 1
    return bytearray()

    # Choose one template plan from the generated JSON plan pool.
    global __mutator__
    global __no_found_counter__
    global __seed_no_found_counter__
    global __last_seed_context__

    original_buf = _coerce_mutated_buffer(buf, bytearray())
    __seed_no_found_counter__ = 0
    __last_seed_context__ = None
    sampled_seed_entry = None
    sampled_seed_data = None
    if _seed_pool_enabled() and _seed_sample_probability() > 0.0:
        if random.random() < _seed_sample_probability():
            candidate = _choose_seed_entry()
            candidate_data = _read_seed_entry(candidate, max_size) if isinstance(candidate, dict) else None
            if isinstance(candidate_data, (bytes, bytearray)) and candidate_data:
                sampled_seed_entry = candidate
                sampled_seed_data = _coerce_mutated_buffer(candidate_data, bytearray())

    # Lazy stage start. This keeps AFL++ scheduling unchanged while moving
    # index/coverage reads out of the hot fuzz() loop.
    _ensure_batch_cache()

    selected_mutator = __batch_cache__.get("stage_mutator")
    if selected_mutator is None:
        selector_input = sampled_seed_data if sampled_seed_data is not None else original_buf
        selected_mutator = mutator_selector(selector_input)
        # Pin the selected plan until the next stage boundary flushes this batch.
        __batch_cache__["stage_mutator"] = selected_mutator
    __mutator__ = selected_mutator
    Mutate = _load_mutate_function(selected_mutator)

    if sampled_seed_data is not None and sampled_seed_entry is not None:
        seed_context = _seed_context_from_entry(sampled_seed_entry, applied_template=False)
        if seed_context is not None:
            _update_seed_stats(seed_context, stage_call=True)
        apply_template = Mutate is not None and random.random() < _seed_mutate_probability()
        if apply_template:
            _evolve_mutator()
            try:
                mutated = Mutate(sampled_seed_data, max_size)
                mutated = _coerce_mutated_buffer(mutated, sampled_seed_data)
                if len(mutated) <= max_size and mutated != sampled_seed_data:
                    if seed_context is not None:
                        seed_context = dict(seed_context)
                        seed_context["applied_template_mutation"] = True
                    __last_seed_context__ = seed_context
                    return mutated
            except Exception:
                pass

        __last_seed_context__ = seed_context
        return sampled_seed_data

    # Apply the local template executor. Missing or invalid plans are treated as
    # no-ops so AFL++ keeps its normal scheduling behavior.
    if __mutator__ is None or Mutate is None:
        if selected_mutator is None:
            _evolve_mutator(force=True)
        return bytearray()
    else:
        _evolve_mutator()
        try:
            mutated = Mutate(buf, max_size)
            mutated = _coerce_mutated_buffer(mutated, original_buf)
            if len(mutated) > max_size:
                return bytearray()

            if DEBUG:
                print('mutated result:', mutated)
                print('\n')
            return mutated

        except Exception as e:
            return bytearray()

def queue_new_entry(filename_new_queue, filename_orig_queue):
    # Called when a new test case is added to the queue
    del filename_orig_queue
    global __counter_stage__
    queue_path = str(filename_new_queue)
    _record_bottleneck_queue_growth(queue_path)
    # Stage and coverage markers belong to the filename, not its parent directories.
    queue_name = os.path.basename(queue_path)
    if 'MutatorMin' in queue_name and isinstance(__counter_stage__, dict):
        __counter_stage__["direct_finds"] = int(__counter_stage__.get("direct_finds", 0) or 0) + 1
        if __counter_stage__.get("op_name") == "__template_executor__" and "+cov" in queue_name:
            __counter_stage__["new_coverage_finds"] = (
                int(__counter_stage__.get("new_coverage_finds", 0) or 0) + 1
            )
    return False

    global __mutator__
    global __no_found_counter__
    global __seed_no_found_counter__
    global __last_seed_context__

    if 'MutatorMin' not in filename_new_queue:
        return False

    seed_context = dict(__last_seed_context__) if isinstance(__last_seed_context__, dict) else None
    if __mutator__ is None and seed_context is None:
        return False

    __no_found_counter__ = 0
    __seed_no_found_counter__ = 0
    if seed_context is not None:
        _append_mutation_pair(filename_new_queue, filename_orig_queue, seed_context)
        _update_seed_stats(seed_context, found=True)
        if not seed_context.get("applied_template_mutation"):
            return False

    if __mutator__ is None or __mutator__ == SEED_POOL_MUTATOR_ID:
        return False

    stable_id = _stable_mutator_id(__mutator__)
    __batch_cache__["mutatormin_direct_finds"] = (
        int(__batch_cache__.get("mutatormin_direct_finds", 0) or 0) + 1
    )
    if False:
        return False

    # Encode a simple reward signal by increasing the JSON plan weight suffix.
    try:
        __mutator__weight = __mutator__.split('_')[-1].split('.')[0]
        __mutator__weight = int(__mutator__weight) + 1
    except (TypeError, ValueError, IndexError):
        return False

    stem, ext = os.path.splitext(__mutator__)
    if ext != ".json":
        return False

    if stable_id is not None:
        _ensure_batch_cache()
        coverage_index = __batch_cache__["coverage"]
        coverage_entry = coverage_index.get(stable_id, {})
        if not isinstance(coverage_entry, dict):
            coverage_entry = {}
        try:
            current_finds = int(coverage_entry.get("finds", 0))
        except (TypeError, ValueError):
            current_finds = 0
        try:
            legacy_finds = max(int(stem.rsplit("_", 1)[-1]) - 1, 0)
        except (TypeError, ValueError, IndexError):
            legacy_finds = 0
        try:
            stage_calls = int(coverage_entry.get("stage_calls", 0))
        except (TypeError, ValueError):
            stage_calls = 0
        updated_entry = dict(coverage_entry)
        finds = max(current_finds, legacy_finds) + 1
        updated_entry.update({
            "stable_id": stable_id,
            "finds": finds,
            "stage_calls": stage_calls,
            "selection_ratio": finds / max(stage_calls, 1),
        })
        coverage_index[stable_id] = updated_entry
        __batch_cache__["coverage_dirty"] = True
        pass

    __mutator__new = '_'.join(stem.split('_')[:-1]) + f"_{__mutator__weight}.json"
    source_entry = _find_template_plan_entry(__mutator__)
    if not isinstance(source_entry, dict):
        sys.stderr.write(f"[MutatorMin] Skip weight update, missing index entry: {__mutator__}\n")
        return False

    # Update plan file name in the configured template plan directory.
    src_file = os.path.join(_template_plan_dir(), __mutator__)
    dir_file = os.path.join(_template_plan_dir(), __mutator__new)
    try:
        if os.path.exists(src_file):
            os.rename(src_file, dir_file)
        elif isinstance(source_entry, dict) and isinstance(source_entry.get("plan"), dict):
            with open(dir_file, "w", encoding="utf-8") as f:
                json.dump(source_entry["plan"], f, indent=2, sort_keys=True)
                f.write("\n")
        else:
            sys.stderr.write(f"[MutatorMin] Skip weight update, missing plan file: {__mutator__}\n")
            return False
    except OSError as e:
        sys.stderr.write(f"[MutatorMin] Failed to rename plan {__mutator__}: {e}\n")
        return False

    # Queue callbacks can happen mid-stage. Update the cached index now and
    # defer the disk write until the stage boundary, keeping selection consistent.
    index = __batch_cache__["index"]
    updated_index = False
    for key in index:
        raw_entry = index[key]
        entry = _normalize_index_entry(raw_entry)
        if __mutator__ in entry["files"]:
            entry["files"].remove(__mutator__)
            entry["files"].append(__mutator__new)
            if isinstance(raw_entry, dict):
                updated_entry = dict(raw_entry)
                updated_entry["files"] = entry["files"]
            else:
                updated_entry = entry
            index[key] = updated_entry
            __batch_cache__["index_dirty"] = True
            __batch_cache__.setdefault("index_dirty_keys", set()).add(key)
            updated_index = True
            break
    if not updated_index:
        sys.stderr.write(f"[MutatorMin] Skip weight cache update, index not updated: {__mutator__}\n")
        return False

    plan_cache = __batch_cache__.setdefault("plans", {})
    if __mutator__ in plan_cache:
        plan_cache[__mutator__new] = plan_cache.pop(__mutator__)
    __mutator__ = __mutator__new
    # Keep the stage pinned to the renamed file after its weight increases.
    __batch_cache__["stage_mutator"] = __mutator__new

    # there is no change to the test case itself
    return False

def mutator_selector(buf=None):

    del buf
    return None

    _ensure_batch_cache()
    _refresh_index_cache_if_changed()
    index = __batch_cache__["index"]
    bandit_context = _bandit_context_for_data(buf)
    optimizer_enabled = False

    optimizer_choice = None
    if optimizer_enabled and _bandit_context_has_explicit_empty_applicable_ops(bandit_context):
        _write_runtime_status("optimizer_no_applicable_ops")
        return None

    def selectable_files(entry):
        if not _is_template_plan_entry(entry):
            return []
        normalized = _normalize_index_entry(entry)
        best_by_stable_id = {}
        has_embedded_plan = isinstance(entry, dict) and isinstance(entry.get("plan"), dict)

        def plan_weight(mutator_file):
            try:
                return max(int(str(mutator_file).rsplit("_", 1)[-1].split(".", 1)[0]), 1)
            except (TypeError, ValueError, IndexError):
                return 1

        for mutator_file in normalized["files"]:
            if not _is_template_plan_file(mutator_file):
                continue
            plan_path = _template_plan_path(mutator_file)
            if has_embedded_plan or (plan_path and os.path.exists(plan_path)):
                stable_id = _stable_mutator_id(mutator_file) or mutator_file
                old_file = best_by_stable_id.get(stable_id)
                if old_file is None or plan_weight(mutator_file) > plan_weight(old_file):
                    best_by_stable_id[stable_id] = mutator_file
        return list(best_by_stable_id.values())

    if not index:
        return None

    mutator_list = []

    for entry in index.values():
        mutator_list.extend(selectable_files(entry))

    if not mutator_list:
        _refresh_index_cache_if_changed()
        index = __batch_cache__["index"]
        for entry in index.values():
            mutator_list.extend(selectable_files(entry))

    if not mutator_list:
        return None

    coverage_items = set()
    for key in __batch_cache__["coverage"].keys():
        coverage_items.add(str(key))

    # Prefer plans that have not yet received stage feedback.
    for entry in index.values():
        for mutator_file in selectable_files(entry):
            if _stable_mutator_id(mutator_file) not in coverage_items:
                return mutator_file

    # If every plan has feedback, avoid early convergence with a small
    # exploration budget:
    # - 20%: sample from low-stage-call plans.
    # - 10%: sample uniformly from all plans.
    # - 70%: exploit by observed return rate, finds / selected stages.
    def selection_stats(mutator_file):
        stable_id = _stable_mutator_id(mutator_file)
        entry = __batch_cache__["coverage"].get(stable_id, {})
        if not isinstance(entry, dict):
            entry = {}

        try:
            finds = int(entry.get("finds", 0))
        except (TypeError, ValueError):
            finds = 0

        # Backward compatibility: before this selector, queue rewards were only
        # stored as the trailing weight in template_plan_*_<weight>.json.
        try:
            legacy_finds = max(int(mutator_file.rsplit("_", 1)[-1].split(".", 1)[0]) - 1, 0)
        except (TypeError, ValueError, IndexError):
            legacy_finds = 0
        finds = max(finds, legacy_finds)

        try:
            stage_calls = int(entry.get("stage_calls", 0))
        except (TypeError, ValueError):
            stage_calls = 0

        if stage_calls <= 0:
            last_stage = entry.get("last_stage", {})
            if isinstance(last_stage, dict):
                try:
                    execs = int(last_stage.get("execs", 0))
                except (TypeError, ValueError):
                    execs = 0
                if execs > 0:
                    stage_calls = max(1, (execs + STAGE_EXEC_COUNT - 1) // STAGE_EXEC_COUNT)

        if stage_calls <= 0:
            return {
                "finds": finds,
                "stage_calls": 0,
                "weight": 1.0,
            }

        return {
            "finds": finds,
            "stage_calls": stage_calls,
            "weight": max(finds / stage_calls, 0.01),
        }

    stats_by_file = {
        mutator_file: selection_stats(mutator_file)
        for mutator_file in mutator_list
    }

    selector_roll = random.random()
    if selector_roll < 0.20:
        # Exploration: give the least tried third of the pool a chance even if
        # they have not found coverage yet.
        sorted_by_calls = sorted(
            mutator_list,
            key=lambda item: stats_by_file[item]["stage_calls"],
        )
        low_call_count = max(1, (len(sorted_by_calls) + 2) // 3)
        selected_mutator = random.choice(sorted_by_calls[:low_call_count])
    elif selector_roll < 0.30:
        # Pure random exploration keeps unusual or previously unlucky plans
        # from being permanently starved.
        selected_mutator = random.choice(mutator_list)
    else:
        # Exploitation: select by observed new-coverage rate per selected stage.
        weights = [stats_by_file[mutator_file]["weight"] for mutator_file in mutator_list]
        selected_mutator = random.choices(mutator_list, weights=weights, k=1)[0]

    _write_runtime_status("template_plan_selected")
    return selected_mutator
