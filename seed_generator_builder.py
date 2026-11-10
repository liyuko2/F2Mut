#!/usr/bin/env python3
"""Build and validate LLM-generated file seed generators.

The builder asks the configured chat model for a JSON feature pool, then builds
one JSON-wrapped Python generator per selected feature. Each generator must
write concrete files under ./tmp/. This script validates the code, executes it
in an isolated temporary working directory, smoke-runs produced files, and
records generated seeds for AFL corpus/import synchronization.
"""

import argparse
import ast
import contextlib
import hashlib
import importlib.util
import json
import os
import random
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time

try:
    import fcntl
except ImportError:
    fcntl = None

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None

try:
    import httpx
except ImportError:
    httpx = None

try:
    from zhipuai import ZhipuAI as ZhipuAiClient
except ImportError:
    ZhipuAiClient = None

import llm_config


DEFAULT_MODULE_URL = "https://api.deepseek.com"
if os.environ.get("MODULE") == "GLM":
    DEFAULT_MODULE_NAME = "glm-4-flash-250414"
else:
    DEFAULT_MODULE_NAME = "deepseek-v4-flash"
MAX_PROMPT_PREFIX_BYTES = 4096
MAX_PROMPT_SUFFIX_BYTES = 512
DEFAULT_MAX_OUTPUT_SIZE = 1024 * 1024
DEFAULT_TIMEOUT_SEC = 8.0
DEFAULT_ATTEMPTS = 3
DEFAULT_EPOCHS = 3
DEFAULT_MAX_FEATURES = 8
DEFAULT_FEATURE_ATTEMPTS = 3
DEFAULT_REQUEST_TIMEOUT_SEC = 60.0
DEFAULT_HTTP_RETRIES = 0
DEFAULT_REQUEST_INTERVAL_SEC = 20.0
DEFAULT_RATE_LIMIT_COOLDOWN_SEC = 180.0
DEFAULT_PIP_INSTALL_TIMEOUT_SEC = 120.0
DEFAULT_PIP_INSTALL_MAX_MODULES = 4
DEFAULT_SOURCE_MODE = "format-only"
SERIAL_REQUEST_ENV = "AFL_LLM_SERIAL_REQUESTS"
REQUEST_LOCK_ENV = "AFL_LLM_REQUEST_LOCK"
REQUEST_STATE_ENV = "AFL_LLM_REQUEST_STATE"
REQUEST_INTERVAL_ENV = "AFL_LLM_SEED_REQUEST_INTERVAL"
RATE_LIMIT_COOLDOWN_ENV = "AFL_LLM_SEED_RATE_LIMIT_COOLDOWN"
SEED_ARTIFACTS_DIR_ENV = "AFL_LLM_SEED_DIR"
SEED_AUTO_PIP_INSTALL_ENV = "AFL_LLM_SEED_AUTO_PIP_INSTALL"
SEED_PIP_INSTALL_TIMEOUT_ENV = "AFL_LLM_SEED_PIP_INSTALL_TIMEOUT"
SEED_PIP_INSTALL_MAX_MODULES_ENV = "AFL_LLM_SEED_PIP_INSTALL_MAX_MODULES"
SEED_PIP_INSTALL_ARGS_ENV = "AFL_LLM_SEED_PIP_INSTALL_ARGS"
SEED_ARTIFACTS_DIR_NAME = "generated_seed_data"
FEATURE_POOL_KIND = "seed_feature_pool"
GENERATOR_KIND = "seed_generator_candidate"
PARENT_GENERATOR_CODE_LIMIT = 12000
FORMAT_EXECUTOR_DIR_NAME = "generated_format_executors"
FORMAT_EXECUTOR_DIR_ENV = "AFL_LLM_FORMAT_EXECUTOR_DIR"
TEMPLATE_EXECUTOR_DIR_ENV = "AFL_LLM_TEMPLATE_EXECUTOR_DIR"
TEMPLATE_EXECUTOR_ENV = "AFL_LLM_TEMPLATE_EXECUTOR"
TEMPLATE_DYNAMIC_RELOAD_ENV = "AFL_LLM_TEMPLATE_DYNAMIC_RELOAD"
CURRENT_TEMPLATE_EXECUTOR_FILE = "current_template_executor.json"
DISABLE_DYNAMIC_TEMPLATE_ENV = "AFL_LLM_DISABLE_DYNAMIC_TEMPLATE"


SYSTEM_PROMPT = """
You analyze file-format features and generate safe, bounded Python file
generators for greybox fuzzing.
Return one valid JSON object only. Do not wrap it in markdown fences such as
```json. Do not return prose, shell commands, target execution instructions,
networking behavior, or exploit logic.
""".strip()


def _base_dir():
    return os.path.dirname(os.path.abspath(__file__))


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


def _env_truthy(name, default=True):
    value = os.environ.get(name)
    if value is None:
        return bool(default)
    return str(value).strip().lower() not in {"0", "false", "no", "off"}


def _env_float(name, default):
    value = os.environ.get(name)
    if value is None:
        return float(default)
    try:
        return float(value)
    except (TypeError, ValueError):
        return float(default)


def _env_int(name, default, lower=None, upper=None):
    try:
        value = int(os.environ.get(name, str(default)) or default)
    except (TypeError, ValueError):
        value = int(default)
    if lower is not None:
        value = max(value, int(lower))
    if upper is not None:
        value = min(value, int(upper))
    return value
    try:
        return float(value)
    except (TypeError, ValueError):
        return float(default)


def _request_lock_path():
    path = os.environ.get(REQUEST_LOCK_ENV)
    if isinstance(path, str) and path.strip():
        return os.path.abspath(path.strip())
    return os.path.join(_seed_artifacts_dir(), "llm_request.lock")


def _request_state_path():
    path = os.environ.get(REQUEST_STATE_ENV)
    if isinstance(path, str) and path.strip():
        return os.path.abspath(path.strip())
    return os.path.join(_seed_artifacts_dir(), "llm_request_state.json")


def _read_request_state(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except (OSError, ValueError, json.JSONDecodeError):
        return {}


def _write_request_state(path, state):
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    tmp_path = f"{path}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, sort_keys=True)
        f.write("\n")
    os.replace(tmp_path, path)


def _is_rate_limit_error(exc):
    text = f"{type(exc).__name__}: {exc}".lower()
    return (
        "429" in text or
        "rate limit" in text or
        "reachlimit" in text or
        "1302" in text or
        "控制请求频率" in text
    )


def _sleep_for(seconds, reason):
    seconds = max(0.0, float(seconds or 0.0))
    if seconds <= 0:
        return
    sys.stderr.write(f"[seed-generator] sleeping {seconds:.1f}s before LLM request: {reason}\n")
    sys.stderr.flush()
    time.sleep(seconds)


class SerializedLLMRequest:
    def __init__(self, request_label, json_try):
        self.request_label = request_label
        self.json_try = json_try
        self.lock_file = None
        self.path = _request_lock_path()
        self.state_path = _request_state_path()

    def _wait_for_turn(self):
        state = _read_request_state(self.state_path)
        now = time.time()
        cooldown_until = float(state.get("rate_limit_until", 0) or 0)
        if cooldown_until > now:
            _sleep_for(cooldown_until - now, "provider rate-limit cooldown")
            now = time.time()
        request_interval = max(0.0, _env_float(REQUEST_INTERVAL_ENV, DEFAULT_REQUEST_INTERVAL_SEC))
        last_request_ts = float(state.get("last_request_ts", 0) or 0)
        next_allowed = last_request_ts + request_interval
        if next_allowed > now:
            _sleep_for(next_allowed - now, "configured inter-request interval")

    def __enter__(self):
        if not _env_truthy(SERIAL_REQUEST_ENV, default=True):
            return self
        if fcntl is None:
            sys.stderr.write(
                "[seed-generator] serial request lock unavailable on this platform; "
                "continuing without cross-process serialization\n"
            )
            sys.stderr.flush()
            return self
        parent = os.path.dirname(self.path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        self.lock_file = open(self.path, "a+", encoding="utf-8")
        sys.stderr.write(
            f"[seed-generator] waiting LLM request lock label={self.request_label} "
            f"json_try={self.json_try} path={self.path}\n"
        )
        sys.stderr.flush()
        fcntl.flock(self.lock_file.fileno(), fcntl.LOCK_EX)
        self._wait_for_turn()
        self.lock_file.seek(0)
        self.lock_file.truncate()
        self.lock_file.write(
            f"pid={os.getpid()} label={self.request_label} json_try={self.json_try} "
            f"ts={int(time.time())}\n"
        )
        self.lock_file.flush()
        sys.stderr.write(
            f"[seed-generator] acquired LLM request lock label={self.request_label} "
            f"json_try={self.json_try}\n"
        )
        sys.stderr.flush()
        return self

    def __exit__(self, exc_type, exc, tb):
        if self.lock_file is None:
            return False
        state = _read_request_state(self.state_path)
        now = time.time()
        state["last_request_ts"] = now
        state["last_request_label"] = self.request_label
        state["last_request_json_try"] = self.json_try
        state["last_request_pid"] = os.getpid()
        if exc is not None and _is_rate_limit_error(exc):
            cooldown = max(0.0, _env_float(RATE_LIMIT_COOLDOWN_ENV, DEFAULT_RATE_LIMIT_COOLDOWN_SEC))
            state["rate_limit_until"] = now + cooldown
            state["last_rate_limit_ts"] = now
            state["last_rate_limit_error"] = _compact_error(exc)
            sys.stderr.write(
                f"[seed-generator] rate limit detected; cooling down {cooldown:.1f}s "
                f"before next LLM request\n"
            )
            sys.stderr.flush()
        else:
            state["rate_limit_until"] = max(0.0, float(state.get("rate_limit_until", 0) or 0))
        try:
            _write_request_state(self.state_path, state)
        except OSError as state_exc:
            sys.stderr.write(f"[seed-generator] failed to write request state: {state_exc}\n")
            sys.stderr.flush()
        try:
            fcntl.flock(self.lock_file.fileno(), fcntl.LOCK_UN)
        finally:
            self.lock_file.close()
            self.lock_file = None
        sys.stderr.write(
            f"[seed-generator] released LLM request lock label={self.request_label} "
            f"json_try={self.json_try}\n"
        )
        sys.stderr.flush()
        return False


def _normalize_model_name(model):
    return llm_config.resolve_model(model, default=DEFAULT_MODULE_NAME)


def _is_glm_model(model):
    return llm_config.is_glm_model(model)


def _is_deepseek_model(model):
    return llm_config.is_deepseek_model(model)


def _api_key_for_model(model, explicit_key=None, api_key_env=None):
    return llm_config.resolve_api_key(
        _normalize_model_name(model),
        explicit_key=explicit_key,
        explicit_key_env=api_key_env,
    )


def _module_url_for_model(model, explicit_url=None):
    return llm_config.resolve_base_url(
        _normalize_model_name(model),
        explicit_url=explicit_url,
        legacy_env_names=("OPENAI_BASE_URL", "DEEPSEEK_BASE_URL"),
        default_openai_compat_base_url=DEFAULT_MODULE_URL,
    )


@contextlib.contextmanager
def _temporary_env_unset(names):
    saved = {}
    for name in names:
        if name in os.environ:
            saved[name] = os.environ.pop(name)
    try:
        yield
    finally:
        for name, value in saved.items():
            os.environ[name] = value


def _create_client(model, api_key, timeout=None, max_retries=DEFAULT_HTTP_RETRIES,
                   module_url=None):
    if not api_key:
        raise RuntimeError("LLM API key is not set")
    if _is_glm_model(model):
        if ZhipuAiClient is None:
            raise RuntimeError("zhipuai module is not installed")
        return ZhipuAiClient(api_key=api_key, timeout=timeout, max_retries=max_retries)
    if OpenAI is None:
        raise RuntimeError("openai module is not installed")
    module_url = _module_url_for_model(model, module_url)
    kwargs = {
        "api_key": api_key,
        "base_url": module_url,
        "timeout": timeout,
        "max_retries": max_retries,
    }
    all_proxy = os.environ.get("ALL_PROXY") or os.environ.get("all_proxy") or ""
    http_proxy = (
        os.environ.get("HTTPS_PROXY")
        or os.environ.get("https_proxy")
        or os.environ.get("HTTP_PROXY")
        or os.environ.get("http_proxy")
    )
    if all_proxy.lower().startswith("socks://"):
        if http_proxy and httpx is not None:
            kwargs["http_client"] = httpx.Client(proxy=http_proxy, timeout=timeout)
            return OpenAI(**kwargs)
        with _temporary_env_unset(("ALL_PROXY", "all_proxy")):
            return OpenAI(**kwargs)
    return OpenAI(**kwargs)


def _response_content(response):
    choices = getattr(response, "choices", None)
    if not choices:
        return ""
    message = getattr(choices[0], "message", None)
    if message is None:
        return ""
    return getattr(message, "content", "") or ""


def _extract_json(text):
    if isinstance(text, dict):
        return text
    text = str(text or "").strip()
    if not text:
        raise ValueError("empty LLM response")
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE)
        text = re.sub(r"\s*```$", "", text).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        start = text.find("{")
        end = text.rfind("}")
        if start == -1 or end == -1 or end <= start:
            raise ValueError(
                f"LLM response did not contain a JSON object: {exc.msg} at char {exc.pos}"
            ) from exc
        try:
            return json.loads(text[start:end + 1])
        except json.JSONDecodeError as inner_exc:
            preview = text[:600].replace("\n", "\\n")
            raise ValueError(
                "LLM response JSON was invalid "
                f"({inner_exc.msg} at char {inner_exc.pos}); preview={preview!r}"
            ) from inner_exc


def _compact_error(exc, limit=1200):
    message = f"{type(exc).__name__}: {exc}"
    message = message.replace("\x00", "")
    if len(message) > limit:
        return message[:limit] + "...<truncated>"
    return message


def _run_noisy_stdout_on_stderr(fn, *args, **kwargs):
    """Keep this CLI's stdout reserved for the final JSON payload."""
    with contextlib.redirect_stdout(sys.stderr):
        return fn(*args, **kwargs)


def _failure_feedback_message(failures, expected_format=None):
    if not failures:
        return ""
    format_value = str(expected_format or "same as requested format")
    payload = {
        "previous_failures": failures[-3:],
        "required_top_level_schema": {
            "version": 1,
            "kind": GENERATOR_KIND,
            "format": format_value,
            "primary_feature": "target feature name",
            "features": ["primary feature and any additional concrete features"],
            "generator_code": "complete Python script as one JSON string",
            "expected_outputs": ["names written under ./tmp/"],
        },
        "repair_instructions": [
            "Return a fresh JSON object only.",
            "Do not wrap the JSON in markdown fences.",
            "Include the exact numeric field version: 1.",
            f"Include the exact string field kind: {GENERATOR_KIND}.",
            f"Include the exact string field format: {format_value}.",
            "Include primary_feature, features, generator_code, and expected_outputs.",
            "Fix the concrete validation/runtime/smoke error listed above.",
            "Keep generator_code safe and write all files under ./tmp/.",
            "Keep generator_code compact; prefer one helper function and 1-3 outputs.",
            "Do not include print/logging/debug output in generator_code.",
            "Ensure generated files follow the requested format and stay small.",
        ],
    }
    return (
        "\n\nPrevious candidate attempts failed. Use these failure details to "
        "repair the next candidate:\n"
        f"{json.dumps(payload, ensure_ascii=True, indent=2, sort_keys=True)}"
    )


def _feature_failure_feedback_message(failures, expected_format=None):
    if not failures:
        return ""
    format_value = str(expected_format or "same as requested format")
    payload = {
        "previous_failures": failures[-3:],
        "required_top_level_schema": {
            "version": 1,
            "kind": FEATURE_POOL_KIND,
            "format": format_value,
            "features": [
                {
                    "name": "short concrete feature name",
                    "description": "generator-actionable file feature description",
                }
            ],
        },
        "repair_instructions": [
            "Return a fresh JSON object only.",
            "Do not wrap the JSON in markdown fences.",
            "Include the exact numeric field version: 1.",
            f"Use kind {FEATURE_POOL_KIND}.",
            f"Include the exact string field format: {format_value}.",
            "Each item in features must be an object with non-empty name and description.",
            "Do not include generator_code in the feature pool response.",
        ],
    }
    return (
        "\n\nPrevious feature-pool attempts failed. Use these failure details "
        "to repair the next response:\n"
        f"{json.dumps(payload, ensure_ascii=True, indent=2, sort_keys=True)}"
    )


def _load_module_from_path(path, module_prefix):
    module_name = f"{module_prefix}_{hashlib.sha256(path.encode()).hexdigest()[:12]}"
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"invalid module spec for {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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
    raw_path = payload.get("code") or payload.get("executor") or payload.get("path")
    if not isinstance(raw_path, str) or not raw_path.strip():
        return None
    raw_path = raw_path.strip()
    if not os.path.isabs(raw_path):
        raw_path = os.path.join(_base_dir(), raw_path)
    path = os.path.abspath(raw_path)
    return path if os.path.isfile(path) else None


def _active_executor_path():
    env_path = os.environ.get(TEMPLATE_EXECUTOR_ENV)
    if isinstance(env_path, str) and env_path.strip():
        env_path = env_path.strip()
        if env_path.endswith(".json"):
            sibling = os.path.splitext(env_path)[0] + ".py"
            if os.path.exists(sibling):
                env_path = sibling
        if not os.path.isabs(env_path):
            env_path = os.path.join(_base_dir(), env_path)
        return os.path.abspath(env_path)

    disabled = str(os.environ.get(DISABLE_DYNAMIC_TEMPLATE_ENV, "")).lower() in {
        "1", "true", "yes", "on",
    }
    dynamic_reload = str(os.environ.get(TEMPLATE_DYNAMIC_RELOAD_ENV, "")).lower() in {
        "1", "true", "yes", "on",
    }
    if dynamic_reload:
        current = _current_template_executor_path()
        if current:
            return current
    if not disabled:
        latest = _latest_generated_executor_path()
        if latest:
            return latest
    return os.path.join(_base_dir(), "elf_template_executor.py")


def _load_active_executor(required=True):
    path = _active_executor_path()
    try:
        module = _load_module_from_path(path, "_seedgen_executor")
    except Exception:
        if required:
            raise
        return None, path
    execute = getattr(module, "execute_template_plan", None)
    if not callable(execute):
        if not required:
            return None, path
        raise RuntimeError(f"active executor missing execute_template_plan: {path}")
    return module, path


def _safe_token(value, fallback="item"):
    token = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(value or "").strip())
    token = token.strip("._-")
    return (token or fallback)[:64]


def _feature_id_from_name(value):
    text = str(value or "").strip().lower()
    text = re.sub(r"[^a-z0-9]+", "_", text).strip("_")
    return text[:64] or "feature"


def _compact_profile(profile):
    if not isinstance(profile, dict):
        return {}
    keys = [
        "format", "class", "endian", "machine", "entry", "phoff", "phentsize",
        "phnum", "shoff", "shentsize", "shnum", "shstrndx",
    ]
    compact = {key: profile.get(key) for key in keys if key in profile}
    regions = profile.get("regions")
    if isinstance(regions, dict):
        compact["regions"] = {
            str(name)[:80]: {
                "offset": info.get("offset"),
                "size": info.get("size"),
            }
            for name, info in list(regions.items())[:16]
            if isinstance(info, dict)
        }
    return compact


def _elf_header_summary(data):
    summary = {
        "magic": data[:4].hex(),
        "length": len(data),
    }
    if len(data) < 16 or data[:4] != b"\x7fELF":
        summary["is_elf"] = False
        return summary
    summary["is_elf"] = True
    summary["ei_class"] = data[4]
    summary["ei_data"] = data[5]
    summary["ei_version"] = data[6]
    return summary


def summarize_input(path, file_format, executor):
    with open(path, "rb") as f:
        data = f.read()
    sha = hashlib.sha256(data).hexdigest()
    summary = {
        "format": file_format,
        "path_basename": os.path.basename(path),
        "length": len(data),
        "sha256": sha,
        "prefix_hex": data[:MAX_PROMPT_PREFIX_BYTES].hex(),
        "suffix_hex": data[-MAX_PROMPT_SUFFIX_BYTES:].hex()
        if len(data) > MAX_PROMPT_PREFIX_BYTES else "",
        "truncated": len(data) > MAX_PROMPT_PREFIX_BYTES,
    }
    if file_format.lower() == "elf":
        summary["elf_header"] = _elf_header_summary(data)
    parse_profile = getattr(executor, "parse_profile", None)
    if callable(parse_profile):
        try:
            summary["executor_profile"] = _compact_profile(parse_profile(data))
        except Exception as exc:
            summary["executor_profile_error"] = str(exc)[:200]
    return summary, data


def format_only_input_summary(file_format):
    normalized = str(file_format or "unknown").strip().lower() or "unknown"
    return {
        "format": normalized,
        "source_mode": "format_only",
        "sha256": "format_only",
        "input_available": False,
        "target_format": normalized,
        "prompt_scope": (
            "No concrete input sample is provided. Infer format-level structures "
            "from the target format name only."
        ),
    }


def _input_summary_for_prompt(input_summary):
    summary = dict(input_summary) if isinstance(input_summary, dict) else {}
    if summary.get("source_mode") == "format_only":
        return {
            "source_mode": "format_only",
            "target_format": summary.get("target_format") or summary.get("format"),
            "input_available": False,
            "instruction": (
                "Use only the target format name. Do not infer constraints from "
                "a sample file because no sample is provided."
            ),
        }
    return summary


def _g2fuzz_feature_lines(features):
    lines = []
    for index, item in enumerate(features or [], 1):
        text = str(item or "").strip()
        if text:
            lines.append(f"{index}. {text[:220]}")
    return "\n".join(lines)


def build_feature_prompt(file_format, input_summary, known_features=None, max_features=DEFAULT_MAX_FEATURES):
    max_features = max(1, int(max_features or DEFAULT_MAX_FEATURES))
    known_features = [str(item)[:220] for item in (known_features or []) if str(item).strip()]
    context = {
        "target_format": file_format,
        "input_source": "format_only" if input_summary.get("source_mode") == "format_only" else "sample",
        "initial_input_summary": _input_summary_for_prompt(input_summary),
        "known_features": known_features,
        "required_output": {
            "version": 1,
            "kind": FEATURE_POOL_KIND,
            "format": file_format,
            "features": [
                {
                    "id": "stable_snake_case_feature_id",
                    "name": "short concrete feature name",
                    "description": "one precise description of the file structure or data property",
                }
            ],
        },
    }
    known_feature_lines = _g2fuzz_feature_lines(known_features)
    if known_features:
        g2fuzz_question = (
            f"Here are some features associated with '{file_format}' files:\n"
            f"{known_feature_lines}\n\n"
            f"Apart from the above features, what other features can "
            f"'{file_format}' files have?"
        )
    else:
        g2fuzz_question = f"What features can '{file_format}' files have?"

    if input_summary.get("source_mode") == "format_only":
        source_instruction = (
            "Use only the target format name. Do not rely on, imagine, or "
            "specialize to any sample file bytes. Cover the broader format "
            "space that a standalone generator could synthesize."
        )
    else:
        source_instruction = (
            "Use the sample summary only as weak context. Do not limit the "
            "feature list to structures present in that one sample."
        )
    return f"""
G2FUZZ-style feature discovery:
{g2fuzz_question}

Translate the answer into the required JSON contract below.

Context:
{json.dumps(context, ensure_ascii=True, indent=2, sort_keys=True)}

Requirements:
- Output exactly one JSON object and nothing else.
- Do not wrap the JSON in ```json or any other markdown fence.
- Include the exact numeric top-level field "version": 1.
- Include the exact top-level field "kind": "{FEATURE_POOL_KIND}".
- Include the exact top-level field "format": "{file_format}".
- Return at most {max_features} features.
- Each feature must be an object with non-empty id, name, and description.
- Feature id must be stable snake_case derived from the feature name. It will be
  used as the one-to-one key for both seed generators and mutation ops.
- Follow the G2FUZZ discovery spirit: enumerate concrete file-format features,
  and when known_features is non-empty, focus on rare or previously uncovered
  features instead of restating the listed ones.
- Prefer concrete, generator-actionable file properties: structure, metadata,
  encoding, container layout, indexes, tables, checksums, compression,
  optional chunks/sections, object relationships, boundary values, unusual but
  valid alignments, and parser-deep edge cases.
- Prioritize parser-deep structures over only top-level header bytes when the
  format has nested tables, sections, records, directories, streams, metadata
  blocks, symbol/reference tables, relocation/linkage records, or optional
  extension areas.
- {source_instruction}
- Do not specialize the answer to one implementation. Describe the format-level
  feature a generator should create.
""".strip()


def build_prompt(file_format, input_summary, prompt_max_files=3, feature=None,
                 generation_mode="initial", parent_generator=None,
                 strategy_context=None):
    prompt_max_files = max(1, min(int(prompt_max_files or 3), 3))
    feature = feature if isinstance(feature, dict) else {}
    primary_feature = str(feature.get("name") or "broad_format_coverage").strip()
    feature_id = _feature_id_from_name(feature.get("id") or primary_feature)
    feature_description = str(
        feature.get("description") or "Create valid files that exercise multiple concrete format features."
    ).strip()
    generation_mode = "mutation" if generation_mode == "mutation" else "initial"
    parent_code = ""
    context = {
        "target_format": file_format,
        "input_source": "format_only" if input_summary.get("source_mode") == "format_only" else "sample",
        "initial_input_summary": _input_summary_for_prompt(input_summary),
        "generation_mode": generation_mode,
        "target_feature": {
            "id": feature_id,
            "name": primary_feature,
            "description": feature_description,
        },
        "required_output": {
            "version": 1,
            "kind": GENERATOR_KIND,
            "format": file_format,
            "feature_id": feature_id,
            "primary_feature": primary_feature,
            "features": [
                primary_feature,
            ],
            "generator_code": "single Python script as a string",
            "expected_outputs": [f"seed_0.{_safe_token(file_format, 'bin')}"],
        },
    }
    if parent_generator:
        parent_code = str(parent_generator.get("generator_code") or "")
        context["parent_generator"] = {
            "generator_id": parent_generator.get("generator_id"),
            "primary_feature": parent_generator.get("primary_feature"),
            "features": list(parent_generator.get("features") or []),
            "generator_code": parent_code[:PARENT_GENERATOR_CODE_LIMIT],
            "truncated": len(parent_code) > PARENT_GENERATOR_CODE_LIMIT,
        }
    if isinstance(strategy_context, dict) and strategy_context:
        context["strategy_context"] = strategy_context
    if generation_mode == "mutation":
        parent_block = parent_code[:PARENT_GENERATOR_CODE_LIMIT] if parent_code else "# no parent generator code provided"
        g2fuzz_task = f"""
G2FUZZ-style generator mutation:
The code below is used to generate {file_format} files.

```python
{parent_block}
```

Extend that generator so it creates a new {file_format} file containing an
additional feature named "{primary_feature}" besides the existing features.
The description of "{primary_feature}" is:

```
{feature_description}
```

Return the extended generator through the JSON field "generator_code".
""".strip()
    else:
        feature_block = f"{primary_feature}: {feature_description}"
        g2fuzz_task = f"""
G2FUZZ-style input generator synthesis:
Generate {file_format} files containing the following feature using Python
without any input files, and save all generated files into ./tmp/.

```
{feature_block}
```

Return the generator through the JSON field "generator_code".
""".strip()
    return f"""
{g2fuzz_task}

Context:
{json.dumps(context, ensure_ascii=True, indent=2, sort_keys=True)}

Requirements:
- Output exactly one JSON object and nothing else.
- Do not wrap the JSON in ```json or any other markdown fence.
- Include the exact numeric top-level field "version": 1.
- Include the exact top-level field "kind": "{GENERATOR_KIND}".
- Include the exact top-level field "format": "{file_format}".
- The generator must create {file_format} files without reading input files.
- If input_source is format_only, the generator must be standalone and must not
  reconstruct, decode, embed, or rely on any sample input bytes.
- The generator must write all produced files under ./tmp/.
- Include feature_id and primary_feature in the JSON. Both must exactly match
  target_feature.
- In initial mode, the JSON features list must contain exactly one string: the
  target primary_feature.
- In mutation mode, the JSON features list must include the target
  primary_feature and may include parent_generator features that are still
  intentionally produced by the combined generator.
- If strategy_context is present, follow its strategy-specific instruction
  while keeping the same output contract and safety limits.
- Follow the G2FUZZ synthesis spirit: generate a compact standalone Python
  program that constructs files for the requested feature, instead of merely
  patching bytes from an existing sample.
- In mutation mode, preserve the useful structure of the parent generator and
  add the new target feature as a real generated structure, not as an inert
  comment or metadata label.
- The produced files must exercise the target_feature description.
- generator_code must be a complete single-file Python script.
- generator_code must be JSON-escaped as one string; escape newlines as \\n.
- Keep generator_code compact, preferably below 2500 characters.
- Do not print, log, or write progress/debug messages. The generator should be
  silent except for writing seed files under ./tmp/.
- Keep generated files small, below 1 MiB each, and produce 1 to {prompt_max_files} files.
- If producing more than one file, each produced file must be byte-distinct
  and must exercise a different bounded value or layout for the target feature.
- Do not enumerate many independent full-file builders; use a small helper
  function and a short loop if producing more than one file.
- Use deterministic structure with some bounded randomness if useful.
- Do not execute the target. Do not use networking, subprocesses, shell, eval,
  exec, or any path outside ./tmp/. Standard-library and third-party imports
  are allowed; missing imported modules may be installed during local validation.
- For binary files, prefer either open("./tmp/name.ext", "wb") or:
  name = os.path.join("./tmp", "name.ext"); open(name, "wb").
""".strip()


def _request_json_from_llm(user_prompt, request_label, model=None, module_url=None,
                           api_key=None, max_tokens=8192, request_timeout=DEFAULT_REQUEST_TIMEOUT_SEC,
                           http_retries=DEFAULT_HTTP_RETRIES, temperature=0.4,
                           parse_retry_hint=None):
    model = _normalize_model_name(model)
    api_key = _api_key_for_model(model, api_key)
    request_timeout = max(1.0, float(request_timeout or DEFAULT_REQUEST_TIMEOUT_SEC))
    http_retries = max(0, int(http_retries or 0))
    if _is_glm_model(model):
        client = _create_client(
            model,
            api_key,
            timeout=request_timeout,
            max_retries=http_retries,
        )
    else:
        client = _create_client(
            model,
            api_key,
            timeout=request_timeout,
            max_retries=http_retries,
            module_url=module_url,
        )
    last_text = ""
    last_error = None
    kwargs = {
        "model": model,
        "temperature": temperature,
        "max_tokens": max_tokens,
        "response_format": {"type": "json_object"},
    }
    if _is_glm_model(model):
        kwargs["thinking"] = {"type": "disabled"}
    elif _is_deepseek_model(model):
        kwargs["extra_body"] = {"thinking": {"type": "disabled"}}
    if not _is_glm_model(model):
        kwargs.update({
            "top_p": 0.95,
            "stream": False,
            "stop": None,
            "frequency_penalty": 0,
            "presence_penalty": 0,
        })
    for attempt in range(2):
        prompt = user_prompt
        if attempt:
            prompt += (
                "\n\nYour previous response could not be parsed as JSON. "
                "Return a compact JSON object only. String fields must be valid "
                "JSON strings with escaped newlines where needed. Do not wrap the "
                "JSON in markdown fences."
            )
            if parse_retry_hint:
                prompt += "\n" + str(parse_retry_hint)
            kwargs["temperature"] = min(float(kwargs.get("temperature", temperature)), 0.2)
        kwargs["messages"] = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ]
        kwargs["timeout"] = request_timeout
        sys.stderr.write(
            f"[seed-generator] requesting {request_label} json_try={attempt + 1}/2 "
            f"model={model} timeout={request_timeout:.1f}s retries={http_retries}\n"
        )
        sys.stderr.flush()
        with SerializedLLMRequest(request_label, attempt + 1):
            response = client.chat.completions.create(**kwargs)
        last_text = _response_content(response)
        try:
            return _extract_json(last_text)
        except ValueError as exc:
            last_error = exc
    preview = (last_text or "")[:600].replace("\n", "\\n")
    raise ValueError(
        f"LLM did not return valid {request_label} JSON after retry: {last_error}; "
        f"preview={preview!r}"
    )


def request_feature_pool_from_llm(file_format, input_summary, known_features=None,
                                  max_features=DEFAULT_MAX_FEATURES, model=None,
                                  module_url=None, api_key=None, max_tokens=8192,
                                  failure_feedback=None,
                                  request_timeout=DEFAULT_REQUEST_TIMEOUT_SEC,
                                  http_retries=DEFAULT_HTTP_RETRIES):
    user_prompt = build_feature_prompt(
        file_format,
        input_summary,
        known_features=known_features,
        max_features=max_features,
    )
    if failure_feedback:
        user_prompt += _feature_failure_feedback_message(
            failure_feedback,
            expected_format=file_format,
        )
    return _request_json_from_llm(
        user_prompt,
        "feature-pool",
        model=model,
        module_url=module_url,
        api_key=api_key,
        max_tokens=max_tokens,
        request_timeout=request_timeout,
        http_retries=http_retries,
        temperature=0.4,
        parse_retry_hint="The features value must be a JSON array of objects with name and description.",
    )


def request_generator_from_llm(file_format, input_summary, model=None,
                               module_url=None, api_key=None, max_tokens=65536,
                               failure_feedback=None, request_timeout=DEFAULT_REQUEST_TIMEOUT_SEC,
                               http_retries=DEFAULT_HTTP_RETRIES,
                               prompt_max_files=3, feature=None,
                               generation_mode="initial", parent_generator=None,
                               strategy_context=None):
    base_user_prompt = build_prompt(
        file_format,
        input_summary,
        prompt_max_files=prompt_max_files,
        feature=feature,
        generation_mode=generation_mode,
        parent_generator=parent_generator,
        strategy_context=strategy_context,
    )
    if failure_feedback:
        base_user_prompt += _failure_feedback_message(
            failure_feedback,
            expected_format=file_format,
        )
    return _request_json_from_llm(
        base_user_prompt,
        "seed-generator",
        model=model,
        module_url=module_url,
        api_key=api_key,
        max_tokens=max_tokens,
        request_timeout=request_timeout,
        http_retries=http_retries,
        temperature=0.4,
        parse_retry_hint=(
            "The generator_code value must be a JSON string with escaped newlines, "
            "not raw multi-line Python."
        ),
    )


def _feature_dedupe_key(name):
    return re.sub(r"\s+", " ", str(name or "").strip().lower())


def _format_tokens(value):
    text = str(value or "").strip().lower()
    safe = re.sub(r"[^a-z0-9]+", " ", text)
    return [token for token in safe.split() if token]


def _format_matches(actual, expected):
    actual_text = str(actual or "").strip().lower()
    expected_text = str(expected or "").strip().lower()
    if not actual_text or not expected_text:
        return False
    if actual_text == expected_text:
        return True
    actual_tokens = set(_format_tokens(actual_text))
    expected_tokens = set(_format_tokens(expected_text))
    if not actual_tokens or not expected_tokens:
        return False
    if actual_tokens == expected_tokens:
        return True
    meaningful_expected = {token for token in expected_tokens if len(token) >= 2}
    meaningful_actual = {token for token in actual_tokens if len(token) >= 2}
    return bool(meaningful_expected & meaningful_actual)


def _normalize_feature_name(item):
    if isinstance(item, dict):
        item = item.get("name") or item.get("feature")
    return str(item or "").strip()[:200]


def normalize_feature_pool(raw, file_format, max_features=None, epoch_added=0):
    pool = _extract_json(raw)
    if not isinstance(pool, dict):
        raise ValueError("feature pool must be a JSON object")
    try:
        version = int(pool.get("version", 0))
    except (TypeError, ValueError):
        version = 0
    if version != 1:
        keys = sorted(str(key) for key in pool.keys())[:12]
        raise ValueError(
            "feature pool version must be numeric 1; "
            f"got {pool.get('version')!r}; keys={keys}"
        )
    if pool.get("kind") != FEATURE_POOL_KIND:
        raise ValueError(f"feature pool kind must be {FEATURE_POOL_KIND}")
    actual_format = pool.get("format", "")
    if not _format_matches(actual_format, file_format):
        raise ValueError(
            "feature pool format does not match requested format; "
            f"expected={file_format!r}; got={actual_format!r}"
        )
    raw_features = pool.get("features")
    if not isinstance(raw_features, list) or not raw_features:
        raise ValueError("feature pool must include non-empty features list")

    limit = int(max_features or len(raw_features))
    normalized = []
    seen = set()
    for item in raw_features:
        if not isinstance(item, dict):
            raise ValueError("each feature must be an object with name and description")
        name = str(item.get("name") or item.get("feature") or "").strip()
        description = str(item.get("description") or "").strip()
        if not name or not description:
            raise ValueError("each feature must include non-empty name and description")
        feature_id = _feature_id_from_name(item.get("id") or name)
        key = feature_id
        if key in seen:
            continue
        seen.add(key)
        normalized.append({
            "id": feature_id,
            "name": name[:160],
            "description": description[:1200],
            "epoch_added": int(epoch_added or 0),
            "status": "pending",
        })
        if len(normalized) >= limit:
            break
    if not normalized:
        raise ValueError("feature pool only contained duplicate or empty features")
    return normalized


def normalize_candidate(raw, file_format, feature=None, generation_mode="initial",
                        parent_generator_id=None, parent_generator=None, epoch=0):
    candidate = _extract_json(raw)
    if not isinstance(candidate, dict):
        raise ValueError("candidate must be a JSON object")
    try:
        version = int(candidate.get("version", 0))
    except (TypeError, ValueError):
        version = 0
    if version != 1:
        keys = sorted(str(key) for key in candidate.keys())[:12]
        raise ValueError(
            "candidate version must be numeric 1; "
            f"got {candidate.get('version')!r}; keys={keys}"
        )
    if candidate.get("kind") != GENERATOR_KIND:
        raise ValueError(f"candidate kind must be {GENERATOR_KIND}")
    actual_format = candidate.get("format", "")
    if not _format_matches(actual_format, file_format):
        raise ValueError(
            "candidate format does not match requested format; "
            f"expected={file_format!r}; got={actual_format!r}"
        )
    primary_feature = str(candidate.get("primary_feature") or "").strip()
    if not primary_feature:
        raise ValueError("candidate must include primary_feature")
    feature = feature if isinstance(feature, dict) else {}
    target_feature = str(feature.get("name") or primary_feature).strip()
    target_feature_id = _feature_id_from_name(feature.get("id") or target_feature)
    candidate_feature_id = _feature_id_from_name(
        candidate.get("feature_id") or candidate.get("primary_feature_id") or primary_feature
    )
    if _feature_dedupe_key(primary_feature) != _feature_dedupe_key(target_feature):
        raise ValueError(
            "candidate primary_feature must exactly target the requested feature; "
            f"expected={target_feature!r}; got={primary_feature!r}"
        )
    if candidate_feature_id != target_feature_id:
        raise ValueError(
            "candidate feature_id must exactly target the requested feature id; "
            f"expected={target_feature_id!r}; got={candidate_feature_id!r}"
        )
    features = candidate.get("features")
    if not isinstance(features, list) or not features:
        raise ValueError("candidate must include non-empty features list")
    features = [_normalize_feature_name(item) for item in features]
    features = [item for item in features if item]
    if not features:
        raise ValueError("candidate features list only contains empty values")
    target_key = _feature_dedupe_key(target_feature)
    feature_keys = {_feature_dedupe_key(item) for item in features}
    if generation_mode == "mutation":
        if target_key not in feature_keys:
            raise ValueError("mutation candidate features must include the requested primary feature")
    elif len(features) != 1 or _feature_dedupe_key(features[0]) != target_key:
        raise ValueError(
            "initial candidate features must contain exactly the requested primary feature "
            "and no incidental features"
        )
    deduped_features = []
    seen_feature_keys = set()
    for name in features:
        key = _feature_dedupe_key(name)
        if key and key not in seen_feature_keys:
            deduped_features.append(name[:200])
            seen_feature_keys.add(key)
    parent_feature_ids = []
    if isinstance(parent_generator, dict):
        parent_feature_ids = [
            _feature_id_from_name(item)
            for item in (parent_generator.get("feature_ids") or [])
            if isinstance(item, str) and item
        ]
    feature_ids = []
    for feature_id in [target_feature_id] + parent_feature_ids:
        if feature_id and feature_id not in feature_ids:
            feature_ids.append(feature_id)
    code = candidate.get("generator_code")
    if not isinstance(code, str) or not code.strip():
        raise ValueError("candidate must include generator_code")
    expected = candidate.get("expected_outputs")
    if not isinstance(expected, list):
        expected = []
    return {
        "version": 1,
        "kind": GENERATOR_KIND,
        "format": file_format.lower(),
        "feature_id": target_feature_id,
        "primary_feature_id": target_feature_id,
        "primary_feature": target_feature[:200],
        "feature_description": str(
            candidate.get("feature_description") or feature.get("description") or ""
        ).strip()[:1200],
        "features": deduped_features,
        "feature_ids": feature_ids,
        "generator_code": code.strip() + "\n",
        "expected_outputs": [str(item)[:200] for item in expected[:16]],
        "generation_mode": "mutation" if generation_mode == "mutation" else "initial",
        "parent_generator_id": parent_generator_id,
        "epoch": int(epoch or 0),
    }


def _call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _call_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def _constant_string(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _is_safe_tmp_path(path):
    if not isinstance(path, str) or "\x00" in path:
        return False
    normalized = path.replace("\\", "/")
    if normalized.startswith("/"):
        return False
    parts = [part for part in normalized.split("/") if part and part != "."]
    if not parts or parts[0] != "tmp" or ".." in parts:
        return False
    return True


def _literal_tmp_path_expr(node):
    value = _constant_string(node)
    if value is not None:
        return value if _is_safe_tmp_path(value) else None
    if isinstance(node, ast.Call) and _call_name(node.func) == "os.path.join" and node.args:
        parts = []
        for arg in node.args:
            part = _constant_string(arg)
            if part is None:
                return None
            parts.append(part)
        joined = "/".join(parts)
        return joined if _is_safe_tmp_path(joined) else None
    return None


def _is_tmp_path_expr(node):
    return _literal_tmp_path_expr(node) is not None


def _is_under_dir(path, root):
    try:
        real_path = os.path.realpath(path)
        real_root = os.path.realpath(root)
        return os.path.commonpath([real_path, real_root]) == real_root
    except (OSError, ValueError):
        return False


class GeneratorSafetyVisitor(ast.NodeVisitor):
    forbidden_calls = {
        "__import__", "breakpoint", "compile", "eval", "exec", "globals",
        "getattr", "help", "input", "locals", "open_code", "setattr", "delattr",
        "print", "logging", "logger", "pprint",
    }
    forbidden_attrs = {
        "os.chdir", "os.chmod", "os.chown",
        "os.execl", "os.execle", "os.execlp", "os.execlpe", "os.execv",
        "os.execve", "os.execvp", "os.execvpe", "os.popen", "os.remove",
        "os.rename", "os.replace", "os.rmdir", "os.spawnl", "os.spawnle",
        "os.spawnlp", "os.spawnlpe", "os.spawnv", "os.spawnve",
        "os.spawnvp", "os.spawnvpe", "os.symlink", "os.system", "os.unlink",
    }
    forbidden_methods = {"write_text", "write_bytes"}
    allowed_os_calls = {
        "os.mkdir", "os.makedirs",
        "os.path.abspath", "os.path.basename", "os.path.dirname", "os.path.join",
        "os.path.splitext",
    }

    def __init__(self):
        self.errors = []

    def visit_Call(self, node):
        name = _call_name(node.func)
        leaf = name.rsplit(".", 1)[-1] if name else ""
        if name in self.forbidden_calls or leaf in self.forbidden_calls:
            self.errors.append(f"call to {name!r} is not allowed")
        if leaf == "open" and name != "open":
            self.errors.append("only direct open('./tmp/...', 'wb') calls are allowed")
        if name in self.forbidden_attrs:
            self.errors.append(f"call to {name!r} is not allowed")
        if name.startswith("os.") and name not in self.allowed_os_calls:
            self.errors.append(f"os call {name!r} is not allowed")
        if leaf in self.forbidden_methods:
            self.errors.append(f"method {leaf!r} is not allowed; use open('./tmp/...', 'wb')")
        if name == "open":
            if not node.args:
                self.errors.append("open() path is required")
            elif _constant_string(node.args[0]) is not None and not _is_tmp_path_expr(node.args[0]):
                self.errors.append("literal open() path must stay under ./tmp/")
            mode = _constant_string(node.args[1]) if len(node.args) > 1 else None
            if mode is None or "r" in mode or "+" in mode:
                self.errors.append("open() must use an explicit write-only mode")
        if name in {"os.mkdir", "os.makedirs"}:
            if not node.args:
                self.errors.append(f"{name}() path is required")
            elif _constant_string(node.args[0]) is not None and not _is_tmp_path_expr(node.args[0]):
                self.errors.append(f"literal {name}() path must stay under ./tmp/")
        self.generic_visit(node)

    def visit_Name(self, node):
        if isinstance(node.ctx, ast.Load) and node.id in self.forbidden_calls:
            self.errors.append(f"use of {node.id!r} is not allowed")
        if isinstance(node.ctx, ast.Load) and node.id in {
            "__builtins__", "__file__", "__loader__", "__package__", "__spec__",
        }:
            self.errors.append(f"use of {node.id!r} is not allowed")
        if isinstance(node.ctx, ast.Load) and node.id == "open":
            parent = getattr(node, "_parent", None)
            if not (isinstance(parent, ast.Call) and parent.func is node):
                self.errors.append("open may not be aliased or passed around")
        self.generic_visit(node)


def validate_generator_code(code):
    if "./tmp" not in code and "tmp/" not in code:
        raise ValueError("generator_code must write generated files into ./tmp/")
    try:
        tree = ast.parse(code, filename="<seed_generator>")
    except SyntaxError as exc:
        raise ValueError(f"generator_code syntax error: {exc}") from exc
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child._parent = parent
    visitor = GeneratorSafetyVisitor()
    visitor.visit(tree)
    if visitor.errors:
        raise ValueError("; ".join(visitor.errors[:8]))


def _generic_smoke_seed(data, max_size):
    if len(data) > max_size:
        return False, "seed exceeds max_size"
    if not data:
        return False, "seed is empty"
    return True, "generic smoke ok"


def _executor_can_parse(executor, data):
    if executor is None:
        return False, "no executor"
    parse_profile = getattr(executor, "parse_profile", None)
    if not callable(parse_profile):
        return True, "executor has no parse_profile"
    try:
        parse_profile(data)
    except Exception as exc:
        return False, f"parse_profile failed: {exc}"
    return True, "parse_profile ok"


def _executor_smoke_seed(executor, data, max_size):
    if len(data) > max_size:
        return False, "seed exceeds max_size"
    plan = {
        "version": 1,
        "kind": "elf_template_plan",
        "template": "dynamic_template_executor",
        "ops": [],
        "limits": {"max_output_size": max_size, "max_ops_per_call": 1},
    }
    try:
        result = executor.execute_template_plan(data, plan, None, max_size)
        if not isinstance(result, (bytes, bytearray)):
            return False, "executor returned non-bytes"
    except Exception as exc:
        return False, f"executor smoke failed: {exc}"
    return True, "ok"


def _smoke_seed(executor, data, max_size, smoke_mode="auto"):
    smoke_mode = str(smoke_mode or "auto").lower()
    if smoke_mode not in {"auto", "executor", "generic"}:
        return False, f"unknown smoke mode: {smoke_mode}"
    if smoke_mode == "generic":
        return _generic_smoke_seed(data, max_size)
    if smoke_mode == "executor":
        return _executor_smoke_seed(executor, data, max_size)

    can_parse, parse_msg = _executor_can_parse(executor, data)
    if can_parse:
        return _executor_smoke_seed(executor, data, max_size)
    generic_ok, generic_msg = _generic_smoke_seed(data, max_size)
    if generic_ok:
        return True, f"{generic_msg}; executor skipped: {parse_msg}"
    return False, generic_msg


def _collect_tmp_files(tmp_dir):
    files = []
    for root, _dirs, names in os.walk(tmp_dir):
        for name in sorted(names):
            path = os.path.join(root, name)
            if not _is_under_dir(path, tmp_dir):
                raise RuntimeError("generator created a path outside ./tmp/")
            if os.path.isfile(path):
                files.append(path)
    return files


def _sandbox_runner_code():
    return r'''
import builtins
import os
import random
import runpy

TMP_ROOT = os.path.realpath(os.path.join(os.getcwd(), "tmp"))
SCRIPT_PATH = os.path.realpath(os.path.join(os.getcwd(), "generator.py"))
_ORIGINAL_OPEN = builtins.open
_ORIGINAL_MKDIR = os.mkdir
_ORIGINAL_MAKEDIRS = os.makedirs
random.seed(int(os.environ.get("AFL_LLM_GENERATOR_RUN_SEED", "0") or 0))


def _safe_target(path):
    if isinstance(path, int):
        raise PermissionError("file descriptors are not allowed")
    if isinstance(path, bytes):
        path = os.fsdecode(path)
    path = os.fspath(path)
    if "\x00" in path:
        raise PermissionError("NUL byte in path")
    if os.path.isabs(path):
        target = os.path.realpath(path)
    else:
        target = os.path.realpath(os.path.join(os.getcwd(), path))
    if os.path.commonpath([target, TMP_ROOT]) != TMP_ROOT:
        raise PermissionError("generator may only write under ./tmp/")
    return target


def _safe_open(path, mode="r", *args, **kwargs):
    if "r" in mode or "+" in mode:
        raise PermissionError("generator may only use write-only open modes")
    target = _safe_target(path)
    parent = os.path.dirname(target)
    if parent:
        _ORIGINAL_MAKEDIRS(parent, exist_ok=True)
    return _ORIGINAL_OPEN(target, mode, *args, **kwargs)


def _safe_mkdir(path, *args, **kwargs):
    return _ORIGINAL_MKDIR(_safe_target(path), *args, **kwargs)


def _safe_makedirs(path, *args, **kwargs):
    return _ORIGINAL_MAKEDIRS(_safe_target(path), *args, **kwargs)


builtins.open = _safe_open
os.mkdir = _safe_mkdir
os.makedirs = _safe_makedirs
for _name in ("open", "remove", "unlink", "rename", "replace", "rmdir", "symlink", "system", "popen"):
    if hasattr(os, _name):
        setattr(os, _name, lambda *args, **kwargs: (_ for _ in ()).throw(
            PermissionError("unsafe os file/process operation is blocked")
        ))

runpy.run_path(SCRIPT_PATH, run_name="__main__")
'''


def _missing_module_from_stderr(stderr):
    text = stderr.decode("utf-8", errors="replace") if isinstance(stderr, bytes) else str(stderr or "")
    matches = re.findall(
        r"(?:ModuleNotFoundError|ImportError):\s+No module named\s+['\"]([^'\"]+)['\"]",
        text,
    )
    if not matches:
        matches = re.findall(r"No module named\s+['\"]([^'\"]+)['\"]", text)
    if not matches:
        return None
    module = matches[-1].split(".", 1)[0].strip()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", module):
        return None
    return module


def _install_missing_generator_module(module):
    timeout_sec = max(
        _env_float(SEED_PIP_INSTALL_TIMEOUT_ENV, DEFAULT_PIP_INSTALL_TIMEOUT_SEC),
        1.0,
    )
    extra_args = shlex.split(os.environ.get(SEED_PIP_INSTALL_ARGS_ENV, "") or "")
    cmd = [
        sys.executable,
        "-m",
        "pip",
        "install",
        "--disable-pip-version-check",
        "--no-input",
        *extra_args,
        module,
    ]
    sys.stderr.write(
        f"[seed-generator] installing missing generator module {module!r}: "
        f"{' '.join(cmd)}\n"
    )
    try:
        completed = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_sec,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"pip install {module!r} failed: {exc}") from exc
    if completed.returncode != 0:
        error = completed.stderr.decode("utf-8", errors="replace")[-2000:]
        raise RuntimeError(
            f"pip install {module!r} exited {completed.returncode}: {error}"
        )
    sys.stderr.write(f"[seed-generator] installed missing generator module {module!r}\n")


def _run_generator_with_dependency_repair(cmd, cwd, env, timeout_sec, installed_modules):
    max_modules = _env_int(
        SEED_PIP_INSTALL_MAX_MODULES_ENV,
        DEFAULT_PIP_INSTALL_MAX_MODULES,
        lower=0,
        upper=32,
    )
    while True:
        completed = subprocess.run(
            cmd,
            cwd=cwd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_sec,
            check=False,
        )
        if completed.returncode == 0 or not _env_truthy(SEED_AUTO_PIP_INSTALL_ENV, True):
            return completed
        module = _missing_module_from_stderr(completed.stderr)
        if not module or module in installed_modules or len(installed_modules) >= max_modules:
            return completed
        _install_missing_generator_module(module)
        installed_modules.add(module)


def run_generator(candidate, executor, seeds_output, metadata_path,
                  input_summary, max_files, max_size, timeout_sec,
                  smoke_mode="auto"):
    validate_generator_code(candidate["generator_code"])
    os.makedirs(seeds_output, exist_ok=True)
    max_seed_count = max(1, int(max_files))
    generator_hash = hashlib.sha256(candidate["generator_code"].encode("utf-8")).hexdigest()
    input_hash = input_summary.get("sha256", "unknown")
    primary_feature_id = candidate.get("primary_feature_id") or candidate.get("feature_id")
    feature_token = _safe_token(primary_feature_id or candidate.get("primary_feature"), "feature")[:32]
    generator_id = f"{candidate['format']}_{input_hash[:8]}_{feature_token[:16]}_{generator_hash[:12]}"

    existing_hashes = _existing_seed_hashes(metadata_path, seeds_output)
    validated_outputs = []
    seen_seed_hashes = set()
    installed_modules = set()
    run_nonce = time.time_ns()
    with tempfile.TemporaryDirectory(prefix="seedgen_") as work_dir:
        tmp_dir = os.path.join(work_dir, "tmp")
        script_path = os.path.join(work_dir, "generator.py")
        with open(script_path, "w", encoding="utf-8") as f:
            f.write(candidate["generator_code"])
        runner_path = os.path.join(work_dir, "runner.py")
        with open(runner_path, "w", encoding="utf-8") as f:
            f.write(_sandbox_runner_code())
        for run_index in range(max_seed_count):
            shutil.rmtree(tmp_dir, ignore_errors=True)
            os.makedirs(tmp_dir, exist_ok=True)
            run_seed = int(hashlib.sha256(
                f"{generator_hash}:{run_nonce}:{run_index}".encode("utf-8")
            ).hexdigest()[:8], 16)
            run_env = dict(os.environ)
            run_env["AFL_LLM_GENERATOR_RUN_INDEX"] = str(run_index)
            run_env["AFL_LLM_GENERATOR_RUN_SEED"] = str(run_seed)
            run_env["PYTHONHASHSEED"] = str(run_seed)
            completed = _run_generator_with_dependency_repair(
                [sys.executable, runner_path],
                work_dir,
                run_env,
                timeout_sec,
                installed_modules,
            )
            if completed.returncode != 0:
                stderr = completed.stderr.decode("utf-8", errors="replace")[:1000]
                raise RuntimeError(
                    f"generator run {run_index + 1}/{max_seed_count} "
                    f"exited {completed.returncode}: {stderr}"
                )

            produced = _collect_tmp_files(tmp_dir)
            if not produced:
                raise RuntimeError(
                    f"generator run {run_index + 1}/{max_seed_count} "
                    "did not create files under ./tmp/"
                )
            if len(produced) > max_seed_count:
                raise RuntimeError(
                    f"generator run {run_index + 1}/{max_seed_count} created "
                    f"too many files: {len(produced)} > {max_seed_count}"
                )
            for path in produced:
                try:
                    if os.stat(path).st_size > max_size:
                        continue
                except OSError:
                    continue
                with open(path, "rb") as f:
                    data = f.read()
                seed_hash = hashlib.sha256(data).hexdigest()
                if seed_hash in existing_hashes or seed_hash in seen_seed_hashes:
                    continue
                smoke_ok, smoke_msg = _smoke_seed(executor, data, max_size, smoke_mode=smoke_mode)
                if not smoke_ok:
                    continue
                seen_seed_hashes.add(seed_hash)
                validated_outputs.append((path, data, seed_hash, smoke_msg))
                if len(validated_outputs) >= max_seed_count:
                    break
            if len(validated_outputs) >= max_seed_count:
                break

        if not validated_outputs:
            raise RuntimeError(
                "generator produced no new distinct smoke-valid seeds "
                f"after {max_seed_count} local runs"
            )
        if len(validated_outputs) < max_seed_count:
            sys.stderr.write(
                "[seed-generator] accepting underfilled generator: "
                f"collected {len(validated_outputs)}/{max_seed_count} distinct "
                "smoke-valid seeds; OP validation will use all available seeds\n"
            )

        saved_seeds = []
        for output_index, (path, data, seed_hash, smoke_msg) in enumerate(validated_outputs, 1):
            ext = os.path.splitext(path)[1] or f".{_safe_token(candidate['format'], 'bin')}"
            seed_name = f"{generator_id}_{feature_token}_{output_index}_{seed_hash[:8]}{ext}"
            seed_path = os.path.join(seeds_output, seed_name)
            with open(seed_path, "wb") as f:
                f.write(data)
            saved_seeds.append({
                "seed_id": seed_hash[:16],
                "path": os.path.relpath(seed_path, _base_dir()),
                "format": candidate["format"],
                "feature_id": candidate.get("feature_id"),
                "primary_feature_id": candidate.get("primary_feature_id"),
                "primary_feature": candidate.get("primary_feature"),
                "features": list(candidate["features"]),
                "feature_ids": list(candidate.get("feature_ids") or []),
                "generator_id": generator_id,
                "input_sha256": input_hash,
                "size": len(data),
                "sha256": seed_hash,
                "smoke_ok": True,
                "smoke_message": smoke_msg,
            })

    update_seed_metadata(metadata_path, candidate, generator_id, input_summary, saved_seeds)
    return generator_id, saved_seeds


def _load_json_dict(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except (OSError, ValueError, json.JSONDecodeError):
        return {}


def _existing_seed_hashes(metadata_path, seeds_output=None):
    hashes = set()
    metadata = _load_json_dict(metadata_path)
    seeds = metadata.get("seeds", {}) if isinstance(metadata, dict) else {}
    if isinstance(seeds, dict):
        for entry in seeds.values():
            if isinstance(entry, dict) and isinstance(entry.get("sha256"), str):
                hashes.add(entry["sha256"])
    if seeds_output and os.path.isdir(seeds_output):
        for name in os.listdir(seeds_output):
            path = os.path.join(seeds_output, name)
            if not os.path.isfile(path):
                continue
            try:
                with open(path, "rb") as f:
                    hashes.add(hashlib.sha256(f.read()).hexdigest())
            except OSError:
                continue
    return hashes


def _atomic_write_json(path, payload):
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    tmp_path = f"{path}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, sort_keys=True)
        f.write("\n")
    os.replace(tmp_path, path)


def _candidate_generation_strategy(candidate):
    if not isinstance(candidate, dict):
        return None
    value = candidate.get("generation_strategy") or candidate.get("strategy")
    if value:
        return str(value)
    mode = candidate.get("generation_mode")
    if candidate.get("source") == "g2fuzz_native":
        return "mutation" if mode == "mutation" else "initial"
    return str(mode or "initial")


def _candidate_mutation_source(candidate):
    if not isinstance(candidate, dict):
        return None
    value = candidate.get("mutation_source")
    if value:
        return str(value)
    strategy = _candidate_generation_strategy(candidate)
    if strategy == "pattern-combine":
        return "g2fuzz_pattern_based_mutation"
    if strategy == "structure-havoc":
        return "g2fuzz_predefined_structure_mutation"
    if strategy == "feature-havoc":
        return "g2fuzz_predefined_feature_mutation"
    if strategy == "rare-feature":
        return "g2fuzz_rare_feature_directed_mutation"
    mode = candidate.get("generation_mode")
    if candidate.get("source") == "g2fuzz_native":
        return (
            "g2fuzz_generator_mutation"
            if mode == "mutation"
            else "g2fuzz_input_generator_synthesis"
        )
    return "llm_seed_generator_mutation" if mode == "mutation" else "llm_seed_generator_synthesis"


def update_seed_metadata(metadata_path, candidate, generator_id, input_summary, seeds):
    metadata = _load_json_dict(metadata_path)
    metadata.setdefault("version", 1)
    features = metadata.setdefault("features", {})
    generators = metadata.setdefault("generators", {})
    seed_entries = metadata.setdefault("seeds", {})
    now = int(time.time())
    generation_strategy = _candidate_generation_strategy(candidate)
    mutation_source = _candidate_mutation_source(candidate)

    generators[generator_id] = {
        "generator_id": generator_id,
        "format": candidate["format"],
        "feature_id": candidate.get("feature_id"),
        "primary_feature_id": candidate.get("primary_feature_id"),
        "primary_feature": candidate.get("primary_feature"),
        "features": list(candidate["features"]),
        "feature_ids": list(candidate.get("feature_ids") or []),
        "input_sha256": input_summary.get("sha256"),
        "created_ts": now,
        "seed_count": len(seeds),
        "generation_mode": candidate.get("generation_mode", "initial"),
        "generation_strategy": generation_strategy,
        "mutation_source": mutation_source,
        "pattern_original_generator_id": candidate.get("pattern_original_generator_id"),
        "pattern_mutated_generator_id": candidate.get("pattern_mutated_generator_id"),
        "pattern_source": candidate.get("pattern_source"),
        "parent_generator_id": candidate.get("parent_generator_id"),
        "epoch": int(candidate.get("epoch", 0) or 0),
        "finds": int(generators.get(generator_id, {}).get("finds", 0) or 0),
        "stage_calls": int(generators.get(generator_id, {}).get("stage_calls", 0) or 0),
    }
    feature_name = candidate.get("primary_feature")
    feature_id = _feature_id_from_name(
        candidate.get("feature_id") or candidate.get("primary_feature_id") or feature_name
    )
    candidate_feature_ids = list(candidate.get("feature_ids") or [])
    if feature_id not in candidate_feature_ids:
        candidate_feature_ids.insert(0, feature_id)
    candidate_feature_names = list(candidate.get("features") or [])
    for index, current_feature_id in enumerate(candidate_feature_ids):
        if not isinstance(current_feature_id, str) or not current_feature_id:
            continue
        current_name = feature_name if current_feature_id == feature_id else (
            candidate_feature_names[index] if index < len(candidate_feature_names) else current_feature_id
        )
        old = features.get(current_feature_id, {}) if isinstance(features.get(current_feature_id), dict) else {}
        generator_ids = sorted(set((old.get("generator_ids") or []) + [generator_id]))
        features[current_feature_id] = {
            "feature_id": current_feature_id,
            "primary_feature_id": feature_id,
            "feature": current_name,
            "format": candidate["format"],
            "description": (
                candidate.get("feature_description")
                if current_feature_id == feature_id else old.get("description", "")
            ) or old.get("description", ""),
            "epoch_added": int(old.get("epoch_added", candidate.get("epoch", 0)) or 0),
            "status": "success",
            "generator_id": generator_id if current_feature_id == feature_id else old.get("generator_id", generator_id),
            "generator_ids": generator_ids,
            "seed_count": int(old.get("seed_count", 0) or 0) + len(seeds),
            "finds": int(old.get("finds", 0) or 0),
            "stage_calls": int(old.get("stage_calls", 0) or 0),
            "last_used": old.get("last_used", 0),
        }
    for seed in seeds:
        old = seed_entries.get(seed["path"], {}) if isinstance(seed_entries.get(seed["path"]), dict) else {}
        entry = dict(seed)
        entry.update({
            "created_ts": now,
            "feature_id": feature_id,
            "primary_feature_id": feature_id,
            "primary_feature": candidate.get("primary_feature"),
            "generation_strategy": generation_strategy,
            "mutation_source": mutation_source,
            "finds": int(old.get("finds", 0) or 0),
            "stage_calls": int(old.get("stage_calls", 0) or 0),
            "last_used": old.get("last_used", 0),
        })
        seed_entries[seed["path"]] = entry
    _atomic_write_json(metadata_path, metadata)


def save_generator(output_dir, candidate, generator_id, input_summary, seeds):
    os.makedirs(output_dir, exist_ok=True)
    py_name = f"{generator_id}.py"
    json_name = f"{generator_id}.json"
    py_path = os.path.join(output_dir, py_name)
    json_path = os.path.join(output_dir, json_name)
    with open(py_path, "w", encoding="utf-8") as f:
        f.write(candidate["generator_code"])
    manifest = dict(candidate)
    manifest.setdefault("generation_strategy", _candidate_generation_strategy(candidate))
    manifest.setdefault("mutation_source", _candidate_mutation_source(candidate))
    manifest.update({
        "generator_id": generator_id,
        "generator_py": py_name,
        "input_summary": input_summary,
        "generated_seeds": seeds,
        "created_ts": int(time.time()),
    })
    _atomic_write_json(json_path, manifest)
    return py_path, json_path


def build_validated_generator(file_format, input_summary, executor, output_dir,
                              seeds_output, metadata_path, max_files, max_size,
                              timeout_sec, model=None, module_url=None,
                              api_key=None, max_tokens=8192, attempts=DEFAULT_ATTEMPTS,
                              candidate_json=None,
                              request_timeout=DEFAULT_REQUEST_TIMEOUT_SEC,
                              http_retries=DEFAULT_HTTP_RETRIES,
                              feature=None, generation_mode="initial",
                              parent_generator=None, epoch=0,
                              smoke_mode="auto", strategy_context=None):
    attempts = max(1, int(attempts or 1))
    failures = []
    raw_candidate_from_file = None
    if candidate_json:
        with open(candidate_json, "r", encoding="utf-8") as f:
            raw_candidate_from_file = json.load(f)
        attempts = 1

    for attempt in range(1, attempts + 1):
        try:
            if raw_candidate_from_file is not None:
                raw_candidate = raw_candidate_from_file
            else:
                raw_candidate = request_generator_from_llm(
                    file_format,
                    input_summary,
                    model=model,
                    module_url=module_url,
                    api_key=api_key,
                    max_tokens=max_tokens,
                    failure_feedback=list(failures),
                    request_timeout=request_timeout,
                    http_retries=http_retries,
                    prompt_max_files=max_files,
                    feature=feature,
                    generation_mode=generation_mode,
                    parent_generator=parent_generator,
                    strategy_context=strategy_context,
                )
        except Exception as exc:
            failure = {
                "attempt": attempt,
                "stage": "llm_request_or_json_parse",
                "error": _compact_error(exc),
            }
            failures.append(failure)
            sys.stderr.write(
                f"[seed-generator] attempt {attempt}/{attempts} failed at "
                f"{failure['stage']}: {failure['error']}\n"
            )
            continue

        try:
            candidate = normalize_candidate(
                raw_candidate,
                file_format,
                feature=feature,
                generation_mode=generation_mode,
                parent_generator_id=(parent_generator or {}).get("generator_id"),
                parent_generator=parent_generator,
                epoch=epoch,
            )
        except Exception as exc:
            failure = {
                "attempt": attempt,
                "stage": "candidate_contract",
                "error": _compact_error(exc),
            }
            failures.append(failure)
            sys.stderr.write(
                f"[seed-generator] attempt {attempt}/{attempts} failed at "
                f"{failure['stage']}: {failure['error']}\n"
            )
            continue

        try:
            generator_id, seeds = run_generator(
                candidate,
                executor,
                seeds_output,
                metadata_path,
                input_summary,
                max_files,
                max_size,
                timeout_sec,
                smoke_mode=smoke_mode,
            )
        except Exception as exc:
            failure = {
                "attempt": attempt,
                "stage": "generator_validate_execute_smoke",
                "error": _compact_error(exc),
            }
            failures.append(failure)
            sys.stderr.write(
                f"[seed-generator] attempt {attempt}/{attempts} failed at "
                f"{failure['stage']}: {failure['error']}\n"
            )
            continue

        try:
            py_path, json_path = save_generator(output_dir, candidate, generator_id, input_summary, seeds)
        except Exception as exc:
            failure = {
                "attempt": attempt,
                "stage": "generator_manifest_save",
                "error": _compact_error(exc),
            }
            failures.append(failure)
            sys.stderr.write(
                f"[seed-generator] attempt {attempt}/{attempts} failed at "
                f"{failure['stage']}: {failure['error']}\n"
            )
            continue

        return {
            "generator_id": generator_id,
            "generator_py": py_path,
            "generator_json": json_path,
            "seeds": seeds,
            "candidate": candidate,
            "attempt": attempt,
            "failures": failures,
        }

    raise RuntimeError(
        "failed to build a smoke-valid seed generator after "
        f"{attempts} attempt(s): "
        f"{json.dumps(failures, ensure_ascii=True, sort_keys=True)}"
    )


def request_validated_feature_pool(file_format, input_summary, known_features,
                                   max_features, epoch, attempts, model=None,
                                   module_url=None, api_key=None, max_tokens=8192,
                                   request_timeout=DEFAULT_REQUEST_TIMEOUT_SEC,
                                   http_retries=DEFAULT_HTTP_RETRIES):
    attempts = max(1, int(attempts or 1))
    failures = []
    for attempt in range(1, attempts + 1):
        try:
            raw_pool = request_feature_pool_from_llm(
                file_format,
                input_summary,
                known_features=known_features,
                max_features=max_features,
                model=model,
                module_url=module_url,
                api_key=api_key,
                max_tokens=max_tokens,
                failure_feedback=list(failures),
                request_timeout=request_timeout,
                http_retries=http_retries,
            )
            features = normalize_feature_pool(
                raw_pool,
                file_format,
                max_features=max_features,
                epoch_added=epoch,
            )
            return features, failures
        except Exception as exc:
            failure = {
                "attempt": attempt,
                "stage": "feature_pool_contract",
                "error": _compact_error(exc),
            }
            failures.append(failure)
            sys.stderr.write(
                f"[seed-generator] feature analysis attempt {attempt}/{attempts} "
                f"failed: {failure['error']}\n"
            )
    raise RuntimeError(
        "failed to build a valid feature pool after "
        f"{attempts} attempt(s): "
        f"{json.dumps(failures, ensure_ascii=True, sort_keys=True)}"
    )


def _feature_pool_limit(max_features):
    if max_features is None:
        return None
    try:
        value = int(max_features)
    except (TypeError, ValueError):
        return DEFAULT_MAX_FEATURES
    if value <= 0:
        return None
    return max(1, value)


def _merge_feature_pool(existing, new_features, max_features):
    merged = []
    seen = set()
    max_features = _feature_pool_limit(max_features)
    for item in existing or []:
        if not isinstance(item, dict):
            continue
        entry = dict(item)
        entry["id"] = _feature_id_from_name(entry.get("id") or entry.get("name"))
        if not entry["id"] or entry["id"] in seen:
            continue
        merged.append(entry)
        seen.add(entry["id"])
    for feature in new_features:
        if max_features is not None and len(merged) >= max_features:
            break
        if not isinstance(feature, dict):
            continue
        entry = dict(feature)
        entry["id"] = _feature_id_from_name(entry.get("id") or entry.get("name"))
        key = entry["id"]
        if not key or key in seen:
            continue
        if max_features is not None and len(merged) >= max_features:
            break
        merged.append(entry)
        seen.add(key)
        if max_features is not None and len(merged) >= max_features:
            break
    return merged


def save_feature_pool(path, file_format, input_summary, feature_pool):
    payload = {
        "version": 1,
        "kind": FEATURE_POOL_KIND,
        "format": file_format,
        "input_sha256": input_summary.get("sha256"),
        "updated_ts": int(time.time()),
        "features": list(feature_pool),
    }
    _atomic_write_json(path, payload)


def _feature_by_key(feature_pool, key):
    for item in feature_pool:
        if item.get("id") == key or _feature_dedupe_key(item.get("name")) == key:
            return item
    return None


def _mark_feature_metadata(metadata_path, file_format, feature, status, generator_id=None):
    metadata = _load_json_dict(metadata_path)
    metadata.setdefault("version", 1)
    features = metadata.setdefault("features", {})
    name = feature.get("name") if isinstance(feature, dict) else str(feature)
    feature_id = _feature_id_from_name(
        (feature.get("id") or name) if isinstance(feature, dict) else name
    )
    key = feature_id
    old = features.get(key, {}) if isinstance(features.get(key), dict) else {}
    generator_ids = list(old.get("generator_ids") or [])
    if generator_id and generator_id not in generator_ids:
        generator_ids.append(generator_id)
    old.update({
        "feature_id": feature_id,
        "primary_feature_id": feature_id,
        "feature": name,
        "format": file_format,
        "description": feature.get("description", "") if isinstance(feature, dict) else old.get("description", ""),
        "epoch_added": int(feature.get("epoch_added", old.get("epoch_added", 0)) or 0)
        if isinstance(feature, dict) else int(old.get("epoch_added", 0) or 0),
        "status": status,
        "generator_id": generator_id or old.get("generator_id"),
        "generator_ids": sorted(generator_ids),
    })
    features[key] = old
    _atomic_write_json(metadata_path, metadata)


def _load_parent_generators(output_dir, metadata_path, file_format):
    metadata = _load_json_dict(metadata_path)
    generators = metadata.get("generators", {}) if isinstance(metadata, dict) else {}
    parents = []
    if not isinstance(generators, dict):
        return parents
    for generator_id, entry in generators.items():
        if not isinstance(entry, dict):
            continue
        if str(entry.get("format", "")).lower() != file_format.lower():
            continue
        path = os.path.join(output_dir, f"{generator_id}.py")
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "r", encoding="utf-8") as f:
                code = f.read()
        except OSError:
            continue
        parent = dict(entry)
        parent.update({
            "generator_id": generator_id,
            "generator_code": code,
        })
        parents.append(parent)
    return parents


def _choose_parent_generator(parents):
    if not parents:
        return None
    weights = []
    for parent in parents:
        try:
            finds = int(parent.get("finds", 0) or 0)
        except (TypeError, ValueError):
            finds = 0
        try:
            calls = int(parent.get("stage_calls", 0) or 0)
        except (TypeError, ValueError):
            calls = 0
        weights.append(1.0 / (1.0 + finds + calls * 0.05))
    try:
        return random.choices(parents, weights=weights, k=1)[0]
    except Exception:
        return random.choice(parents)


def _result_as_parent(result):
    candidate = result.get("candidate", {}) if isinstance(result, dict) else {}
    if not candidate:
        return None
    return {
        "generator_id": result.get("generator_id"),
        "primary_feature": candidate.get("primary_feature"),
        "features": list(candidate.get("features") or []),
        "feature_ids": list(candidate.get("feature_ids") or []),
        "generator_code": candidate.get("generator_code", ""),
        "finds": 0,
        "stage_calls": 0,
    }


def _load_feature_pool(path, file_format):
    payload = _load_json_dict(path)
    raw_features = payload.get("features") if isinstance(payload, dict) else []
    if not isinstance(raw_features, list):
        raw_features = []
    features = []
    seen = set()
    for item in raw_features:
        if not isinstance(item, dict):
            continue
        entry = dict(item)
        entry["id"] = _feature_id_from_name(entry.get("id") or entry.get("name") or entry.get("feature"))
        if not entry["id"] or entry["id"] in seen:
            continue
        if str(payload.get("format") or file_format).lower() != file_format.lower():
            continue
        entry.setdefault("name", entry.get("feature") or entry["id"])
        entry.setdefault("description", "")
        entry.setdefault("status", "pending")
        features.append(entry)
        seen.add(entry["id"])
    return features


def _known_feature_strings(feature_pool, metadata_path):
    known = []
    for item in feature_pool or []:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or item.get("feature") or item.get("id") or "").strip()
        description = str(item.get("description") or "").strip()
        if name:
            known.append(f"{name}: {description}" if description else name)
    metadata = _load_json_dict(metadata_path)
    features = metadata.get("features", {}) if isinstance(metadata, dict) else {}
    if isinstance(features, dict):
        for item in features.values():
            if not isinstance(item, dict):
                continue
            name = str(item.get("feature") or item.get("name") or item.get("feature_id") or "").strip()
            description = str(item.get("description") or "").strip()
            value = f"{name}: {description}" if description else name
            if value and value not in known:
                known.append(value)
    return known


def _feature_from_candidate_json(path):
    if not path:
        return None
    try:
        raw = _load_json_dict(path)
    except Exception:
        return None
    name = str(raw.get("primary_feature") or raw.get("feature") or "").strip()
    if not name:
        return None
    feature_id = _feature_id_from_name(raw.get("feature_id") or raw.get("primary_feature_id") or name)
    return {
        "id": feature_id,
        "name": name,
        "description": str(raw.get("feature_description") or raw.get("description") or "offline candidate feature"),
        "status": "pending",
    }


def _select_parent_by_id(parents, parent_generator):
    if not parent_generator or parent_generator == "auto":
        return None
    for parent in parents:
        if parent.get("generator_id") == parent_generator:
            return parent
    return None


def _choose_pattern_parent(output_dir, metadata_path, file_format):
    parents = _load_parent_generators(output_dir, metadata_path, file_format)
    if not parents:
        return None
    parent_by_id = {parent.get("generator_id"): parent for parent in parents}
    pair_path = os.path.join(os.path.dirname(os.path.abspath(metadata_path)), "mutation_pairs.jsonl")
    weights = {}
    try:
        with open(pair_path, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue
                seed_context = item.get("seed_context")
                if not isinstance(seed_context, dict):
                    continue
                generator_id = seed_context.get("generator_id")
                if generator_id in parent_by_id:
                    bonus = 2.0 if seed_context.get("applied_template_mutation") else 1.0
                    if "+cov" in str(item.get("new_queue", "")):
                        bonus += 2.0
                    weights[generator_id] = weights.get(generator_id, 0.0) + bonus
    except OSError:
        pass
    if weights:
        choices = [parent_by_id[generator_id] for generator_id in weights]
        try:
            return random.choices(choices, weights=[weights[item["generator_id"]] for item in choices], k=1)[0]
        except Exception:
            return choices[0]
    return _choose_parent_generator(parents)


def _load_pattern_examples(metadata_path, file_format, parent_generator_id=None, limit=3):
    pair_path = os.path.join(os.path.dirname(os.path.abspath(metadata_path)), "mutation_pairs.jsonl")
    metadata = _load_json_dict(metadata_path)
    generators = metadata.get("generators", {}) if isinstance(metadata, dict) else {}
    examples = []
    try:
        with open(pair_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except OSError:
        return examples
    for line in reversed(lines):
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        seed_context = item.get("seed_context")
        if not isinstance(seed_context, dict):
            continue
        generator_id = seed_context.get("generator_id")
        if parent_generator_id and generator_id != parent_generator_id:
            continue
        if str(seed_context.get("format") or file_format).lower() != file_format.lower():
            continue
        generator_entry = generators.get(generator_id, {}) if isinstance(generators, dict) else {}
        if not isinstance(generator_entry, dict):
            generator_entry = {}
        examples.append({
            "generator_id": generator_id,
            "primary_feature": seed_context.get("primary_feature") or generator_entry.get("primary_feature"),
            "features": list(seed_context.get("features") or generator_entry.get("features") or []),
            "applied_template_mutation": bool(seed_context.get("applied_template_mutation")),
            "mutator": item.get("mutator"),
            "stable_id": item.get("stable_id"),
            "orig_queue": os.path.basename(str(item.get("orig_queue") or "")),
            "new_queue": os.path.basename(str(item.get("new_queue") or "")),
        })
        if len(examples) >= max(1, int(limit or 1)):
            break
    return examples


def _incremental_strategy_context(strategy, metadata_path, file_format, parent_generator=None):
    if strategy == "feature-havoc":
        return {
            "strategy": "feature-havoc",
            "instruction": (
                "Mutate the parent generator by adding the target feature or one "
                "bounded structure variation while preserving existing valid "
                "features where practical."
            ),
        }
    if strategy == "structure-havoc":
        return {
            "strategy": "structure-havoc",
            "instruction": (
                "Mutate the parent generator by adding more complex format "
                "structures, nested tables, offsets, counts, or layout variants "
                "while preserving executable generator behavior."
            ),
        }
    if strategy == "pattern-combine":
        parent_id = parent_generator.get("generator_id") if isinstance(parent_generator, dict) else None
        examples = _load_pattern_examples(metadata_path, file_format, parent_id, limit=3)
        if not examples and parent_id:
            examples = _load_pattern_examples(metadata_path, file_format, None, limit=3)
        return {
            "strategy": "pattern-combine",
            "instruction": (
                "Use coverage-positive mutation_pairs as pattern hints. Mimic the "
                "successful structural change at generator level and apply a "
                "similar variation while adding the target feature. Do not copy "
                "queue bytes; synthesize a reusable generator."
            ),
            "coverage_positive_examples": examples,
        }
    return {}


def _choose_incremental_features(feature_pool, batch_size, parent_generator=None):
    candidates = [
        dict(item) for item in feature_pool
        if isinstance(item, dict) and item.get("id")
    ]
    if not candidates:
        return []
    parent_ids = set()
    if isinstance(parent_generator, dict):
        parent_ids = set(parent_generator.get("feature_ids") or [])
    candidates.sort(key=lambda item: (
        item.get("id") in parent_ids,
        str(item.get("status") or "") == "failed",
        random.random(),
    ))
    return candidates[:max(1, int(batch_size or 1))]


def build_incremental_generators(file_format, input_summary, executor, output_dir,
                                 seeds_output, metadata_path, feature_pool_path,
                                 max_files, max_size, timeout_sec, model=None,
                                 module_url=None, api_key=None, max_tokens=8192,
                                 attempts=DEFAULT_ATTEMPTS,
                                 feature_attempts=DEFAULT_FEATURE_ATTEMPTS,
                                 max_features=DEFAULT_MAX_FEATURES,
                                 request_timeout=DEFAULT_REQUEST_TIMEOUT_SEC,
                                 http_retries=DEFAULT_HTTP_RETRIES,
                                 smoke_mode="auto",
                                 strategy="rare-feature",
                                 feature_batch=2,
                                 parent_generator="auto",
                                 candidate_json=None):
    strategy = strategy if strategy in {"rare-feature", "feature-havoc", "structure-havoc", "pattern-combine"} else "rare-feature"
    feature_batch = max(1, int(feature_batch or 1))
    feature_pool = _load_feature_pool(feature_pool_path, file_format)
    original_ids = {item.get("id") for item in feature_pool if isinstance(item, dict)}
    max_total_features = _feature_pool_limit(max_features)
    results = []
    failures = []
    added_features = []

    offline_feature = _feature_from_candidate_json(candidate_json)
    if offline_feature is not None:
        feature_pool = _merge_feature_pool(feature_pool, [offline_feature], max_total_features)
        added_features = [item for item in feature_pool if item.get("id") == offline_feature["id"]]
        save_feature_pool(feature_pool_path, file_format, input_summary, feature_pool)
    elif strategy == "rare-feature" or not feature_pool:
        try:
            new_features, feature_failures = request_validated_feature_pool(
                file_format,
                input_summary,
                _known_feature_strings(feature_pool, metadata_path),
                feature_batch,
                int(time.time()),
                feature_attempts,
                model=model,
                module_url=module_url,
                api_key=api_key,
                max_tokens=max_tokens,
                request_timeout=request_timeout,
                http_retries=http_retries,
            )
            failures.extend(feature_failures)
            feature_pool = _merge_feature_pool(feature_pool, new_features, max_total_features)
            added_features = [
                item for item in feature_pool
                if item.get("id") not in original_ids
            ][:feature_batch]
            save_feature_pool(feature_pool_path, file_format, input_summary, feature_pool)
        except Exception as exc:
            failures.append({"stage": "incremental_feature_pool", "error": _compact_error(exc)})
            if not feature_pool:
                raise

    parents = _load_parent_generators(output_dir, metadata_path, file_format)
    selected_parent = _select_parent_by_id(parents, parent_generator)
    if selected_parent is None and parent_generator == "auto":
        selected_parent = (
            _choose_pattern_parent(output_dir, metadata_path, file_format)
            if strategy == "pattern-combine"
            else _choose_parent_generator(parents)
        )

    if strategy == "rare-feature" and added_features:
        target_features = added_features
        generation_mode = "initial"
        selected_parent = None
    else:
        target_features = _choose_incremental_features(feature_pool, feature_batch, selected_parent)
        generation_mode = "mutation" if selected_parent else "initial"
    strategy_context = _incremental_strategy_context(
        strategy,
        metadata_path,
        file_format,
        selected_parent if generation_mode == "mutation" else None,
    )

    for feature in target_features[:feature_batch]:
        try:
            result = build_validated_generator(
                file_format,
                input_summary,
                executor,
                output_dir,
                seeds_output,
                metadata_path,
                max_files,
                max_size,
                timeout_sec,
                model=model,
                module_url=module_url,
                api_key=api_key,
                max_tokens=max_tokens,
                attempts=attempts,
                candidate_json=candidate_json,
                request_timeout=request_timeout,
                http_retries=http_retries,
                feature=feature,
                generation_mode=generation_mode,
                parent_generator=selected_parent if generation_mode == "mutation" else None,
                epoch=int(feature.get("epoch_added", 0) or 0),
                smoke_mode=smoke_mode,
                strategy_context=strategy_context,
            )
            feature["status"] = "success"
            feature["generator_id"] = result["generator_id"]
            _mark_feature_metadata(metadata_path, file_format, feature, "success", generator_id=result["generator_id"])
            results.append(result)
            result_parent = _result_as_parent(result)
            if result_parent:
                parents.append(result_parent)
                if selected_parent is None:
                    selected_parent = result_parent
        except Exception as exc:
            feature["status"] = "failed" if feature.get("id") in {item.get("id") for item in added_features} else feature.get("status", "success")
            feature["error"] = _compact_error(exc)
            _mark_feature_metadata(metadata_path, file_format, feature, "failed")
            failures.append({
                "strategy": strategy,
                "feature": feature.get("name"),
                "stage": "incremental_generator",
                "error": feature["error"],
            })
        save_feature_pool(feature_pool_path, file_format, input_summary, feature_pool)

    if not results:
        raise RuntimeError(
            "incremental seed generation did not produce smoke-valid generators: "
            f"{json.dumps(failures, ensure_ascii=True, sort_keys=True)}"
        )
    return {
        "mode": "incremental",
        "strategy": strategy,
        "feature_pool": feature_pool,
        "new_features": added_features,
        "results": results,
        "failures": failures,
        "parent_generator_id": (selected_parent or {}).get("generator_id"),
    }


def build_g2fuzz_generators(file_format, input_summary, executor, output_dir,
                            seeds_output, metadata_path, feature_pool_path,
                            max_files, max_size, timeout_sec, model=None,
                            module_url=None, api_key=None, max_tokens=8192,
                            attempts=DEFAULT_ATTEMPTS,
                            feature_attempts=DEFAULT_FEATURE_ATTEMPTS,
                            epochs=DEFAULT_EPOCHS,
                            max_features=DEFAULT_MAX_FEATURES,
                            request_timeout=DEFAULT_REQUEST_TIMEOUT_SEC,
                            http_retries=DEFAULT_HTTP_RETRIES,
                            smoke_mode="auto"):
    epochs = max(1, int(epochs or 1))
    max_features = max(1, int(max_features or DEFAULT_MAX_FEATURES))
    feature_attempts = max(1, int(feature_attempts or 1))
    feature_pool = []
    known_names = []
    results = []
    failures = []

    for epoch in range(epochs):
        remaining = max_features - len(feature_pool)
        if remaining > 0:
            try:
                new_features, feature_failures = request_validated_feature_pool(
                    file_format,
                    input_summary,
                    known_names,
                    remaining,
                    epoch,
                    feature_attempts,
                    model=model,
                    module_url=module_url,
                    api_key=api_key,
                    max_tokens=max_tokens,
                    request_timeout=request_timeout,
                    http_retries=http_retries,
                )
                failures.extend(feature_failures)
                feature_pool = _merge_feature_pool(feature_pool, new_features, max_features)
                known_names = [item.get("name") for item in feature_pool]
                save_feature_pool(feature_pool_path, file_format, input_summary, feature_pool)
                sys.stderr.write(
                    f"[seed-generator] epoch {epoch}: feature pool size={len(feature_pool)}\n"
                )
            except Exception as exc:
                failure = {
                    "epoch": epoch,
                    "stage": "feature_pool",
                    "error": _compact_error(exc),
                }
                failures.append(failure)
                sys.stderr.write(
                    f"[seed-generator] epoch {epoch}: feature analysis failed: "
                    f"{failure['error']}\n"
                )
                if epoch == 0 and not feature_pool:
                    raise

        pending = [
            item for item in feature_pool
            if item.get("status") not in {"success", "failed"}
        ]
        if not pending:
            continue

        for feature in pending:
            feature["status"] = "running"
            save_feature_pool(feature_pool_path, file_format, input_summary, feature_pool)
            parent_generator = None
            generation_mode = "initial"
            try:
                result = build_validated_generator(
                    file_format,
                    input_summary,
                    executor,
                    output_dir,
                    seeds_output,
                    metadata_path,
                    max_files,
                    max_size,
                    timeout_sec,
                    model=model,
                    module_url=module_url,
                    api_key=api_key,
                    max_tokens=max_tokens,
                    attempts=attempts,
                    request_timeout=request_timeout,
                    http_retries=http_retries,
                    feature=feature,
                    generation_mode=generation_mode,
                    parent_generator=parent_generator,
                    epoch=epoch,
                    smoke_mode=smoke_mode,
                )
                feature["status"] = "success"
                feature["generator_id"] = result["generator_id"]
                _mark_feature_metadata(
                    metadata_path,
                    file_format,
                    feature,
                    "success",
                    generator_id=result["generator_id"],
                )
                results.append(result)
            except Exception as exc:
                feature["status"] = "failed"
                feature["error"] = _compact_error(exc)
                _mark_feature_metadata(metadata_path, file_format, feature, "failed")
                failures.append({
                    "epoch": epoch,
                    "feature": feature.get("name"),
                    "stage": "feature_generator",
                    "error": feature["error"],
                })
                sys.stderr.write(
                    f"[seed-generator] epoch {epoch}: feature {feature.get('name')!r} "
                    f"failed: {feature['error']}\n"
                )
            save_feature_pool(feature_pool_path, file_format, input_summary, feature_pool)

    if not results:
        raise RuntimeError(
            "failed to build any smoke-valid seed generator: "
            f"{json.dumps(failures, ensure_ascii=True, sort_keys=True)}"
        )
    return {
        "mode": "g2fuzz",
        "feature_pool": feature_pool,
        "results": results,
        "failures": failures,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Generate and validate LLM seed generators.")
    parser.add_argument("--format", default=os.environ.get("AFL_LLM_SEED_FORMAT", "elf"))
    parser.add_argument("--input", help="optional initial input sample path; ignored in format-only mode")
    parser.add_argument(
        "--source-mode",
        choices=("format-only", "format_only", "sample"),
        default=os.environ.get("AFL_LLM_SEED_SOURCE_MODE", DEFAULT_SOURCE_MODE),
        help=(
            "format-only: feature extraction and generator synthesis use only "
            "the target format name; sample: summarize --input and include it "
            "in prompts"
        ),
    )
    parser.add_argument("--mode", choices=("g2fuzz-native", "g2fuzz", "one-shot"),
                        default=os.environ.get("AFL_LLM_SEED_MODE", "g2fuzz-native"),
                        help=(
                            "g2fuzz-native uses the local G2FUZZ prompt/self-debug "
                            "implementation, g2fuzz uses the legacy JSON prompt, "
                            "one-shot builds one candidate generator"
                        ))
    parser.add_argument("--incremental", action="store_true",
                        help="append to existing feature_pool/metadata instead of rebuilding from an empty pool")
    parser.add_argument("--strategy", choices=("rare-feature", "feature-havoc", "structure-havoc", "pattern-combine"),
                        default=os.environ.get("AFL_LLM_SEED_STRATEGY", "rare-feature"))
    parser.add_argument("--feature-batch", type=int,
                        default=int(os.environ.get("AFL_LLM_SEED_FEATURE_BATCH", "2") or 2))
    parser.add_argument("--parent-generator", default=os.environ.get("AFL_LLM_SEED_PARENT_GENERATOR", "auto"),
                        help="parent generator id for mutation mode, or auto")
    parser.add_argument("--output", default=os.path.join(_seed_artifacts_dir(), "seed_generators"))
    parser.add_argument("--seeds-output", default=os.path.join(_seed_artifacts_dir(), "generated_seeds"))
    parser.add_argument("--metadata", default=os.path.join(_seed_artifacts_dir(), "seed_features.json"))
    parser.add_argument("--feature-pool", default=os.path.join(_seed_artifacts_dir(), "feature_pool.json"))
    parser.add_argument("--candidate-json", help="offline candidate JSON for tests/debugging")
    parser.add_argument("--model", default=None)
    parser.add_argument("--module-url", default=None)
    parser.add_argument("--api-key", default=None)
    parser.add_argument(
        "--max-files",
        type=int,
        default=int(os.environ.get("AFL_LLM_SEED_MAX_FILES", "10") or 10),
        help="maximum local runs and distinct valid seeds saved per generator; at least one is required",
    )
    parser.add_argument(
        "--max-features",
        type=int,
        default=int(os.environ.get("AFL_LLM_SEED_MAX_FEATURES", "0") or 0),
        help="incremental feature-pool cap; 0 means unlimited",
    )
    parser.add_argument(
        "--initial-max-features",
        type=int,
        default=int(os.environ.get("AFL_LLM_SEED_INITIAL_MAX_FEATURES", "20") or 20),
        help="initial G2FUZZ-style feature extraction cap",
    )
    parser.add_argument("--max-size", type=int, default=DEFAULT_MAX_OUTPUT_SIZE)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_SEC)
    parser.add_argument("--max-tokens", type=int, default=int(os.environ.get("AFL_LLM_SEED_MAX_TOKENS", "8192") or 8192))
    parser.add_argument("--attempts", type=int, default=int(os.environ.get("AFL_LLM_SEED_ATTEMPTS", str(DEFAULT_ATTEMPTS)) or DEFAULT_ATTEMPTS))
    parser.add_argument("--feature-attempts", type=int, default=int(os.environ.get("AFL_LLM_SEED_FEATURE_ATTEMPTS", str(DEFAULT_FEATURE_ATTEMPTS)) or DEFAULT_FEATURE_ATTEMPTS))
    parser.add_argument("--epochs", type=int, default=int(os.environ.get("AFL_LLM_SEED_EPOCHS", str(DEFAULT_EPOCHS)) or DEFAULT_EPOCHS))
    parser.add_argument("--request-timeout", type=float, default=float(os.environ.get("AFL_LLM_SEED_REQUEST_TIMEOUT", str(DEFAULT_REQUEST_TIMEOUT_SEC)) or DEFAULT_REQUEST_TIMEOUT_SEC))
    parser.add_argument("--http-retries", type=int, default=int(os.environ.get("AFL_LLM_SEED_HTTP_RETRIES", str(DEFAULT_HTTP_RETRIES)) or DEFAULT_HTTP_RETRIES))
    parser.add_argument("--request-interval", type=float, default=float(os.environ.get(REQUEST_INTERVAL_ENV, str(DEFAULT_REQUEST_INTERVAL_SEC)) or DEFAULT_REQUEST_INTERVAL_SEC))
    parser.add_argument("--rate-limit-cooldown", type=float, default=float(os.environ.get(RATE_LIMIT_COOLDOWN_ENV, str(DEFAULT_RATE_LIMIT_COOLDOWN_SEC)) or DEFAULT_RATE_LIMIT_COOLDOWN_SEC))
    parser.add_argument("--smoke-mode", choices=("auto", "executor", "generic"),
                        default=os.environ.get("AFL_LLM_SEED_SMOKE_MODE", "auto"))
    args = parser.parse_args(argv)

    file_format = str(args.format or "elf").lower()
    os.environ[REQUEST_INTERVAL_ENV] = str(max(0.0, float(args.request_interval)))
    os.environ[RATE_LIMIT_COOLDOWN_ENV] = str(max(0.0, float(args.rate_limit_cooldown)))
    executor, executor_path = _load_active_executor(required=args.smoke_mode == "executor")
    source_mode = str(args.source_mode or DEFAULT_SOURCE_MODE).strip().lower().replace("_", "-")
    if source_mode == "sample":
        if not args.input:
            raise SystemExit("[seed-generator] --source-mode sample requires --input")
        if not os.path.isfile(args.input):
            raise SystemExit(f"[seed-generator] missing --input sample: {args.input}")
        input_summary, _data = summarize_input(args.input, file_format, executor)
        input_summary["source_mode"] = "sample"
    else:
        input_summary = format_only_input_summary(file_format)
        _data = b""

    mode = args.mode
    if args.candidate_json and mode in {"g2fuzz-native", "g2fuzz"} and not args.incremental:
        sys.stderr.write(
            "[seed-generator] --candidate-json supplied; using one-shot offline mode\n"
        )
        mode = "one-shot"

    if args.incremental:
        if mode == "g2fuzz-native":
            import g2fuzz_adapter

            result = _run_noisy_stdout_on_stderr(
                g2fuzz_adapter.build_g2fuzz_native_incremental,
                file_format,
                input_summary,
                executor,
                args.output,
                args.seeds_output,
                args.metadata,
                args.feature_pool,
                max(1, int(args.max_files)),
                max(1, int(args.max_size)),
                max(1.0, float(args.timeout)),
                model=args.model,
                module_url=args.module_url,
                api_key=args.api_key,
                max_tokens=args.max_tokens,
                attempts=args.attempts,
                feature_attempts=args.feature_attempts,
                request_timeout=args.request_timeout,
                http_retries=args.http_retries,
                smoke_mode=args.smoke_mode,
                strategy=args.strategy,
                feature_batch=args.feature_batch,
                parent_generator=args.parent_generator,
                candidate_json=args.candidate_json,
            )
            result["g2fuzz_compat_rebuilt"] = g2fuzz_adapter.rebuild_g2fuzz_compat_state(
                args.output,
                args.metadata,
            )
        else:
            result = build_incremental_generators(
                file_format,
                input_summary,
                executor,
                args.output,
                args.seeds_output,
                args.metadata,
                args.feature_pool,
                max(1, int(args.max_files)),
                max(1, int(args.max_size)),
                max(1.0, float(args.timeout)),
                model=args.model,
                module_url=args.module_url,
                api_key=args.api_key,
                max_tokens=args.max_tokens,
                attempts=args.attempts,
                feature_attempts=args.feature_attempts,
                max_features=args.max_features,
                request_timeout=args.request_timeout,
                http_retries=args.http_retries,
                smoke_mode=args.smoke_mode,
                strategy=args.strategy,
                feature_batch=args.feature_batch,
                parent_generator=args.parent_generator,
                candidate_json=args.candidate_json,
            )
        seed_count = sum(len(item.get("seeds", [])) for item in result["results"])
        print(json.dumps({
            "ok": True,
            "mode": result.get("mode", "incremental"),
            "seed_mode": mode,
            "strategy": result["strategy"],
            "generator_count": len(result["results"]),
            "seed_count": seed_count,
            "feature_count": len(result["feature_pool"]),
            "new_features": result["new_features"],
            "parent_generator_id": result.get("parent_generator_id"),
            "parent_selection": result.get("parent_selection"),
            "target_selection": result.get("target_selection"),
            "generators": [
                {
                    "generator_id": item["generator_id"],
                    "generator_py": item["generator_py"],
                    "generator_json": item["generator_json"],
                    "g2fuzz_compat": item.get("g2fuzz_compat"),
                    "seed_count": len(item["seeds"]),
                    "seeds": item["seeds"],
                    "attempt": item["attempt"],
                    "primary_feature": item["candidate"].get("primary_feature"),
                    "features": item["candidate"].get("features"),
                    "feature_ids": item["candidate"].get("feature_ids"),
                    "generation_mode": item["candidate"].get("generation_mode"),
                    "generation_strategy": item["candidate"].get("generation_strategy"),
                    "mutation_source": item["candidate"].get("mutation_source"),
                    "pattern_source": item["candidate"].get("pattern_source"),
                    "parent_generator_id": item["candidate"].get("parent_generator_id"),
                }
                for item in result["results"]
            ],
            "failures": result["failures"],
            "raw_feature_outputs": result.get("raw_feature_outputs"),
            "g2fuzz_source_dir": result.get("g2fuzz_source_dir"),
            "g2fuzz_compat_rebuilt": result.get("g2fuzz_compat_rebuilt"),
            "executor_path": executor_path,
        }, indent=2, sort_keys=True))
        return 0

    if mode == "g2fuzz-native":
        import g2fuzz_adapter

        result = _run_noisy_stdout_on_stderr(
            g2fuzz_adapter.build_g2fuzz_native_generators,
            file_format,
            input_summary,
            executor,
            args.output,
            args.seeds_output,
            args.metadata,
            args.feature_pool,
            max(1, int(args.max_files)),
            max(1, int(args.max_size)),
            max(1.0, float(args.timeout)),
            model=args.model,
            module_url=args.module_url,
            api_key=args.api_key,
            max_tokens=args.max_tokens,
            attempts=args.attempts,
            feature_attempts=args.feature_attempts,
            epochs=args.epochs,
            max_features=args.initial_max_features,
            request_timeout=args.request_timeout,
            http_retries=args.http_retries,
            smoke_mode=args.smoke_mode,
        )
        result["g2fuzz_compat_rebuilt"] = g2fuzz_adapter.rebuild_g2fuzz_compat_state(
            args.output,
            args.metadata,
        )
        seed_count = sum(len(item.get("seeds", [])) for item in result["results"])
        print(json.dumps({
            "ok": True,
            "mode": "g2fuzz-native",
            "generator_count": len(result["results"]),
            "seed_count": seed_count,
            "feature_count": len(result["feature_pool"]),
            "feature_pool": result["feature_pool"],
            "target_selections": result.get("target_selections"),
            "parent_selections": result.get("parent_selections"),
            "generators": [
                {
                    "generator_id": item["generator_id"],
                    "generator_py": item["generator_py"],
                    "generator_json": item["generator_json"],
                    "g2fuzz_compat": item.get("g2fuzz_compat"),
                    "seed_count": len(item["seeds"]),
                    "seeds": item["seeds"],
                    "attempt": item["attempt"],
                    "primary_feature": item["candidate"].get("primary_feature"),
                    "features": item["candidate"].get("features"),
                    "generation_mode": item["candidate"].get("generation_mode"),
                    "generation_strategy": item["candidate"].get("generation_strategy"),
                    "mutation_source": item["candidate"].get("mutation_source"),
                    "pattern_source": item["candidate"].get("pattern_source"),
                    "parent_generator_id": item["candidate"].get("parent_generator_id"),
                    "feature_ids": item["candidate"].get("feature_ids"),
                    "target_selection": item.get("target_selection"),
                }
                for item in result["results"]
            ],
            "failures": result["failures"],
            "raw_feature_outputs": result.get("raw_feature_outputs"),
            "g2fuzz_source_dir": result.get("g2fuzz_source_dir"),
            "g2fuzz_compat_rebuilt": result.get("g2fuzz_compat_rebuilt"),
            "executor_path": executor_path,
        }, indent=2, sort_keys=True))
        return 0

    if mode == "g2fuzz":
        result = build_g2fuzz_generators(
            file_format,
            input_summary,
            executor,
            args.output,
            args.seeds_output,
            args.metadata,
            args.feature_pool,
            max(1, int(args.max_files)),
            max(1, int(args.max_size)),
            max(1.0, float(args.timeout)),
            model=args.model,
            module_url=args.module_url,
            api_key=args.api_key,
            max_tokens=args.max_tokens,
            attempts=args.attempts,
            feature_attempts=args.feature_attempts,
            epochs=args.epochs,
            max_features=args.initial_max_features,
            request_timeout=args.request_timeout,
            http_retries=args.http_retries,
            smoke_mode=args.smoke_mode,
        )
        seed_count = sum(len(item.get("seeds", [])) for item in result["results"])
        print(json.dumps({
            "ok": True,
            "mode": "g2fuzz",
            "generator_count": len(result["results"]),
            "seed_count": seed_count,
            "feature_count": len(result["feature_pool"]),
            "feature_pool": result["feature_pool"],
            "generators": [
                {
                    "generator_id": item["generator_id"],
                    "generator_py": item["generator_py"],
                    "generator_json": item["generator_json"],
                    "seed_count": len(item["seeds"]),
                    "attempt": item["attempt"],
                    "primary_feature": item["candidate"].get("primary_feature"),
                    "generation_mode": item["candidate"].get("generation_mode"),
                    "generation_strategy": item["candidate"].get("generation_strategy"),
                    "mutation_source": item["candidate"].get("mutation_source"),
                    "parent_generator_id": item["candidate"].get("parent_generator_id"),
                }
                for item in result["results"]
            ],
            "failures": result["failures"],
            "executor_path": executor_path,
        }, indent=2, sort_keys=True))
        return 0

    result = build_validated_generator(
        file_format,
        input_summary,
        executor,
        args.output,
        args.seeds_output,
        args.metadata,
        max(1, int(args.max_files)),
        max(1, int(args.max_size)),
        max(1.0, float(args.timeout)),
        model=args.model,
        module_url=args.module_url,
        api_key=args.api_key,
        max_tokens=args.max_tokens,
        attempts=args.attempts,
        candidate_json=args.candidate_json,
        request_timeout=args.request_timeout,
        http_retries=args.http_retries,
        smoke_mode=args.smoke_mode,
    )
    print(json.dumps({
        "ok": True,
        "mode": "one-shot",
        "generator_id": result["generator_id"],
        "generator_py": result["generator_py"],
        "generator_json": result["generator_json"],
        "seed_count": len(result["seeds"]),
        "seeds": result["seeds"],
        "attempt": result["attempt"],
        "previous_failures": result["failures"],
        "executor_path": executor_path,
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
