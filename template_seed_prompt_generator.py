#!/usr/bin/env python3
"""Build an LLM prompt for seed-specific format-template executor generation.

By default this script only prints the prompt.  With --call-llm it sends the
prompt through an OpenAI-compatible API, defaulting to DeepSeek, and can save
the raw response, JSON wrapper, and extracted executor code.
"""

import argparse
import ast
import base64
import hashlib
import importlib.util
import inspect
import json
import os
import random
import re
import subprocess
import sys
import tempfile
import time

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

try:
    from template_safety import validate_template_memory_safety
except ImportError:
    validate_template_memory_safety = None

import llm_config
from llm_generation_metrics import GenerationMetrics, add_metrics_to_timing_record, response_usage


DEFAULT_PREFIX_BYTES = 4096
DEFAULT_SUFFIX_BYTES = 1024
DEFAULT_FULL_BASE64_LIMIT = 32768
DEFAULT_OUTPUT_MODE = "json"
DEFAULT_DEEPSEEK_BASE_URL = "https://api.deepseek.com"
DEFAULT_DEEPSEEK_MODEL = "deepseek-chat"
DEFAULT_MAX_TOKENS = 65536
DEFAULT_REQUEST_TIMEOUT = 120.0
DEFAULT_TEMPERATURE = 0.2
DEFAULT_TOP_P = 0.95
FORMAT_EXECUTOR_DIR_NAME = "generated_format_executors"
FORMAT_EXECUTOR_DIR_ENV = "AFL_LLM_FORMAT_EXECUTOR_DIR"
TEMPLATE_EXECUTOR_DIR_ENV = "AFL_LLM_TEMPLATE_EXECUTOR_DIR"
TEMPLATE_TIMING_LOG_ENV = "AFL_LLM_TEMPLATE_TIMING_LOG"
TEMPLATE_TIMING_LOG_NAME = "template_generation_timing.jsonl"
TEMPLATE_MODEL_ENV = "AFL_LLM_TEMPLATE_MODEL"
TEMPLATE_API_KEY_ENV_ENV = "AFL_LLM_TEMPLATE_API_KEY_ENV"


SYSTEM_PROMPT = """
You generate safe local file-format mutation-template executors for authorized
greybox fuzzing.  Do not generate exploit logic, networking, shell commands,
persistence, or target-execution code.  Follow the requested output contract
exactly.
""".strip()


def _safe_text(value, max_chars=20000):
    text = "" if value is None else str(value)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    if len(text) > max_chars:
        return text[:max_chars] + "\n...[truncated]..."
    return text


def _base_dir():
    return os.path.dirname(os.path.abspath(__file__))


def _repo_relative_abs_path(path):
    path = str(path or "").strip()
    if not path:
        return None
    if not os.path.isabs(path):
        path = os.path.join(_base_dir(), path)
    return os.path.abspath(path)


def default_format_executor_dir():
    path = (
        os.environ.get(FORMAT_EXECUTOR_DIR_ENV) or
        os.environ.get(TEMPLATE_EXECUTOR_DIR_ENV) or
        FORMAT_EXECUTOR_DIR_NAME
    )
    return _repo_relative_abs_path(path)


def _timestamp_utc(epoch_seconds):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch_seconds))


def _resolve_timing_log_path(explicit_path=None, output_dir=None, disabled=False):
    if disabled:
        return None
    value = explicit_path if explicit_path is not None else os.environ.get(TEMPLATE_TIMING_LOG_ENV)
    if isinstance(value, str):
        value = value.strip()
    if value:
        if str(value).lower() in {"0", "false", "no", "off", "none"}:
            return None
        return _repo_relative_abs_path(value)
    base_dir = output_dir or default_format_executor_dir()
    return os.path.abspath(os.path.join(base_dir, TEMPLATE_TIMING_LOG_NAME))


def _finish_timing_record(record, status, error=None):
    finished_at = time.time()
    record["status"] = status
    record["finished_at"] = finished_at
    record["finished_at_utc"] = _timestamp_utc(finished_at)
    record["duration_sec"] = round(finished_at - float(record["started_at"]), 6)
    if error:
        record["error"] = str(error)[:2000]
    return record["duration_sec"]


def _append_timing_record(path, record):
    if not path:
        return
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        json.dump(record, f, ensure_ascii=True, sort_keys=True)
        f.write("\n")


def _format_id(format_name):
    text = str(format_name or "unknown").strip().lower()
    text = re.sub(r"[^a-z0-9]+", "_", text).strip("_")
    return text[:80] or "unknown"


def _hexdump(data, base_offset=0, width=16):
    lines = []
    for rel in range(0, len(data), width):
        chunk = data[rel:rel + width]
        hex_part = " ".join(f"{byte:02x}" for byte in chunk)
        ascii_part = "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in chunk)
        lines.append(f"{base_offset + rel:08x}  {hex_part:<{width * 3 - 1}}  |{ascii_part}|")
    return "\n".join(lines)


def _try_file_output(path):
    try:
        proc = subprocess.run(
            ["file", "-b", path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=2.0,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    output = (proc.stdout or proc.stderr or "").strip()
    return output or None


def _read_tool_output(items):
    result = {}
    for item in items or []:
        if "=" not in item:
            raise ValueError("--tool-output must use NAME=PATH")
        name, path = item.split("=", 1)
        name = _format_id(name)
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            result[name] = _safe_text(f.read(), max_chars=16000)
    return result


def summarize_seed(
    seed_path,
    format_name,
    target_program=None,
    target_args=None,
    file_output=None,
    tool_outputs=None,
    max_prefix_bytes=DEFAULT_PREFIX_BYTES,
    max_suffix_bytes=DEFAULT_SUFFIX_BYTES,
    full_base64_limit=DEFAULT_FULL_BASE64_LIMIT,
):
    with open(seed_path, "rb") as f:
        data = f.read()

    max_prefix_bytes = max(int(max_prefix_bytes), 0)
    max_suffix_bytes = max(int(max_suffix_bytes), 0)
    full_base64_limit = max(int(full_base64_limit), 0)

    prefix = data[:max_prefix_bytes]
    suffix = b""
    if max_suffix_bytes and len(data) > len(prefix):
        suffix = data[-max_suffix_bytes:]

    printable = sum(1 for byte in data if 32 <= byte <= 126)
    summary = {
        "format_name": str(format_name),
        "format_id": _format_id(format_name),
        "seed_filename": os.path.basename(seed_path),
        "seed_path": os.path.abspath(seed_path),
        "seed_size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "target_program": target_program,
        "target_args": target_args,
        "file_output": file_output if file_output is not None else _try_file_output(seed_path),
        "prefix_bytes": len(prefix),
        "prefix_hex": prefix.hex(),
        "prefix_hexdump": _hexdump(prefix, 0),
        "suffix_bytes": len(suffix),
        "suffix_hex": suffix.hex(),
        "suffix_hexdump": _hexdump(suffix, max(len(data) - len(suffix), 0)) if suffix else "",
        "full_base64": (
            base64.b64encode(data).decode("ascii")
            if full_base64_limit and len(data) <= full_base64_limit
            else None
        ),
        "full_base64_included": bool(full_base64_limit and len(data) <= full_base64_limit),
        "byte_windows_truncated": len(data) > len(prefix) + len(suffix),
        "seed_bytes_complete": bool(full_base64_limit and len(data) <= full_base64_limit),
        "byte_stats": {
            "zero_count": data.count(0),
            "printable_ascii_count": printable,
            "printable_ascii_ratio": (float(printable) / float(len(data))) if data else 0.0,
            "unique_byte_count": len(set(data)),
        },
        "tool_outputs": dict(tool_outputs or {}),
    }
    return summary


def build_template_generation_prompt(summary, output_mode=DEFAULT_OUTPUT_MODE):
    output_mode = str(output_mode or DEFAULT_OUTPUT_MODE).strip().lower()
    if output_mode not in {"json", "python"}:
        raise ValueError("--output-mode must be json or python")

    if output_mode == "json":
        response_contract = """
Return one JSON object only, with exactly these top-level keys:
{
  "kind": "format_template_executor_code",
  "version": 1,
  "format": "<format_id>",
  "executor_name": "<short_snake_case_name>",
  "filename": "<executor_filename.py>",
  "code": "<complete Python3 source as one string>",
  "assumptions": ["..."],
  "notes": ["..."]
}

Do not output markdown fences or prose outside the JSON object.
""".strip()
    else:
        response_contract = """
Return only the complete Python3 source code.  Do not output markdown fences,
JSON, or explanatory prose.
""".strip()

    # Hexdump already contains these bytes; omit the duplicate hex only in the
    # prompt and preserve the original summary for callers and JSON artifacts.
    prompt_summary = {
        key: value for key, value in summary.items()
        if key not in {"prefix_hex", "suffix_hex"}
    }
    context_json = json.dumps(prompt_summary, ensure_ascii=True, indent=2, sort_keys=True)
    return f"""
You are a senior fuzzing engineer specializing in file-format parsers,
coverage-guided fuzzing, and safe local mutation-template design.

Known format name:
{summary.get("format_name")}

Task:
Generate a standalone Python3 mutation-template executor from exactly one
initial seed.  You may use the known format name to guide field names and common
format invariants, but the seed bytes are the source of truth.  Because only one
seed is provided, infer only observed structural constraints and conservative
well-known invariants.  Do not claim to implement a complete parser for every
possible file of this format.

Seed and target context:
{context_json}

Output contract:
{response_contract}

Generated Python module contract:
- Use only Python standard-library imports from this allowlist:
  struct, random, json, argparse, os, sys, zlib, binascii.
- Define MAX_OUTPUT_SIZE = 1024 * 1024.
- Define DEFAULT_PROFILE as a conservative seed-derived profile.
- Define DEFAULT_PLAN as a dict with exactly this runtime shape:
  {{
    "template": "<format_id>_template_executor",
    "ops": [bounded operation descriptors],
    "limits": {{"max_output_size": MAX_OUTPUT_SIZE, "max_ops_per_call": <small integer>}}
  }}
  Do not use "operations" as the primary plan key.
- Define OP_HANDLERS as a dict mapping operation names to handler functions.
- Provide execute_template_plan(data, plan=None, profile=None, max_size=None) -> bytes.
- Provide mutate(data) -> bytes.
- Provide a CLI:
  python template_executor.py input output --plan optional_plan.json --seed optional_integer
- The module must never raise uncaught exceptions during mutation.  On internal
  failure, return the original input bytes only when len(original) <= max_size.
  If the input is already larger than max_size, return a bounded prefix no
  longer than max_size.  execute_template_plan must never return bytes longer
  than max_size.

MutatorMin runtime compatibility contract:
- Every callable registered in OP_HANDLERS MUST accept exactly the runtime
  positional arguments (buf, op, profile, max_size), or at least be bindable by:
    inspect.signature(handler).bind(bytearray(), {{}}, {{}}, MAX_OUTPUT_SIZE)
- Do not register 3-argument handlers such as (buf, profile, args).
- Each handler should read parameters directly from the op descriptor, e.g.
    field = op.get("field", default)
  It may also support op.get("args", {{}}) as a legacy alias, but must not require
  parameters to be nested only under "args".
- execute_template_plan MUST read plan operations from:
    ops = plan.get("ops", [])
  It may optionally fall back to plan.get("operations", []) for legacy plans,
  but random execution must work when only "ops" is present.
- execute_template_plan MUST dispatch handlers as:
    handler(buf, op_desc, current_profile, effective_max_size)
- execute_template_plan MUST preserve the order of plan["ops"].  Do not call
  random.sample, random.shuffle, random.choice, or any other random function
  inside execute_template_plan.  Randomness belongs inside individual mutation
  handlers only.
- The generated module must work when called as:
    execute_template_plan(data, random_plan_with_ops, DEFAULT_PROFILE, max_size)
- Random plans are assembled from OP_HANDLERS names. Therefore DEFAULT_PLAN["ops"]
  should contain one descriptor for every important handler so random selection
  can reuse safe default parameters.
- DEFAULT_PLAN["limits"]["max_ops_per_call"] must be greater than or equal to
  len(DEFAULT_PLAN["ops"]) so the default plan can run in the intended order.

Required design:
	1. Implement parse_profile(data) -> dict.
	   It should parse the current bytes dynamically when possible.  The returned
	   profile should contain:
   - "format": the normalized format id,
   - "valid": whether the seed appears to satisfy basic format evidence,
   - "header": observed header fields,
   - "regions": a list of bounded regions with name, offset, and size,
   - "tables" or "chunks" if visible,
	   - "counts", "offsets", "sizes", and "flags" if visible,
	   - "assumptions" for uncertain structure.
	   Treat every count, length, table size, entry count, sample count, and
	   offset read from the current input as attacker-controlled.  Never use a
	   declared count directly in range(), list multiplication, bytes
	   multiplication, extend(), or any allocation.  First derive a bounded count:
	     safe_count = min(declared_count, remaining_bytes // entry_size, HARD_CAP)
	   where HARD_CAP is a small literal cap appropriate for metadata parsing
	   (for example 64, 128, or 256).  Store the original declared value in
	   profile["counts"], but only materialize at most safe_count entries.
	   If the bounds cannot be proven from len(data), skip that table.

2. Implement bounded helpers.
   Include helpers for checked reads/writes, length extension, region lookup,
   and endian-aware integer handling if the format contains numeric fields.

3. Implement mutation operators in these roles when supported by the observed
   seed structure:
   - ensure_magic_or_header: restore magic bytes/signature and minimal header.
   - mutate_header_enum_or_flags: mutate type, version, flags, class, or mode fields.
   - mutate_count_length_offset_fields: mutate size/count/offset fields within
     safe bounds.
   - mutate_region: mutate bytes inside named payload regions without touching
     mandatory magic bytes.
   - construct_optional_chunk_or_record: append or insert a conservative
     chunk/record/section only when the format visibly supports such units.
   - sync_or_repair_headers: repair simple dependencies such as sizes not
     exceeding file length, offsets pointing inside the buffer, and counts
     matching generated entries.
   - append_tail_block: optional, bounded, and not the main exploration strategy.

4. Keep mutations parseable by default.
   The default plan should start with ensure/repair operations, perform a small
   number of structure-aware mutations, then run sync_or_repair_headers.
   execute_template_plan must execute this plan sequentially.  Do not randomly
   drop or reorder default operations.

5. If the format has checksums.
   Update checksums only when the algorithm is obvious from the format name and
   seed structure, such as CRC32 in PNG chunks.  Otherwise preserve checksum
   fields or document the limitation in assumptions.

6. If the format is chunk/table/section based.
   Use the format name and observed seed evidence to expose named regions.
   Examples:
   - executable/object formats: header, program/section tables, code/data regions.
   - image formats: signature, chunk/segment headers, metadata, pixel/data payload.
   - archive/container formats: member headers, directory/index, data blocks.
   - text formats: line/block/token regions and delimiter-preserving mutations.
   These are examples, not mandatory features.

	Safety and robustness rules:
	- Do not use network, subprocess, sockets, eval, exec, compile, dynamic imports,
	  shell commands, environment-variable dependent behavior, or target execution.
	- Do not read or write files except in the CLI main function for input, output,
	  and optional JSON plan loading.
	- Check every offset, count, length, table, and region before using it.
	- Do not trust parser count fields.  Code like "for i in range(entry_count)",
	  "for i in range(sample_count)", "[value] * sample_count",
	  "bytearray(count)", "b'\\0' * count", or "buf.extend(b'X' * count)" is
	  forbidden unless count was first clamped with both input-size evidence and
	  a small literal HARD_CAP.  Prefer bounded_count names for clamped values.
	- For table parsing, compute available_entries from the containing box/table
	  size before looping.  Example pattern:
	    declared = read_u32(...)
	    available = max(0, (table_end - entries_start) // entry_size)
	    bounded_count = min(declared, available, 128)
	    for i in range(bounded_count): ...
	  Do not allocate placeholder lists for unparsed declared entries.
	- Enforce max_output_size before growing the buffer.
	- Enforce max_size again before returning from execute_template_plan.  If the
	  result exceeds max_size, return a bounded result whose length is <= max_size.
	- Avoid unbounded loops and unbounded allocation.
- Return False from an operator if it cannot safely mutate.
- Return True only if the operator actually changed the buffer.
- When choosing from candidate values, exclude the current value.  If no
  different candidate exists, return False.
- When assigning random bytes or integers, retry or compute a different value
  so the handler does not report success without changing the buffer.
- If a structure is uncertain, prefer a conservative generic bounded region
  mutation instead of inventing unsupported format features.

Quality checklist before finalizing:
- The code is syntactically valid Python3.
- execute_template_plan(bytes) returns bytes for empty input and for the seed.
- mutate(data) calls execute_template_plan with DEFAULT_PLAN and DEFAULT_PROFILE.
- DEFAULT_PLAN contains a non-empty "ops" list, and every op name is present in
  OP_HANDLERS.
- Every OP_HANDLERS callable accepts (buf, op, profile, max_size).
- execute_template_plan preserves the order of plan["ops"] and contains no
  random sampling/shuffling of operations.
- execute_template_plan never returns more than max_size bytes, even when
  max_size is smaller than the input length.
- Any handler that returns True has actually modified the buffer, and any
  handler that modifies the buffer returns True.
- A random plan shaped as {{"ops": [{{"op": "..."}}], "limits": {{...}}}} actually
  reaches the selected handlers and changes the supplied seed when a mutation
  operator is selected.
- The code can run as a CLI and write the output file.
	- The generated executor is profile-specific to the supplied seed but parses
	  the current input dynamically where practical.
	- parse_profile cannot be driven into large CPU or memory use by corrupted
	  count fields; every loop over entries uses a clamped bounded_count.
	""".strip()


def _is_deepseek_model(model):
    return llm_config.is_deepseek_model(model)


def _resolve_model_name(model=None):
    return llm_config.resolve_model(
        model,
        legacy_env_names=(TEMPLATE_MODEL_ENV,),
        default=DEFAULT_DEEPSEEK_MODEL,
    )


def _module_url_for_model(model, explicit_url=None):
    model = _resolve_model_name(model)
    return llm_config.resolve_base_url(
        model,
        explicit_url=explicit_url,
        legacy_env_names=("DEEPSEEK_BASE_URL", "OPENAI_BASE_URL"),
        default_openai_compat_base_url=DEFAULT_DEEPSEEK_BASE_URL,
    )


def _api_key_for_model(model, explicit_key=None, api_key_env=None):
    model = _resolve_model_name(model)
    return llm_config.resolve_api_key(
        model,
        explicit_key=explicit_key,
        explicit_key_env=api_key_env,
        legacy_pointer_env_names=(TEMPLATE_API_KEY_ENV_ENV,),
    )


def _create_openai_client(model, base_url=None, api_key=None, timeout=DEFAULT_REQUEST_TIMEOUT):
    model = _resolve_model_name(model)
    resolved_key = _api_key_for_model(model, explicit_key=api_key)
    if not resolved_key:
        if _is_deepseek_model(model):
            raise RuntimeError(
                "missing API key; set AFL_LLM_API_KEY, AFL_LLM_API_KEY_ENV, "
                "DEEPSEEK_API_KEY, or OPENAI_API_KEY"
            )
        if llm_config.is_glm_model(model):
            raise RuntimeError(
                "missing API key; set AFL_LLM_API_KEY, AFL_LLM_API_KEY_ENV, "
                "ZHIPU_API_KEY, GLM_API_KEY, or OPENAI_API_KEY"
            )
        raise RuntimeError(
            "missing API key; set AFL_LLM_API_KEY, AFL_LLM_API_KEY_ENV, or OPENAI_API_KEY"
        )
    if llm_config.is_glm_model(model):
        if ZhipuAiClient is None:
            raise RuntimeError("zhipuai package is not installed; run `pip install zhipuai`")
        return ZhipuAiClient(api_key=resolved_key, timeout=timeout)
    if OpenAI is None:
        raise RuntimeError("openai package is not installed; run `pip install openai`")
    resolved_url = _module_url_for_model(model, base_url)
    kwargs = {"api_key": resolved_key, "timeout": timeout}
    if resolved_url:
        kwargs["base_url"] = resolved_url
    # httpx does not recognize the commonly used "socks://" alias.  If a
    # conventional HTTP(S) proxy is also configured, select it explicitly so
    # an invalid ALL_PROXY value cannot make client construction fail before
    # the request is sent.
    all_proxy = os.environ.get("ALL_PROXY") or os.environ.get("all_proxy") or ""
    http_proxy = (
        os.environ.get("HTTPS_PROXY") or
        os.environ.get("https_proxy") or
        os.environ.get("HTTP_PROXY") or
        os.environ.get("http_proxy")
    )
    if all_proxy.lower().startswith("socks://") and http_proxy and httpx is not None:
        kwargs["http_client"] = httpx.Client(proxy=http_proxy, timeout=timeout)
    return OpenAI(**kwargs)


def _build_completion_kwargs(
    model,
    user_prompt,
    output_mode=DEFAULT_OUTPUT_MODE,
    system_prompt=SYSTEM_PROMPT,
    temperature=DEFAULT_TEMPERATURE,
    max_tokens=DEFAULT_MAX_TOKENS,
    top_p=DEFAULT_TOP_P,
):
    kwargs = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": temperature,
        "max_tokens": max_tokens,
        "top_p": top_p,
        "stream": False,
    }
    if str(output_mode or DEFAULT_OUTPUT_MODE).strip().lower() == "json":
        kwargs["response_format"] = {"type": "json_object"}
    if _is_deepseek_model(model):
        kwargs["extra_body"] = {"thinking": {"type": "disabled"}}
    return kwargs


def _response_content(response):
    try:
        return (response.choices[0].message.content or "").strip()
    except (AttributeError, IndexError, TypeError):
        return ""


def _response_usage(response):
    return response_usage(response)


def _strip_code_fences(text):
    text = str(text or "").strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json|python|JSON|Python)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    return text.strip()


def extract_json_object(text):
    stripped = _strip_code_fences(text)
    try:
        parsed = json.loads(stripped)
        return parsed if isinstance(parsed, dict) else None
    except (TypeError, ValueError):
        pass

    decoder = json.JSONDecoder()
    for match in re.finditer(r"\{", stripped):
        try:
            parsed, _end = decoder.raw_decode(stripped[match.start():])
            if isinstance(parsed, dict):
                return parsed
        except (TypeError, ValueError):
            continue
    return None


def normalize_template_response(content, output_mode, format_id):
    mode = str(output_mode or DEFAULT_OUTPUT_MODE).strip().lower()
    if mode == "json":
        parsed = extract_json_object(content)
        if not isinstance(parsed, dict):
            raise ValueError("LLM response did not contain a valid JSON object")
        code = parsed.get("code")
        if not isinstance(code, str) or not code.strip():
            raise ValueError("JSON response missing non-empty 'code' field")
        parsed.setdefault("kind", "format_template_executor_code")
        parsed.setdefault("version", 1)
        parsed.setdefault("format", format_id)
        parsed.setdefault("filename", f"{format_id}_template_executor.py")
        return parsed

    code = _strip_code_fences(content)
    if not code:
        raise ValueError("LLM response did not contain Python source")
    return {
        "kind": "format_template_executor_code",
        "version": 1,
        "format": format_id,
        "executor_name": f"{format_id}_seed_template_executor",
        "filename": f"{format_id}_template_executor.py",
        "code": code,
        "assumptions": [],
        "notes": ["Response normalized from direct Python output."],
    }


def _bytes_or_none(value):
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    return None


def _effective_max_size(module):
    try:
        max_size = int(getattr(module, "MAX_OUTPUT_SIZE", 1024 * 1024))
    except (TypeError, ValueError):
        max_size = 1024 * 1024
    return max(1, max_size)


def _profile_for_validation(module, data):
    default_profile = getattr(module, "DEFAULT_PROFILE", None)
    if isinstance(default_profile, dict):
        return default_profile
    parse_profile = getattr(module, "parse_profile", None)
    if callable(parse_profile):
        try:
            profile = parse_profile(data)
            if isinstance(profile, dict):
                return profile
        except Exception:
            pass
    return {}


def _default_ops(module):
    plan = getattr(module, "DEFAULT_PLAN", None)
    if not isinstance(plan, dict):
        return []
    ops = plan.get("ops", [])
    return ops if isinstance(ops, list) else []


def _default_op_templates_for(module, op_name):
    result = []
    for op in _default_ops(module):
        if isinstance(op, dict) and op.get("op") == op_name:
            result.append(dict(op))
    return result


def _runtime_validation_op(module, op_name):
    templates = _default_op_templates_for(module, op_name)
    if templates:
        return templates[0]
    return {"op": op_name}


def _compose_validation_random_plan(module):
    handlers = getattr(module, "OP_HANDLERS", None)
    if not isinstance(handlers, dict) or not handlers:
        return None

    repair_prefix = []
    repair_suffix = []
    mutation_names = []
    for op_name in handlers:
        if not isinstance(op_name, str) or not op_name:
            continue
        lowered = op_name.lower()
        if lowered.startswith("ensure_"):
            repair_prefix.append(op_name)
        elif lowered.startswith(("sync_", "repair_")):
            repair_suffix.append(op_name)
        else:
            mutation_names.append(op_name)

    if not mutation_names:
        return None

    selected = mutation_names[:min(len(mutation_names), 4)]
    ops = []
    ops.extend(_runtime_validation_op(module, name) for name in repair_prefix)
    ops.extend(_runtime_validation_op(module, name) for name in selected)
    ops.extend(_runtime_validation_op(module, name) for name in repair_suffix)
    max_size = _effective_max_size(module)
    return {
        "template": "random_template_plan",
        "ops": ops,
        "limits": {
            "max_output_size": max_size,
            "max_ops_per_call": max(1, len(ops)),
        },
    }


def _plan_op_names(plan):
    if not isinstance(plan, dict):
        return []
    ops = plan.get("ops", [])
    if not isinstance(ops, list):
        return []
    return [
        op.get("op")
        for op in ops
        if isinstance(op, dict) and isinstance(op.get("op"), str)
    ]


def _is_mutation_op_name(op_name):
    if not isinstance(op_name, str) or not op_name:
        return False
    lowered = op_name.lower()
    return not lowered.startswith(("ensure_", "sync_", "repair_", "fix_"))


def _validate_source_quality(code):
    try:
        tree = ast.parse(code, filename="<generated_template_executor>", mode="exec")
    except SyntaxError as exc:
        return False, f"syntax error: {exc}"

    execute_node = None
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == "execute_template_plan":
            execute_node = node
            break
    if execute_node is None:
        return False, "missing execute_template_plan function"

    for node in ast.walk(execute_node):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if (
            isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Name)
            and func.value.id == "random"
        ):
            return False, (
                "execute_template_plan must preserve plan order and must not "
                f"call random.{func.attr} at line {node.lineno}"
            )
        if isinstance(func, ast.Name) and func.id in {
            "sample", "shuffle", "choice", "choices",
        }:
            return False, (
                "execute_template_plan must preserve plan order and must not "
                f"call {func.id} at line {node.lineno}"
            )
    return True, None


def _validate_handler_return_semantics(module, sample_data, max_size):
    if not sample_data:
        return True, None
    handlers = getattr(module, "OP_HANDLERS", {})
    parse_profile = getattr(module, "parse_profile", None)
    ops = _default_ops(module)
    for op in ops:
        if not isinstance(op, dict):
            continue
        op_name = op.get("op")
        handler = handlers.get(op_name)
        if not callable(handler):
            continue
        for trial in range(12):
            random.seed(trial)
            buf = bytearray(sample_data)
            before = bytes(buf)
            if callable(parse_profile):
                try:
                    profile = parse_profile(before)
                    if not isinstance(profile, dict):
                        profile = _profile_for_validation(module, before)
                except Exception:
                    profile = _profile_for_validation(module, before)
            else:
                profile = _profile_for_validation(module, before)
            try:
                returned = bool(handler(buf, op, profile, max_size))
            except Exception:
                continue
            changed = bytes(buf) != before
            if returned and not changed:
                return False, (
                    f"OP_HANDLERS[{op_name!r}] returned True without changing "
                    f"the buffer for DEFAULT_PLAN op {op!r}"
                )
            if changed and not returned:
                return False, (
                    f"OP_HANDLERS[{op_name!r}] changed the buffer but returned "
                    f"False for DEFAULT_PLAN op {op!r}"
                )
            if len(buf) > max_size:
                return False, (
                    f"OP_HANDLERS[{op_name!r}] exceeded max_size for "
                    f"DEFAULT_PLAN op {op!r}"
                )
    return True, None


def _validate_executor_module(module, sample_data=None):
    for attr in ("MAX_OUTPUT_SIZE", "DEFAULT_PROFILE", "DEFAULT_PLAN",
                 "OP_HANDLERS", "execute_template_plan", "mutate"):
        if not hasattr(module, attr):
            return False, f"missing required module attribute: {attr}"

    default_plan = getattr(module, "DEFAULT_PLAN", None)
    if not isinstance(default_plan, dict):
        return False, "DEFAULT_PLAN must be a dict"
    ops = default_plan.get("ops")
    if not isinstance(ops, list) or not ops:
        return False, 'DEFAULT_PLAN must contain a non-empty "ops" list'
    limits = default_plan.get("limits", {})
    if isinstance(limits, dict) and "max_ops_per_call" in limits:
        try:
            max_ops_per_call = int(limits.get("max_ops_per_call"))
        except (TypeError, ValueError):
            return False, 'DEFAULT_PLAN["limits"]["max_ops_per_call"] must be an integer'
        if max_ops_per_call < len(ops):
            return False, (
                'DEFAULT_PLAN["limits"]["max_ops_per_call"] must be >= '
                'len(DEFAULT_PLAN["ops"]) so the default plan can run in order'
            )

    handlers = getattr(module, "OP_HANDLERS", None)
    if not isinstance(handlers, dict) or not handlers:
        return False, "OP_HANDLERS must be a non-empty dict"

    max_size = _effective_max_size(module)
    for op_name, handler in handlers.items():
        if not isinstance(op_name, str) or not op_name:
            return False, "OP_HANDLERS keys must be non-empty strings"
        if not callable(handler):
            return False, f"OP_HANDLERS[{op_name!r}] is not callable"
        try:
            inspect.signature(handler).bind(bytearray(), {}, {}, max_size)
        except (TypeError, ValueError) as exc:
            return False, (
                f"OP_HANDLERS[{op_name!r}] must accept runtime arguments "
                f"(buf, op, profile, max_size): {exc}"
            )

    for index, op in enumerate(ops):
        if not isinstance(op, dict):
            return False, f"DEFAULT_PLAN['ops'][{index}] must be a dict"
        op_name = op.get("op")
        if op_name not in handlers:
            return False, (
                f"DEFAULT_PLAN['ops'][{index}] references missing handler "
                f"{op_name!r}"
            )

    execute = getattr(module, "execute_template_plan", None)
    if not callable(execute):
        return False, "execute_template_plan is not callable"
    try:
        inspect.signature(execute).bind(b"", default_plan, None, max_size)
    except (TypeError, ValueError) as exc:
        return False, (
            "execute_template_plan must accept runtime arguments "
            "(data, plan, profile, max_size): "
            f"{exc}"
        )

    mutate = getattr(module, "mutate", None)
    if not callable(mutate):
        return False, "mutate is not callable"

    for label, data in (("empty input", b""), ("seed input", sample_data or b"")):
        try:
            result = execute(data, default_plan, None, max_size)
        except Exception as exc:
            return False, f"execute_template_plan raised on {label}: {exc}"
        result_bytes = _bytes_or_none(result)
        if result_bytes is None:
            return False, f"execute_template_plan returned non-bytes on {label}"
        if len(result_bytes) > max_size:
            return False, f"execute_template_plan exceeded max_size on {label}"

    if sample_data:
        strict_limit = max(1, len(sample_data) - 1)
        try:
            result = execute(sample_data, default_plan, None, strict_limit)
        except Exception as exc:
            return False, f"execute_template_plan raised with small max_size: {exc}"
        result_bytes = _bytes_or_none(result)
        if result_bytes is None:
            return False, "execute_template_plan returned non-bytes with small max_size"
        if len(result_bytes) > strict_limit:
            return False, (
                "execute_template_plan must never return more than max_size bytes; "
                f"got {len(result_bytes)} bytes for max_size={strict_limit}"
            )

        ok, error = _validate_handler_return_semantics(module, sample_data, max_size)
        if not ok:
            return False, error

        random_plan = _compose_validation_random_plan(module)
        if not isinstance(random_plan, dict):
            return False, "could not compose a random ops plan from OP_HANDLERS"
        profile = _profile_for_validation(module, sample_data)
        try:
            result = execute(sample_data, random_plan, profile, max_size)
        except Exception as exc:
            return False, f"random ops plan execution raised: {exc}"
        result_bytes = _bytes_or_none(result)
        if result_bytes is None:
            return False, "random ops plan returned non-bytes"
        if len(result_bytes) > max_size:
            return False, "random ops plan exceeded max_size"
        if result_bytes == sample_data:
            return False, (
                "random ops plan did not change the seed; the executor may be "
                'ignoring plan["ops"] or the selected handlers are ineffective'
            )

    return True, None


def validate_generated_template_code(code, sample_data=None):
    if not isinstance(code, str) or not code.strip():
        return False, "generated code is empty"
    try:
        compile(code, "<generated_template_executor>", "exec")
    except SyntaxError as exc:
        return False, f"syntax error: {exc}"

    ok, error = _validate_source_quality(code)
    if not ok:
        return False, error

    if validate_template_memory_safety is not None:
        ok, error = validate_template_memory_safety(code)
        if not ok:
            return False, error

    with tempfile.TemporaryDirectory(prefix="template_seed_validate_") as tmp_dir:
        module_path = os.path.join(tmp_dir, "generated_template_executor.py")
        with open(module_path, "w", encoding="utf-8") as f:
            f.write(code)
        try:
            spec = importlib.util.spec_from_file_location(
                "_generated_template_executor_validation",
                module_path,
            )
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
        except Exception as exc:
            return False, f"import error: {exc}"
        return _validate_executor_module(module, sample_data=sample_data)


def validate_template_response_wrapper(wrapper, sample_data=None):
    if not isinstance(wrapper, dict):
        return False, "normalized response is not a JSON object"
    return validate_generated_template_code(wrapper.get("code"), sample_data=sample_data)


def _prompt_with_validation_feedback(prompt, validation_error):
    feedback = _safe_text(validation_error, max_chars=4000)
    return f"""
{prompt}

Previous generated executor failed local MutatorMin compatibility validation:
{feedback}

	Regenerate the complete executor from scratch.  Fix the reported issue.  In
	particular, ensure OP_HANDLERS callables accept (buf, op, profile, max_size),
	DEFAULT_PLAN uses a non-empty "ops" list, execute_template_plan dispatches
	plan["ops"] sequentially without random sampling/shuffling, no output exceeds
	max_size, handlers return True only after changing the buffer, and a random ops
	plan changes the supplied seed.  Also treat all input-derived count/length
	fields as attacker-controlled: never loop over or allocate from entry_count,
	sample_count, size, or length until it is clamped by remaining input bytes and
	a small literal HARD_CAP.
	""".strip()


def request_template_from_llm(
    prompt,
    output_mode=DEFAULT_OUTPUT_MODE,
    format_id="unknown",
    model=None,
    base_url=None,
    api_key=None,
    api_key_env=None,
    temperature=DEFAULT_TEMPERATURE,
    max_tokens=DEFAULT_MAX_TOKENS,
    top_p=DEFAULT_TOP_P,
    timeout=DEFAULT_REQUEST_TIMEOUT,
    retries=1,
    retry_delay=2.0,
    raw_output_path=None,
    validate_generated=True,
    sample_data=None,
):
    metrics = GenerationMetrics("llm_client_retries_validation")
    model = _resolve_model_name(model)
    api_key = _api_key_for_model(model, explicit_key=api_key, api_key_env=api_key_env)
    client = _create_openai_client(model, base_url=base_url, api_key=api_key, timeout=timeout)
    attempts = max(int(retries), 0) + 1
    last_error = None
    last_content = ""
    attempt_prompt = prompt

    for attempt in range(attempts):
        if attempt and retry_delay > 0:
            time.sleep(float(retry_delay))
        try:
            response = metrics.call(
                client.chat.completions.create,
                **_build_completion_kwargs(
                    model,
                    attempt_prompt,
                    output_mode=output_mode,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    top_p=top_p,
                )
            )
            content = _response_content(response)
            if raw_output_path:
                write_or_print(content, raw_output_path)
            last_content = content
            wrapper = normalize_template_response(content, output_mode, format_id)
            if validate_generated:
                ok, error = validate_template_response_wrapper(
                    wrapper,
                    sample_data=sample_data,
                )
                if not ok:
                    last_error = ValueError(
                        f"generated executor validation failed: {error}"
                    )
                    attempt_prompt = _prompt_with_validation_feedback(prompt, error)
                    continue
            wrapper["_llm"] = {
                "model": model,
                "base_url": _module_url_for_model(model, base_url),
                "usage": _response_usage(response),
                "validated": bool(validate_generated),
                "metrics": metrics.snapshot(),
            }
            return wrapper
        except Exception as exc:
            last_error = exc
            if last_content:
                attempt_prompt = _prompt_with_validation_feedback(prompt, str(exc))

    if last_content and raw_output_path:
        write_or_print(last_content, raw_output_path)
    failure = RuntimeError(f"LLM template request failed after {attempts} attempt(s): {last_error}")
    failure.generation_metrics = metrics.snapshot()
    raise failure


def save_template_artifacts(wrapper, output_json=None, output_code=None, output_dir=None):
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
    format_id = _format_id(wrapper.get("format") or "unknown")
    filename = str(wrapper.get("filename") or f"{format_id}_template_executor.py")
    filename = os.path.basename(filename)

    if output_code is None and output_dir:
        output_code = os.path.join(output_dir, filename)
    if output_json is None and output_dir:
        output_json = os.path.join(output_dir, f"{os.path.splitext(filename)[0]}.json")

    code = wrapper.get("code")
    if output_code and isinstance(code, str):
        write_or_print(code, output_code)
    if output_json:
        write_or_print(json.dumps(wrapper, ensure_ascii=True, indent=2, sort_keys=True), output_json)

    return {
        "json": os.path.abspath(output_json) if output_json else None,
        "code": os.path.abspath(output_code) if output_code else None,
    }


def write_or_print(text, output_path=None):
    if output_path:
        parent = os.path.dirname(os.path.abspath(output_path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(text)
            if not text.endswith("\n"):
                f.write("\n")
    else:
        print(text)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Generate an LLM prompt for one-seed format-template executor synthesis."
    )
    parser.add_argument("format", help="known file format name, e.g. elf, png, pdf, zip")
    parser.add_argument("seed", help="initial seed file")
    parser.add_argument("-o", "--output", help="write prompt to this file instead of stdout")
    parser.add_argument("--summary-json", help="also write the seed summary JSON to this file")
    parser.add_argument("--target-program", help="target program name, e.g. objdump")
    parser.add_argument("--target-args", help="target invocation shape, e.g. '-d @@'")
    parser.add_argument("--file-output", help="override file(1) output text")
    parser.add_argument(
        "--tool-output",
        action="append",
        default=[],
        help="additional parser/tool output as NAME=PATH; may be repeated",
    )
    parser.add_argument("--max-prefix-bytes", type=int, default=DEFAULT_PREFIX_BYTES)
    parser.add_argument("--max-suffix-bytes", type=int, default=DEFAULT_SUFFIX_BYTES)
    parser.add_argument("--full-base64-limit", type=int, default=DEFAULT_FULL_BASE64_LIMIT)
    parser.add_argument(
        "--output-mode",
        choices=("json", "python"),
        default=DEFAULT_OUTPUT_MODE,
        help="ask the LLM for JSON-wrapped code or direct Python source",
    )
    parser.add_argument(
        "--call-llm",
        action="store_true",
        help="send the generated prompt to an OpenAI-compatible LLM endpoint",
    )
    parser.add_argument(
        "--model",
        default=None,
        help=(
            "LLM model name; defaults to AFL_LLM_MODEL, then "
            f"{TEMPLATE_MODEL_ENV}, then MODULE_NAME, then {DEFAULT_DEEPSEEK_MODEL}"
        ),
    )
    parser.add_argument(
        "--base-url",
        default=None,
        help=f"OpenAI-compatible base URL; defaults to {DEFAULT_DEEPSEEK_BASE_URL} for DeepSeek",
    )
    parser.add_argument("--api-key", help="explicit API key; otherwise use env")
    parser.add_argument(
        "--api-key-env",
        help=(
            "environment variable that stores the API key; defaults to "
            "AFL_LLM_API_KEY/AFL_LLM_API_KEY_ENV, then legacy provider envs"
        ),
    )
    parser.add_argument("--temperature", type=float, default=DEFAULT_TEMPERATURE)
    parser.add_argument("--max-tokens", type=int, default=DEFAULT_MAX_TOKENS)
    parser.add_argument("--top-p", type=float, default=DEFAULT_TOP_P)
    parser.add_argument("--timeout", type=float, default=DEFAULT_REQUEST_TIMEOUT)
    parser.add_argument("--retries", type=int, default=1)
    parser.add_argument("--retry-delay", type=float, default=2.0)
    parser.add_argument("--raw-output", help="write raw LLM response text to this path")
    parser.add_argument("--output-json", help="write normalized LLM JSON wrapper to this path")
    parser.add_argument("--output-code", help="write extracted executor Python code to this path")
    parser.add_argument(
        "--timing-log",
        help=(
            "append template generation timing records to this JSONL file; "
            f"default uses ${TEMPLATE_TIMING_LOG_ENV}, then output-dir/{TEMPLATE_TIMING_LOG_NAME}"
        ),
    )
    parser.add_argument(
        "--no-timing-log",
        action="store_true",
        help="disable template generation timing log output",
    )
    parser.add_argument(
        "--no-validate",
        action="store_true",
        help="skip local MutatorMin compatibility validation for generated code",
    )
    parser.add_argument(
        "--output-dir",
        help=(
            "directory for generated wrapper/code artifacts when --call-llm is used; "
            f"default uses ${FORMAT_EXECUTOR_DIR_ENV}, then ${TEMPLATE_EXECUTOR_DIR_ENV}, "
            f"then {FORMAT_EXECUTOR_DIR_NAME}"
        ),
    )
    args = parser.parse_args(argv)
    generation_started_at = time.time()
    resolved_model = _resolve_model_name(args.model)

    tool_outputs = _read_tool_output(args.tool_output)
    summary = summarize_seed(
        args.seed,
        args.format,
        target_program=args.target_program,
        target_args=args.target_args,
        file_output=args.file_output,
        tool_outputs=tool_outputs,
        max_prefix_bytes=args.max_prefix_bytes,
        max_suffix_bytes=args.max_suffix_bytes,
        full_base64_limit=args.full_base64_limit,
    )
    prompt = build_template_generation_prompt(summary, output_mode=args.output_mode)

    if args.summary_json:
        write_or_print(json.dumps(summary, ensure_ascii=True, indent=2, sort_keys=True), args.summary_json)
    if args.output:
        write_or_print(prompt, args.output)
    elif not args.call_llm:
        write_or_print(prompt, None)

    if args.call_llm:
        output_dir = args.output_dir
        if not output_dir and not args.output_json and not args.output_code:
            output_dir = default_format_executor_dir()
        timing_log_path = _resolve_timing_log_path(
            args.timing_log,
            output_dir=output_dir,
            disabled=args.no_timing_log,
        )
        started_at = generation_started_at
        timing_record = {
            "version": 1,
            "tool": "template_seed_prompt_generator",
            "event": "template_generation",
            "timer_scope": "seed_summary_prompt_llm_validation_save",
            "format": summary["format_id"],
            "seed": os.path.abspath(args.seed),
            "target_program": args.target_program,
            "target_args": args.target_args,
            "model": resolved_model,
            "base_url": _module_url_for_model(resolved_model, args.base_url),
            "output_mode": args.output_mode,
            "output_dir": os.path.abspath(output_dir) if output_dir else None,
            "output_json": os.path.abspath(args.output_json) if args.output_json else None,
            "output_code": os.path.abspath(args.output_code) if args.output_code else None,
            "raw_output": os.path.abspath(args.raw_output) if args.raw_output else None,
            "validation_enabled": not args.no_validate,
            "retries": args.retries,
            "retry_delay": args.retry_delay,
            "max_tokens": args.max_tokens,
            "timeout": args.timeout,
            "started_at": started_at,
            "started_at_utc": _timestamp_utc(started_at),
        }
        sample_data = None
        if not args.no_validate:
            with open(args.seed, "rb") as f:
                sample_data = f.read()
        try:
            wrapper = request_template_from_llm(
                prompt,
                output_mode=args.output_mode,
                format_id=summary["format_id"],
                model=resolved_model,
                base_url=args.base_url,
                api_key=args.api_key,
                api_key_env=args.api_key_env,
                temperature=args.temperature,
                max_tokens=args.max_tokens,
                top_p=args.top_p,
                timeout=args.timeout,
                retries=args.retries,
                retry_delay=args.retry_delay,
                raw_output_path=args.raw_output,
                validate_generated=not args.no_validate,
                sample_data=sample_data,
            )
            add_metrics_to_timing_record(timing_record, wrapper.get("_llm", {}).get("metrics"))
            artifacts = save_template_artifacts(
                wrapper,
                output_json=args.output_json,
                output_code=args.output_code,
                output_dir=output_dir,
            )
            timing_record["artifacts"] = artifacts
            timing_record["executor_name"] = wrapper.get("executor_name")
            _finish_timing_record(timing_record, "ok")
        except Exception as exc:
            add_metrics_to_timing_record(timing_record, getattr(exc, "generation_metrics", None))
            _finish_timing_record(timing_record, "failed", error=exc)
            _append_timing_record(timing_log_path, timing_record)
            raise
        _append_timing_record(timing_log_path, timing_record)
        result = {
            "ok": True,
            "format": wrapper.get("format"),
            "filename": wrapper.get("filename"),
            "executor_name": wrapper.get("executor_name"),
            "artifacts": artifacts,
            "llm": wrapper.get("_llm", {}),
            "timing": {
                "duration_sec": timing_record.get("duration_sec"),
                "log": timing_log_path,
            },
            "validated": not args.no_validate,
        }
        print(json.dumps(result, ensure_ascii=True, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
